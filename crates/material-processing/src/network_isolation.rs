use crate::types::{
    NetworkIsolationEvidence, NetworkIsolationRuleEvidence, ProcessingError,
    WINDOWS_FIREWALL_ISOLATION_MECHANISM,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

const MAX_FIREWALL_RULE_NAME_BYTES: usize = 128;
const MAX_NETWORK_PROGRAMS: usize = 64;
const MAX_PROBE_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIsolationMeasurement {
    pub schema_version: u16,
    pub rule_name: String,
    pub program_path: String,
    pub policy_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeNetworkIsolationMeasurement {
    pub schema_version: u16,
    pub measurements: Vec<NetworkIsolationMeasurement>,
    pub bundle_sha256: String,
}

/// Re-measure one active Windows Firewall rule bound to one executable.
///
/// This function never mutates firewall policy. Non-Windows production OCR
/// deliberately fails closed.
pub fn measure_windows_firewall_isolation(
    executable: &Path,
    rule_name: &str,
) -> Result<NetworkIsolationMeasurement, ProcessingError> {
    validate_rule_name(rule_name)?;
    platform::measure(executable, rule_name)
}

/// Build the only PowerShell process allowed at the MinerU network-isolation
/// boundary. The executable is resolved from the Windows directory API rather
/// than inherited environment variables, every path component is checked for
/// reparse points, and the child receives a fixed minimal environment.
#[cfg(windows)]
pub fn trusted_windows_powershell_command() -> Result<std::process::Command, ProcessingError> {
    platform::trusted_powershell_command()
}

#[cfg(windows)]
pub(crate) fn trusted_windows_directory() -> Result<PathBuf, ProcessingError> {
    platform::windows_directory()
}

/// Verify that every trusted runtime executable has exactly one expected,
/// active, program-scoped outbound block rule, and that no evidence entry is
/// unused. The active policy is measured on every call.
pub fn verify_network_isolation(
    executables: &[PathBuf],
    evidence: &NetworkIsolationEvidence,
) -> Result<RuntimeNetworkIsolationMeasurement, ProcessingError> {
    if !evidence.verified
        || evidence.checked_at_unix == 0
        || evidence.mechanism != WINDOWS_FIREWALL_ISOLATION_MECHANISM
        || executables.is_empty()
        || executables.len() > MAX_NETWORK_PROGRAMS
        || evidence.rules.len() != executables.len()
    {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }

    let mut expected_programs = BTreeMap::<String, PathBuf>::new();
    for executable in executables {
        let canonical = fs::canonicalize(executable)
            .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        let key = normalized_path(&canonical)?;
        if expected_programs.insert(key, canonical).is_some() {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
    }

    let mut rules = BTreeMap::<String, &NetworkIsolationRuleEvidence>::new();
    let mut names = BTreeSet::new();
    for rule in &evidence.rules {
        validate_rule_name(&rule.firewall_rule_name)?;
        if !valid_sha256(&rule.expected_policy_sha256)
            || !names.insert(rule.firewall_rule_name.to_ascii_lowercase())
        {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
        let canonical = fs::canonicalize(&rule.program_path)
            .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        let key = normalized_path(&canonical)?;
        if rules.insert(key, rule).is_some() {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
    }
    if expected_programs.keys().ne(rules.keys()) {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }

    let mut measurements = Vec::with_capacity(expected_programs.len());
    for (key, executable) in expected_programs {
        let rule = rules
            .get(&key)
            .ok_or(ProcessingError::OcrWorkerIsolationUnverified)?;
        let measured = measure_windows_firewall_isolation(&executable, &rule.firewall_rule_name)?;
        if measured.policy_sha256 != rule.expected_policy_sha256.to_ascii_lowercase() {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
        measurements.push(measured);
    }
    measurements.sort();

    let canonical = measurements
        .iter()
        .map(|measurement| {
            format!(
                "{}\n{}\n{}",
                measurement.program_path, measurement.rule_name, measurement.policy_sha256
            )
        })
        .collect::<Vec<_>>()
        .join("\n--\n");
    Ok(RuntimeNetworkIsolationMeasurement {
        schema_version: 1,
        measurements,
        bundle_sha256: sha256_hex(canonical.as_bytes()),
    })
}

fn validate_rule_name(value: &str) -> Result<(), ProcessingError> {
    if value.is_empty()
        || value.len() > MAX_FIREWALL_RULE_NAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallProbe {
    schema_version: u16,
    rule_name: String,
    enabled: String,
    direction: String,
    action: String,
    profiles: String,
    program: String,
    protocol: String,
    local_port: String,
    remote_port: String,
    local_address: String,
    remote_address: String,
    interface_type: String,
    service: String,
    domain_profile_enabled: String,
    private_profile_enabled: String,
    public_profile_enabled: String,
}

fn validate_probe(
    bytes: &[u8],
    executable: &Path,
    expected_rule_name: &str,
) -> Result<NetworkIsolationMeasurement, ProcessingError> {
    if bytes.is_empty() || bytes.len() > MAX_PROBE_OUTPUT_BYTES {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }
    let probe: FirewallProbe =
        serde_json::from_slice(bytes).map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
    let expected_program = normalized_path(executable)?;
    let actual_program = normalized_path(Path::new(&probe.program))?;
    if probe.schema_version != 1
        || probe.rule_name != expected_rule_name
        || !eq(&probe.enabled, "true")
        || !eq(&probe.direction, "outbound")
        || !eq(&probe.action, "block")
        || !eq(&probe.profiles, "any")
        || actual_program != expected_program
        || !(eq(&probe.protocol, "any") || probe.protocol == "256")
        || !eq(&probe.local_port, "any")
        || !eq(&probe.remote_port, "any")
        || !eq(&probe.local_address, "any")
        || !eq(&probe.remote_address, "any")
        || !eq(&probe.interface_type, "any")
        || !eq(&probe.service, "any")
        || !eq(&probe.domain_profile_enabled, "true")
        || !eq(&probe.private_profile_enabled, "true")
        || !eq(&probe.public_profile_enabled, "true")
    {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }

    let canonical = [
        "windows-defender-firewall-program-block-v1",
        &probe.rule_name,
        &expected_program,
        "enabled=true",
        "direction=outbound",
        "action=block",
        "profiles=any",
        "protocol=any",
        "local_port=any",
        "remote_port=any",
        "local_address=any",
        "remote_address=any",
        "interface_type=any",
        "service=any",
        "domain_profile_enabled=true",
        "private_profile_enabled=true",
        "public_profile_enabled=true",
    ]
    .join("\n");
    Ok(NetworkIsolationMeasurement {
        schema_version: 1,
        rule_name: probe.rule_name,
        program_path: expected_program,
        policy_sha256: sha256_hex(canonical.as_bytes()),
    })
}

fn normalized_path(path: &Path) -> Result<String, ProcessingError> {
    if !path.is_absolute() {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }
    let rendered = path
        .to_str()
        .ok_or(ProcessingError::OcrWorkerIsolationUnverified)?
        .replace('/', "\\");
    #[cfg(windows)]
    {
        let without_verbatim = if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{unc}")
        } else if let Some(dos) = rendered.strip_prefix(r"\\?\") {
            dos.to_owned()
        } else {
            rendered
        };
        Ok(without_verbatim.to_ascii_lowercase())
    }
    #[cfg(not(windows))]
    {
        Ok(rendered)
    }
}

fn eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use super::{validate_probe, NetworkIsolationMeasurement, MAX_PROBE_OUTPUT_BYTES};
    use crate::types::ProcessingError;
    use std::{
        ffi::OsString,
        fs,
        io::Read,
        os::windows::ffi::OsStringExt,
        path::{Path, PathBuf},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
    const POWERSHELL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$targetName = $env:LA_FIREWALL_RULE_NAME
$targetProgram = [IO.Path]::GetFullPath($env:LA_FIREWALL_PROGRAM)
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
$domain = @($profiles | Where-Object { [string]$_.Name -eq 'Domain' })
$private = @($profiles | Where-Object { [string]$_.Name -eq 'Private' })
$public = @($profiles | Where-Object { [string]$_.Name -eq 'Public' })
if ($domain.Count -ne 1 -or $private.Count -ne 1 -or $public.Count -ne 1) {
    throw 'profile-count'
}
$rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Name $targetName |
    Where-Object { $_.Name -ceq $targetName })
if ($rules.Count -ne 1) { throw 'rule-count' }
$rule = $rules[0]
$app = @($rule | Get-NetFirewallApplicationFilter)
$port = @($rule | Get-NetFirewallPortFilter)
$address = @($rule | Get-NetFirewallAddressFilter)
$interface = @($rule | Get-NetFirewallInterfaceTypeFilter)
$service = @($rule | Get-NetFirewallServiceFilter)
if ($app.Count -ne 1 -or $port.Count -ne 1 -or $address.Count -ne 1 -or
    $interface.Count -ne 1 -or $service.Count -ne 1) { throw 'filter-count' }
$program = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$app[0].Program))
$result = [ordered]@{
    schemaVersion = 1
    ruleName = [string]$rule.Name
    enabled = [string]$rule.Enabled
    direction = [string]$rule.Direction
    action = [string]$rule.Action
    profiles = [string]$rule.Profile
    program = $program
    protocol = [string]$port[0].Protocol
    localPort = ([string[]]$port[0].LocalPort -join ',')
    remotePort = ([string[]]$port[0].RemotePort -join ',')
    localAddress = ([string[]]$address[0].LocalAddress -join ',')
    remoteAddress = ([string[]]$address[0].RemoteAddress -join ',')
    interfaceType = ([string[]]$interface[0].InterfaceType -join ',')
    service = [string]$service[0].Service
    domainProfileEnabled = [string]$domain[0].Enabled
    privateProfileEnabled = [string]$private[0].Enabled
    publicProfileEnabled = [string]$public[0].Enabled
}
$result | ConvertTo-Json -Compress
"#;

    pub(super) fn measure(
        executable: &Path,
        rule_name: &str,
    ) -> Result<NetworkIsolationMeasurement, ProcessingError> {
        let executable = fs::canonicalize(executable)
            .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        let mut child = trusted_powershell_command()?
            .arg("-NoLogo")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(POWERSHELL_SCRIPT)
            .env("LA_FIREWALL_RULE_NAME", rule_name)
            .env("LA_FIREWALL_PROGRAM", &executable)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        let started = Instant::now();
        let status = loop {
            if started.elapsed() >= PROBE_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ProcessingError::OcrWorkerIsolationUnverified);
            }
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ProcessingError::OcrWorkerIsolationUnverified);
                }
            }
        };
        if !status.success() {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
        let stdout = child
            .stdout
            .take()
            .ok_or(ProcessingError::OcrWorkerIsolationUnverified)?;
        let mut bytes = Vec::new();
        stdout
            .take(MAX_PROBE_OUTPUT_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        validate_probe(&bytes, &executable, rule_name)
    }

    pub(super) fn trusted_powershell_command() -> Result<Command, ProcessingError> {
        let (powershell, system_root) = trusted_powershell_path()?;
        let system32 = system_root.join("System32");
        let module_path = system32.join("WindowsPowerShell/v1.0/Modules");
        let mut command = Command::new(powershell);
        command
            .env_clear()
            .env("SystemRoot", &system_root)
            .env("WINDIR", &system_root)
            .env("PATH", &system32)
            .env("PSModulePath", &module_path);
        Ok(command)
    }

    fn trusted_powershell_path() -> Result<(PathBuf, PathBuf), ProcessingError> {
        let system_root = windows_directory()?;
        let canonical_root = fs::canonicalize(&system_root)
            .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        let path = system_root.join("System32/WindowsPowerShell/v1.0/powershell.exe");
        for component in path.ancestors() {
            let metadata = fs::symlink_metadata(component)
                .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
            if std::os::windows::fs::MetadataExt::file_attributes(&metadata) & 0x400 != 0 {
                return Err(ProcessingError::OcrWorkerIsolationUnverified);
            }
            if component == system_root {
                break;
            }
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        if !metadata.is_file()
            || std::os::windows::fs::MetadataExt::file_attributes(&metadata) & 0x400 != 0
        {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
        let canonical =
            fs::canonicalize(&path).map_err(|_| ProcessingError::OcrWorkerIsolationUnverified)?;
        if !canonical.starts_with(&canonical_root) {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
        Ok((canonical, system_root))
    }

    pub(super) fn windows_directory() -> Result<PathBuf, ProcessingError> {
        let mut buffer = vec![0u16; 32_768];
        let written = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if written == 0 || written as usize >= buffer.len() {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
        buffer.truncate(written as usize);
        let path = PathBuf::from(OsString::from_wide(&buffer));
        if !path.is_absolute() {
            return Err(ProcessingError::OcrWorkerIsolationUnverified);
        }
        Ok(path)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::NetworkIsolationMeasurement;
    use crate::types::ProcessingError;
    use std::path::Path;

    pub(super) fn measure(
        _executable: &Path,
        _rule_name: &str,
    ) -> Result<NetworkIsolationMeasurement, ProcessingError> {
        Err(ProcessingError::OcrWorkerIsolationUnverified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    const TRUSTED_POWERSHELL_CHILD_ENV: &str = "LA_TEST_TRUSTED_POWERSHELL_CHILD";
    #[cfg(windows)]
    const TRUSTED_POWERSHELL_POISON_ENV: &str = "LA_TEST_TRUSTED_POWERSHELL_POISON";

    fn probe(program: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "ruleName": "LawyerAssistance-MinerU-v1",
            "enabled": "True",
            "direction": "Outbound",
            "action": "Block",
            "profiles": "Any",
            "program": program,
            "protocol": "Any",
            "localPort": "Any",
            "remotePort": "Any",
            "localAddress": "Any",
            "remoteAddress": "Any",
            "interfaceType": "Any",
            "service": "Any",
            "domainProfileEnabled": "True",
            "privateProfileEnabled": "True",
            "publicProfileEnabled": "True"
        }))
        .expect("probe")
    }

    /// Exact child-process helper for the following test. A normal test run
    /// has no marker and returns without changing process-global environment.
    #[cfg(windows)]
    #[test]
    fn trusted_powershell_poison_child() {
        if std::env::var_os(TRUSTED_POWERSHELL_CHILD_ENV).is_none() {
            return;
        }
        let mut command = trusted_windows_powershell_command().expect("trusted PowerShell");
        let windows = platform::windows_directory().expect("Windows directory");
        let expected_program =
            std::fs::canonicalize(windows.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
                .expect("canonical system PowerShell");
        assert_eq!(
            normalized_path(Path::new(command.get_program())).expect("program path"),
            normalized_path(&expected_program).expect("expected program path")
        );

        let output = command
            .arg("-NoLogo")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(
                r#"[ordered]@{systemRoot=$env:SystemRoot;windir=$env:WINDIR;path=$env:PATH;psModulePath=$env:PSModulePath;poison=$env:LA_TEST_TRUSTED_POWERSHELL_POISON;psHome=$PSHOME}|ConvertTo-Json -Compress"#,
            )
            .output()
            .expect("trusted PowerShell starts");
        assert!(
            output.status.success(),
            "trusted PowerShell environment probe failed"
        );
        let text = String::from_utf8(output.stdout).expect("UTF-8 PowerShell probe");
        let value: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}').trim()).expect("probe JSON");
        let expected_system32 = windows.join("System32");
        let expected_module_path = expected_system32.join("WindowsPowerShell/v1.0/Modules");
        for (field, expected) in [
            ("systemRoot", windows.as_path()),
            ("windir", windows.as_path()),
            ("path", expected_system32.as_path()),
            ("psModulePath", expected_module_path.as_path()),
        ] {
            let actual = value[field].as_str().expect("environment path");
            assert_eq!(
                normalized_path(Path::new(actual)).expect("actual environment path"),
                normalized_path(expected).expect("expected environment path")
            );
        }
        assert!(value["poison"].is_null());
        assert_eq!(
            normalized_path(Path::new(value["psHome"].as_str().expect("PSHOME")))
                .expect("PSHOME path"),
            normalized_path(
                expected_program
                    .parent()
                    .expect("PowerShell executable parent")
            )
            .expect("expected PSHOME path")
        );
    }

    #[cfg(windows)]
    #[test]
    fn trusted_powershell_ignores_forged_parent_environment() {
        let temporary = tempfile::tempdir().expect("temporary poison root");
        let forged = temporary.path().join("forged-system-root");
        let output = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .arg("--exact")
            .arg("network_isolation::tests::trusted_powershell_poison_child")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(TRUSTED_POWERSHELL_CHILD_ENV, "1")
            .env(TRUSTED_POWERSHELL_POISON_ENV, "must-not-survive")
            .env("SystemRoot", &forged)
            .env("WINDIR", &forged)
            .env("PATH", &forged)
            .env("PSModulePath", &forged)
            .output()
            .expect("spawn exact child test");
        assert!(
            output.status.success(),
            "trusted PowerShell child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn exact_active_firewall_shape_produces_stable_measurement() {
        let executable = if cfg!(windows) {
            Path::new(r"C:\Program Files\Lawyer Assistance\mineru-worker.exe")
        } else {
            Path::new("/opt/lawyer-assistance/mineru-worker")
        };
        let measured = validate_probe(
            &probe(executable.to_str().expect("path")),
            executable,
            "LawyerAssistance-MinerU-v1",
        )
        .expect("valid probe");
        assert!(valid_sha256(&measured.policy_sha256));
    }

    #[test]
    fn permissive_or_mismatched_rules_fail_closed() {
        let executable = if cfg!(windows) {
            Path::new(r"C:\Program Files\Lawyer Assistance\mineru-worker.exe")
        } else {
            Path::new("/opt/lawyer-assistance/mineru-worker")
        };
        let mut value: serde_json::Value =
            serde_json::from_slice(&probe(executable.to_str().expect("path"))).expect("json");
        for (field, unsafe_value) in [
            ("action", "Allow"),
            ("direction", "Inbound"),
            ("profiles", "Private"),
            ("remoteAddress", "10.0.0.0/8"),
            ("protocol", "TCP"),
            ("service", "Dnscache"),
            ("domainProfileEnabled", "False"),
            ("privateProfileEnabled", "False"),
            ("publicProfileEnabled", "False"),
        ] {
            value[field] = serde_json::Value::String(unsafe_value.to_owned());
            let bytes = serde_json::to_vec(&value).expect("bytes");
            assert_eq!(
                validate_probe(&bytes, executable, "LawyerAssistance-MinerU-v1"),
                Err(ProcessingError::OcrWorkerIsolationUnverified)
            );
            value =
                serde_json::from_slice(&probe(executable.to_str().expect("path"))).expect("reset");
        }
    }

    #[test]
    fn unknown_probe_fields_and_unsafe_rule_names_are_rejected() {
        let executable = if cfg!(windows) {
            Path::new(r"C:\worker.exe")
        } else {
            Path::new("/worker")
        };
        let mut value: serde_json::Value =
            serde_json::from_slice(&probe(executable.to_str().expect("path"))).expect("json");
        value["unexpected"] = serde_json::Value::Bool(true);
        assert_eq!(
            validate_probe(
                &serde_json::to_vec(&value).expect("bytes"),
                executable,
                "LawyerAssistance-MinerU-v1"
            ),
            Err(ProcessingError::OcrWorkerIsolationUnverified)
        );
        assert!(validate_rule_name("bad rule *").is_err());
    }
}
