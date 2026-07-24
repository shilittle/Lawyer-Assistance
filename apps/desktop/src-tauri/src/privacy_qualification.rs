use crate::atomic_file;
use material_processing::{
    bind_local_mineru_runtime_executable, build_local_mineru_runtime_manifest,
    measure_windows_firewall_isolation, probe_local_mineru_worker_v1, process_pdf,
    trusted_windows_powershell_command, verify_local_mineru_support_manifest_full,
    verify_network_isolation, DeviceSelection, ExtractionBackend, LocalMineruConfig,
    LocalMineruRuntimeExecutableRole, MineruBackend, NetworkIsolationEvidence,
    NetworkIsolationRuleEvidence, OcrMode, ProcessedDocument, ProcessingError, ProcessingLimits,
    WorkerDeviceV1, WorkerProtocolProbeEvidenceV1, MINERU_WORKER_PROTOCOL_V1,
    WINDOWS_FIREWALL_ISOLATION_MECHANISM,
};
use privacy::{protect_local, sha256_hex, unprotect_local};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
        FILE_NAME_NORMALIZED, FILE_SHARE_READ, VOLUME_NAME_DOS,
    },
    System::SystemInformation::GetWindowsDirectoryW,
    UI::Shell::IsUserAnAdmin,
};

const TRUST_SCHEMA_VERSION: u16 = 3;
const QUALIFICATION_STATE_SCHEMA_VERSION: u16 = 3;
const MODEL_MANIFEST_VERSION: &str = "mineru-model-manifest-v1";
const QUALIFICATION_POLICY_ID: &str = "lawyer-assistance-local-mineru-v4";
const QUALIFICATION_POLICY_VERSION: u32 = 4;
const TRUST_DIRECTORY_NAME: &str = "mineru-trust";
const KEY_FILE_NAME: &str = "qualification-signing-key.dpapi";
const TRUST_FILE_NAME: &str = "trusted-installation.json";
const MODEL_MANIFEST_FILE_NAME: &str = "model-manifest.json";
const QUALIFICATION_FILE_NAME: &str = "qualification-state.json";
const PROTOCOL_REPORT_FILE_NAME: &str = "qualification-protocol-report.json";
const RUNTIME_MANIFEST_FILE_NAME: &str = "local-mineru-runtime-manifest.json";
const OCR_RUNTIME_DIRECTORY_NAME: &str = "ocr-runtime";
const QUALIFICATION_SCRIPT_FILE_NAME: &str = "qualify-local-mineru.ps1";
const FIREWALL_REQUEST_FILE_NAME: &str = "firewall-request.json";
const MAX_SIGNING_KEY_FILE_BYTES: u64 = 4096;
const MAX_STATE_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CANARY_PDF_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MODEL_FILES: usize = 100_000;
const MAX_MODEL_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
const MAX_RUNTIME_EXECUTABLES: usize = 32;
const MAX_QUALIFICATION_STDOUT_BYTES: usize = 4 * 1024;
const QUALIFICATION_SIGNING_DOMAIN: &[u8] =
    b"LawyerAssistance/local-mineru-qualification-state/v3\0";
const TRUST_SIGNING_DOMAIN: &[u8] = b"LawyerAssistance/local-mineru-trust/v3\0";
const QUALIFICATION_SCRIPT: &str = include_str!("../../../../scripts/qualify_local_mineru.ps1");
const FIREWALL_VERIFY_SCRIPT: &str = r#"
param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference='Stop'
$request=Get-Content -Raw -Encoding UTF8 -LiteralPath $RequestPath | ConvertFrom-Json
if($request.schemaVersion -ne 1 -or @($request.rules).Count -lt 1){ exit 41 }
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
foreach($requiredName in @('Domain','Private','Public')){
  $matching=@($profiles | Where-Object { [string]$_.Name -eq $requiredName })
  if($matching.Count -ne 1 -or [string]$matching[0].Enabled -ne 'True'){ exit 44 }
}
foreach($item in @($request.rules)){
  $rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Name $item.name -ErrorAction SilentlyContinue)
  if($rules.Count -ne 1){ exit 42 }
  $rule=$rules[0]
  if([string]$rule.Enabled -ne 'True' -or [string]$rule.Direction -ne 'Outbound' -or [string]$rule.Action -ne 'Block' -or [string]$rule.Profile -ne 'Any'){ exit 42 }
  $filters=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
  if($filters.Count -ne 1){ exit 43 }
  $actual=[IO.Path]::GetFullPath([string]$filters[0].Program)
  $expected=[IO.Path]::GetFullPath([string]$item.program)
  if(-not $actual.Equals($expected,[StringComparison]::OrdinalIgnoreCase)){ exit 43 }
}
@{verified=$true;ruleCount=@($request.rules).Count;profilesEnabled=$true} | ConvertTo-Json -Compress
"#;

const FIREWALL_INSTALL_SCRIPT: &str = r#"
param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference='Stop'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){ exit 5 }
$request=Get-Content -Raw -Encoding UTF8 -LiteralPath $RequestPath | ConvertFrom-Json
if($request.schemaVersion -ne 1 -or @($request.rules).Count -lt 1){ exit 41 }
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
foreach($requiredName in @('Domain','Private','Public')){
  $matching=@($profiles | Where-Object { [string]$_.Name -eq $requiredName })
  if($matching.Count -ne 1 -or [string]$matching[0].Enabled -ne 'True'){ exit 44 }
}
try {
  foreach($item in @($request.rules)){
    Get-NetFirewallRule -PolicyStore PersistentStore -Name $item.name -ErrorAction SilentlyContinue |
      Remove-NetFirewallRule -ErrorAction Stop
  }
  foreach($item in @($request.rules)){
    New-NetFirewallRule -PolicyStore PersistentStore -Name $item.name -DisplayName $item.name -Group 'Lawyer Assistance MinerU Isolation' -Enabled True -Profile Any -Direction Outbound -Action Block -Program ([IO.Path]::GetFullPath([string]$item.program)) -ErrorAction Stop | Out-Null
  }
} catch {
  $rollbackFailed=$false
  foreach($item in @($request.rules)){
    try {
      Get-NetFirewallRule -PolicyStore PersistentStore -Name $item.name -ErrorAction SilentlyContinue |
        Remove-NetFirewallRule -ErrorAction Stop
    } catch {
      $rollbackFailed=$true
    }
  }
  if($rollbackFailed){ exit 46 }
  exit 45
}
"#;
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QualificationError {
    code: &'static str,
    message: &'static str,
}

impl QualificationError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) const fn message(&self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for QualificationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for QualificationError {}

#[derive(Debug, Clone)]
pub(crate) struct QualificationEnvironment {
    pub worker_path: PathBuf,
    pub tools_config_path: PathBuf,
    pub model_root: PathBuf,
    pub nvidia_smi_path: PathBuf,
    pub runtime_executable_paths: Vec<PathBuf>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustInstallationStatus {
    pub installation_id: String,
    pub worker_sha256: String,
    pub tools_config_sha256: String,
    pub model_manifest_sha256: String,
    pub nvidia_smi_sha256: String,
    pub model_file_count: u32,
    pub runtime_executable_count: u32,
    pub support_manifest_sha256: String,
    pub support_tree_sha256: String,
    pub support_identity_sha256: String,
    pub support_file_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedTrustInstallation {
    claims: TrustedInstallationClaimsV1,
    model_manifest_path: PathBuf,
}

impl VerifiedTrustInstallation {
    pub(crate) fn worker_sha256(&self) -> &str {
        &self.claims.worker.sha256
    }

    pub(crate) fn tools_config_sha256(&self) -> &str {
        &self.claims.tools_config.sha256
    }

    pub(crate) fn model_manifest_sha256(&self) -> &str {
        &self.claims.model_manifest_sha256
    }

    pub(crate) fn model_manifest_path(&self) -> &Path {
        &self.model_manifest_path
    }

    pub(crate) fn support_manifest_sha256(&self) -> &str {
        &self.claims.support_manifest.sha256
    }

    pub(crate) fn firewall_rule_names(&self) -> &[String] {
        &self.claims.firewall_rule_names
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileBindingV1 {
    path_sha256: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustedInstallationClaimsV1 {
    schema_version: u16,
    installation_id: String,
    installed_at_unix: u64,
    application_version: String,
    policy_id: String,
    policy_version: u32,
    worker: FileBindingV1,
    tools_config: FileBindingV1,
    nvidia_smi: FileBindingV1,
    support_manifest: FileBindingV1,
    support_tree_sha256: String,
    support_identity_sha256: String,
    support_file_count: u32,
    model_root_path_sha256: String,
    model_manifest_sha256: String,
    model_file_count: u32,
    model_bytes: u64,
    runtime_executables: Vec<FileBindingV1>,
    firewall_rule_names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedTrustedInstallationV1 {
    claims: TrustedInstallationClaimsV1,
    signature_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelManifestV1 {
    version: String,
    files: Vec<ModelManifestFileV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelManifestFileV1 {
    relative_path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationStateClaimsV1 {
    schema_version: u16,
    qualification_id: String,
    qualification_report_id: String,
    qualification_report_sha256: String,
    trust_installation_id: String,
    worker_sha256: String,
    tools_config_sha256: String,
    model_manifest_sha256: String,
    nvidia_smi_sha256: String,
    runtime_manifest_sha256: String,
    worker_protocol_version: String,
    worker_protocol_identity_sha256: String,
    worker_health_evidence_sha256: String,
    worker_version: String,
    python_version: String,
    mineru_version: String,
    pytorch_version: String,
    cuda_runtime_version: String,
    gpu_driver_version: String,
    model_version: String,
    selected_cuda_device: u32,
    selected_gpu_descriptor_sha256: String,
    selected_gpu_name: String,
    selected_gpu_memory_mib: u32,
    application_version: String,
    policy_id: String,
    policy_version: u32,
    issued_at_unix: u64,
    expires_at_unix: u64,
    revoked_at_unix: Option<u64>,
    synthetic_canary_qualified: bool,
    processing_chain_qualified: bool,
    network_isolation_enforced: bool,
    model_manifest_trust_established: bool,
    production_case_ocr_authorized: bool,
    app_auto_enable_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedGpuMeasurement {
    selected_cuda_device: u32,
    selected_gpu_descriptor_sha256: String,
    selected_gpu_name: String,
    selected_gpu_memory_mib: u32,
    selected_gpu_driver_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SignedQualificationStateV1 {
    claims: QualificationStateClaimsV1,
    signature_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedQualificationState {
    pub qualification_id: String,
    pub qualification_report_id: String,
    pub qualification_report_sha256: String,
    pub expires_at_unix: u64,
    pub worker_protocol_version: String,
    pub worker_protocol_identity_sha256: String,
    pub worker_health_evidence_sha256: String,
    pub worker_version: String,
    pub python_version: String,
    pub mineru_version: String,
    pub pytorch_version: String,
    pub cuda_runtime_version: String,
    pub gpu_driver_version: String,
    pub model_version: String,
    pub selected_cuda_device: u32,
    pub selected_gpu_descriptor_sha256: String,
    pub selected_gpu_name: String,
    pub selected_gpu_memory_mib: u32,
    pub synthetic_canary_qualified: bool,
    pub processing_chain_qualified: bool,
    pub network_isolation_enforced: bool,
    pub model_manifest_trust_established: bool,
    pub production_case_ocr_authorized: bool,
    pub app_auto_enable_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtocolQualificationReportV1 {
    schema_version: u16,
    qualification_report_id: String,
    protocol_version: String,
    worker_identity_sha256: String,
    worker_health_evidence_sha256: String,
    worker_sha256: String,
    runtime_manifest_sha256: String,
    config_sha256: String,
    model_manifest_sha256: String,
    isolation_bundle_sha256: String,
    selected_gpu_descriptor_sha256: String,
    source_sha256: String,
    processed_document_sha256: String,
    expected_text_sha256: String,
    page_count: u32,
    entry_count: u32,
    completed_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FirewallIsolationStatus {
    pub verified: bool,
    pub mechanism: &'static str,
    pub rule_count: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct QualificationRepository {
    key_path: PathBuf,
    trust_path: PathBuf,
    model_manifest_path: PathBuf,
    qualification_path: PathBuf,
    protocol_report_path: PathBuf,
    runtime_manifest_path: PathBuf,
    ocr_runtime_root: PathBuf,
    script_path: PathBuf,
    firewall_request_path: PathBuf,
}

struct SensitiveRequestFileGuard {
    path: PathBuf,
    cleaned: bool,
}

impl SensitiveRequestFileGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            cleaned: false,
        }
    }

    fn cleanup(&mut self) -> Result<(), QualificationError> {
        remove_file_if_present(&self.path).map_err(|_| {
            QualificationError::new(
                "network_isolation_request_cleanup_failed",
                "The temporary Windows Firewall request could not be removed.",
            )
        })?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for SensitiveRequestFileGuard {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl QualificationRepository {
    pub(crate) fn new(privacy_directory: &Path) -> Result<Self, QualificationError> {
        let root = privacy_directory.join(TRUST_DIRECTORY_NAME);
        ensure_private_directory(&root)?;
        Ok(Self {
            key_path: root.join(KEY_FILE_NAME),
            trust_path: root.join(TRUST_FILE_NAME),
            model_manifest_path: root.join(MODEL_MANIFEST_FILE_NAME),
            qualification_path: root.join(QUALIFICATION_FILE_NAME),
            protocol_report_path: root.join(PROTOCOL_REPORT_FILE_NAME),
            runtime_manifest_path: root.join(RUNTIME_MANIFEST_FILE_NAME),
            ocr_runtime_root: root.join(OCR_RUNTIME_DIRECTORY_NAME),
            script_path: root.join(QUALIFICATION_SCRIPT_FILE_NAME),
            firewall_request_path: root.join(FIREWALL_REQUEST_FILE_NAME),
        })
    }

    pub(crate) fn install_trust(
        &self,
        environment: &QualificationEnvironment,
    ) -> Result<TrustInstallationStatus, QualificationError> {
        validate_environment(environment)?;
        let support_manifest_path = environment
            .worker_path
            .with_file_name("mineru-worker.support-manifest.json");
        let support_manifest = file_binding(&support_manifest_path)?;
        let support_evidence = verify_local_mineru_support_manifest_full(
            &environment.worker_path,
            &support_manifest_path,
            &support_manifest.sha256,
        )
        .map_err(qualification_processing_error)?;
        let support_file_count = u32::try_from(support_evidence.file_count).map_err(|_| {
            QualificationError::new(
                "support_manifest_too_large",
                "The MinerU support manifest contains too many files.",
            )
        })?;

        let model_manifest = build_model_manifest(&environment.model_root)?;
        let model_file_count = u32::try_from(model_manifest.files.len()).map_err(|_| {
            QualificationError::new("model_manifest_too_large", "模型文件数量超过安全上限。")
        })?;
        let model_bytes = model_manifest.files.iter().try_fold(0u64, |total, entry| {
            total.checked_add(entry.size_bytes).ok_or_else(|| {
                QualificationError::new("model_manifest_too_large", "模型文件总大小超过安全上限。")
            })
        })?;
        let model_manifest_bytes = serde_json::to_vec(&model_manifest).map_err(|_| {
            QualificationError::new("model_manifest_invalid", "模型 manifest 无法序列化。")
        })?;
        atomic_write(&self.model_manifest_path, &model_manifest_bytes)?;
        let model_manifest_sha256 = sha256_hex(&model_manifest_bytes);

        let worker = file_binding(&environment.worker_path)?;
        let tools_config = file_binding(&environment.tools_config_path)?;
        let nvidia_smi = file_binding(&environment.nvidia_smi_path)?;
        let runtime_paths = normalized_runtime_paths(environment)?;
        let runtime_executables = runtime_paths
            .iter()
            .map(|path| file_binding(path))
            .collect::<Result<Vec<_>, _>>()?;
        let installation_id = Uuid::new_v4().simple().to_string();
        let firewall_rule_names = (0..runtime_executables.len())
            .map(|index| format!("LawyerAssistance-MinerU-{installation_id}-{index}"))
            .collect::<Vec<_>>();
        let claims = TrustedInstallationClaimsV1 {
            schema_version: TRUST_SCHEMA_VERSION,
            installation_id: installation_id.clone(),
            installed_at_unix: unix_now()?,
            application_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: QUALIFICATION_POLICY_ID.to_owned(),
            policy_version: QUALIFICATION_POLICY_VERSION,
            worker: worker.clone(),
            support_manifest: support_manifest.clone(),
            support_tree_sha256: support_evidence.support_tree_sha256.clone(),
            support_identity_sha256: support_evidence.support_identity_sha256.clone(),
            support_file_count,
            tools_config: tools_config.clone(),
            nvidia_smi: nvidia_smi.clone(),
            model_root_path_sha256: path_sha256(&environment.model_root)?,
            model_manifest_sha256: model_manifest_sha256.clone(),
            model_file_count,
            model_bytes,
            runtime_executables,
            firewall_rule_names,
        };
        let key = self.load_or_create_key()?;
        let signed = SignedTrustedInstallationV1 {
            signature_sha256: sign_claims(TRUST_SIGNING_DOMAIN, &key, &claims)?,
            claims,
        };
        let bytes = serde_json::to_vec(&signed).map_err(|_| {
            QualificationError::new("trust_state_invalid", "本地信任状态无法序列化。")
        })?;
        atomic_write(&self.trust_path, &bytes)?;
        remove_file_if_present(&self.qualification_path)?;
        Ok(TrustInstallationStatus {
            installation_id,
            worker_sha256: worker.sha256,
            support_manifest_sha256: support_manifest.sha256,
            support_tree_sha256: support_evidence.support_tree_sha256,
            support_identity_sha256: support_evidence.support_identity_sha256,
            support_file_count,
            tools_config_sha256: tools_config.sha256,
            model_manifest_sha256,
            nvidia_smi_sha256: nvidia_smi.sha256,
            model_file_count,
            runtime_executable_count: u32::try_from(runtime_paths.len()).unwrap_or(u32::MAX),
        })
    }

    pub(crate) fn verify_trust(
        &self,
        environment: &QualificationEnvironment,
    ) -> Result<VerifiedTrustInstallation, QualificationError> {
        validate_environment(environment)?;
        let bytes = read_bounded(&self.trust_path, MAX_STATE_FILE_BYTES)?;
        let signed: SignedTrustedInstallationV1 = serde_json::from_slice(&bytes).map_err(|_| {
            QualificationError::new("trust_state_invalid", "本地信任状态格式无效。")
        })?;
        validate_trust_claims(&signed.claims)?;
        let key = self.load_existing_key()?;
        let expected = sign_claims(TRUST_SIGNING_DOMAIN, &key, &signed.claims)?;
        if !constant_time_eq(expected.as_bytes(), signed.signature_sha256.as_bytes()) {
            return Err(QualificationError::new(
                "trust_signature_invalid",
                "本地信任状态签名校验失败。",
            ));
        }
        if signed.claims.worker != file_binding(&environment.worker_path)?
            || signed.claims.tools_config != file_binding(&environment.tools_config_path)?
            || signed.claims.support_manifest
                != file_binding(
                    &environment
                        .worker_path
                        .with_file_name("mineru-worker.support-manifest.json"),
                )?
            || signed.claims.model_root_path_sha256 != path_sha256(&environment.model_root)?
        {
            return Err(QualificationError::new(
                "trusted_component_changed",
                "本地 OCR worker、配置或模型目录已变化，资格已失效。",
            ));
        }
        if signed.claims.nvidia_smi != file_binding(&environment.nvidia_smi_path)? {
            return Err(QualificationError::new(
                "trusted_gpu_probe_changed",
                "The trusted local NVIDIA GPU probe changed; OCR qualification is invalid.",
            ));
        }
        let runtime_paths = normalized_runtime_paths(environment)?;
        let runtime = runtime_paths
            .iter()
            .map(|path| file_binding(path))
            .collect::<Result<Vec<_>, _>>()?;
        if runtime != signed.claims.runtime_executables {
            return Err(QualificationError::new(
                "trusted_runtime_changed",
                "本地 OCR 运行时已变化，资格已失效。",
            ));
        }
        let manifest_bytes = read_bounded(&self.model_manifest_path, MAX_STATE_FILE_BYTES)?;
        if sha256_hex(&manifest_bytes) != signed.claims.model_manifest_sha256 {
            return Err(QualificationError::new(
                "model_manifest_changed",
                "受信模型 manifest 已变化，资格已失效。",
            ));
        }
        let expected_manifest = build_model_manifest(&environment.model_root)?;
        let actual_manifest: ModelManifestV1 =
            serde_json::from_slice(&manifest_bytes).map_err(|_| {
                QualificationError::new("model_manifest_invalid", "受信模型 manifest 格式无效。")
            })?;
        if actual_manifest != expected_manifest {
            return Err(QualificationError::new(
                "model_files_changed",
                "模型文件全集与受信 manifest 不一致，资格已失效。",
            ));
        }
        Ok(VerifiedTrustInstallation {
            claims: signed.claims,
            model_manifest_path: self.model_manifest_path.clone(),
        })
    }

    pub(crate) fn install_firewall_isolation(
        &self,
        environment: &QualificationEnvironment,
        trust: &VerifiedTrustInstallation,
    ) -> Result<FirewallIsolationStatus, QualificationError> {
        // Detect a filtered/non-elevated token before invoking the installer.
        // The PowerShell script repeats the same check as defense in depth.
        require_administrator_token()?;
        let runtime_paths = normalized_runtime_paths(environment)?;
        let request = FirewallRequestV1::new(trust, &runtime_paths)?;
        self.write_firewall_request(&request)?;
        let mut request_guard = SensitiveRequestFileGuard::new(&self.firewall_request_path);
        let result = run_firewall_script(&self.firewall_request_path, true);
        request_guard.cleanup()?;
        result?;
        self.verify_firewall_isolation(environment, trust)
    }

    pub(crate) fn verify_firewall_isolation(
        &self,
        environment: &QualificationEnvironment,
        trust: &VerifiedTrustInstallation,
    ) -> Result<FirewallIsolationStatus, QualificationError> {
        let runtime_paths = normalized_runtime_paths(environment)?;
        let request = FirewallRequestV1::new(trust, &runtime_paths)?;
        self.write_firewall_request(&request)?;
        let mut request_guard = SensitiveRequestFileGuard::new(&self.firewall_request_path);
        let result = run_firewall_script(&self.firewall_request_path, false);
        request_guard.cleanup()?;
        result?;
        Ok(FirewallIsolationStatus {
            verified: true,
            mechanism: "windows_defender_firewall_program_block_v1",
            rule_count: u32::try_from(runtime_paths.len()).unwrap_or(u32::MAX),
        })
    }

    fn protocol_config(
        &self,
        environment: &QualificationEnvironment,
        trust: &VerifiedTrustInstallation,
        qualification_report_id: &str,
        expected_worker_identity_sha256: &str,
    ) -> Result<(LocalMineruConfig, String), QualificationError> {
        let runtime_paths = normalized_runtime_paths(environment)?;
        if runtime_paths.len() != trust.firewall_rule_names().len() {
            return Err(QualificationError::new(
                "qualification_runtime_binding_mismatch",
                "The trusted runtime and isolation rule sets do not match.",
            ));
        }
        let mut runtime_executables = Vec::with_capacity(runtime_paths.len());
        for (index, path) in runtime_paths.iter().enumerate() {
            let role = if index == 0 {
                LocalMineruRuntimeExecutableRole::Launcher
            } else {
                LocalMineruRuntimeExecutableRole::Executable
            };
            runtime_executables.push(
                bind_local_mineru_runtime_executable(path, role)
                    .map_err(qualification_processing_error)?,
            );
        }
        if runtime_executables[0].expected_sha256 != trust.worker_sha256() {
            return Err(QualificationError::new(
                "qualification_worker_binding_mismatch",
                "The protocol worker no longer matches the trusted installation.",
            ));
        }
        let manifest = build_local_mineru_runtime_manifest(
            "lawyer-assistance-mineru-runtime-v1",
            &runtime_executables,
        )
        .map_err(qualification_processing_error)?;
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| {
            QualificationError::new(
                "runtime_manifest_invalid",
                "The local OCR runtime manifest could not be serialized.",
            )
        })?;
        atomic_write(&self.runtime_manifest_path, &manifest_bytes)?;
        let runtime_manifest_sha256 = sha256_hex(&manifest_bytes);
        let support_manifest_path = environment
            .worker_path
            .with_file_name("mineru-worker.support-manifest.json");

        let mut rules = Vec::with_capacity(runtime_executables.len());
        for (binding, rule_name) in runtime_executables
            .iter()
            .zip(trust.firewall_rule_names().iter())
        {
            let measured = measure_windows_firewall_isolation(&binding.path, rule_name)
                .map_err(qualification_processing_error)?;
            rules.push(NetworkIsolationRuleEvidence {
                program_path: binding.path.clone(),
                firewall_rule_name: rule_name.clone(),
                expected_policy_sha256: measured.policy_sha256,
            });
        }
        let network_isolation = NetworkIsolationEvidence {
            verified: true,
            mechanism: WINDOWS_FIREWALL_ISOLATION_MECHANISM.to_owned(),
            checked_at_unix: unix_now()?,
            rules,
        };
        let runtime_programs = runtime_executables
            .iter()
            .map(|entry| entry.path.clone())
            .collect::<Vec<_>>();
        let isolation = verify_network_isolation(&runtime_programs, &network_isolation)
            .map_err(qualification_processing_error)?;
        ensure_private_directory(&self.ocr_runtime_root)?;
        let timeout_ms = environment
            .timeout_seconds
            .checked_mul(1_000)
            .ok_or_else(|| {
                QualificationError::new("qualification_timeout_invalid", "OCR timeout overflowed.")
            })?;
        let config = LocalMineruConfig {
            executable: runtime_executables[0].path.clone(),
            expected_executable_sha256: runtime_executables[0].expected_sha256.clone(),
            runtime_executables,
            runtime_manifest: self.runtime_manifest_path.clone(),
            expected_runtime_manifest_sha256: runtime_manifest_sha256,
            support_manifest: support_manifest_path,
            expected_support_manifest_sha256: trust.support_manifest_sha256().to_owned(),
            mineru_config: environment.tools_config_path.clone(),
            expected_config_sha256: trust.tools_config_sha256().to_owned(),
            model_root: environment.model_root.clone(),
            model_manifest: trust.model_manifest_path().to_path_buf(),
            expected_model_manifest_sha256: trust.model_manifest_sha256().to_owned(),
            temporary_root: self.ocr_runtime_root.clone(),
            backend: MineruBackend::Pipeline,
            device: DeviceSelection::Cuda { indices: vec![0] },
            language: "ch".to_owned(),
            timeout_ms,
            max_output_bytes: 512 * 1024 * 1024,
            strict_offline: true,
            network_isolation,
            qualification_report_id: format!("qrep_{qualification_report_id}"),
            expected_worker_identity_sha256: expected_worker_identity_sha256.to_owned(),
        };
        Ok((config, isolation.bundle_sha256))
    }

    pub(crate) fn run_qualification(
        &self,
        environment: &QualificationEnvironment,
        trust: &VerifiedTrustInstallation,
        expires_at_unix: u64,
        production_case_ocr_authorized: bool,
        app_auto_enable_authorized: bool,
    ) -> Result<VerifiedQualificationState, QualificationError> {
        let now = unix_now()?;
        if expires_at_unix <= now || expires_at_unix.saturating_sub(now) > 90 * 24 * 60 * 60 {
            return Err(QualificationError::new(
                "qualification_expiry_invalid",
                "Qualification expiry must be within the next 90 days.",
            ));
        }
        self.verify_firewall_isolation(environment, trust)?;
        let measured_gpu = measure_selected_gpu(environment)?;
        atomic_write(&self.script_path, QUALIFICATION_SCRIPT.as_bytes())?;
        ensure_private_directory(&self.ocr_runtime_root)?;
        let canary_root = tempfile::Builder::new()
            .prefix("qualification-canary-")
            .tempdir_in(&self.ocr_runtime_root)
            .map_err(|_| {
                QualificationError::new(
                    "qualification_canary_unavailable",
                    "The private synthetic canary directory could not be created.",
                )
            })?;
        let canary_path = canary_root.path().join("qualification-canary.pdf");
        let qualification_report_id = Uuid::new_v4().simple().to_string();
        let run_result = (|| {
            run_canary_generator(&self.script_path, &canary_path)?;
            let canary_path = ordinary_local_file(&canary_path)?;
            let canary_bytes = read_bounded(&canary_path, MAX_CANARY_PDF_BYTES)?;
            let (mut config, isolation_bundle_sha256) = self.protocol_config(
                environment,
                trust,
                &qualification_report_id,
                &"0".repeat(64),
            )?;
            let probe =
                probe_local_mineru_worker_v1(&config).map_err(qualification_processing_error)?;
            validate_protocol_probe(&probe, trust, &measured_gpu)?;
            config.expected_worker_identity_sha256 = probe.identity_sha256.clone();
            let limits = ProcessingLimits {
                max_input_bytes: MAX_CANARY_PDF_BYTES as usize,
                max_pages: 3,
                max_output_bytes: 512 * 1024 * 1024,
                ..ProcessingLimits::default()
            };
            let document = process_pdf(&canary_bytes, OcrMode::ForceLocal, Some(&config), limits)
                .map_err(qualification_processing_error)?;
            validate_canary_document(&document, trust)?;
            Ok::<_, QualificationError>((
                probe,
                document,
                sha256_hex(&canary_bytes),
                isolation_bundle_sha256,
                config.expected_runtime_manifest_sha256,
            ))
        })();
        let cleanup_result = canary_root.close().map_err(|_| {
            QualificationError::new(
                "qualification_canary_cleanup_failed",
                "The synthetic qualification material could not be securely removed.",
            )
        });
        let (probe, document, source_sha256, isolation_bundle_sha256, runtime_manifest_sha256) =
            match (run_result, cleanup_result) {
                (_, Err(error)) => return Err(error),
                (Err(error), Ok(())) => return Err(error),
                (Ok(value), Ok(())) => value,
            };

        let measured_gpu_after = measure_selected_gpu(environment)?;
        if measured_gpu_after != measured_gpu {
            return Err(QualificationError::new(
                "qualification_gpu_runtime_changed",
                "The selected CUDA GPU changed while the canary was running.",
            ));
        }
        let post_trust = self.verify_trust(environment)?;
        if &post_trust != trust {
            return Err(QualificationError::new(
                "qualification_environment_changed",
                "The trusted OCR environment changed while the canary was running.",
            ));
        }
        self.verify_firewall_isolation(environment, trust)?;

        let document_bytes = serde_json::to_vec(&document).map_err(|_| {
            QualificationError::new(
                "qualification_report_invalid",
                "The validated canary document could not be hashed.",
            )
        })?;
        let report = ProtocolQualificationReportV1 {
            schema_version: 1,
            qualification_report_id: qualification_report_id.clone(),
            protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            worker_identity_sha256: probe.identity_sha256.clone(),
            worker_health_evidence_sha256: probe.health_evidence_sha256.clone(),
            worker_sha256: trust.worker_sha256().to_owned(),
            runtime_manifest_sha256: runtime_manifest_sha256.clone(),
            config_sha256: trust.tools_config_sha256().to_owned(),
            model_manifest_sha256: trust.model_manifest_sha256().to_owned(),
            isolation_bundle_sha256,
            selected_gpu_descriptor_sha256: measured_gpu.selected_gpu_descriptor_sha256.clone(),
            source_sha256,
            processed_document_sha256: sha256_hex(&document_bytes),
            expected_text_sha256: expected_canary_text_sha256(),
            page_count: 3,
            entry_count: 24,
            completed_at_unix: unix_now()?,
        };
        let report_bytes = serde_json::to_vec(&report).map_err(|_| {
            QualificationError::new(
                "qualification_report_invalid",
                "The protocol qualification report could not be serialized.",
            )
        })?;
        atomic_write(&self.protocol_report_path, &report_bytes)?;

        let claims = QualificationStateClaimsV1 {
            schema_version: QUALIFICATION_STATE_SCHEMA_VERSION,
            qualification_id: format!("qlf_{}", Uuid::new_v4().simple()),
            qualification_report_id,
            qualification_report_sha256: sha256_hex(&report_bytes),
            trust_installation_id: trust.claims.installation_id.clone(),
            worker_sha256: trust.claims.worker.sha256.clone(),
            tools_config_sha256: trust.claims.tools_config.sha256.clone(),
            model_manifest_sha256: trust.claims.model_manifest_sha256.clone(),
            nvidia_smi_sha256: trust.claims.nvidia_smi.sha256.clone(),
            runtime_manifest_sha256,
            worker_protocol_version: MINERU_WORKER_PROTOCOL_V1.to_owned(),
            worker_protocol_identity_sha256: probe.identity_sha256,
            worker_health_evidence_sha256: probe.health_evidence_sha256,
            worker_version: probe.identity.worker_version,
            python_version: probe.identity.python_version,
            mineru_version: probe.identity.mineru_version,
            pytorch_version: probe.identity.pytorch_version,
            cuda_runtime_version: probe.identity.cuda_runtime_version,
            gpu_driver_version: probe.identity.gpu_driver_version,
            model_version: probe.identity.model_version,
            selected_cuda_device: measured_gpu.selected_cuda_device,
            selected_gpu_descriptor_sha256: measured_gpu.selected_gpu_descriptor_sha256,
            selected_gpu_name: measured_gpu.selected_gpu_name,
            selected_gpu_memory_mib: measured_gpu.selected_gpu_memory_mib,
            application_version: env!("CARGO_PKG_VERSION").to_owned(),
            policy_id: QUALIFICATION_POLICY_ID.to_owned(),
            policy_version: QUALIFICATION_POLICY_VERSION,
            issued_at_unix: now,
            expires_at_unix,
            revoked_at_unix: None,
            synthetic_canary_qualified: true,
            processing_chain_qualified: true,
            network_isolation_enforced: true,
            model_manifest_trust_established: true,
            production_case_ocr_authorized,
            app_auto_enable_authorized,
        };
        let key = self.load_existing_key()?;
        let signed = SignedQualificationStateV1 {
            signature_sha256: sign_claims(QUALIFICATION_SIGNING_DOMAIN, &key, &claims)?,
            claims,
        };
        atomic_write(
            &self.qualification_path,
            &serde_json::to_vec(&signed).map_err(|_| {
                QualificationError::new(
                    "qualification_state_invalid",
                    "The qualification state could not be serialized.",
                )
            })?,
        )?;
        match self.verify_qualification(environment, trust) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.revoke_qualification()?;
                Err(error)
            }
        }
    }

    pub(crate) fn verify_qualification(
        &self,
        environment: &QualificationEnvironment,
        trust: &VerifiedTrustInstallation,
    ) -> Result<VerifiedQualificationState, QualificationError> {
        let bytes = read_bounded(&self.qualification_path, MAX_STATE_FILE_BYTES)?;
        let signed: SignedQualificationStateV1 = serde_json::from_slice(&bytes).map_err(|_| {
            QualificationError::new(
                "qualification_state_invalid",
                "The signed qualification state is invalid.",
            )
        })?;
        validate_qualification_claims(&signed.claims)?;
        let key = self.load_existing_key()?;
        let expected = sign_claims(QUALIFICATION_SIGNING_DOMAIN, &key, &signed.claims)?;
        if !constant_time_eq(expected.as_bytes(), signed.signature_sha256.as_bytes()) {
            return Err(QualificationError::new(
                "qualification_signature_invalid",
                "The local qualification signature is invalid.",
            ));
        }
        let now = unix_now()?;
        if signed.claims.revoked_at_unix.is_some() {
            return Err(QualificationError::new(
                "qualification_revoked",
                "The local OCR qualification was revoked.",
            ));
        }
        if now >= signed.claims.expires_at_unix {
            return Err(QualificationError::new(
                "qualification_expired",
                "The local OCR qualification expired.",
            ));
        }
        if signed.claims.trust_installation_id != trust.claims.installation_id
            || signed.claims.worker_sha256 != trust.claims.worker.sha256
            || signed.claims.tools_config_sha256 != trust.claims.tools_config.sha256
            || signed.claims.model_manifest_sha256 != trust.claims.model_manifest_sha256
        {
            return Err(QualificationError::new(
                "qualification_environment_changed",
                "The trusted worker, configuration, runtime, or model environment changed.",
            ));
        }
        if signed.claims.nvidia_smi_sha256 != trust.claims.nvidia_smi.sha256 {
            return Err(QualificationError::new(
                "qualification_gpu_probe_changed",
                "The trusted NVIDIA probe binding changed; OCR qualification is invalid.",
            ));
        }
        let measured_gpu = measure_selected_gpu(environment)?;
        if signed.claims.selected_cuda_device != measured_gpu.selected_cuda_device
            || signed.claims.selected_gpu_descriptor_sha256
                != measured_gpu.selected_gpu_descriptor_sha256
            || signed.claims.selected_gpu_name != measured_gpu.selected_gpu_name
            || signed.claims.selected_gpu_memory_mib != measured_gpu.selected_gpu_memory_mib
        {
            return Err(QualificationError::new(
                "qualification_gpu_runtime_changed",
                "The selected CUDA GPU or NVIDIA driver changed; OCR qualification is invalid.",
            ));
        }
        self.verify_firewall_isolation(environment, trust)?;

        let report_bytes = read_bounded(&self.protocol_report_path, MAX_STATE_FILE_BYTES)?;
        if sha256_hex(&report_bytes) != signed.claims.qualification_report_sha256 {
            return Err(QualificationError::new(
                "qualification_report_changed",
                "The protocol qualification report changed or is unavailable.",
            ));
        }
        let report: ProtocolQualificationReportV1 =
            serde_json::from_slice(&report_bytes).map_err(|_| {
                QualificationError::new(
                    "qualification_report_invalid",
                    "The protocol qualification report is invalid.",
                )
            })?;
        validate_protocol_report(&report, &signed.claims)?;

        let (config, isolation_bundle_sha256) = self.protocol_config(
            environment,
            trust,
            &signed.claims.qualification_report_id,
            &signed.claims.worker_protocol_identity_sha256,
        )?;
        if config.expected_runtime_manifest_sha256 != signed.claims.runtime_manifest_sha256
            || report.runtime_manifest_sha256 != signed.claims.runtime_manifest_sha256
            || report.isolation_bundle_sha256 != isolation_bundle_sha256
        {
            return Err(QualificationError::new(
                "qualification_runtime_changed",
                "The trusted runtime manifest or isolation evidence changed.",
            ));
        }
        let probe =
            probe_local_mineru_worker_v1(&config).map_err(qualification_processing_error)?;
        validate_protocol_probe(&probe, trust, &measured_gpu)?;
        if probe.protocol_version != signed.claims.worker_protocol_version
            || probe.identity_sha256 != signed.claims.worker_protocol_identity_sha256
            || probe.identity.worker_version != signed.claims.worker_version
            || probe.identity.python_version != signed.claims.python_version
            || probe.identity.mineru_version != signed.claims.mineru_version
            || probe.identity.pytorch_version != signed.claims.pytorch_version
            || probe.identity.cuda_runtime_version != signed.claims.cuda_runtime_version
            || probe.identity.gpu_driver_version != signed.claims.gpu_driver_version
            || probe.identity.model_version != signed.claims.model_version
        {
            return Err(QualificationError::new(
                "qualification_worker_identity_changed",
                "The worker hello identity changed; OCR qualification is invalid.",
            ));
        }

        Ok(VerifiedQualificationState {
            qualification_id: signed.claims.qualification_id,
            qualification_report_id: signed.claims.qualification_report_id,
            qualification_report_sha256: signed.claims.qualification_report_sha256,
            expires_at_unix: signed.claims.expires_at_unix,
            worker_protocol_version: signed.claims.worker_protocol_version,
            worker_protocol_identity_sha256: signed.claims.worker_protocol_identity_sha256,
            worker_health_evidence_sha256: signed.claims.worker_health_evidence_sha256,
            worker_version: signed.claims.worker_version,
            python_version: signed.claims.python_version,
            mineru_version: signed.claims.mineru_version,
            pytorch_version: signed.claims.pytorch_version,
            cuda_runtime_version: signed.claims.cuda_runtime_version,
            gpu_driver_version: signed.claims.gpu_driver_version,
            model_version: signed.claims.model_version,
            selected_cuda_device: signed.claims.selected_cuda_device,
            selected_gpu_descriptor_sha256: signed.claims.selected_gpu_descriptor_sha256,
            selected_gpu_name: signed.claims.selected_gpu_name,
            selected_gpu_memory_mib: signed.claims.selected_gpu_memory_mib,
            synthetic_canary_qualified: signed.claims.synthetic_canary_qualified,
            processing_chain_qualified: signed.claims.processing_chain_qualified,
            network_isolation_enforced: signed.claims.network_isolation_enforced,
            model_manifest_trust_established: signed.claims.model_manifest_trust_established,
            production_case_ocr_authorized: signed.claims.production_case_ocr_authorized,
            app_auto_enable_authorized: signed.claims.app_auto_enable_authorized,
        })
    }

    pub(crate) fn revoke_qualification(&self) -> Result<(), QualificationError> {
        let bytes = read_bounded(&self.qualification_path, MAX_STATE_FILE_BYTES)?;
        let mut signed: SignedQualificationStateV1 =
            serde_json::from_slice(&bytes).map_err(|_| {
                QualificationError::new("qualification_state_invalid", "资格状态格式无效。")
            })?;
        let key = self.load_existing_key()?;
        let expected = sign_claims(QUALIFICATION_SIGNING_DOMAIN, &key, &signed.claims)?;
        if !constant_time_eq(expected.as_bytes(), signed.signature_sha256.as_bytes()) {
            return Err(QualificationError::new(
                "qualification_signature_invalid",
                "资格状态签名校验失败。",
            ));
        }
        if signed.claims.revoked_at_unix.is_none() {
            signed.claims.revoked_at_unix = Some(unix_now()?);
            signed.signature_sha256 =
                sign_claims(QUALIFICATION_SIGNING_DOMAIN, &key, &signed.claims)?;
            atomic_write(
                &self.qualification_path,
                &serde_json::to_vec(&signed).map_err(|_| {
                    QualificationError::new("qualification_state_invalid", "资格状态无法序列化。")
                })?,
            )?;
        }
        Ok(())
    }

    pub(crate) fn revoke_qualification_if_present(&self) -> Result<(), QualificationError> {
        match fs::symlink_metadata(&self.qualification_path) {
            Ok(_) => self.revoke_qualification(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(QualificationError::new(
                "qualification_state_unavailable",
                "The qualification state could not be inspected before revocation.",
            )),
        }
    }

    fn load_or_create_key(&self) -> Result<Vec<u8>, QualificationError> {
        if self.key_path.exists() {
            return self.load_existing_key();
        }
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(Uuid::new_v4().as_bytes());
        key.extend_from_slice(Uuid::new_v4().as_bytes());
        let protected = protect_local(&key).map_err(|_| {
            QualificationError::new(
                "qualification_key_unavailable",
                "本机资格签名密钥无法保护。",
            )
        })?;
        let temporary = temporary_sibling(&self.key_path);
        let result = (|| {
            write_new_file(&temporary, &protected)?;
            match fs::rename(&temporary, &self.key_path) {
                Ok(()) => Ok(key),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(&temporary);
                    self.load_existing_key()
                }
                Err(_) => Err(QualificationError::new(
                    "qualification_key_unavailable",
                    "本机资格签名密钥无法持久化。",
                )),
            }
        })();
        let _ = fs::remove_file(&temporary);
        result
    }

    fn load_existing_key(&self) -> Result<Vec<u8>, QualificationError> {
        let protected = read_bounded(&self.key_path, MAX_SIGNING_KEY_FILE_BYTES)?;
        let key = unprotect_local(&protected).map_err(|_| {
            QualificationError::new(
                "qualification_key_unavailable",
                "本机资格签名密钥无法读取。",
            )
        })?;
        if key.len() != 32 {
            return Err(QualificationError::new(
                "qualification_key_invalid",
                "本机资格签名密钥格式无效。",
            ));
        }
        Ok(key)
    }

    fn write_firewall_request(
        &self,
        request: &FirewallRequestV1,
    ) -> Result<(), QualificationError> {
        let bytes = serde_json::to_vec(request).map_err(|_| {
            QualificationError::new(
                "network_isolation_request_invalid",
                "网络隔离请求无法序列化。",
            )
        })?;
        atomic_write(&self.firewall_request_path, &bytes)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FirewallRuleRequestV1 {
    name: String,
    program: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FirewallRequestV1 {
    schema_version: u16,
    rules: Vec<FirewallRuleRequestV1>,
}

impl FirewallRequestV1 {
    fn new(
        trust: &VerifiedTrustInstallation,
        paths: &[PathBuf],
    ) -> Result<Self, QualificationError> {
        if paths.len() != trust.firewall_rule_names().len() {
            return Err(QualificationError::new(
                "network_isolation_binding_mismatch",
                "网络隔离规则与受信运行时不匹配。",
            ));
        }
        Ok(Self {
            schema_version: 1,
            rules: paths
                .iter()
                .zip(trust.firewall_rule_names())
                .map(|(path, name)| FirewallRuleRequestV1 {
                    name: name.clone(),
                    program: path.to_string_lossy().into_owned(),
                })
                .collect(),
        })
    }
}

fn validate_environment(environment: &QualificationEnvironment) -> Result<(), QualificationError> {
    ordinary_local_file(&environment.worker_path)?;
    ordinary_local_file(&environment.tools_config_path)?;
    ordinary_local_file(&environment.nvidia_smi_path)?;
    ordinary_local_directory(&environment.model_root)?;
    if environment.timeout_seconds < 10 || environment.timeout_seconds > 7200 {
        return Err(QualificationError::new(
            "qualification_timeout_invalid",
            "资格检查超时配置无效。",
        ));
    }
    let _ = normalized_runtime_paths(environment)?;
    Ok(())
}

fn measure_selected_gpu(
    environment: &QualificationEnvironment,
) -> Result<SelectedGpuMeasurement, QualificationError> {
    let nvidia_smi = ordinary_local_file(&environment.nvidia_smi_path)?;
    let system32 = nvidia_smi.parent().ok_or_else(|| {
        QualificationError::new(
            "gpu_probe_path_invalid",
            "The NVIDIA probe path is invalid.",
        )
    })?;
    let windows_root = system32.parent().ok_or_else(|| {
        QualificationError::new(
            "gpu_probe_path_invalid",
            "The NVIDIA probe path is invalid.",
        )
    })?;
    let expected = windows_root.join("System32").join("nvidia-smi.exe");
    if !nvidia_smi
        .to_string_lossy()
        .eq_ignore_ascii_case(&ordinary_local_file(&expected)?.to_string_lossy())
    {
        return Err(QualificationError::new(
            "gpu_probe_path_invalid",
            "Only the fixed local Windows NVIDIA probe is accepted.",
        ));
    }
    let drive_root = windows_root.parent().ok_or_else(|| {
        QualificationError::new("gpu_probe_path_invalid", "The Windows root is invalid.")
    })?;
    let program_files = ordinary_local_directory(&drive_root.join("Program Files"))?;
    let mut child = Command::new(&nvidia_smi)
        .arg("--query-gpu=index,name,driver_version,memory.total")
        .arg("--format=csv,noheader,nounits")
        .env_clear()
        .env("SystemRoot", windows_root)
        .env("WINDIR", windows_root)
        .env("ProgramFiles", program_files)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            QualificationError::new(
                "gpu_runtime_unavailable",
                "The local NVIDIA GPU probe could not start.",
            )
        })?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| {
            QualificationError::new(
                "gpu_runtime_unavailable",
                "The local NVIDIA GPU probe could not be observed.",
            )
        })? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(QualificationError::new(
                "gpu_runtime_probe_timeout",
                "The local NVIDIA GPU probe timed out.",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| {
            QualificationError::new(
                "gpu_runtime_unavailable",
                "The local NVIDIA GPU probe returned no bounded output stream.",
            )
        })?
        .take(16 * 1024 + 1)
        .read_to_end(&mut stdout)
        .map_err(|_| {
            QualificationError::new(
                "gpu_runtime_unavailable",
                "The local NVIDIA GPU probe output could not be read.",
            )
        })?;
    if !status.success() || stdout.is_empty() || stdout.len() > 16 * 1024 {
        return Err(QualificationError::new(
            "gpu_runtime_unavailable",
            "The local NVIDIA GPU probe did not return valid bounded output.",
        ));
    }
    let stdout = std::str::from_utf8(&stdout).map_err(|_| {
        QualificationError::new(
            "gpu_runtime_invalid",
            "The local NVIDIA GPU probe output was not UTF-8.",
        )
    })?;
    let mut selected = None;
    let mut indices = BTreeSet::new();
    let mut device_count = 0usize;
    for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
        device_count += 1;
        if device_count > 16 {
            return Err(QualificationError::new(
                "gpu_runtime_invalid",
                "The local NVIDIA GPU count exceeds the supported bound.",
            ));
        }
        let fields = line.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(QualificationError::new(
                "gpu_runtime_invalid",
                "The local NVIDIA GPU descriptor shape is invalid.",
            ));
        }
        let index = fields[0].parse::<u32>().map_err(|_| {
            QualificationError::new("gpu_runtime_invalid", "The CUDA device index is invalid.")
        })?;
        let memory_mib = fields[3].parse::<u32>().map_err(|_| {
            QualificationError::new("gpu_runtime_invalid", "The GPU memory value is invalid.")
        })?;
        if !indices.insert(index)
            || !valid_gpu_probe_name(fields[1])
            || !valid_gpu_probe_driver(fields[2])
            || memory_mib < 1024
        {
            return Err(QualificationError::new(
                "gpu_runtime_invalid",
                "The local NVIDIA GPU descriptor is invalid.",
            ));
        }
        if index == 0 {
            if memory_mib < 6144 || selected.is_some() {
                return Err(QualificationError::new(
                    "gpu_runtime_not_qualified",
                    "CUDA device 0 does not meet the local OCR memory requirement.",
                ));
            }
            selected = Some(SelectedGpuMeasurement {
                selected_cuda_device: index,
                selected_gpu_descriptor_sha256: sha256_hex(
                    format!("{index}|{}|{}|{memory_mib}", fields[1], fields[2]).as_bytes(),
                ),
                selected_gpu_name: fields[1].to_owned(),
                selected_gpu_memory_mib: memory_mib,
                selected_gpu_driver_version: fields[2].to_owned(),
            });
        }
    }
    if device_count == 0 {
        return Err(QualificationError::new(
            "gpu_runtime_invalid",
            "No local NVIDIA GPU was reported.",
        ));
    }
    selected.ok_or_else(|| {
        QualificationError::new(
            "gpu_runtime_not_qualified",
            "CUDA device 0 is unavailable for local OCR.",
        )
    })
}

fn valid_gpu_probe_name(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value == value.trim()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

fn valid_gpu_probe_driver(value: &str) -> bool {
    let segments = value.split('.').collect::<Vec<_>>();
    (2..=4).contains(&segments.len())
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && segment.len() <= 5
                && segment.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn normalized_runtime_paths(
    environment: &QualificationEnvironment,
) -> Result<Vec<PathBuf>, QualificationError> {
    let mut values = vec![environment.worker_path.clone()];
    values.extend(environment.runtime_executable_paths.iter().cloned());
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for path in values {
        let canonical = ordinary_local_file(&path)?;
        let key = canonical.to_string_lossy().to_ascii_lowercase();
        if seen.insert(key) {
            output.push(canonical);
        }
    }
    if output.is_empty() || output.len() > MAX_RUNTIME_EXECUTABLES {
        return Err(QualificationError::new(
            "trusted_runtime_invalid",
            "受信运行时可执行文件数量无效。",
        ));
    }
    Ok(output)
}

fn build_model_manifest(model_root: &Path) -> Result<ModelManifestV1, QualificationError> {
    let root = ordinary_local_directory(model_root)?;
    let mut stack = vec![root.clone()];
    let mut files = Vec::new();
    let mut total_bytes = 0u64;
    while let Some(directory) = stack.pop() {
        let entries = fs::read_dir(&directory).map_err(|_| {
            QualificationError::new("model_manifest_unavailable", "模型目录无法枚举。")
        })?;
        for entry in entries {
            let entry = entry.map_err(|_| {
                QualificationError::new("model_manifest_unavailable", "模型目录无法枚举。")
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| {
                QualificationError::new("model_manifest_unavailable", "模型文件无法检查。")
            })?;
            reject_link_cloud_or_hardlink(&metadata)?;
            if metadata.is_dir() {
                stack.push(path);
            } else if metadata.is_file() {
                total_bytes = total_bytes.checked_add(metadata.len()).ok_or_else(|| {
                    QualificationError::new(
                        "model_manifest_too_large",
                        "模型文件总大小超过安全上限。",
                    )
                })?;
                if total_bytes > MAX_MODEL_BYTES || files.len() >= MAX_MODEL_FILES {
                    return Err(QualificationError::new(
                        "model_manifest_too_large",
                        "模型文件数量或总大小超过安全上限。",
                    ));
                }
                let relative = path.strip_prefix(&root).map_err(|_| {
                    QualificationError::new("model_manifest_invalid", "模型文件越过受信目录。")
                })?;
                let relative_path = relative
                    .components()
                    .map(|component| match component {
                        Component::Normal(value) => Ok(value.to_string_lossy().into_owned()),
                        _ => Err(QualificationError::new(
                            "model_manifest_invalid",
                            "模型相对路径无效。",
                        )),
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .join("/");
                files.push(ModelManifestFileV1 {
                    relative_path,
                    sha256: hash_file(&path)?,
                    size_bytes: metadata.len(),
                });
            } else {
                return Err(QualificationError::new(
                    "model_manifest_invalid",
                    "模型目录包含不支持的对象类型。",
                ));
            }
        }
    }
    files.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    if files.is_empty() {
        return Err(QualificationError::new(
            "model_manifest_invalid",
            "模型目录不能为空。",
        ));
    }
    Ok(ModelManifestV1 {
        version: MODEL_MANIFEST_VERSION.to_owned(),
        files,
    })
}

fn validate_trust_claims(claims: &TrustedInstallationClaimsV1) -> Result<(), QualificationError> {
    if claims.schema_version != TRUST_SCHEMA_VERSION
        || claims.application_version != env!("CARGO_PKG_VERSION")
        || claims.policy_id != QUALIFICATION_POLICY_ID
        || claims.policy_version != QUALIFICATION_POLICY_VERSION
        || !is_lower_hex(&claims.installation_id, 32)
        || !valid_hash(&claims.worker.sha256)
        || !valid_hash(&claims.support_manifest.sha256)
        || !valid_hash(&claims.support_tree_sha256)
        || !valid_hash(&claims.support_identity_sha256)
        || claims.support_file_count == 0
        || !valid_hash(&claims.tools_config.sha256)
        || !valid_hash(&claims.nvidia_smi.sha256)
        || !valid_hash(&claims.model_root_path_sha256)
        || !valid_hash(&claims.model_manifest_sha256)
        || claims.model_file_count == 0
        || claims.runtime_executables.is_empty()
        || claims.runtime_executables.len() > MAX_RUNTIME_EXECUTABLES
        || claims.runtime_executables.len() != claims.firewall_rule_names.len()
    {
        return Err(QualificationError::new(
            "trust_state_invalid",
            "本地信任状态字段无效或版本不兼容。",
        ));
    }
    Ok(())
}

fn validate_qualification_claims(
    claims: &QualificationStateClaimsV1,
) -> Result<(), QualificationError> {
    if claims.schema_version != QUALIFICATION_STATE_SCHEMA_VERSION
        || !claims.qualification_id.starts_with("qlf_")
        || !is_lower_hex(&claims.qualification_id[4..], 32)
        || !is_lower_hex(&claims.qualification_report_id, 32)
        || !valid_hash(&claims.qualification_report_sha256)
        || !is_lower_hex(&claims.trust_installation_id, 32)
        || !valid_hash(&claims.worker_sha256)
        || !valid_hash(&claims.tools_config_sha256)
        || !valid_hash(&claims.model_manifest_sha256)
        || !valid_hash(&claims.nvidia_smi_sha256)
        || !valid_hash(&claims.runtime_manifest_sha256)
        || claims.worker_protocol_version != MINERU_WORKER_PROTOCOL_V1
        || !valid_hash(&claims.worker_protocol_identity_sha256)
        || !valid_hash(&claims.worker_health_evidence_sha256)
        || !valid_version_evidence(&claims.worker_version)
        || !valid_version_evidence(&claims.python_version)
        || !valid_version_evidence(&claims.mineru_version)
        || !valid_version_evidence(&claims.pytorch_version)
        || !valid_version_evidence(&claims.cuda_runtime_version)
        || !valid_gpu_probe_driver(&claims.gpu_driver_version)
        || !valid_version_evidence(&claims.model_version)
        || !valid_hash(&claims.selected_gpu_descriptor_sha256)
        || claims.selected_cuda_device != 0
        || !valid_gpu_probe_name(&claims.selected_gpu_name)
        || claims.selected_gpu_memory_mib < 6144
        || claims.application_version != env!("CARGO_PKG_VERSION")
        || claims.policy_id != QUALIFICATION_POLICY_ID
        || claims.policy_version != QUALIFICATION_POLICY_VERSION
        || claims.issued_at_unix == 0
        || claims.expires_at_unix <= claims.issued_at_unix
        || !claims.synthetic_canary_qualified
        || !claims.processing_chain_qualified
        || !claims.network_isolation_enforced
        || !claims.model_manifest_trust_established
    {
        return Err(QualificationError::new(
            "qualification_state_invalid",
            "资格状态字段无效或版本不兼容。",
        ));
    }
    Ok(())
}

fn file_binding(path: &Path) -> Result<FileBindingV1, QualificationError> {
    let canonical = ordinary_local_file(path)?;
    let metadata = fs::metadata(&canonical).map_err(|_| {
        QualificationError::new("trusted_component_unavailable", "受信组件无法检查。")
    })?;
    Ok(FileBindingV1 {
        path_sha256: path_sha256(&canonical)?,
        sha256: hash_file(&canonical)?,
        size_bytes: metadata.len(),
    })
}

fn ordinary_local_file(path: &Path) -> Result<PathBuf, QualificationError> {
    ordinary_local_path(path, false)
}

fn ordinary_local_directory(path: &Path) -> Result<PathBuf, QualificationError> {
    ordinary_local_path(path, true)
}

fn ordinary_local_path(path: &Path, directory: bool) -> Result<PathBuf, QualificationError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
    {
        return Err(QualificationError::new(
            "trusted_path_invalid",
            "受信组件必须位于本机绝对路径。",
        ));
    }
    for ancestor in path.ancestors() {
        if let Ok(metadata) = fs::symlink_metadata(ancestor) {
            reject_link_or_cloud(&metadata)?;
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        QualificationError::new(
            "trusted_component_unavailable",
            "受信组件不存在或不可访问。",
        )
    })?;
    reject_link_cloud_or_hardlink(&metadata)?;
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(QualificationError::new(
            "trusted_path_invalid",
            "受信组件对象类型无效。",
        ));
    }
    fs::canonicalize(path)
        .map_err(|_| QualificationError::new("trusted_component_unavailable", "受信组件无法解析。"))
}

fn reject_link_or_cloud(metadata: &fs::Metadata) -> Result<(), QualificationError> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    let attributes = metadata.file_attributes();
    if metadata.file_type().is_symlink()
        || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || attributes
            & (FILE_ATTRIBUTE_OFFLINE
                | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
            != 0
    {
        return Err(QualificationError::new(
            "trusted_path_rejected",
            "受信组件不得位于链接、reparse point 或云端占位对象。",
        ));
    }
    Ok(())
}

fn reject_link_cloud_or_hardlink(metadata: &fs::Metadata) -> Result<(), QualificationError> {
    reject_link_or_cloud(metadata)
}

fn ensure_private_directory(path: &Path) -> Result<(), QualificationError> {
    fs::create_dir_all(path).map_err(|_| {
        QualificationError::new("qualification_store_unavailable", "资格状态目录无法创建。")
    })?;
    let _ = ordinary_local_directory(path)?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, QualificationError> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| {
            QualificationError::new(
                "trusted_component_unavailable",
                "Trusted component cannot be read.",
            )
        })?;
    validate_pinned_file(&file, path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| {
            QualificationError::new(
                "trusted_component_unavailable",
                "Trusted component cannot be read.",
            )
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    validate_pinned_file(&file, path)?;
    Ok(format!("{:x}", digest.finalize()))
}
fn is_fixed_system_nvidia_probe(path: &Path) -> bool {
    let mut buffer = vec![0u16; 32_768];
    let written = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if written == 0 || written as usize >= buffer.len() {
        return false;
    }
    buffer.truncate(written as usize);
    let expected = PathBuf::from(std::ffi::OsString::from_wide(&buffer))
        .join("System32")
        .join("nvidia-smi.exe");
    fs::canonicalize(expected)
        .is_ok_and(|expected| normalize_windows_path(&expected) == normalize_windows_path(path))
}

fn validate_pinned_file(file: &File, expected: &Path) -> Result<(), QualificationError> {
    let handle = file.as_raw_handle() as HANDLE;
    if handle.is_null() {
        return Err(QualificationError::new(
            "trusted_component_unavailable",
            "Trusted component handle is invalid.",
        ));
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(QualificationError::new(
            "trusted_component_unavailable",
            "Trusted component file identity cannot be read.",
        ));
    }
    if information.nNumberOfLinks == 0
        || (information.nNumberOfLinks != 1 && !is_fixed_system_nvidia_probe(expected))
    {
        return Err(QualificationError::new(
            "trusted_hardlink_rejected",
            "Trusted components must be single-link files except for the fixed Windows NVIDIA probe.",
        ));
    }
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if required == 0 {
        return Err(QualificationError::new(
            "trusted_component_unavailable",
            "Trusted component identity cannot be read.",
        ));
    }
    let mut buffer = vec![0u16; required as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(QualificationError::new(
            "trusted_component_unavailable",
            "Trusted component identity cannot be read.",
        ));
    }
    let actual = PathBuf::from(std::ffi::OsString::from_wide(&buffer[..written as usize]));
    if normalize_windows_path(&actual) != normalize_windows_path(expected) {
        return Err(QualificationError::new(
            "trusted_component_changed",
            "Trusted component identity changed while it was read.",
        ));
    }
    Ok(())
}

fn normalize_windows_path(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}").to_ascii_lowercase()
    } else if let Some(dos) = rendered.strip_prefix(r"\\?\") {
        dos.to_ascii_lowercase()
    } else {
        rendered.to_ascii_lowercase()
    }
}

fn path_sha256(path: &Path) -> Result<String, QualificationError> {
    let canonical = fs::canonicalize(path).map_err(|_| {
        QualificationError::new("trusted_component_unavailable", "受信组件无法解析。")
    })?;
    let normalized = canonical
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    Ok(sha256_hex(normalized.as_bytes()))
}

fn sign_claims<T: Serialize>(
    domain: &[u8],
    key: &[u8],
    claims: &T,
) -> Result<String, QualificationError> {
    let canonical = serde_json::to_vec(claims).map_err(|_| {
        QualificationError::new("qualification_state_invalid", "资格状态无法签名。")
    })?;
    Ok(hex(&hmac_sha256(key, domain, &canonical)))
}

fn hmac_sha256(key: &[u8], domain: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(domain);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn valid_hash(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn unix_now() -> Result<u64, QualificationError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| {
            QualificationError::new("system_clock_invalid", "系统时间无效，资格状态不可用。")
        })
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, QualificationError> {
    let canonical = ordinary_local_file(path)?;
    let metadata = fs::metadata(&canonical).map_err(|_| {
        QualificationError::new("qualification_store_unavailable", "资格状态无法读取。")
    })?;
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(QualificationError::new(
            "qualification_state_invalid",
            "资格状态大小无效。",
        ));
    }
    fs::read(canonical).map_err(|_| {
        QualificationError::new("qualification_store_unavailable", "资格状态无法读取。")
    })
}

fn temporary_sibling(destination: &Path) -> PathBuf {
    destination.with_file_name(format!(
        ".{}.{}.tmp",
        destination
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
        Uuid::new_v4().simple()
    ))
}

fn atomic_write(destination: &Path, bytes: &[u8]) -> Result<(), QualificationError> {
    let parent = destination.parent().ok_or_else(|| {
        QualificationError::new("qualification_store_unavailable", "资格状态路径无效。")
    })?;
    ensure_private_directory(parent)?;
    let temporary = temporary_sibling(destination);
    let result = (|| {
        write_new_file(&temporary, bytes)?;
        atomic_file::install(&temporary, destination, None).map_err(|_| {
            QualificationError::new("qualification_store_unavailable", "资格状态无法原子提交。")
        })
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), QualificationError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|_| {
            QualificationError::new(
                "qualification_store_unavailable",
                "资格状态临时文件无法创建。",
            )
        })?;
    file.write_all(bytes).map_err(|_| {
        QualificationError::new(
            "qualification_store_unavailable",
            "资格状态临时文件无法写入。",
        )
    })?;
    file.sync_all().map_err(|_| {
        QualificationError::new(
            "qualification_store_unavailable",
            "资格状态临时文件无法同步。",
        )
    })
}

fn remove_file_if_present(path: &Path) -> Result<(), QualificationError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(QualificationError::new(
            "qualification_store_unavailable",
            "资格状态临时文件无法清理。",
        )),
    }
}

pub(crate) fn require_administrator_token() -> Result<(), QualificationError> {
    if unsafe { IsUserAnAdmin() } == 0 {
        return Err(QualificationError::new(
            "network_isolation_install_requires_administrator",
            "安装 Windows 防火墙隔离规则需要管理员权限。",
        ));
    }
    Ok(())
}

fn run_firewall_script(request_path: &Path, install: bool) -> Result<(), QualificationError> {
    let mut command = trusted_windows_powershell_command().map_err(|_| {
        QualificationError::new(
            "network_isolation_unavailable",
            "Windows 防火墙网络隔离检查无法启动。",
        )
    })?;
    let output = command
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-Command")
        .arg(if install {
            FIREWALL_INSTALL_SCRIPT
        } else {
            FIREWALL_VERIFY_SCRIPT
        })
        .arg("-RequestPath")
        .arg(request_path)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| {
            QualificationError::new(
                "network_isolation_unavailable",
                "Windows 防火墙网络隔离检查无法启动。",
            )
        })?;
    if !output.status.success() {
        return Err(firewall_script_error(install, output.status.code()));
    }
    if !install {
        let stdout = String::from_utf8(output.stdout).map_err(|_| {
            QualificationError::new(
                "network_isolation_not_enforced",
                "Windows 防火墙隔离检查输出无效。",
            )
        })?;
        let value: serde_json::Value = serde_json::from_str(stdout.trim()).map_err(|_| {
            QualificationError::new(
                "network_isolation_not_enforced",
                "Windows 防火墙隔离检查输出无效。",
            )
        })?;
        if value.get("verified").and_then(serde_json::Value::as_bool) != Some(true)
            || value
                .get("profilesEnabled")
                .and_then(serde_json::Value::as_bool)
                != Some(true)
        {
            return Err(QualificationError::new(
                "network_isolation_not_enforced",
                "Windows 防火墙隔离规则或全局防火墙 Profile 未通过验证。",
            ));
        }
    }
    Ok(())
}

fn firewall_script_error(install: bool, exit_code: Option<i32>) -> QualificationError {
    match (install, exit_code) {
        (true, Some(5)) => QualificationError::new(
            "network_isolation_install_requires_administrator",
            "安装 Windows 防火墙隔离规则需要管理员权限。",
        ),
        (_, Some(44)) => QualificationError::new(
            "network_isolation_firewall_profile_disabled",
            "Windows Defender Firewall 的 Domain、Private 或 Public Profile 未全部启用。",
        ),
        (true, Some(45)) => QualificationError::new(
            "network_isolation_install_failed_rolled_back",
            "Windows 防火墙隔离规则安装失败；本次规则已全部回滚。",
        ),
        (true, Some(46)) => QualificationError::new(
            "network_isolation_install_rollback_failed",
            "Windows 防火墙隔离规则安装失败且本次规则未能完整回滚。",
        ),
        _ => QualificationError::new(
            "network_isolation_not_enforced",
            "Windows 防火墙隔离规则不存在、失效、Profile 未启用或与受信运行时不匹配。",
        ),
    }
}

const EXPECTED_CANARY_PAGES: [[&str; 8]; 3] = [
    [
        "合成法律文书 OCR 测试 第1页",
        "原告：张三",
        "被告：某某科技有限公司",
        "联系电话：13800138000",
        "身份证号：11010519491231002X",
        "邮箱：case.test@example.invalid",
        "案号：（2026）京0101民初123号",
        "页面标识：LOCAL-CANARY-PAGE-ONE",
    ],
    [
        "合成法律文书 OCR 测试 第2页",
        "申请人：李四",
        "被申请人：某某贸易有限公司",
        "联系电话：13900139000",
        "身份证号：310101198001010037",
        "邮箱：case.two@example.invalid",
        "案号：（2026）沪0101民初456号",
        "页面标识：LOCAL-CANARY-PAGE-TWO",
    ],
    [
        "合成法律文书 OCR 测试 第3页",
        "委托人：王五",
        "相对方：某某服务有限公司",
        "联系电话：13700137000",
        "身份证号：440106199002020018",
        "邮箱：case.three@example.invalid",
        "案号：（2026）粤0106民初789号",
        "页面标识：LOCAL-CANARY-PAGE-THREE",
    ],
];

fn qualification_processing_error(error: ProcessingError) -> QualificationError {
    QualificationError::new(
        error.code(),
        "The local MinerU worker protocol or OCR validation failed closed.",
    )
}

fn validate_protocol_probe(
    probe: &WorkerProtocolProbeEvidenceV1,
    trust: &VerifiedTrustInstallation,
    gpu: &SelectedGpuMeasurement,
) -> Result<(), QualificationError> {
    let versions = [
        probe.identity.worker_version.as_str(),
        probe.identity.python_version.as_str(),
        probe.identity.mineru_version.as_str(),
        probe.identity.pytorch_version.as_str(),
        probe.identity.cuda_runtime_version.as_str(),
        probe.identity.gpu_driver_version.as_str(),
        probe.identity.model_version.as_str(),
    ];
    if probe.protocol_version != MINERU_WORKER_PROTOCOL_V1
        || !valid_hash(&probe.identity_sha256)
        || !valid_hash(&probe.health_evidence_sha256)
        || probe.health.case_material_loaded
        || probe.identity.worker_sha256 != trust.worker_sha256()
        || probe.identity.config_sha256 != trust.tools_config_sha256()
        || probe.identity.model_manifest_sha256 != trust.model_manifest_sha256()
        || probe.identity.gpu_driver_version != gpu.selected_gpu_driver_version
        || versions.iter().any(|value| !valid_version_evidence(value))
    {
        return Err(QualificationError::new(
            "qualification_worker_identity_invalid",
            "The worker hello or health evidence is not bound to the trusted environment.",
        ));
    }
    match &probe.identity.actual_device {
        WorkerDeviceV1::Cuda {
            indices,
            hardware_fingerprint_sha256,
        } if indices.as_slice() == [0]
            && hardware_fingerprint_sha256 == &gpu.selected_gpu_descriptor_sha256 => {}
        _ => {
            return Err(QualificationError::new(
                "qualification_gpu_binding_mismatch",
                "The worker did not prove the exact selected CUDA GPU.",
            ));
        }
    }
    Ok(())
}

fn validate_canary_document(
    document: &ProcessedDocument,
    trust: &VerifiedTrustInstallation,
) -> Result<(), QualificationError> {
    if document.media_type != "application/pdf"
        || document.page_count != 3
        || document.pages.len() != 3
        || document.backend_trace.len() != 1
    {
        return Err(QualificationError::new(
            "qualification_canary_incomplete",
            "The synthetic canary did not produce exactly three complete OCR pages.",
        ));
    }
    let trace = &document.backend_trace[0];
    if trace.backend != ExtractionBackend::MineruLocal
        || trace.worker_sha256.as_deref() != Some(trust.worker_sha256())
        || trace.model_manifest_sha256.as_deref() != Some(trust.model_manifest_sha256())
        || trace.config_sha256.as_deref() != Some(trust.tools_config_sha256())
        || trace.device != "cuda:0"
        || trace.page_numbers != [1, 2, 3]
        || !trace.isolation_verified
        || trace.isolation_mechanism.as_deref() != Some(WINDOWS_FIREWALL_ISOLATION_MECHANISM)
    {
        return Err(QualificationError::new(
            "qualification_canary_binding_mismatch",
            "The synthetic canary trace is not bound to the trusted local OCR tuple.",
        ));
    }
    for (page_index, page) in document.pages.iter().enumerate() {
        if page.page_number != u32::try_from(page_index + 1).unwrap_or(u32::MAX)
            || page.spans.len() != EXPECTED_CANARY_PAGES[page_index].len()
            || page
                .spans
                .iter()
                .any(|span| span.backend != ExtractionBackend::MineruLocal)
        {
            return Err(QualificationError::new(
                "qualification_canary_incomplete",
                "The synthetic canary page or entry count is incomplete.",
            ));
        }
        for (span, expected) in page
            .spans
            .iter()
            .zip(EXPECTED_CANARY_PAGES[page_index].iter())
        {
            if normalized_canary_text(&span.text) != normalized_canary_text(expected) {
                return Err(QualificationError::new(
                    "qualification_canary_text_mismatch",
                    "The synthetic canary OCR text did not exactly match the fixed fixture.",
                ));
            }
        }
    }
    Ok(())
}

fn normalized_canary_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn expected_canary_text_sha256() -> String {
    sha256_hex(
        EXPECTED_CANARY_PAGES
            .iter()
            .flat_map(|page| page.iter())
            .copied()
            .collect::<Vec<_>>()
            .join("\n")
            .as_bytes(),
    )
}

fn validate_protocol_report(
    report: &ProtocolQualificationReportV1,
    claims: &QualificationStateClaimsV1,
) -> Result<(), QualificationError> {
    if report.schema_version != 1
        || report.qualification_report_id != claims.qualification_report_id
        || report.protocol_version != claims.worker_protocol_version
        || report.worker_identity_sha256 != claims.worker_protocol_identity_sha256
        || report.worker_health_evidence_sha256 != claims.worker_health_evidence_sha256
        || report.worker_sha256 != claims.worker_sha256
        || report.runtime_manifest_sha256 != claims.runtime_manifest_sha256
        || report.config_sha256 != claims.tools_config_sha256
        || report.model_manifest_sha256 != claims.model_manifest_sha256
        || report.selected_gpu_descriptor_sha256 != claims.selected_gpu_descriptor_sha256
        || report.expected_text_sha256 != expected_canary_text_sha256()
        || report.page_count != 3
        || report.entry_count != 24
        || report.completed_at_unix < claims.issued_at_unix
        || report.completed_at_unix >= claims.expires_at_unix
        || !valid_hash(&report.isolation_bundle_sha256)
        || !valid_hash(&report.source_sha256)
        || !valid_hash(&report.processed_document_sha256)
    {
        return Err(QualificationError::new(
            "qualification_report_invalid",
            "The protocol qualification report is incomplete or not bound to signed state.",
        ));
    }
    Ok(())
}

fn valid_version_evidence(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value == value.trim()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanaryGeneratorResultV1 {
    schema_version: u16,
    kind: String,
    page_count: u32,
    expected_entry_count: u32,
}

fn run_canary_generator(script_path: &Path, destination: &Path) -> Result<(), QualificationError> {
    let mut command = trusted_windows_powershell_command().map_err(|_| {
        QualificationError::new(
            "qualification_canary_unavailable",
            "受信 Windows PowerShell 无法启动合成资格 canary。",
        )
    })?;
    let mut child = command
        .arg("-NoLogo")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-ExecutionPolicy")
        .arg("Bypass")
        .arg("-File")
        .arg(script_path)
        .arg("-GenerateCanaryOnlyPath")
        .arg(destination)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            QualificationError::new(
                "qualification_canary_unavailable",
                "The fixed synthetic canary generator could not start.",
            )
        })?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| {
            QualificationError::new(
                "qualification_canary_unavailable",
                "The fixed synthetic canary generator could not be observed.",
            )
        })? {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(60) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(QualificationError::new(
                "qualification_canary_timeout",
                "The fixed synthetic canary generator timed out.",
            ));
        }
        thread::sleep(Duration::from_millis(20));
    };
    let mut stdout = Vec::new();
    child
        .stdout
        .take()
        .ok_or_else(|| {
            QualificationError::new(
                "qualification_canary_invalid",
                "The fixed synthetic canary generator returned no bounded result.",
            )
        })?
        .take(MAX_QUALIFICATION_STDOUT_BYTES as u64 + 1)
        .read_to_end(&mut stdout)
        .map_err(|_| {
            QualificationError::new(
                "qualification_canary_invalid",
                "The fixed synthetic canary generator result could not be read.",
            )
        })?;
    if !status.success() || stdout.is_empty() || stdout.len() > MAX_QUALIFICATION_STDOUT_BYTES {
        return Err(QualificationError::new(
            "qualification_canary_failed",
            "The fixed synthetic canary generator failed closed.",
        ));
    }
    let result: CanaryGeneratorResultV1 = serde_json::from_slice(&stdout).map_err(|_| {
        QualificationError::new(
            "qualification_canary_invalid",
            "The fixed synthetic canary generator result was invalid.",
        )
    })?;
    if result.schema_version != 1
        || result.kind != "lawyer-assistance-local-mineru-synthetic-canary"
        || result.page_count != 3
        || result.expected_entry_count != 24
    {
        return Err(QualificationError::new(
            "qualification_canary_invalid",
            "The fixed synthetic canary generator result did not match the fixed fixture.",
        ));
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_canary_generator_runs_under_trusted_clean_powershell() {
        let root = tempfile::tempdir().expect("temporary canary root");
        let script = root.path().join(QUALIFICATION_SCRIPT_FILE_NAME);
        let destination = root.path().join("qualification-canary.pdf");
        fs::write(&script, QUALIFICATION_SCRIPT.as_bytes()).expect("write embedded script");
        run_canary_generator(&script, &destination).expect("generate fixed canary");
        let bytes = fs::read(destination).expect("read generated canary");
        assert!(bytes.starts_with(b"%PDF-"));
        assert!(bytes.len() <= MAX_CANARY_PDF_BYTES as usize);
    }

    #[test]
    fn arbitrary_hardlinks_remain_rejected_by_trust_hashing() {
        let root = tempfile::tempdir().expect("temp");
        let original = root.path().join("probe.exe");
        let alias = root.path().join("probe-alias.exe");
        fs::write(&original, b"MZsynthetic").expect("fixture");
        fs::hard_link(&original, &alias).expect("hardlink");
        assert_eq!(
            hash_file(&original)
                .expect_err("arbitrary hardlink rejected")
                .code(),
            "trusted_hardlink_rejected"
        );
    }

    #[test]
    fn fixed_system_nvidia_probe_can_bind_driverstore_hardlink_when_present() {
        let Some(system_root) = std::env::var_os("SystemRoot") else {
            return;
        };
        let probe = PathBuf::from(system_root)
            .join("System32")
            .join("nvidia-smi.exe");
        if probe.is_file() && is_fixed_system_nvidia_probe(&probe) {
            assert_eq!(hash_file(&probe).expect("fixed probe hashes").len(), 64);
        }
    }

    const TEST_CRITICAL_SUPPORT_FILES: [&str; 16] = [
        "worker/lawyer_assistance_mineru_worker/__init__.py",
        "worker/lawyer_assistance_mineru_worker/main.py",
        "worker/lawyer_assistance_mineru_worker/output_document.py",
        "worker/lawyer_assistance_mineru_worker/protocol.py",
        "worker/lawyer_assistance_mineru_worker/runtime.py",
        "worker/lawyer_assistance_mineru_worker/single_process.py",
        "worker/lawyer_assistance_mineru_worker/support_manifest.py",
        "worker/mineru-worker._pth",
        "worker/python312._pth",
        "worker/python312.dll",
        "worker/sitecustomize.py",
        "python/Lib/os.py",
        "python/Lib/site.py",
        "runtime/site-packages/mineru/__init__.py",
        "runtime/site-packages/pypdfium2/__init__.py",
        "runtime/site-packages/torch/__init__.py",
    ];

    fn write_test_support_component(root: &Path) -> PathBuf {
        let component_root = root.join("component");
        let worker = component_root.join("worker/mineru-worker.exe");
        fs::create_dir_all(worker.parent().expect("worker parent")).expect("worker directory");
        fs::write(&worker, b"MZsynthetic-worker").expect("worker");

        let mut declared = TEST_CRITICAL_SUPPORT_FILES.to_vec();
        declared.sort_unstable();
        let mut files = Vec::with_capacity(declared.len());
        let mut tree = Sha256::new();
        tree.update(b"la-mineru-support-tree-v1\n");
        for relative in declared {
            let path = relative
                .split('/')
                .fold(component_root.clone(), |path, part| path.join(part));
            fs::create_dir_all(path.parent().expect("support parent")).expect("support directory");
            let bytes = format!("synthetic support fixture: {relative}\n").into_bytes();
            fs::write(&path, &bytes).expect("support file");
            let sha256 = sha256_hex(&bytes);
            tree.update(relative.as_bytes());
            tree.update(b"\n");
            tree.update(bytes.len().to_string().as_bytes());
            tree.update(b"\n");
            tree.update(sha256.as_bytes());
            tree.update(b"\n");
            files.push(serde_json::json!({
                "relativePath": relative,
                "sizeBytes": bytes.len(),
                "sha256": sha256,
            }));
        }
        let support_tree_digest = tree.finalize();
        let support_tree_sha256 = hex(&support_tree_digest);
        let support_identity_sha256 = sha256_hex(
            format!(
                "la-mineru-support-identity-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
                MINERU_WORKER_PROTOCOL_V1,
                "1.0.0",
                "3.12.13",
                "3.4.3",
                "2.8.0+cu128",
                support_tree_sha256,
            )
            .as_bytes(),
        );
        let manifest = serde_json::json!({
            "schemaVersion": 1,
            "manifestVersion": "lawyer-assistance-mineru-support-v1",
            "selfContained": true,
            "protocolVersion": MINERU_WORKER_PROTOCOL_V1,
            "workerVersion": "1.0.0",
            "pythonVersion": "3.12.13",
            "mineruVersion": "3.4.3",
            "pytorchVersion": "2.8.0+cu128",
            "supportTreeSha256": support_tree_sha256,
            "supportIdentitySha256": support_identity_sha256,
            "criticalFiles": TEST_CRITICAL_SUPPORT_FILES,
            "files": files,
        });
        fs::write(
            component_root.join("worker/mineru-worker.support-manifest.json"),
            serde_json::to_vec(&manifest).expect("support manifest serializes"),
        )
        .expect("support manifest");
        worker
    }

    fn make_environment(root: &Path) -> QualificationEnvironment {
        let worker = write_test_support_component(root);
        let config = root.join("mineru.json");
        let nvidia_smi = root.join("nvidia-smi.exe");
        let models = root.join("models");
        fs::create_dir(&models).expect("models");
        fs::write(&config, br#"{"models-dir":{"pipeline":"models"}}"#).expect("config");
        fs::write(&nvidia_smi, b"synthetic-nvidia-smi").expect("nvidia-smi");
        fs::write(models.join("model.bin"), b"synthetic-model").expect("model");
        QualificationEnvironment {
            worker_path: worker,
            tools_config_path: config,
            model_root: models,
            nvidia_smi_path: nvidia_smi,
            runtime_executable_paths: Vec::new(),
            timeout_seconds: 30,
        }
    }

    #[test]
    fn trust_install_is_signed_and_environment_changes_invalidate_it() {
        let directory = tempfile::tempdir().expect("temp");
        let privacy = directory.path().join("privacy");
        fs::create_dir(&privacy).expect("privacy");
        let environment = make_environment(directory.path());
        let repository = QualificationRepository::new(&privacy).expect("repository");
        let installed = repository
            .install_trust(&environment)
            .expect("install trust");
        assert_eq!(installed.model_file_count, 1);
        repository.verify_trust(&environment).expect("verify trust");

        fs::write(environment.model_root.join("extra.bin"), b"extra").expect("extra");
        assert_eq!(
            repository
                .verify_trust(&environment)
                .expect_err("extra model invalidates")
                .code(),
            "model_files_changed"
        );
    }

    #[test]
    fn trust_signature_tampering_fails_closed() {
        let directory = tempfile::tempdir().expect("temp");
        let privacy = directory.path().join("privacy");
        fs::create_dir(&privacy).expect("privacy");
        let environment = make_environment(directory.path());
        let repository = QualificationRepository::new(&privacy).expect("repository");
        repository
            .install_trust(&environment)
            .expect("install trust");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&repository.trust_path).expect("trust bytes"))
                .expect("trust json");
        value["claims"]["policyVersion"] = serde_json::json!(999);
        fs::write(
            &repository.trust_path,
            serde_json::to_vec(&value).expect("tampered json"),
        )
        .expect("tamper");
        assert!(repository.verify_trust(&environment).is_err());
    }

    #[test]
    fn trusted_nvidia_probe_change_fails_closed() {
        let directory = tempfile::tempdir().expect("temp");
        let privacy = directory.path().join("privacy");
        fs::create_dir(&privacy).expect("privacy");
        let environment = make_environment(directory.path());
        let repository = QualificationRepository::new(&privacy).expect("repository");
        repository
            .install_trust(&environment)
            .expect("install trust");

        fs::write(&environment.nvidia_smi_path, b"changed-nvidia-smi").expect("change nvidia-smi");
        assert_eq!(
            repository
                .verify_trust(&environment)
                .expect_err("changed GPU probe invalidates trust")
                .code(),
            "trusted_gpu_probe_changed"
        );
    }

    #[test]
    fn qualification_state_requires_real_os_rule_and_cannot_be_self_asserted() {
        let directory = tempfile::tempdir().expect("temp");
        let privacy = directory.path().join("privacy");
        fs::create_dir(&privacy).expect("privacy");
        let environment = make_environment(directory.path());
        let repository = QualificationRepository::new(&privacy).expect("repository");
        repository
            .install_trust(&environment)
            .expect("install trust");
        let trust = repository.verify_trust(&environment).expect("trust");
        assert_eq!(
            repository
                .verify_firewall_isolation(&environment, &trust)
                .expect_err("test worker has no firewall rule")
                .code(),
            "network_isolation_not_enforced"
        );
    }
    #[test]
    fn firewall_install_is_profile_gated_and_rolls_back_every_requested_rule() {
        assert!(FIREWALL_INSTALL_SCRIPT.contains("Get-NetFirewallProfile -PolicyStore ActiveStore"));
        assert!(FIREWALL_INSTALL_SCRIPT.contains("@('Domain','Private','Public')"));
        assert!(FIREWALL_INSTALL_SCRIPT.contains("if($rollbackFailed){ exit 46 }"));
        assert!(FIREWALL_INSTALL_SCRIPT.contains("exit 45"));
        let create = FIREWALL_INSTALL_SCRIPT
            .find("New-NetFirewallRule")
            .expect("create command");
        let catch = FIREWALL_INSTALL_SCRIPT
            .find("} catch {")
            .expect("transaction catch");
        let rollback_remove = FIREWALL_INSTALL_SCRIPT[catch..]
            .find("Remove-NetFirewallRule")
            .expect("rollback removal");
        assert!(create < catch);
        assert!(rollback_remove > 0);
        assert!(FIREWALL_VERIFY_SCRIPT.contains("Get-NetFirewallProfile -PolicyStore ActiveStore"));
        assert!(FIREWALL_VERIFY_SCRIPT.contains("profilesEnabled=$true"));
    }

    #[test]
    fn firewall_script_exit_codes_are_stable_and_fail_closed() {
        for (install, exit_code, expected) in [
            (
                true,
                Some(5),
                "network_isolation_install_requires_administrator",
            ),
            (
                false,
                Some(44),
                "network_isolation_firewall_profile_disabled",
            ),
            (
                true,
                Some(45),
                "network_isolation_install_failed_rolled_back",
            ),
            (true, Some(46), "network_isolation_install_rollback_failed"),
            (false, Some(42), "network_isolation_not_enforced"),
            (true, None, "network_isolation_not_enforced"),
        ] {
            assert_eq!(firewall_script_error(install, exit_code).code(), expected);
        }
    }
}
