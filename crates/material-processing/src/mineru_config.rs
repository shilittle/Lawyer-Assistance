use crate::types::{DeviceSelection, LocalMineruConfig, ProcessingError};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MODEL_FILES: usize = 100_000;

#[derive(Debug, Clone)]
pub(crate) struct ValidatedLocalMineru {
    pub executable_sha256: String,
    pub config_sha256: String,
    pub model_manifest_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelManifest {
    version: String,
    files: Vec<ModelFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelFile {
    relative_path: String,
    sha256: String,
    size_bytes: u64,
}

pub fn validate_local_mineru_config(config: &LocalMineruConfig) -> Result<(), ProcessingError> {
    validate_config(config).map(|_| ())
}

pub(crate) fn validate_config(
    config: &LocalMineruConfig,
) -> Result<ValidatedLocalMineru, ProcessingError> {
    if config.timeout_ms < 1_000
        || config.timeout_ms > 3_600_000
        || config.max_output_bytes == 0
        || !supported_language(&config.language)
        || !valid_hash(&config.expected_executable_sha256)
        || !valid_hash(&config.expected_config_sha256)
        || !valid_hash(&config.expected_model_manifest_sha256)
    {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    validate_device(&config.device)?;
    if config.strict_offline
        && (!config.network_isolation.verified
            || config.network_isolation.mechanism.trim().is_empty()
            || config.network_isolation.checked_at_unix == 0)
    {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }

    require_absolute_regular_file(&config.executable)
        .map_err(|_| ProcessingError::OcrBackendUnavailable)?;
    require_absolute_regular_file(&config.mineru_config)
        .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    require_absolute_regular_file(&config.model_manifest)
        .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    let model_root = require_absolute_directory(&config.model_root)
        .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    let temporary_root = require_absolute_directory(&config.temporary_root)
        .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    if temporary_root.starts_with(&model_root) || model_root.starts_with(&temporary_root) {
        return Err(ProcessingError::OcrConfigUnsafe);
    }

    let executable_sha256 =
        hash_file(&config.executable, None).map_err(|_| ProcessingError::OcrWorkerUntrusted)?;
    if executable_sha256 != config.expected_executable_sha256.to_ascii_lowercase() {
        return Err(ProcessingError::OcrWorkerUntrusted);
    }

    let config_bytes = read_bounded(&config.mineru_config, MAX_CONFIG_BYTES)
        .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    let config_sha256 = sha256_hex(&config_bytes);
    if config_sha256 != config.expected_config_sha256.to_ascii_lowercase() {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    validate_mineru_json(&config_bytes, &model_root)?;

    let manifest_bytes = read_bounded(&config.model_manifest, MAX_MANIFEST_BYTES)
        .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    let model_manifest_sha256 = sha256_hex(&manifest_bytes);
    if model_manifest_sha256 != config.expected_model_manifest_sha256.to_ascii_lowercase() {
        return Err(ProcessingError::OcrModelUntrusted);
    }
    let manifest: ModelManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| ProcessingError::OcrModelUntrusted)?;
    validate_model_manifest(&manifest, &model_root)?;

    Ok(ValidatedLocalMineru {
        executable_sha256,
        config_sha256,
        model_manifest_sha256,
    })
}

fn validate_device(device: &DeviceSelection) -> Result<(), ProcessingError> {
    if let DeviceSelection::Cuda { indices } = device {
        let unique = indices.iter().copied().collect::<BTreeSet<_>>();
        if indices.is_empty()
            || indices.len() > 16
            || unique.len() != indices.len()
            || indices.iter().any(|index| *index > 63)
        {
            return Err(ProcessingError::OcrConfigUnsafe);
        }
    }
    Ok(())
}

fn supported_language(language: &str) -> bool {
    matches!(
        language,
        "ch" | "ch_server"
            | "korean"
            | "ta"
            | "te"
            | "ka"
            | "th"
            | "el"
            | "arabic"
            | "east_slavic"
            | "cyrillic"
            | "devanagari"
    )
}

fn validate_mineru_json(bytes: &[u8], model_root: &Path) -> Result<(), ProcessingError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    if contains_remote_url(&value)
        || value
            .get("llm-aided-config")
            .and_then(|entry| entry.get("enable"))
            .and_then(Value::as_bool)
            == Some(true)
    {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    let models = value
        .get("models-dir")
        .and_then(Value::as_object)
        .ok_or(ProcessingError::OcrConfigUnsafe)?;
    for key in ["pipeline", "vlm"] {
        if let Some(path) = models.get(key).and_then(Value::as_str) {
            let canonical = fs::canonicalize(path).map_err(|_| ProcessingError::OcrConfigUnsafe)?;
            if !canonical.starts_with(model_root) {
                return Err(ProcessingError::OcrConfigUnsafe);
            }
        }
    }
    if !models.values().any(Value::is_string) {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    Ok(())
}

fn contains_remote_url(value: &Value) -> bool {
    match value {
        Value::String(text) => {
            let lowered = text.trim().to_ascii_lowercase();
            lowered.starts_with("http://")
                || lowered.starts_with("https://")
                || lowered.starts_with("ssh://")
        }
        Value::Array(values) => values.iter().any(contains_remote_url),
        Value::Object(values) => values.values().any(contains_remote_url),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn validate_model_manifest(
    manifest: &ModelManifest,
    model_root: &Path,
) -> Result<(), ProcessingError> {
    if manifest.version.trim().is_empty()
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_MODEL_FILES
    {
        return Err(ProcessingError::OcrModelUntrusted);
    }
    let mut unique = BTreeSet::new();
    for entry in &manifest.files {
        if entry.relative_path.is_empty()
            || !valid_hash(&entry.sha256)
            || !unique.insert(entry.relative_path.clone())
        {
            return Err(ProcessingError::OcrModelUntrusted);
        }
        let relative = Path::new(&entry.relative_path);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(ProcessingError::OcrModelUntrusted);
        }
        let path = model_root.join(relative);
        let canonical =
            require_absolute_regular_file(&path).map_err(|_| ProcessingError::OcrModelUntrusted)?;
        if !canonical.starts_with(model_root) {
            return Err(ProcessingError::OcrModelUntrusted);
        }
        let actual = hash_file(&canonical, Some(entry.size_bytes))
            .map_err(|_| ProcessingError::OcrModelUntrusted)?;
        if actual != entry.sha256.to_ascii_lowercase() {
            return Err(ProcessingError::OcrModelUntrusted);
        }
    }
    Ok(())
}

fn require_absolute_regular_file(path: &Path) -> Result<PathBuf, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    ensure_local_path_chain(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_file() || is_link_or_reparse(&metadata) {
        return Err(());
    }
    fs::canonicalize(path).map_err(|_| ())
}

fn require_absolute_directory(path: &Path) -> Result<PathBuf, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    ensure_local_path_chain(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir() || is_link_or_reparse(&metadata) {
        return Err(());
    }
    fs::canonicalize(path).map_err(|_| ())
}

fn ensure_local_path_chain(path: &Path) -> Result<(), ()> {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};

        let drive = match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => return Err(()),
            },
            _ => return Err(()),
        };
        ensure_windows_fixed_local_drive(drive)?;
    }

    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_link_or_reparse(&metadata) => return Err(()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(()),
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn ensure_windows_fixed_local_drive(drive: u8) -> Result<(), ()> {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: `root` is a stack-allocated, NUL-terminated `X:\` UTF-16 buffer
    // whose pointer remains valid for the duration of this read-only call.
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    windows_drive_type_is_allowed(drive_type)
        .then_some(())
        .ok_or(())
}

#[cfg(windows)]
fn windows_drive_type_is_allowed(drive_type: u32) -> bool {
    // Win32 GetDriveTypeW: 3 is DRIVE_FIXED. Values 0,1,2,4,5,6 are
    // unknown/no-root/removable/remote/CD-ROM/RAM disk and are rejected.
    const DRIVE_FIXED_LOCAL: u32 = 3;
    drive_type == DRIVE_FIXED_LOCAL
}

#[cfg(windows)]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ()> {
    let metadata = fs::metadata(path).map_err(|_| ())?;
    if metadata.len() > limit {
        return Err(());
    }
    let mut file = File::open(path).map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| ())?);
    file.read_to_end(&mut bytes).map_err(|_| ())?;
    if u64::try_from(bytes.len()).map_err(|_| ())? > limit {
        return Err(());
    }
    Ok(bytes)
}

fn hash_file(path: &Path, expected_size: Option<u64>) -> Result<String, ()> {
    let metadata = fs::metadata(path).map_err(|_| ())?;
    if expected_size.is_some_and(|expected| metadata.len() != expected) {
        return Err(());
    }
    let mut file = File::open(path).map_err(|_| ())?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex(&digest.finalize()))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_urls_and_enabled_llm_aid_are_rejected() {
        let root = Path::new(".");
        for json in [
            br#"{"models-dir":{"pipeline":"."},"server":"https://example.invalid"}"#.as_slice(),
            br#"{"models-dir":{"pipeline":"."},"llm-aided-config":{"enable":true}}"#.as_slice(),
        ] {
            assert_eq!(
                validate_mineru_json(json, root),
                Err(ProcessingError::OcrConfigUnsafe)
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn unc_and_reparse_ancestor_paths_are_rejected() {
        assert!(ensure_local_path_chain(Path::new(r"\\server\share\mineru.exe")).is_err());

        let link_parent = tempfile::tempdir().expect("link parent");
        let target = tempfile::tempdir().expect("link target");
        fs::write(target.path().join("mineru.exe"), b"worker").expect("worker fixture");
        let link = link_parent.path().join("linked-models");
        if std::os::windows::fs::symlink_dir(target.path(), &link).is_ok() {
            assert!(require_absolute_regular_file(&link.join("mineru.exe")).is_err());
        }
    }

    #[cfg(windows)]
    #[test]
    fn drive_type_policy_accepts_only_fixed_local_volumes() {
        assert!(windows_drive_type_is_allowed(3));
        for rejected in [0, 1, 2, 4, 5, 6] {
            assert!(!windows_drive_type_is_allowed(rejected));
        }
    }

    #[test]
    fn device_selection_rejects_empty_duplicate_and_implausible_indices() {
        for device in [
            DeviceSelection::Cuda { indices: vec![] },
            DeviceSelection::Cuda {
                indices: vec![0, 0],
            },
            DeviceSelection::Cuda { indices: vec![64] },
        ] {
            assert_eq!(
                validate_device(&device),
                Err(ProcessingError::OcrConfigUnsafe)
            );
        }
    }
}
