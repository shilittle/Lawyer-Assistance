use crate::{
    network_isolation::verify_network_isolation,
    types::{
        DeviceSelection, LocalMineruConfig, LocalMineruRuntimeExecutable,
        LocalMineruRuntimeExecutableRole, LocalMineruRuntimeManifestExecutableV1,
        LocalMineruRuntimeManifestV1, MineruBackend, ProcessingError,
        WINDOWS_FIREWALL_ISOLATION_MECHANISM,
    },
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MODEL_FILES: usize = 100_000;
const MAX_RUNTIME_EXECUTABLES: usize = 64;
const MAX_OCR_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
pub const LOCAL_MINERU_RUNTIME_MANIFEST_SCHEMA_VERSION: u16 = 1;
const SUPPORT_MANIFEST_SCHEMA_VERSION: u16 = 1;
const SUPPORT_MANIFEST_VERSION: &str = "lawyer-assistance-mineru-support-v1";
const SUPPORT_WORKER_VERSION: &str = "1.0.0";
const SUPPORT_PYTHON_VERSION: &str = "3.12.13";
const SUPPORT_MINERU_VERSION: &str = "3.4.3";
const SUPPORT_PYTORCH_VERSION: &str = "2.8.0+cu128";
const SUPPORT_PROTOCOL_VERSION: &str = "la-mineru-worker-v1";
const MAX_SUPPORT_FILES: usize = 150_000;
const CRITICAL_SUPPORT_FILES: [&str; 16] = [
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

#[derive(Debug)]
pub(crate) struct ValidatedLocalMineru {
    pub executable_sha256: String,
    pub config_sha256: String,
    pub model_manifest_sha256: String,
    pub support_manifest_sha256: String,
    pub support_identity_sha256: String,
    pub runtime_manifest_sha256: String,
    pub runtime_search_path: OsString,
    pub runtime_programs: Vec<PathBuf>,
    identity_sha256: String,
    _pinned_files: Vec<File>,
}

impl ValidatedLocalMineru {
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.executable_sha256 == other.executable_sha256
            && self.config_sha256 == other.config_sha256
            && self.model_manifest_sha256 == other.model_manifest_sha256
            && self.support_manifest_sha256 == other.support_manifest_sha256
            && self.support_identity_sha256 == other.support_identity_sha256
            && self.runtime_manifest_sha256 == other.runtime_manifest_sha256
            && self.runtime_programs == other.runtime_programs
            && self.identity_sha256 == other.identity_sha256
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelManifest {
    version: String,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManifestFile {
    relative_path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SupportManifest {
    schema_version: u16,
    manifest_version: String,
    self_contained: bool,
    protocol_version: String,
    worker_version: String,
    python_version: String,
    mineru_version: String,
    pytorch_version: String,
    support_tree_sha256: String,
    support_identity_sha256: String,
    critical_files: Vec<String>,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalMineruSupportEvidence {
    pub manifest_sha256: String,
    pub support_tree_sha256: String,
    pub support_identity_sha256: String,
    pub file_count: usize,
}

#[derive(Debug)]
struct PinnedFile {
    canonical: PathBuf,
    sha256: String,
    size_bytes: u64,
    file: File,
}

#[derive(Debug, Clone, Copy)]
enum SizeConstraint {
    AnyNonEmpty,
    Exact(u64),
    MaxNonEmpty(u64),
}

#[derive(Debug)]
struct RuntimeValidation {
    launcher_sha256: String,
    manifest_entries: Vec<LocalMineruRuntimeManifestExecutableV1>,
    programs: Vec<PathBuf>,
    search_path: OsString,
    pins: Vec<File>,
}

#[derive(Debug)]
struct SupportValidation {
    evidence: LocalMineruSupportEvidence,
    pins: Vec<File>,
}

pub fn bind_local_mineru_runtime_executable(
    path: &Path,
    role: LocalMineruRuntimeExecutableRole,
) -> Result<LocalMineruRuntimeExecutable, ProcessingError> {
    let mut pinned = open_pinned_file(path, SizeConstraint::AnyNonEmpty)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    validate_process_image(&mut pinned.file, &pinned.canonical)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    Ok(LocalMineruRuntimeExecutable {
        path: pinned.canonical,
        expected_sha256: pinned.sha256,
        expected_size_bytes: pinned.size_bytes,
        role,
    })
}

pub fn build_local_mineru_runtime_manifest(
    version: &str,
    executables: &[LocalMineruRuntimeExecutable],
) -> Result<LocalMineruRuntimeManifestV1, ProcessingError> {
    if !valid_version(version) {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let validation = validate_runtime_bindings(executables, None, None, &[])?;
    Ok(LocalMineruRuntimeManifestV1 {
        schema_version: LOCAL_MINERU_RUNTIME_MANIFEST_SCHEMA_VERSION,
        version: version.to_owned(),
        executables: validation.manifest_entries,
    })
}

pub fn verify_local_mineru_support_manifest_full(
    executable: &Path,
    support_manifest: &Path,
    expected_support_manifest_sha256: &str,
) -> Result<LocalMineruSupportEvidence, ProcessingError> {
    validate_support_manifest(
        executable,
        support_manifest,
        expected_support_manifest_sha256,
        true,
    )
    .map(|validation| validation.evidence)
}

pub fn validate_local_mineru_config(config: &LocalMineruConfig) -> Result<(), ProcessingError> {
    let validated = validate_config_full_support(config)?;
    verify_network_isolation(&validated.runtime_programs, &config.network_isolation)?;
    Ok(())
}

pub(crate) fn validate_config(
    config: &LocalMineruConfig,
) -> Result<ValidatedLocalMineru, ProcessingError> {
    validate_config_with_support_scope(config, false)
}

pub(crate) fn validate_config_full_support(
    config: &LocalMineruConfig,
) -> Result<ValidatedLocalMineru, ProcessingError> {
    validate_config_with_support_scope(config, true)
}

fn validate_config_with_support_scope(
    config: &LocalMineruConfig,
    full_support: bool,
) -> Result<ValidatedLocalMineru, ProcessingError> {
    if config.timeout_ms < 1_000
        || config.timeout_ms > 3_600_000
        || config.max_output_bytes == 0
        || config.max_output_bytes > MAX_OCR_OUTPUT_BYTES
        || !config.strict_offline
        || !supported_language(&config.language)
        || !valid_hash(&config.expected_executable_sha256)
        || !valid_hash(&config.expected_runtime_manifest_sha256)
        || !valid_lower_hash(&config.expected_support_manifest_sha256)
        || !valid_hash(&config.expected_config_sha256)
        || !valid_hash(&config.expected_model_manifest_sha256)
        || !valid_hash(&config.expected_worker_identity_sha256)
        || !valid_opaque_id(&config.qualification_report_id)
    {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    validate_device(&config.device)?;
    if !config.network_isolation.verified
        || config.network_isolation.mechanism != WINDOWS_FIREWALL_ISOLATION_MECHANISM
        || config.network_isolation.checked_at_unix == 0
        || config.network_isolation.rules.is_empty()
        || config.network_isolation.rules.len() > MAX_RUNTIME_EXECUTABLES
    {
        return Err(ProcessingError::OcrWorkerIsolationUnverified);
    }

    let model_root = require_absolute_directory(&config.model_root)
        .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    let temporary_root = require_absolute_directory(&config.temporary_root)
        .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    if roots_overlap(&model_root, &temporary_root) {
        return Err(ProcessingError::OcrConfigUnsafe);
    }

    let mut config_file = open_pinned_file(
        &config.mineru_config,
        SizeConstraint::MaxNonEmpty(MAX_CONFIG_BYTES),
    )
    .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    if config_file.canonical.starts_with(&model_root)
        || config_file.canonical.starts_with(&temporary_root)
        || config_file.sha256 != config.expected_config_sha256.to_ascii_lowercase()
    {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    let config_bytes = read_pinned_bounded(&mut config_file.file, MAX_CONFIG_BYTES, false)
        .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    validate_mineru_json(&config_bytes, &model_root, config.backend)?;

    let mut runtime_manifest = open_pinned_file(
        &config.runtime_manifest,
        SizeConstraint::MaxNonEmpty(MAX_MANIFEST_BYTES),
    )
    .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    if runtime_manifest.canonical == config_file.canonical
        || runtime_manifest.canonical.starts_with(&model_root)
        || runtime_manifest.canonical.starts_with(&temporary_root)
        || runtime_manifest.sha256 != config.expected_runtime_manifest_sha256.to_ascii_lowercase()
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let runtime_manifest_bytes =
        read_pinned_bounded(&mut runtime_manifest.file, MAX_MANIFEST_BYTES, false)
            .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    let runtime_manifest_claims: LocalMineruRuntimeManifestV1 =
        serde_json::from_slice(&runtime_manifest_bytes)
            .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    validate_runtime_manifest_shape(&runtime_manifest_claims)?;

    let excluded_roots = [&model_root, &temporary_root];
    let mut runtime = validate_runtime_bindings(
        &config.runtime_executables,
        Some(&config.executable),
        Some(&config.expected_executable_sha256),
        &excluded_roots,
    )?;
    if runtime_manifest_claims.executables != runtime.manifest_entries {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    if runtime
        .programs
        .iter()
        .any(|path| path == &config_file.canonical || path == &runtime_manifest.canonical)
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let support_manifest_canonical = fs::canonicalize(&config.support_manifest)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    if support_manifest_canonical == config_file.canonical
        || support_manifest_canonical == runtime_manifest.canonical
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let mut support = validate_support_manifest(
        &runtime.programs[0],
        &config.support_manifest,
        &config.expected_support_manifest_sha256,
        full_support,
    )?;

    let mut model_manifest = open_pinned_file(
        &config.model_manifest,
        SizeConstraint::MaxNonEmpty(MAX_MANIFEST_BYTES),
    )
    .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    if model_manifest.canonical == config_file.canonical
        || model_manifest.canonical == runtime_manifest.canonical
        || model_manifest.canonical == support_manifest_canonical
        || model_manifest.canonical.starts_with(&temporary_root)
        || runtime
            .programs
            .iter()
            .any(|path| path == &model_manifest.canonical)
        || model_manifest.sha256 != config.expected_model_manifest_sha256.to_ascii_lowercase()
    {
        return Err(ProcessingError::OcrModelUntrusted);
    }
    let model_manifest_bytes =
        read_pinned_bounded(&mut model_manifest.file, MAX_MANIFEST_BYTES, false)
            .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    let model: ModelManifest = serde_json::from_slice(&model_manifest_bytes)
        .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    let mut model_pins = validate_model_manifest(&model, &model_root, &model_manifest.canonical)?;

    let config_sha256 = config_file.sha256.clone();
    let executable_sha256 = runtime.launcher_sha256.clone();
    let runtime_manifest_sha256 = runtime_manifest.sha256.clone();
    let support_manifest_sha256 = support.evidence.manifest_sha256.clone();
    let support_identity_sha256 = support.evidence.support_identity_sha256.clone();
    let model_manifest_sha256 = model_manifest.sha256.clone();
    let runtime_identity = serde_json::to_vec(&runtime.manifest_entries)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    let identity_sha256 = sha256_hex(
        [
            b"mineru-runtime-identity-v3\n".as_slice(),
            executable_sha256.as_bytes(),
            b"\n",
            runtime_manifest_sha256.as_bytes(),
            b"\n",
            support_manifest_sha256.as_bytes(),
            b"\n",
            support_identity_sha256.as_bytes(),
            b"\n",
            config_sha256.as_bytes(),
            b"\n",
            model_manifest_sha256.as_bytes(),
            b"\n",
            &runtime_identity,
        ]
        .concat()
        .as_slice(),
    );

    let mut pinned_files =
        Vec::with_capacity(runtime.pins.len() + support.pins.len() + model_pins.len() + 3);
    pinned_files.push(config_file.file);
    pinned_files.push(runtime_manifest.file);
    pinned_files.append(&mut runtime.pins);
    pinned_files.append(&mut support.pins);
    pinned_files.push(model_manifest.file);
    pinned_files.append(&mut model_pins);

    Ok(ValidatedLocalMineru {
        executable_sha256,
        config_sha256,
        model_manifest_sha256,
        support_manifest_sha256,
        support_identity_sha256,
        runtime_manifest_sha256,
        runtime_search_path: runtime.search_path,
        runtime_programs: runtime.programs,
        identity_sha256,
        _pinned_files: pinned_files,
    })
}

fn validate_support_manifest(
    executable: &Path,
    manifest_path: &Path,
    expected_manifest_sha256: &str,
    full: bool,
) -> Result<SupportValidation, ProcessingError> {
    if !valid_lower_hash(expected_manifest_sha256) {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let mut worker = open_pinned_file(executable, SizeConstraint::AnyNonEmpty)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    validate_process_image(&mut worker.file, &worker.canonical)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    if worker
        .canonical
        .file_name()
        .and_then(|value| value.to_str())
        .is_none_or(|value| !value.eq_ignore_ascii_case("mineru-worker.exe"))
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let mut manifest = open_pinned_file(
        manifest_path,
        SizeConstraint::MaxNonEmpty(MAX_MANIFEST_BYTES),
    )
    .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    if manifest.sha256 != expected_manifest_sha256
        || manifest
            .canonical
            .file_name()
            .and_then(|value| value.to_str())
            != Some("mineru-worker.support-manifest.json")
        || manifest.canonical.parent() != worker.canonical.parent()
        || manifest
            .canonical
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            != Some("worker")
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let component_root = manifest
        .canonical
        .parent()
        .and_then(Path::parent)
        .ok_or(ProcessingError::OcrRuntimeUntrusted)?;
    let component_root = require_absolute_directory(component_root)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    let bytes = read_pinned_bounded(&mut manifest.file, MAX_MANIFEST_BYTES, false)
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    let claims: SupportManifest =
        serde_json::from_slice(&bytes).map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    if claims.schema_version != SUPPORT_MANIFEST_SCHEMA_VERSION
        || claims.manifest_version != SUPPORT_MANIFEST_VERSION
        || !claims.self_contained
        || claims.protocol_version != SUPPORT_PROTOCOL_VERSION
        || claims.worker_version != SUPPORT_WORKER_VERSION
        || claims.python_version != SUPPORT_PYTHON_VERSION
        || claims.mineru_version != SUPPORT_MINERU_VERSION
        || claims.pytorch_version != SUPPORT_PYTORCH_VERSION
        || !valid_lower_hash(&claims.support_tree_sha256)
        || !valid_lower_hash(&claims.support_identity_sha256)
        || claims.critical_files != CRITICAL_SUPPORT_FILES
        || claims.files.is_empty()
        || claims.files.len() > MAX_SUPPORT_FILES
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }

    let mut previous: Option<&str> = None;
    let mut folded = BTreeSet::new();
    let mut files = BTreeMap::new();
    let mut tree = Sha256::new();
    tree.update(b"la-mineru-support-tree-v1\n");
    for entry in &claims.files {
        let relative = validate_support_relative(&entry.relative_path)
            .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
        if entry.size_bytes == 0
            || !valid_lower_hash(&entry.sha256)
            || previous.is_some_and(|value| value >= relative)
            || !folded.insert(relative.to_lowercase())
        {
            return Err(ProcessingError::OcrRuntimeUntrusted);
        }
        previous = Some(relative);
        tree.update(relative.as_bytes());
        tree.update(b"\n");
        tree.update(entry.size_bytes.to_string().as_bytes());
        tree.update(b"\n");
        tree.update(entry.sha256.as_bytes());
        tree.update(b"\n");
        files.insert(
            relative.to_owned(),
            (entry.size_bytes, entry.sha256.clone()),
        );
    }
    let support_tree_sha256 = hex(&tree.finalize());
    if support_tree_sha256 != claims.support_tree_sha256 {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let support_identity_sha256 = sha256_hex(
        format!(
            "la-mineru-support-identity-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
            SUPPORT_PROTOCOL_VERSION,
            SUPPORT_WORKER_VERSION,
            SUPPORT_PYTHON_VERSION,
            SUPPORT_MINERU_VERSION,
            SUPPORT_PYTORCH_VERSION,
            support_tree_sha256,
        )
        .as_bytes(),
    );
    if support_identity_sha256 != claims.support_identity_sha256 {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    if CRITICAL_SUPPORT_FILES
        .iter()
        .any(|relative| !files.contains_key(*relative))
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }

    let targets = if full {
        files.keys().map(String::as_str).collect::<Vec<_>>()
    } else {
        CRITICAL_SUPPORT_FILES.to_vec()
    };
    let mut pins = Vec::with_capacity(targets.len() + 2);
    pins.push(worker.file);
    pins.push(manifest.file);
    for relative in targets {
        let (expected_size, expected_sha256) = files
            .get(relative)
            .ok_or(ProcessingError::OcrRuntimeUntrusted)?;
        let candidate = relative
            .split('/')
            .fold(component_root.clone(), |path, part| path.join(part));
        let pinned = open_pinned_file(&candidate, SizeConstraint::Exact(*expected_size))
            .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
        if !pinned.canonical.starts_with(&component_root) || pinned.sha256 != *expected_sha256 {
            return Err(ProcessingError::OcrRuntimeUntrusted);
        }
        pins.push(pinned.file);
    }
    if full {
        validate_exact_support_tree(&component_root, files.keys().map(String::as_str))
            .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    }
    Ok(SupportValidation {
        evidence: LocalMineruSupportEvidence {
            manifest_sha256: manifest.sha256,
            support_tree_sha256,
            support_identity_sha256,
            file_count: files.len(),
        },
        pins,
    })
}

fn validate_support_relative(value: &str) -> Result<&str, ()> {
    if value.is_empty()
        || value.len() > 240
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains(':')
    {
        return Err(());
    }
    let parts = value.split('/').collect::<Vec<_>>();
    if parts.is_empty()
        || parts.len() > 32
        || !matches!(parts[0], "worker" | "python" | "runtime")
        || parts
            .iter()
            .any(|part| part.is_empty() || matches!(*part, "." | ".."))
    {
        return Err(());
    }
    Ok(value)
}

fn validate_exact_support_tree<'a>(
    component_root: &Path,
    declared: impl Iterator<Item = &'a str>,
) -> Result<(), ()> {
    let declared = declared.map(str::to_owned).collect::<BTreeSet<_>>();
    let exempt = BTreeSet::from([
        "worker/mineru-worker.exe".to_owned(),
        "worker/mineru-worker.exe.manifest.json".to_owned(),
        "worker/mineru-worker.support-manifest.json".to_owned(),
    ]);
    let mut actual = BTreeSet::new();
    for top in ["worker", "python", "runtime"] {
        let root = component_root.join(top);
        let mut stack = vec![require_absolute_directory(&root)?];
        while let Some(directory) = stack.pop() {
            for entry in fs::read_dir(&directory).map_err(|_| ())? {
                let entry = entry.map_err(|_| ())?;
                let metadata = fs::symlink_metadata(entry.path()).map_err(|_| ())?;
                if is_link_reparse_or_cloud(&metadata) {
                    return Err(());
                }
                let canonical = fs::canonicalize(entry.path()).map_err(|_| ())?;
                if !canonical.starts_with(component_root) {
                    return Err(());
                }
                if metadata.is_dir() {
                    stack.push(canonical);
                } else if metadata.is_file() {
                    let relative = canonical.strip_prefix(component_root).map_err(|_| ())?;
                    let relative = relative
                        .components()
                        .map(|component| match component {
                            Component::Normal(value) => value.to_str().ok_or(()),
                            _ => Err(()),
                        })
                        .collect::<Result<Vec<_>, _>>()?
                        .join("/");
                    if !exempt.contains(&relative) && !actual.insert(relative) {
                        return Err(());
                    }
                } else {
                    return Err(());
                }
            }
        }
    }
    if actual == declared {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_runtime_manifest_shape(
    manifest: &LocalMineruRuntimeManifestV1,
) -> Result<(), ProcessingError> {
    if manifest.schema_version != LOCAL_MINERU_RUNTIME_MANIFEST_SCHEMA_VERSION
        || !valid_version(&manifest.version)
        || manifest.executables.is_empty()
        || manifest.executables.len() > MAX_RUNTIME_EXECUTABLES
    {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let mut previous: Option<&LocalMineruRuntimeManifestExecutableV1> = None;
    let mut launchers = 0usize;
    for entry in &manifest.executables {
        if !valid_lower_hash(&entry.path_sha256)
            || !valid_lower_hash(&entry.sha256)
            || entry.size_bytes == 0
            || previous.is_some_and(|value| value >= entry)
        {
            return Err(ProcessingError::OcrRuntimeUntrusted);
        }
        if entry.role == LocalMineruRuntimeExecutableRole::Launcher {
            launchers += 1;
        }
        previous = Some(entry);
    }
    if launchers != 1 {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    Ok(())
}

fn validate_runtime_bindings(
    bindings: &[LocalMineruRuntimeExecutable],
    configured_launcher: Option<&Path>,
    expected_launcher_sha256: Option<&str>,
    excluded_roots: &[&PathBuf],
) -> Result<RuntimeValidation, ProcessingError> {
    if bindings.is_empty() || bindings.len() > MAX_RUNTIME_EXECUTABLES {
        return Err(ProcessingError::OcrRuntimeUntrusted);
    }
    let configured_launcher = configured_launcher
        .map(|path| {
            ensure_local_path_chain(path)?;
            fs::canonicalize(path).map_err(|_| ())
        })
        .transpose()
        .map_err(|_| ProcessingError::OcrWorkerUntrusted)?;

    let mut pins = Vec::with_capacity(bindings.len());
    let mut programs_by_key = BTreeMap::<String, PathBuf>::new();
    let mut manifest_entries = Vec::with_capacity(bindings.len());
    let mut search_directories = BTreeMap::<String, PathBuf>::new();
    let mut launcher_sha256 = None;

    for binding in bindings {
        if binding.expected_size_bytes == 0 || !valid_hash(&binding.expected_sha256) {
            return Err(ProcessingError::OcrRuntimeUntrusted);
        }
        let mut pinned = open_pinned_file(
            &binding.path,
            SizeConstraint::Exact(binding.expected_size_bytes),
        )
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
        if excluded_roots
            .iter()
            .any(|root| pinned.canonical.starts_with(root))
            || pinned.sha256 != binding.expected_sha256.to_ascii_lowercase()
        {
            return Err(ProcessingError::OcrRuntimeUntrusted);
        }
        validate_process_image(&mut pinned.file, &pinned.canonical)
            .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;

        let normalized = normalized_absolute_path(&pinned.canonical)
            .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
        if programs_by_key
            .insert(normalized.clone(), pinned.canonical.clone())
            .is_some()
        {
            return Err(ProcessingError::OcrRuntimeUntrusted);
        }
        if binding.role == LocalMineruRuntimeExecutableRole::Launcher {
            if launcher_sha256.is_some()
                || configured_launcher
                    .as_ref()
                    .is_some_and(|path| path != &pinned.canonical)
                || expected_launcher_sha256
                    .is_some_and(|hash| pinned.sha256 != hash.to_ascii_lowercase())
            {
                return Err(ProcessingError::OcrWorkerUntrusted);
            }
            launcher_sha256 = Some(pinned.sha256.clone());
        }
        let parent = pinned
            .canonical
            .parent()
            .ok_or(ProcessingError::OcrRuntimeUntrusted)?
            .to_path_buf();
        let parent_key =
            normalized_absolute_path(&parent).map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
        search_directories.insert(parent_key, parent);
        manifest_entries.push(LocalMineruRuntimeManifestExecutableV1 {
            path_sha256: sha256_hex(normalized.as_bytes()),
            sha256: pinned.sha256,
            size_bytes: pinned.size_bytes,
            role: binding.role,
        });
        pins.push(pinned.file);
    }

    if configured_launcher.is_some() && launcher_sha256.is_none() {
        return Err(ProcessingError::OcrWorkerUntrusted);
    }
    let launcher_sha256 = launcher_sha256.ok_or(ProcessingError::OcrRuntimeUntrusted)?;
    manifest_entries.sort();
    let search_path = std::env::join_paths(search_directories.into_values())
        .map_err(|_| ProcessingError::OcrRuntimeUntrusted)?;
    Ok(RuntimeValidation {
        launcher_sha256,
        manifest_entries,
        programs: programs_by_key.into_values().collect(),
        search_path,
        pins,
    })
}
fn roots_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
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

fn validate_mineru_json(
    bytes: &[u8],
    model_root: &Path,
    backend: MineruBackend,
) -> Result<(), ProcessingError> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| ProcessingError::OcrConfigUnsafe)?;
    if contains_remote_locator(&value)
        || contains_forbidden_network_directive(&value)
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
    let required_key = match backend {
        MineruBackend::Pipeline => "pipeline",
        MineruBackend::HybridEngine | MineruBackend::VlmEngine => "vlm",
    };
    if !models.contains_key(required_key) {
        return Err(ProcessingError::OcrConfigUnsafe);
    }
    for path in models.values() {
        let path = path.as_str().ok_or(ProcessingError::OcrConfigUnsafe)?;
        let canonical = require_absolute_directory(Path::new(path))
            .map_err(|_| ProcessingError::OcrConfigUnsafe)?;
        if !canonical.starts_with(model_root) {
            return Err(ProcessingError::OcrConfigUnsafe);
        }
    }
    Ok(())
}

fn contains_remote_locator(value: &Value) -> bool {
    match value {
        Value::String(text) => {
            let lowered = text.trim().to_ascii_lowercase();
            lowered.contains("://")
                || lowered.starts_with(r"\\")
                || lowered.starts_with("//")
                || lowered.starts_with("ssh:")
                || lowered.starts_with("s3:")
                || lowered.starts_with("hf:")
        }
        Value::Array(values) => values.iter().any(contains_remote_locator),
        Value::Object(values) => values.values().any(contains_remote_locator),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn contains_forbidden_network_directive(value: &Value) -> bool {
    const TOKENS: [&str; 12] = [
        "download",
        "remote",
        "cloud",
        "endpoint",
        "server",
        "upload",
        "telemetry",
        "huggingface",
        "modelscope",
        "repository",
        "api_key",
        "access_token",
    ];
    match value {
        Value::Object(values) => values.iter().any(|(key, child)| {
            let key = key.to_ascii_lowercase().replace('-', "_");
            TOKENS.iter().any(|token| key.contains(token))
                || contains_forbidden_network_directive(child)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_network_directive),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn validate_model_manifest(
    manifest: &ModelManifest,
    model_root: &Path,
    manifest_path: &Path,
) -> Result<Vec<File>, ProcessingError> {
    if !valid_version(&manifest.version)
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_MODEL_FILES
    {
        return Err(ProcessingError::OcrModelUntrusted);
    }
    let exempt = relative_if_within(model_root, manifest_path);
    let mut declared = BTreeSet::new();
    let mut pins = Vec::with_capacity(manifest.files.len());
    for entry in &manifest.files {
        validate_model_manifest_entry(&entry.relative_path, &entry.sha256, &mut declared)
            .map_err(|_| ProcessingError::OcrModelUntrusted)?;
        if exempt.as_deref().is_some_and(|value| {
            normalized_relative(Path::new(&entry.relative_path))
                .ok()
                .as_deref()
                == Some(value)
        }) {
            return Err(ProcessingError::OcrModelUntrusted);
        }
        let candidate = model_root.join(&entry.relative_path);
        let pinned = open_pinned_file(&candidate, SizeConstraint::Exact(entry.size_bytes))
            .map_err(|_| ProcessingError::OcrModelUntrusted)?;
        if !pinned.canonical.starts_with(model_root)
            || pinned.sha256 != entry.sha256.to_ascii_lowercase()
        {
            return Err(ProcessingError::OcrModelUntrusted);
        }
        pins.push(pinned.file);
    }
    validate_exact_tree(model_root, &declared, exempt.as_deref())
        .map_err(|_| ProcessingError::OcrModelUntrusted)?;
    Ok(pins)
}

fn valid_version(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
}

fn validate_model_manifest_entry(
    relative_path: &str,
    sha256: &str,
    declared: &mut BTreeSet<String>,
) -> Result<(), ()> {
    if relative_path.is_empty() || !valid_hash(sha256) {
        return Err(());
    }
    let relative = Path::new(relative_path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(());
    }
    let normalized = normalized_relative(relative)?;
    if !declared.insert(normalized) {
        return Err(());
    }
    Ok(())
}

fn validate_exact_tree(
    root: &Path,
    declared: &BTreeSet<String>,
    exempt: Option<&str>,
) -> Result<(), ()> {
    let root = fs::canonicalize(root).map_err(|_| ())?;
    let mut actual = BTreeSet::new();
    let mut stack = vec![root.clone()];
    while let Some(directory) = stack.pop() {
        let entries = fs::read_dir(&directory).map_err(|_| ())?;
        for entry in entries {
            let entry = entry.map_err(|_| ())?;
            let metadata = fs::symlink_metadata(entry.path()).map_err(|_| ())?;
            if is_link_reparse_or_cloud(&metadata) {
                return Err(());
            }
            let canonical = fs::canonicalize(entry.path()).map_err(|_| ())?;
            if !canonical.starts_with(&root) {
                return Err(());
            }
            if metadata.is_dir() {
                stack.push(canonical);
            } else if metadata.is_file() {
                let relative = canonical.strip_prefix(&root).map_err(|_| ())?;
                let normalized = normalized_relative(relative)?;
                if exempt != Some(normalized.as_str()) && !actual.insert(normalized) {
                    return Err(());
                }
            } else {
                return Err(());
            }
        }
    }
    if &actual != declared {
        return Err(());
    }
    Ok(())
}

fn normalized_relative(path: &Path) -> Result<String, ()> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(());
        };
        let part = value.to_str().ok_or(())?;
        if part.is_empty() {
            return Err(());
        }
        #[cfg(windows)]
        parts.push(part.to_ascii_lowercase());
        #[cfg(not(windows))]
        parts.push(part.to_owned());
    }
    if parts.is_empty() {
        return Err(());
    }
    Ok(parts.join("/"))
}

fn normalized_absolute_path(path: &Path) -> Result<String, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    let rendered = path.to_str().ok_or(())?.replace('/', "\\");
    #[cfg(windows)]
    {
        let rendered = if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{unc}")
        } else if let Some(dos) = rendered.strip_prefix(r"\\?\") {
            dos.to_owned()
        } else {
            rendered
        };
        Ok(rendered.to_ascii_lowercase())
    }
    #[cfg(not(windows))]
    {
        Ok(rendered)
    }
}

fn relative_if_within(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root)
        .ok()
        .and_then(|relative| normalized_relative(relative).ok())
}

fn require_absolute_directory(path: &Path) -> Result<PathBuf, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    ensure_local_path_chain(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir() || is_link_reparse_or_cloud(&metadata) {
        return Err(());
    }
    fs::canonicalize(path).map_err(|_| ())
}

fn open_pinned_file(path: &Path, size_constraint: SizeConstraint) -> Result<PinnedFile, ()> {
    if !path.is_absolute() {
        return Err(());
    }
    ensure_local_path_chain(path)?;
    let path_metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !path_metadata.is_file() || is_link_reparse_or_cloud(&path_metadata) {
        return Err(());
    }
    let canonical = fs::canonicalize(path).map_err(|_| ())?;
    let mut file = platform::open_pinned(&canonical)?;
    platform::validate_open_handle(&file, &canonical)?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || is_link_reparse_or_cloud(&metadata) {
        return Err(());
    }
    match size_constraint {
        SizeConstraint::AnyNonEmpty if metadata.len() == 0 => return Err(()),
        SizeConstraint::Exact(expected) if metadata.len() != expected => return Err(()),
        SizeConstraint::MaxNonEmpty(limit) if metadata.len() == 0 || metadata.len() > limit => {
            return Err(());
        }
        SizeConstraint::AnyNonEmpty | SizeConstraint::Exact(_) | SizeConstraint::MaxNonEmpty(_) => {
        }
    }
    let sha256 = hash_open_file(&mut file)?;
    Ok(PinnedFile {
        canonical,
        sha256,
        size_bytes: metadata.len(),
        file,
    })
}

fn read_pinned_bounded(file: &mut File, limit: u64, allow_empty: bool) -> Result<Vec<u8>, ()> {
    let metadata = file.metadata().map_err(|_| ())?;
    if (!allow_empty && metadata.len() == 0) || metadata.len() > limit {
        return Err(());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let capacity = usize::try_from(metadata.len()).map_err(|_| ())?;
    let mut bytes = Vec::with_capacity(capacity);
    let read_limit = limit.checked_add(1).ok_or(())?;
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 != metadata.len() {
        return Err(());
    }
    Ok(bytes)
}

fn validate_process_image(file: &mut File, path: &Path) -> Result<(), ()> {
    #[cfg(windows)]
    if !path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("exe"))
    {
        return Err(());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic).map_err(|_| ())?;
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    if magic != *b"MZ" {
        return Err(());
    }
    Ok(())
}

fn hash_open_file(file: &mut File) -> Result<String, ()> {
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    Ok(hex(&digest.finalize()))
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
            Ok(metadata) if is_link_reparse_or_cloud(&metadata) => return Err(()),
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
    let drive_type = unsafe { GetDriveTypeW(root.as_ptr()) };
    (drive_type == 3).then_some(()).ok_or(())
}

#[cfg(windows)]
fn is_link_reparse_or_cloud(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
    const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
    let attributes = metadata.file_attributes();
    metadata.file_type().is_symlink()
        || attributes
            & (FILE_ATTRIBUTE_REPARSE_POINT
                | FILE_ATTRIBUTE_OFFLINE
                | FILE_ATTRIBUTE_RECALL_ON_OPEN
                | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
            != 0
}

#[cfg(not(windows))]
fn is_link_reparse_or_cloud(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_opaque_id(value: &str) -> bool {
    let Some((prefix, suffix)) = value.split_once('_') else {
        return false;
    };
    (2..=16).contains(&prefix.len())
        && prefix
            .bytes()
            .enumerate()
            .all(|(index, byte)| byte.is_ascii_lowercase() || (index > 0 && byte.is_ascii_digit()))
        && suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_lower_hash(value: &str) -> bool {
    valid_hash(value) && !value.bytes().any(|byte| byte.is_ascii_uppercase())
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
#[cfg(windows)]
mod platform {
    #![allow(unsafe_code)]

    use std::{
        ffi::OsString,
        fs::{File, OpenOptions},
        os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle},
        path::{Path, PathBuf},
    };
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            GetFileInformationByHandle, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
            FILE_NAME_NORMALIZED, FILE_SHARE_READ, VOLUME_NAME_DOS,
        },
    };

    pub(super) fn open_pinned(path: &Path) -> Result<File, ()> {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|_| ())
    }

    pub(super) fn validate_open_handle(file: &File, expected: &Path) -> Result<(), ()> {
        let handle = file.as_raw_handle() as HANDLE;
        if handle.is_null() {
            return Err(());
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
            || information.nNumberOfLinks != 1
        {
            return Err(());
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
            return Err(());
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
            return Err(());
        }
        let rendered = OsString::from_wide(&buffer[..written as usize]);
        let rendered = rendered.to_string_lossy();
        let normalized = if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
            PathBuf::from(format!(r"\\{unc}"))
        } else if let Some(dos) = rendered.strip_prefix(r"\\?\") {
            PathBuf::from(dos)
        } else {
            PathBuf::from(rendered.as_ref())
        };
        fn normalize(value: &Path) -> String {
            let rendered = value.to_string_lossy();
            if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
                format!(r"\\{unc}").to_ascii_lowercase()
            } else if let Some(dos) = rendered.strip_prefix(r"\\?\") {
                dos.to_ascii_lowercase()
            } else {
                rendered.to_ascii_lowercase()
            }
        }
        (normalize(&normalized) == normalize(expected))
            .then_some(())
            .ok_or(())
    }
}

#[cfg(not(windows))]
mod platform {
    use std::{
        fs::{File, OpenOptions},
        os::unix::fs::MetadataExt,
        path::Path,
    };

    pub(super) fn open_pinned(path: &Path) -> Result<File, ()> {
        OpenOptions::new().read(true).open(path).map_err(|_| ())
    }

    pub(super) fn validate_open_handle(file: &File, _expected: &Path) -> Result<(), ()> {
        let metadata = file.metadata().map_err(|_| ())?;
        (metadata.nlink() == 1).then_some(()).ok_or(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn pinned_file_handle_denies_write_and_delete_until_validation_scope_ends() {
        let root = tempfile::tempdir().expect("temp");
        let path = root.path().join("support.py");
        fs::write(&path, b"trusted support").expect("fixture");
        let pinned =
            open_pinned_file(&path, SizeConstraint::AnyNonEmpty).expect("pinned support file");

        assert!(fs::write(&path, b"tampered").is_err());
        assert!(fs::remove_file(&path).is_err());
        drop(pinned);

        fs::write(&path, b"after validation").expect("lock released after pins drop");
    }

    #[test]
    fn remote_locators_and_download_directives_are_rejected() {
        let root = Path::new(".");
        for json in [
            br#"{"models-dir":{"pipeline":"."},"server":"https://example.invalid"}"#.as_slice(),
            br#"{"models-dir":{"pipeline":"."},"llm-aided-config":{"enable":true}}"#.as_slice(),
            br#"{"models-dir":{"pipeline":"."},"model":"s3://bucket/model"}"#.as_slice(),
            br#"{"models-dir":{"pipeline":"."},"allow-download":true}"#.as_slice(),
            br#"{"models-dir":{"pipeline":"."},"repository":"some-model"}"#.as_slice(),
        ] {
            assert_eq!(
                validate_mineru_json(json, root, MineruBackend::Pipeline),
                Err(ProcessingError::OcrConfigUnsafe)
            );
        }
    }

    #[test]
    fn runtime_manifest_requires_canonical_sorted_exact_set() {
        let entry = LocalMineruRuntimeManifestExecutableV1 {
            path_sha256: "a".repeat(64),
            sha256: "b".repeat(64),
            size_bytes: 1,
            role: LocalMineruRuntimeExecutableRole::Launcher,
        };
        let valid = LocalMineruRuntimeManifestV1 {
            schema_version: 1,
            version: "runtime-1".to_owned(),
            executables: vec![entry.clone()],
        };
        validate_runtime_manifest_shape(&valid).expect("valid manifest");

        let mut duplicate = valid.clone();
        duplicate.executables.push(entry);
        assert_eq!(
            validate_runtime_manifest_shape(&duplicate),
            Err(ProcessingError::OcrRuntimeUntrusted)
        );
    }

    #[test]
    fn exact_model_tree_rejects_extra_files_and_case_aliases() {
        let root = tempfile::tempdir().expect("root");
        fs::create_dir(root.path().join("weights")).expect("dir");
        fs::write(root.path().join("weights/model.bin"), b"model").expect("model");
        let expected = [normalized_relative(Path::new("weights/model.bin")).expect("relative")]
            .into_iter()
            .collect();
        validate_exact_tree(root.path(), &expected, None).expect("exact");
        fs::write(root.path().join("unexpected.json"), b"{}").expect("extra");
        assert!(validate_exact_tree(root.path(), &expected, None).is_err());

        let mut seen = BTreeSet::new();
        validate_model_manifest_entry("weights/model.bin", &"a".repeat(64), &mut seen)
            .expect("first");
        #[cfg(windows)]
        assert!(
            validate_model_manifest_entry("WEIGHTS/MODEL.BIN", &"b".repeat(64), &mut seen).is_err()
        );
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

    #[cfg(windows)]
    #[test]
    fn scripts_unc_reparse_and_hardlinks_are_rejected() {
        assert!(ensure_local_path_chain(Path::new(r"\\server\share\mineru.exe")).is_err());

        let root = tempfile::tempdir().expect("root");
        let script = root.path().join("renamed.exe");
        fs::write(&script, b"@echo off").expect("script");
        assert!(bind_local_mineru_runtime_executable(
            &script,
            LocalMineruRuntimeExecutableRole::Launcher
        )
        .is_err());

        let original = root.path().join("worker.exe");
        fs::write(&original, b"MZsynthetic").expect("worker");
        let hardlink = root.path().join("worker-hardlink.exe");
        fs::hard_link(&original, &hardlink).expect("hardlink");
        assert!(open_pinned_file(&original, SizeConstraint::AnyNonEmpty).is_err());

        let link_parent = tempfile::tempdir().expect("link parent");
        let target = tempfile::tempdir().expect("link target");
        fs::write(target.path().join("mineru.exe"), b"MZworker").expect("worker fixture");
        let link = link_parent.path().join("linked-runtime");
        if std::os::windows::fs::symlink_dir(target.path(), &link).is_ok() {
            assert!(
                open_pinned_file(&link.join("mineru.exe"), SizeConstraint::AnyNonEmpty).is_err()
            );
        }
    }
}
