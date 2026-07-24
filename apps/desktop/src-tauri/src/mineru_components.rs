//! Trust-rooted lifecycle for local-only MinerU/OCR component packages.
//!
//! This module manages executable/model packages only. It has no API that
//! accepts case material, OCR text, source paths or provider credentials.

use semver::Version;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};
use uuid::Uuid;

mod catalog;
mod package;
mod state;

use catalog::{
    download_catalog_package, entry_view, load_trusted_catalog, persist_trusted_catalog,
    read_and_verify_catalog, ComponentCatalogEntryV1,
};
use package::{
    cleanup_safe_transient, installed_versions, remove_installed_component,
    validate_installed_component,
};

const ROOT_RELATIVE_PATH: &str = "components/mineru";
const AUDIT_FILE_NAME: &str = "audit.jsonl";
const CURRENT_SCHEMA_VERSION: u16 = 1;
const AUDIT_SCHEMA_VERSION: u16 = 1;
const MAX_COMPONENT_VERSIONS: usize = 32;
const MAX_TRANSIENT_GC_ROOT_ENTRIES: usize = 512;
const MAX_RESUMABLE_DOWNLOAD_DIRECTORIES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MineruComponentError {
    code: &'static str,
    message: &'static str,
}

impl MineruComponentError {
    pub(super) fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) const fn message(&self) -> &'static str {
        self.message
    }
}

impl std::fmt::Display for MineruComponentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for MineruComponentError {}

type ComponentResult<T> = Result<T, MineruComponentError>;

pub(super) fn error(code: &'static str) -> MineruComponentError {
    let message = match code {
        "catalog_missing" => "A trusted MinerU component catalog is not installed.",
        "catalog_signature_invalid" => "The MinerU component catalog signature is not trusted.",
        "package_not_catalogued" | "package_integrity_mismatch" => {
            "The selected MinerU package is not pinned by the trusted catalog."
        }
        "download_failed" => "The MinerU component download did not complete.",
        "component_runtime_path_too_long" => {
            "The local application-data path is too long for the pinned MinerU runtime; OCR remains blocked."
        }
        "cleanup_failed" | "uninstall_incomplete" => {
            "The component cleanup did not complete; OCR remains blocked."
        }
        _ => "The local MinerU component operation was rejected or did not complete.",
    };
    MineruComponentError::new(code, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleState {
    Active,
    Inactive,
    Drifted,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CurrentComponentV1 {
    schema_version: u16,
    generation: u64,
    active_version: Option<Version>,
    active_manifest_sha256: Option<String>,
    previous_version: Option<Version>,
    activated_at_unix: u64,
    state: LifecycleState,
    reason_codes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CatalogEntryView {
    pub package_id: String,
    pub component_version: String,
    pub mineru_version: String,
    pub package_size_bytes: u64,
    pub package_sha256: String,
    pub package_manifest_sha256: String,
    pub download_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InstalledComponentView {
    pub component_version: String,
    pub mineru_version: Option<String>,
    pub manifest_sha256: Option<String>,
    pub active: bool,
    pub integrity_valid: bool,
    pub lifecycle_state: &'static str,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MineruComponentStatus {
    pub catalog_id: Option<String>,
    pub catalog_expires_at_unix: Option<u64>,
    pub catalog_trusted: bool,
    pub available_packages: Vec<CatalogEntryView>,
    pub installed_versions: Vec<InstalledComponentView>,
    pub active_version: Option<String>,
    pub active_manifest_sha256: Option<String>,
    pub active_integrity_valid: bool,
    pub qualification_recheck_required: bool,
    pub remote_ocr_allowed: bool,
    pub case_material_downloaded_or_uploaded: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManagedMineruBinding {
    pub component_version: Version,
    pub worker_path: PathBuf,
    pub model_root: PathBuf,
    pub tools_config_path: PathBuf,
    pub runtime_executable_paths: Vec<PathBuf>,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ComponentMutation {
    pub binding: Option<ManagedMineruBinding>,
    pub removed_active_component: bool,
}

#[derive(Debug)]
struct Shared {
    root: PathBuf,
    operation: Mutex<()>,
    download_operation: tokio::sync::Mutex<()>,
}

#[derive(Clone, Debug)]
pub(crate) struct MineruComponentManager {
    shared: Arc<Shared>,
}

impl MineruComponentManager {
    pub(crate) fn new(app_local_data_directory: PathBuf) -> ComponentResult<Self> {
        package::ensure_private_fixed_directory(&app_local_data_directory)?;
        let root = app_local_data_directory.join(ROOT_RELATIVE_PATH);
        package::ensure_private_fixed_directory(&root)?;
        let manager = Self {
            shared: Arc::new(Shared {
                root,
                operation: Mutex::new(()),
                download_operation: tokio::sync::Mutex::new(()),
            }),
        };
        manager.cleanup_stale_transients()?;
        manager.remeasure_active_component()?;
        Ok(manager)
    }

    pub(crate) fn managed_root(&self) -> &Path {
        &self.shared.root
    }

    pub(crate) fn status(&self) -> ComponentResult<MineruComponentStatus> {
        let _guard = self.operation();
        self.status_locked()
    }

    pub(crate) fn import_catalog(
        &self,
        catalog_path: &Path,
        signature_path: &Path,
    ) -> ComponentResult<MineruComponentStatus> {
        let _guard = self.operation();
        let (catalog, catalog_bytes, signature_bytes) =
            read_and_verify_catalog(catalog_path, signature_path)?;
        let catalog_hash = package::sha256_bytes(&catalog_bytes);
        state::authorize_catalog_import(&self.shared.root, catalog.issued_at_unix, &catalog_hash)?;
        persist_trusted_catalog(&self.shared.root, &catalog_bytes, &signature_bytes)?;
        append_audit(
            &self.shared.root,
            "catalog_imported",
            Some(&catalog.catalog_id),
            None,
            Some(&catalog_hash),
        )?;
        self.status_locked()
    }

    pub(crate) fn install_offline_package(
        &self,
        package_path: &Path,
    ) -> ComponentResult<ComponentMutation> {
        let _guard = self.operation();
        let catalog = load_trusted_catalog(&self.shared.root)?;
        let (hash, size) = package::sha256_pinned_file(package_path, package::MAX_PACKAGE_BYTES)?;
        if package_path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.ends_with(".laocrparts"))
        {
            let entry = catalog
                .entries
                .iter()
                .find(|entry| {
                    !entry.revoked
                        && entry.part_set_manifest_size_bytes == Some(size)
                        && entry.part_set_manifest_sha256.as_deref() == Some(hash.as_str())
                })
                .ok_or_else(|| error("package_not_catalogued"))?;
            let (directory, assembled) =
                package::assemble_offline_part_set(&self.shared.root, package_path, entry)?;
            let result = self.install_locked(&assembled, entry);
            let cleanup = package::cleanup_exact_transient(&directory, &[assembled]);
            return match (result, cleanup) {
                (_, Err(cleanup_error)) => Err(cleanup_error),
                (result, Ok(())) => result,
            };
        }
        let entry = catalog
            .entries
            .iter()
            .find(|entry| {
                !entry.revoked
                    && entry.parts.is_empty()
                    && entry.package_size_bytes == size
                    && entry.package_sha256 == hash
            })
            .ok_or_else(|| error("package_not_catalogued"))?;
        self.install_locked(package_path, entry)
    }

    pub(crate) async fn download_and_install(
        &self,
        package_id: &str,
    ) -> ComponentResult<ComponentMutation> {
        let _download_guard = self.shared.download_operation.lock().await;
        let entry = {
            let _guard = self.operation();
            let catalog = load_trusted_catalog(&self.shared.root)?;
            catalog
                .entries
                .into_iter()
                .find(|entry| entry.package_id == package_id && !entry.revoked)
                .ok_or_else(|| error("catalog_package_unavailable"))?
        };
        package::ensure_download_capacity(&self.shared.root, entry.package_size_bytes)?;
        if entry.parts.is_empty() {
            let directory = self
                .shared
                .root
                .join(format!(".download-{}", Uuid::new_v4()));
            fs::create_dir(&directory).map_err(|_| error("download_staging_failed"))?;
            let package_path = directory.join("component.laocrpkg");
            let result = async {
                download_catalog_package(&entry, &package_path).await?;
                let _guard = self.operation();
                let fresh = load_trusted_catalog(&self.shared.root)?;
                let fresh_entry = fresh
                    .entries
                    .iter()
                    .find(|candidate| candidate.package_id == package_id && !candidate.revoked)
                    .ok_or_else(|| error("catalog_package_unavailable"))?;
                if fresh_entry != &entry {
                    return Err(error("catalog_changed_during_download"));
                }
                self.install_locked(&package_path, fresh_entry)
            }
            .await;
            let cleanup = package::cleanup_exact_transient(&directory, &[package_path]);
            return match (result, cleanup) {
                (_, Err(cleanup_error)) => Err(cleanup_error),
                (result, Ok(())) => result,
            };
        }

        let directory = self
            .shared
            .root
            .join(format!(".download-resume-{}", entry.package_sha256));
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(failure) if failure.kind() == std::io::ErrorKind::AlreadyExists => {
                package::ensure_private_fixed_directory(&directory)?;
            }
            Err(_) => return Err(error("download_staging_failed")),
        }
        let result = async {
            let descriptor = catalog::download_catalog_parts(&entry, &directory).await?;
            let _guard = self.operation();
            let fresh = load_trusted_catalog(&self.shared.root)?;
            let fresh_entry = fresh
                .entries
                .iter()
                .find(|candidate| candidate.package_id == package_id && !candidate.revoked)
                .ok_or_else(|| error("catalog_package_unavailable"))?;
            if fresh_entry != &entry {
                return Err(error("catalog_changed_during_download"));
            }
            let (assembly_directory, assembled) =
                package::assemble_offline_part_set(&self.shared.root, &descriptor, fresh_entry)?;
            let install = self.install_locked(&assembled, fresh_entry);
            let cleanup = package::cleanup_exact_transient(&assembly_directory, &[assembled]);
            match (install, cleanup) {
                (_, Err(cleanup_error)) => Err(cleanup_error),
                (install, Ok(())) => install,
            }
        }
        .await;
        let should_cleanup = match &result {
            Ok(_) => true,
            Err(failure) => failure.code() != "download_failed",
        };
        if should_cleanup {
            let cleanup = package::cleanup_safe_transient(&directory);
            if cleanup.is_err() {
                return Err(error("cleanup_failed"));
            }
        }
        result
    }

    pub(crate) fn rollback(&self, version: &str) -> ComponentResult<ComponentMutation> {
        let _guard = self.operation();
        let version = Version::parse(version).map_err(|_| error("version_invalid"))?;
        let catalog = load_trusted_catalog(&self.shared.root)?;
        let binding = validate_installed_component(&self.shared.root, &version, &catalog)?;
        let current = self.read_current()?;
        if current.active_version.as_ref() == Some(&version) {
            return Err(error("component_already_active"));
        }
        self.activate_locked(&binding, current.active_version)?;
        append_audit(
            &self.shared.root,
            "component_rolled_back",
            None,
            Some(&version),
            Some(&binding.manifest_sha256),
        )?;
        Ok(ComponentMutation {
            binding: Some(binding),
            removed_active_component: false,
        })
    }

    pub(crate) fn uninstall(&self, version: &str) -> ComponentResult<ComponentMutation> {
        let _guard = self.operation();
        let version = Version::parse(version).map_err(|_| error("version_invalid"))?;
        let current = self.read_current()?;
        let active = current.active_version.as_ref() == Some(&version);
        if active {
            persist_current(
                &self.shared.root,
                &CurrentComponentV1 {
                    schema_version: CURRENT_SCHEMA_VERSION,
                    generation: current.generation.saturating_add(1),
                    active_version: None,
                    active_manifest_sha256: None,
                    previous_version: Some(version.clone()),
                    activated_at_unix: package::unix_now()?,
                    state: LifecycleState::Inactive,
                    reason_codes: vec!["component_uninstalled".to_owned()],
                },
            )?;
        }
        if remove_installed_component(&self.shared.root.join(version.to_string())).is_err() {
            if active {
                let mut quarantined = self.read_current()?;
                quarantined.state = LifecycleState::Quarantined;
                quarantined.reason_codes = vec!["component_uninstall_incomplete".to_owned()];
                let _ = persist_current(&self.shared.root, &quarantined);
            }
            return Err(error("uninstall_incomplete"));
        }
        append_audit(
            &self.shared.root,
            "component_uninstalled",
            None,
            Some(&version),
            None,
        )?;
        Ok(ComponentMutation {
            binding: None,
            removed_active_component: active,
        })
    }

    fn install_locked(
        &self,
        package_path: &Path,
        entry: &ComponentCatalogEntryV1,
    ) -> ComponentResult<ComponentMutation> {
        let previous = match self.read_current() {
            Ok(state) => state.active_version,
            Err(failure) if failure.code() == "component_file_missing" => None,
            Err(failure) => return Err(failure),
        };
        let binding = package::install_package(&self.shared.root, package_path, entry)?;
        self.activate_locked(&binding, previous)?;
        append_audit(
            &self.shared.root,
            "component_installed",
            Some(&entry.package_id),
            Some(&binding.component_version),
            Some(&binding.manifest_sha256),
        )?;
        Ok(ComponentMutation {
            binding: Some(binding),
            removed_active_component: false,
        })
    }

    fn activate_locked(
        &self,
        binding: &ManagedMineruBinding,
        previous: Option<Version>,
    ) -> ComponentResult<()> {
        let generation = match self.read_current() {
            Ok(state) => state.generation.saturating_add(1),
            Err(failure) if failure.code() == "component_file_missing" => 1,
            Err(failure) => return Err(failure),
        };
        persist_current(
            &self.shared.root,
            &CurrentComponentV1 {
                schema_version: CURRENT_SCHEMA_VERSION,
                generation,
                active_version: Some(binding.component_version.clone()),
                active_manifest_sha256: Some(binding.manifest_sha256.clone()),
                previous_version: previous.filter(|value| value != &binding.component_version),
                activated_at_unix: package::unix_now()?,
                state: LifecycleState::Active,
                reason_codes: vec!["qualification_recheck_required".to_owned()],
            },
        )
    }

    fn status_locked(&self) -> ComponentResult<MineruComponentStatus> {
        let mut reasons = Vec::new();
        let catalog = match load_trusted_catalog(&self.shared.root) {
            Ok(value) => Some(value),
            Err(failure) => {
                reasons.push(failure.code().to_owned());
                None
            }
        };
        let mut current = self.read_current().unwrap_or_else(|failure| {
            if failure.code() != "component_file_missing" {
                reasons.push(failure.code().to_owned());
            }
            inactive_current()
        });
        let mut versions = Vec::new();
        for version in installed_versions(&self.shared.root, MAX_COMPONENT_VERSIONS)? {
            let active = current.active_version.as_ref() == Some(&version);
            let validation = catalog
                .as_ref()
                .ok_or_else(|| error("catalog_missing"))
                .and_then(|catalog| {
                    validate_installed_component(&self.shared.root, &version, catalog)
                });
            match validation {
                Ok(binding) => {
                    if active
                        && current.active_manifest_sha256.as_deref()
                            != Some(binding.manifest_sha256.as_str())
                    {
                        current.state = LifecycleState::Drifted;
                        current.reason_codes = vec!["current_manifest_binding_mismatch".to_owned()];
                        persist_current(&self.shared.root, &current)?;
                        reasons.push("current_manifest_binding_mismatch".to_owned());
                    }
                    let mineru_version =
                        package::read_manifest(&self.shared.root.join(version.to_string()))
                            .ok()
                            .map(|(manifest, _)| manifest.mineru_version);
                    versions.push(InstalledComponentView {
                        component_version: version.to_string(),
                        mineru_version,
                        manifest_sha256: Some(binding.manifest_sha256),
                        active,
                        integrity_valid: true,
                        lifecycle_state: if active { "active" } else { "inactive" },
                        reason_codes: if active {
                            vec!["qualification_recheck_required".to_owned()]
                        } else {
                            Vec::new()
                        },
                    });
                }
                Err(failure) => {
                    if active {
                        current.state = LifecycleState::Drifted;
                        current.reason_codes = vec![failure.code().to_owned()];
                        persist_current(&self.shared.root, &current)?;
                        reasons.push(failure.code().to_owned());
                    }
                    versions.push(InstalledComponentView {
                        component_version: version.to_string(),
                        mineru_version: None,
                        manifest_sha256: None,
                        active,
                        integrity_valid: false,
                        lifecycle_state: if active { "drifted" } else { "quarantined" },
                        reason_codes: vec![failure.code().to_owned()],
                    });
                }
            }
        }
        versions.sort_by(|left, right| right.component_version.cmp(&left.component_version));
        let active_valid = current.state == LifecycleState::Active
            && versions
                .iter()
                .any(|version| version.active && version.integrity_valid);
        Ok(MineruComponentStatus {
            catalog_id: catalog.as_ref().map(|value| value.catalog_id.clone()),
            catalog_expires_at_unix: catalog.as_ref().map(|value| value.expires_at_unix),
            catalog_trusted: catalog.is_some(),
            available_packages: catalog
                .as_ref()
                .map(|value| {
                    value
                        .entries
                        .iter()
                        .filter(|entry| !entry.revoked)
                        .map(entry_view)
                        .collect()
                })
                .unwrap_or_default(),
            installed_versions: versions,
            active_version: current.active_version.map(|value| value.to_string()),
            active_manifest_sha256: current.active_manifest_sha256,
            active_integrity_valid: active_valid,
            qualification_recheck_required: active_valid,
            remote_ocr_allowed: false,
            case_material_downloaded_or_uploaded: false,
            reason_codes: reasons,
        })
    }

    fn read_current(&self) -> ComponentResult<CurrentComponentV1> {
        let value = state::read_current(&self.shared.root)?;
        validate_current(&value)?;
        Ok(value)
    }

    fn remeasure_active_component(&self) -> ComponentResult<()> {
        let _guard = self.operation();
        let current = match self.read_current() {
            Ok(value) => value,
            Err(failure) if failure.code() == "component_file_missing" => return Ok(()),
            Err(failure) => return Err(failure),
        };
        let Some(version) = current.active_version.clone() else {
            return Ok(());
        };
        let validation = load_trusted_catalog(&self.shared.root).and_then(|catalog| {
            validate_installed_component(&self.shared.root, &version, &catalog)
        });
        let binding_mismatch = validation.as_ref().is_ok_and(|binding| {
            current.active_manifest_sha256.as_deref() != Some(binding.manifest_sha256.as_str())
        });
        if let Err(failure) = validation {
            let mut drifted = current;
            drifted.state = LifecycleState::Drifted;
            drifted.reason_codes = vec![failure.code().to_owned()];
            persist_current(&self.shared.root, &drifted)?;
        } else if binding_mismatch {
            let mut drifted = current;
            drifted.state = LifecycleState::Drifted;
            drifted.reason_codes = vec!["current_manifest_binding_mismatch".to_owned()];
            persist_current(&self.shared.root, &drifted)?;
        }
        Ok(())
    }

    fn cleanup_stale_transients(&self) -> ComponentResult<()> {
        let live_resume_hashes = load_trusted_catalog(&self.shared.root)
            .map(|catalog| {
                catalog
                    .entries
                    .into_iter()
                    .filter(|entry| !entry.revoked && !entry.parts.is_empty())
                    .map(|entry| entry.package_sha256)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        self.cleanup_stale_transients_with_live_resume_hashes(&live_resume_hashes)
    }

    fn cleanup_stale_transients_with_live_resume_hashes(
        &self,
        live_resume_hashes: &BTreeSet<String>,
    ) -> ComponentResult<()> {
        if live_resume_hashes.len() > MAX_RESUMABLE_DOWNLOAD_DIRECTORIES
            || live_resume_hashes
                .iter()
                .any(|hash| !package::valid_hash(hash))
        {
            return Err(error("transient_gc_limit_exceeded"));
        }
        let mut root_entry_count = 0usize;
        let mut resume_directory_count = 0usize;
        let mut cleanup = Vec::new();
        for entry in
            fs::read_dir(&self.shared.root).map_err(|_| error("component_root_unavailable"))?
        {
            let entry = entry.map_err(|_| error("component_root_unavailable"))?;
            root_entry_count = root_entry_count.saturating_add(1);
            if root_entry_count > MAX_TRANSIENT_GC_ROOT_ENTRIES {
                return Err(error("transient_gc_limit_exceeded"));
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let transient = name
                .strip_prefix(".staging-")
                .or_else(|| name.strip_prefix(".download-"))
                .and_then(|suffix| Uuid::parse_str(suffix).ok())
                .is_some();
            if transient {
                cleanup.push(entry.path());
                continue;
            }
            if let Some(hash) = name.strip_prefix(".download-resume-") {
                resume_directory_count = resume_directory_count.saturating_add(1);
                if resume_directory_count > MAX_RESUMABLE_DOWNLOAD_DIRECTORIES {
                    return Err(error("transient_gc_limit_exceeded"));
                }
                if package::valid_hash(hash) && live_resume_hashes.contains(hash) {
                    package::ensure_private_fixed_directory(&entry.path())?;
                } else {
                    cleanup.push(entry.path());
                }
            }
        }
        for path in cleanup {
            cleanup_safe_transient(&path)?;
        }
        Ok(())
    }

    fn operation(&self) -> MutexGuard<'_, ()> {
        self.shared
            .operation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn persist_current(root: &Path, current: &CurrentComponentV1) -> ComponentResult<()> {
    validate_current(current)?;
    state::write_current(root, current)
}

fn validate_current(current: &CurrentComponentV1) -> ComponentResult<()> {
    if current.schema_version != CURRENT_SCHEMA_VERSION
        || current.reason_codes.len() > 16
        || current
            .reason_codes
            .iter()
            .any(|value| !package::valid_reason_code(value))
        || current
            .active_manifest_sha256
            .as_deref()
            .is_some_and(|value| !package::valid_hash(value))
        || current.active_version.is_some() != current.active_manifest_sha256.is_some()
        || (current.state == LifecycleState::Active && current.active_version.is_none())
    {
        return Err(error("current_state_invalid"));
    }
    Ok(())
}

fn inactive_current() -> CurrentComponentV1 {
    CurrentComponentV1 {
        schema_version: CURRENT_SCHEMA_VERSION,
        generation: 0,
        active_version: None,
        active_manifest_sha256: None,
        previous_version: None,
        activated_at_unix: 0,
        state: LifecycleState::Inactive,
        reason_codes: vec!["component_not_installed".to_owned()],
    }
}

fn append_audit(
    root: &Path,
    event: &'static str,
    package_id: Option<&str>,
    version: Option<&Version>,
    manifest_sha256: Option<&str>,
) -> ComponentResult<()> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Audit<'a> {
        schema_version: u16,
        event_id: String,
        occurred_at_unix: u64,
        event: &'a str,
        package_id_sha256: Option<String>,
        component_version: Option<String>,
        manifest_sha256: Option<&'a str>,
    }
    let path = root.join(AUDIT_FILE_NAME);
    if path.exists() {
        package::ordinary_file(&path, 16 * 1024 * 1024)?;
    }
    let event = Audit {
        schema_version: AUDIT_SCHEMA_VERSION,
        event_id: Uuid::new_v4().to_string(),
        occurred_at_unix: package::unix_now()?,
        event,
        package_id_sha256: package_id.map(|value| package::sha256_bytes(value.as_bytes())),
        component_version: version.map(ToString::to_string),
        manifest_sha256,
    };
    let mut bytes = serde_json::to_vec(&event).map_err(|_| error("audit_failed"))?;
    bytes.push(b'\n');
    package::append_file(&path, &bytes)
}

#[cfg(test)]
mod download_tests;

#[cfg(test)]
mod tests;
