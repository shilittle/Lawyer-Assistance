#![allow(unsafe_code)]

use super::privacy_workflow::IpcError;
use crate::{
    approved_mcp::{
        observe_application_restore_workspace_identity_read_only,
        validate_application_restore_components_read_only,
        ApplicationRestoreApprovedComponentsProof, ApplicationRestoreWorkspaceIdentityProof,
        ApprovedMcpWorkspace,
    },
    privacy_manager,
    privacy_workflow::{ApplicationBackupPrivacyGuard, PrivacyWorkflowManager},
    state::AppState,
};
use privacy::vault_store::VaultStore;
use privacy::{
    open_application_backup, open_application_backup_for_migration_recovery, protect_local,
    seal_application_backup, seal_application_backup_v3, sha256_hex, stage_encrypted_vault_backup,
    unprotect_local, ApplicationBackupCreateRequest, ApplicationBackupCreateRequestV3,
    ApplicationBackupMetadata, ApplicationBackupOpenContext, MigrationApplicationBackupOpenContext,
    PrivacyLifecycle, PrivacyStore, PrivacyStoreSchemaStatus, MAX_APPLICATION_BACKUP_BYTES,
    MAX_USER_DATABASE_BACKUP_BYTES, PRIVACY_STORE_SCHEMA_VERSION,
};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, PathBuf},
    sync::atomic::{compiler_fence, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    },
};

const FULL_BACKUP_EXTENSION: &str = "lavbackup";
const FULL_BACKUP_DEFAULT_NAME: &str = "Lawyer-Assistance-完整加密备份.lavbackup";
const FULL_RESTORE_FORMAT_VERSION: u16 = 2;
const FULL_RESTORE_V3_FORMAT_VERSION: u16 = 3;
const FULL_RESTORE_MARKER_NAME: &str = "application-restore-pending.dpapi";
const FULL_RESTORE_MARKER_MAX_BYTES: usize = 128 * 1024;
const PRIVACY_DATABASE_RELATIVE: &str = "privacy/privacy-workflow.sqlite";
const PRIVACY_INCOMING_RELATIVE: &str =
    "privacy/privacy-workflow.sqlite.application-restore-incoming";
const VAULT_DIRECTORY_NAME: &str = "case-vault-v2";
const APPROVED_DIRECTORY_NAME: &str = "approved-generations";
const WORK_PRODUCTS_DIRECTORY_NAME: &str = "work-products";
const APPROVED_DATABASE_FILE_NAME: &str = "workspace-state.sqlite";
const WORK_PRODUCTS_DATABASE_FILE_NAME: &str = "work-products.sqlite";
const APPROVED_DIRECTORY_RELATIVE: &str = "privacy/approved-mcp/approved-generations";
const WORK_PRODUCTS_DIRECTORY_RELATIVE: &str = "privacy/approved-mcp/work-products";
const MIGRATION_BACKUP_DIRECTORY_NAME: &str = "migration-backups";
const MIGRATION_BACKUP_IDENTITY_SUFFIX: &str = ".identity.dpapi";
const MIGRATION_BACKUP_IDENTITY_SCHEMA_VERSION: &str =
    "lawyer-assistance-migration-backup-identity-v1";
const MAX_MIGRATION_BACKUP_IDENTITY_BYTES: usize = 128 * 1024;
const MAX_MIGRATION_BACKUP_CANDIDATES: usize = 64;
pub(crate) const CASE_MATERIAL_UNIFICATION_MIGRATION_ID: &str = "case-material-unification-v1";
pub(crate) const PROJECT_PRIVACY_CASE_BINDING_MIGRATION_ID: &str =
    "project-privacy-case-binding-v1";
pub(crate) const APPROVED_CASE_PROJECTION_MIGRATION_ID: &str =
    privacy::APPROVED_CASE_PROJECTION_MIGRATION_ID;
pub const FULL_RESTORE_CONFIRMATION: &str = "恢复完整应用备份";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationBackupResponse {
    pub cancelled: bool,
    pub file_name: Option<String>,
    pub metadata: Option<ApplicationBackupMetadata>,
    pub restart_required: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct MigrationApplicationBackup {
    pub path: PathBuf,
    pub metadata: ApplicationBackupMetadata,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationComponentIdentityV1 {
    user_database_sha256: String,
    privacy_store_schema_version: i64,
    privacy_store_manifest_sha256: String,
    privacy_database_sha256: String,
    encrypted_privacy_bundle_sha256: String,
    vault_store_schema_version: u32,
    vault_content_manifest_sha256: String,
    vault_manifest_sha256: String,
    encrypted_vault_bundle_sha256: String,
    approved_workspace_manifest_sha256: String,
    approved_workspace_bundle_sha256: String,
    work_products_manifest_sha256: String,
    work_products_bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentMigrationComponentIdentity {
    user_database_sha256: String,
    privacy_store_schema_version: i64,
    privacy_store_manifest_sha256: String,
    vault_store_schema_version: u32,
    vault_content_manifest_sha256: String,
    vault_manifest_sha256: String,
    approved_workspace_manifest_sha256: String,
    work_products_manifest_sha256: String,
}

#[derive(Debug, Clone)]
struct BuiltMigrationComponentIdentity {
    current: CurrentMigrationComponentIdentity,
    privacy_database_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MigrationBackupIdentityV1 {
    schema_version: String,
    migration_id: String,
    source_fingerprint: String,
    workspace_instance_id: String,
    backup_file_name: String,
    backup_bundle_sha256: String,
    backup_id: String,
    privacy_backup_id: String,
    app_version: String,
    user_schema_version: i64,
    created_at_unix: u64,
    expires_at_unix: u64,
    components: MigrationComponentIdentityV1,
}

struct VerifiedMigrationBackupCandidate {
    path: PathBuf,
    identity: MigrationBackupIdentityV1,
    metadata: ApplicationBackupMetadata,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageApplicationRestoreRequest {
    pub confirmation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingApplicationRestoreV2 {
    format_version: u16,
    backup_id: String,
    privacy_backup_id: String,
    workspace_instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_user_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_privacy_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_vault_present: Option<bool>,
    app_version: String,
    user_schema_version: i64,
    user_database_sha256: String,
    privacy_database_sha256: String,
    privacy_key_epoch: u64,
    vault_manifest_sha256: String,
    vault_archive_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingApplicationRestoreV3 {
    format_version: u16,
    backup_id: String,
    privacy_backup_id: String,
    workspace_instance_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_user_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_privacy_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_vault_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_approved_workspace_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original_work_products_present: Option<bool>,
    app_version: String,
    user_schema_version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    privacy_store_schema_version: Option<i64>,
    user_database_sha256: String,
    privacy_database_sha256: String,
    privacy_key_epoch: u64,
    vault_manifest_sha256: String,
    vault_archive_sha256: String,
    approved_workspace_bundle_sha256: String,
    approved_workspace_manifest_sha256: String,
    work_products_bundle_sha256: String,
    work_products_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum PendingApplicationRestore {
    V2(PendingApplicationRestoreV2),
    V3(PendingApplicationRestoreV3),
}

struct ApplicationRestorePaths {
    marker: PathBuf,
    user_active: PathBuf,
    user_incoming: PathBuf,
    user_rollback: PathBuf,
    legacy_user_incoming: PathBuf,
    legacy_user_marker: PathBuf,
    legacy_user_rollback: PathBuf,
    privacy_active: PathBuf,
    privacy_incoming: PathBuf,
    privacy_rollback: PathBuf,
    vault_active: PathBuf,
    vault_incoming: PathBuf,
    vault_rollback: PathBuf,
    approved_active: PathBuf,
    approved_incoming: PathBuf,
    approved_rollback: PathBuf,
    work_products_active: PathBuf,
    work_products_incoming: PathBuf,
    work_products_rollback: PathBuf,
}

const MAX_APPLICATION_RESTORE_TREE_ENTRIES: usize = 400_000;
const MAX_APPLICATION_RESTORE_TREE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingApplicationRestorePhase {
    Prepared,
    UserMovedToRollback,
    UserInstalled,
    PrivacyMovedToRollback,
    PrivacyInstalled,
    VaultMovedToRollback,
    VaultInstalled,
    ApprovedWorkspaceMovedToRollback,
    ApprovedWorkspaceInstalled,
    WorkProductsMovedToRollback,
    InstalledPendingCleanup { removed_rollback_prefix: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreSlotProgress {
    PreparedWithOriginal,
    PreparedFromAbsent,
    MovedToRollback,
    InstalledWithRollback,
    InstalledFromAbsent,
    Cleaned,
    /// Compatibility-only interpretation for durable V2/V3 pending markers
    /// written before original-presence evidence was added.  A new marker
    /// never produces this state.
    LegacyInstalledWithoutRollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreComponentKind {
    User,
    Privacy,
    Vault,
    ApprovedWorkspace,
    WorkProducts,
}

#[derive(Clone, PartialEq, Eq)]
struct RestoreFileProof {
    identity_sha256: String,
    bytes: u64,
    created: u64,
    modified: u64,
    attributes: u32,
    sha256: String,
}

impl std::fmt::Debug for RestoreFileProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoreFileProof")
            .field("identity_sha256", &self.identity_sha256)
            .field("bytes", &self.bytes)
            .field("created", &self.created)
            .field("modified", &self.modified)
            .field("attributes", &self.attributes)
            .field("sha256", &self.sha256)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreTreeEntryKind {
    Directory,
    File,
}

#[derive(Clone, PartialEq, Eq)]
struct RestoreTreeEntryProof {
    relative_path_sha256: String,
    kind: RestoreTreeEntryKind,
    identity_sha256: String,
    bytes: u64,
    created: u64,
    modified: u64,
    attributes: u32,
    content_sha256: Option<String>,
}

impl std::fmt::Debug for RestoreTreeEntryProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestoreTreeEntryProof")
            .field("relative_path_sha256", &self.relative_path_sha256)
            .field("kind", &self.kind)
            .field("identity_sha256", &self.identity_sha256)
            .field("bytes", &self.bytes)
            .field("created", &self.created)
            .field("modified", &self.modified)
            .field("attributes", &self.attributes)
            .field("content_sha256", &self.content_sha256)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RestoreDirectoryProof {
    root: RestoreTreeEntryProof,
    entries: Vec<RestoreTreeEntryProof>,
    total_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RestorePathProof {
    Absent,
    File(RestoreFileProof),
    Directory(RestoreDirectoryProof),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ApplicationRestoreSlotsProof {
    user_active: RestorePathProof,
    user_incoming: RestorePathProof,
    user_rollback: RestorePathProof,
    privacy_active: RestorePathProof,
    privacy_incoming: RestorePathProof,
    privacy_rollback: RestorePathProof,
    vault_active: RestorePathProof,
    vault_incoming: RestorePathProof,
    vault_rollback: RestorePathProof,
    approved_active: RestorePathProof,
    approved_incoming: RestorePathProof,
    approved_rollback: RestorePathProof,
    work_products_active: RestorePathProof,
    work_products_incoming: RestorePathProof,
    work_products_rollback: RestorePathProof,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PendingApplicationRestoreGate {
    marker: PendingApplicationRestore,
    marker_file: RestoreFileProof,
    workspace_instance_id: privacy::vnext::WorkspaceInstanceId,
    phase: PendingApplicationRestorePhase,
    slots: ApplicationRestoreSlotsProof,
    workspace_identity: ApplicationRestoreWorkspaceIdentityProof,
    approved_components: Option<ApplicationRestoreApprovedComponentsProof>,
}

impl std::fmt::Debug for PendingApplicationRestoreGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingApplicationRestoreGate")
            .field("marker", &"[DPAPI_AUTHENTICATED]")
            .field("marker_file", &self.marker_file)
            .field("workspace_instance_id", &"[AUTHENTICATED_WORKSPACE]")
            .field("phase", &self.phase)
            .field("slots", &self.slots)
            .field("workspace_identity", &self.workspace_identity)
            .field("approved_components", &self.approved_components)
            .finish()
    }
}

impl PendingApplicationRestoreGate {
    #[cfg(test)]
    pub(crate) fn workspace_instance_id(&self) -> &privacy::vnext::WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    #[cfg(test)]
    pub(crate) const fn phase(&self) -> PendingApplicationRestorePhase {
        self.phase
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// The authenticated observation intentionally owns the complete fixed-slot
// proof so callers cannot separate classification from its capability.
#[allow(clippy::large_enum_variant)]
pub(crate) enum PendingApplicationRestoreObservation {
    Absent,
    Authenticated(PendingApplicationRestoreGate),
}

struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

#[tauri::command]
pub async fn export_application_backup(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    approved_workspace: State<'_, ApprovedMcpWorkspace>,
) -> Result<ApplicationBackupResponse, IpcError> {
    let selected = app
        .dialog()
        .file()
        .set_title("导出用户数据库、隐私数据库与加密案件 Vault 完整备份")
        .set_file_name(FULL_BACKUP_DEFAULT_NAME)
        .add_filter("Lawyer Assistance 加密备份", &[FULL_BACKUP_EXTENSION])
        .blocking_save_file();
    let Some(selected) = selected else {
        return Ok(cancelled_response());
    };
    let mut destination = selected.into_path().map_err(|_| {
        ipc_error(
            "application_backup_invalid_destination",
            "所选完整备份目标不是本地文件。",
        )
    })?;
    force_extension(&mut destination);
    validate_new_local_file(&destination)?;
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    let approved_workspace = approved_workspace.inner().clone();
    let app_local_data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|_| ipc_error("application_backup_io", "无法定位固定的本机应用数据目录。"))?;
    tauri::async_runtime::spawn_blocking(move || {
        let (bytes, metadata, privacy_backup_id) = build_application_backup_v3(
            &app_local_data_dir,
            &state,
            &workflow,
            &approved_workspace,
        )?;
        if let Err(error) = install_and_verify_backup(&destination, &bytes, &workflow) {
            let _ = workflow.revoke_privacy_backup(&privacy_backup_id);
            return Err(error);
        }
        Ok(ApplicationBackupResponse {
            cancelled: false,
            file_name: Some(safe_file_name(&destination)),
            metadata: Some(metadata),
            restart_required: false,
        })
    })
    .await
    .map_err(|_| ipc_error("runtime_failure", "完整加密备份任务未完成。"))?
}

#[tauri::command]
pub async fn verify_application_backup(
    app: tauri::AppHandle,
    workflow: State<'_, PrivacyWorkflowManager>,
) -> Result<ApplicationBackupResponse, IpcError> {
    let selected = app
        .dialog()
        .file()
        .set_title("验证完整加密备份")
        .add_filter("Lawyer Assistance 加密备份", &[FULL_BACKUP_EXTENSION])
        .blocking_pick_file();
    let Some(selected) = selected else {
        return Ok(cancelled_response());
    };
    let source = selected.into_path().map_err(|_| {
        ipc_error(
            "application_backup_invalid_source",
            "所选完整备份不是本地文件。",
        )
    })?;
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let bytes = read_local_file(&source, MAX_APPLICATION_BACKUP_BYTES)?;
        let opened = open_current_application_backup(&bytes, &workflow)?;
        Ok(ApplicationBackupResponse {
            cancelled: false,
            file_name: Some(safe_file_name(&source)),
            metadata: Some(opened.metadata.clone()),
            restart_required: false,
        })
    })
    .await
    .map_err(|_| ipc_error("runtime_failure", "完整加密备份验证任务未完成。"))?
}

#[tauri::command]
pub async fn stage_application_restore(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    approved_workspace: State<'_, ApprovedMcpWorkspace>,
    request: StageApplicationRestoreRequest,
) -> Result<ApplicationBackupResponse, IpcError> {
    if request.confirmation != FULL_RESTORE_CONFIRMATION {
        return Err(ipc_error(
            "application_restore_confirmation_required",
            "恢复完整应用备份需要输入界面显示的完整确认短语。",
        ));
    }
    let selected = app
        .dialog()
        .file()
        .set_title("选择要恢复的完整加密备份")
        .add_filter("Lawyer Assistance 加密备份", &[FULL_BACKUP_EXTENSION])
        .blocking_pick_file();
    let Some(selected) = selected else {
        return Ok(cancelled_response());
    };
    let source = selected.into_path().map_err(|_| {
        ipc_error(
            "application_backup_invalid_source",
            "所选完整备份不是本地文件。",
        )
    })?;
    let workflow = workflow.inner().clone();
    let state = state.inner().clone();
    let approved_workspace = approved_workspace.inner().clone();
    let app_local_data_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|_| ipc_error("application_restore_io", "无法定位固定的本机应用数据目录。"))?;
    tauri::async_runtime::spawn_blocking(move || {
        let bytes = read_local_file(&source, MAX_APPLICATION_BACKUP_BYTES)?;
        let metadata = stage_selected_application_restore_with_approved(
            &app_local_data_dir,
            state.user_database_path(),
            &workflow,
            &approved_workspace,
            &source,
            &bytes,
        )?;
        Ok(ApplicationBackupResponse {
            cancelled: false,
            file_name: Some(safe_file_name(&source)),
            metadata: Some(metadata),
            restart_required: true,
        })
    })
    .await
    .map_err(|_| ipc_error("runtime_failure", "完整加密备份恢复暂存任务未完成。"))?
}

#[cfg(test)]
fn build_application_backup(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
) -> Result<(Vec<u8>, ApplicationBackupMetadata, String), IpcError> {
    build_application_backup_with_lock_hook(app_local_data_dir, state, workflow, || {})
}

fn build_application_backup_v3(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(Vec<u8>, ApplicationBackupMetadata, String), IpcError> {
    let (bytes, metadata, privacy_backup_id, _) = build_application_backup_internal(
        app_local_data_dir,
        state,
        workflow,
        Some(approved_workspace),
        || {},
    )?;
    Ok((bytes, metadata, privacy_backup_id))
}

pub(crate) fn ensure_pre_migration_application_backup(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    migration_id: &str,
    source_fingerprint: &str,
) -> Result<MigrationApplicationBackup, IpcError> {
    ensure_pre_migration_application_backup_internal(
        app_local_data_dir,
        state,
        workflow,
        approved_workspace,
        migration_id,
        source_fingerprint,
        atomic_install_new_migration_backup,
    )
}

#[cfg(test)]
fn ensure_pre_migration_application_backup_with_install_hook<Install>(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    migration_id: &str,
    source_fingerprint: &str,
    install: Install,
) -> Result<MigrationApplicationBackup, IpcError>
where
    Install: FnOnce(&Path, &Path) -> Result<(), IpcError>,
{
    ensure_pre_migration_application_backup_internal(
        app_local_data_dir,
        state,
        workflow,
        approved_workspace,
        migration_id,
        source_fingerprint,
        install,
    )
}

fn ensure_pre_migration_application_backup_internal<Install>(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    migration_id: &str,
    source_fingerprint: &str,
    install: Install,
) -> Result<MigrationApplicationBackup, IpcError>
where
    Install: FnOnce(&Path, &Path) -> Result<(), IpcError>,
{
    let canonical_file_name = migration_backup_file_name(migration_id, source_fingerprint)?;
    verify_current_migration_source_fingerprint(workflow, migration_id, source_fingerprint)?;
    let directory = ensure_migration_backup_directory(app_local_data_dir)?;
    // Recover a bundle whose authenticated identity was already installed before treating
    // remaining dot-files as pre-commit staging. The durable identity is the commit record for
    // this no-replacement install; cleaning first would misclassify its staged bundle as orphaned.
    let candidates =
        load_migration_backup_candidates(&directory, workflow, migration_id, source_fingerprint)?;
    cleanup_orphaned_migration_backup_staging(
        &directory,
        workflow,
        migration_id,
        source_fingerprint,
    )?;
    if !candidates.is_empty() {
        let current = capture_current_migration_components(
            app_local_data_dir,
            state,
            workflow,
            approved_workspace,
        )?;
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| identity_matches_current(&candidate.identity.components, &current))
            .or_else(|| {
                candidates.iter().find(|candidate| {
                    identity_is_recovery_compatible(&candidate.identity.components, &current)
                })
            })
        {
            verify_current_migration_source_fingerprint(
                workflow,
                migration_id,
                source_fingerprint,
            )?;
            return Ok(MigrationApplicationBackup {
                path: candidate.path.clone(),
                metadata: candidate.metadata.clone(),
                created: false,
            });
        }
    }

    let (bytes, expected_metadata, privacy_backup_id, built_identity) =
        build_application_backup_internal(
            app_local_data_dir,
            state,
            workflow,
            Some(approved_workspace),
            || {},
        )?;
    let built_identity = built_identity.ok_or_else(five_component_backup_error)?;
    let expected_bundle_sha256 = sha256_hex(&bytes);
    if let Err(error) =
        verify_current_migration_source_fingerprint(workflow, migration_id, source_fingerprint)
    {
        return Err(abort_built_migration_backup(
            workflow,
            &privacy_backup_id,
            None,
            None,
            error,
        ));
    }
    if let Err(error) =
        validate_five_component_application_backup(&bytes, workflow, &expected_metadata)
    {
        return Err(abort_built_migration_backup(
            workflow,
            &privacy_backup_id,
            None,
            None,
            error,
        ));
    }
    let identity = match migration_backup_identity(
        migration_id,
        source_fingerprint,
        &canonical_file_name,
        workflow,
        &expected_metadata,
        &built_identity,
    ) {
        Ok(identity) => identity,
        Err(error) => {
            return Err(abort_built_migration_backup(
                workflow,
                &privacy_backup_id,
                None,
                None,
                error,
            ));
        }
    };
    let identity_fingerprint = migration_component_fingerprint(&built_identity.current);
    let file_name = if candidates.is_empty() {
        canonical_file_name
    } else {
        migration_backup_file_name_for_components(
            migration_id,
            source_fingerprint,
            &identity_fingerprint,
        )?
    };
    let destination = directory.join(&file_name);
    let identity_destination = migration_backup_identity_path(&destination)?;
    let identity = MigrationBackupIdentityV1 {
        backup_file_name: file_name,
        ..identity
    };
    if destination.parent() != Some(directory.as_path())
        || identity_destination.parent() != Some(directory.as_path())
    {
        return Err(abort_built_migration_backup(
            workflow,
            &privacy_backup_id,
            None,
            None,
            ipc_error(
                "migration_backup_unsafe_path",
                "The fixed migration backup pair escaped its controlled application directory.",
            ),
        ));
    }
    if path_is_present(&destination)? || path_is_present(&identity_destination)? {
        return Err(abort_built_migration_backup(
            workflow,
            &privacy_backup_id,
            None,
            None,
            ipc_error(
                "migration_backup_install_conflict",
                "A migration backup identity destination already exists and was not replaced.",
            ),
        ));
    }

    let staging = directory.join(format!(
        ".{migration_id}-{source_fingerprint}-{}.staged.{FULL_BACKUP_EXTENSION}",
        Uuid::new_v4().simple()
    ));
    let identity_staging = directory.join(format!(
        ".{migration_id}-{source_fingerprint}-{}.staged.identity.dpapi",
        Uuid::new_v4().simple()
    ));
    if staging.parent() != Some(directory.as_path())
        || identity_staging.parent() != Some(directory.as_path())
    {
        return Err(abort_built_migration_backup(
            workflow,
            &privacy_backup_id,
            None,
            None,
            ipc_error(
                "migration_backup_unsafe_path",
                "The migration backup staging path escaped its controlled directory.",
            ),
        ));
    }
    if let Err(error) = stage_migration_backup_pair(
        &staging,
        &identity_staging,
        &bytes,
        &identity,
        workflow,
        &expected_metadata,
    ) {
        return Err(abort_built_migration_backup(
            workflow,
            &privacy_backup_id,
            Some(&staging),
            None,
            match remove_migration_backup_file_if_exists(&identity_staging) {
                Ok(()) => error,
                Err(cleanup_error) => cleanup_error,
            },
        ));
    }

    if let Err(error) = atomic_install_new_migration_file(&identity_staging, &identity_destination)
    {
        return Err(abort_built_migration_backup(
            workflow,
            &privacy_backup_id,
            Some(&staging),
            None,
            match remove_migration_backup_file_if_exists(&identity_staging) {
                Ok(()) => error,
                Err(cleanup_error) => cleanup_error,
            },
        ));
    }
    if let Err(_install_error) = install(&staging, &destination) {
        // The authenticated identity is installed first. Preserve both it and the staged bundle:
        // the next startup can finish this exact no-replacement install by hash.
        return Err(ipc_error(
            "migration_backup_install_incomplete",
            "The migration backup identity is durable, but its matching bundle install is incomplete; no valid rollback point was overwritten or deleted.",
        ));
    }

    let installed = match verify_migration_backup_pair(
        &destination,
        &identity_destination,
        workflow,
        Some(&expected_bundle_sha256),
        Some((&identity, &expected_metadata)),
    ) {
        Ok(candidate) => candidate,
        Err(error) => {
            // Installed rollback artifacts are append-only forensic/recovery evidence.
            return Err(error);
        }
    };
    // The pair is already durably installed and may be the only coherent rollback point for
    // the old source. Preserve its active Privacy backup state; only block this migration run.
    verify_current_migration_source_fingerprint(workflow, migration_id, source_fingerprint)?;
    Ok(MigrationApplicationBackup {
        path: destination,
        metadata: installed.metadata,
        created: true,
    })
}

fn cleanup_orphaned_migration_backup_staging(
    directory: &Path,
    workflow: &PrivacyWorkflowManager,
    migration_id: &str,
    source_fingerprint: &str,
) -> Result<(), IpcError> {
    let prefix = format!(".{migration_id}-{source_fingerprint}-");
    let backup_suffix = format!(".staged.{FULL_BACKUP_EXTENSION}");
    let identity_suffix = ".staged.identity.dpapi";
    let mut staged_backups = Vec::new();
    let mut staged_identities = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| {
        ipc_error(
            "migration_backup_io",
            "Migration backup staging could not be enumerated.",
        )
    })? {
        let entry = entry.map_err(|_| {
            ipc_error(
                "migration_backup_io",
                "A migration backup staging entry could not be inspected.",
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        if name.ends_with(identity_suffix) {
            staged_identities.push(entry.path());
        } else if name.ends_with(&backup_suffix) {
            staged_backups.push(entry.path());
        }
    }
    if staged_backups.len() > MAX_MIGRATION_BACKUP_CANDIDATES
        || staged_identities.len() > MAX_MIGRATION_BACKUP_CANDIDATES
    {
        return Err(ipc_error(
            "migration_backup_candidate_limit",
            "Too many incomplete migration backup artifacts require manual inspection.",
        ));
    }
    let mut retained = BTreeSet::new();
    let mut consumed = BTreeSet::new();
    for identity_path in staged_identities {
        let identity = read_migration_backup_identity(&identity_path)?;
        validate_migration_backup_identity(&identity, workflow, migration_id, source_fingerprint)?;
        let final_backup = directory.join(&identity.backup_file_name);
        let final_identity = migration_backup_identity_path(&final_backup)?;
        let mut matching = Vec::new();
        for path in &staged_backups {
            let bytes = SensitiveBytes(read_local_file(path, MAX_APPLICATION_BACKUP_BYTES)?);
            if sha256_hex(bytes.as_slice()) == identity.backup_bundle_sha256 {
                matching.push(path.clone());
            }
        }
        if path_is_present(&final_identity)? {
            if matching.len() == 1 {
                retained.insert(matching[0].clone());
                continue;
            }
            return Err(ipc_error(
                "migration_backup_install_incomplete",
                "A durable migration identity does not have exactly one recoverable staged bundle.",
            ));
        }
        if matching.len() != 1 {
            return Err(ipc_error(
                "migration_backup_install_incomplete",
                "An orphaned staged migration identity does not have exactly one authenticated bundle.",
            ));
        }
        let matching_backup = &matching[0];
        let bytes = SensitiveBytes(read_local_file(
            matching_backup,
            MAX_APPLICATION_BACKUP_BYTES,
        )?);
        let opened = open_application_backup_for_migration_recovery(
            bytes.as_slice(),
            &MigrationApplicationBackupOpenContext {
                expected_workspace_instance_id: &workflow.workspace_instance_id(),
                expected_user_schema_version: identity.user_schema_version,
                expected_backup_id: &identity.backup_id,
                expected_privacy_backup_id: &identity.privacy_backup_id,
                expected_app_version: &identity.app_version,
                expected_created_at_unix: identity.created_at_unix,
                expected_expires_at_unix: identity.expires_at_unix,
                expected_bundle_sha256: &identity.backup_bundle_sha256,
            },
        )
        .map_err(application_backup_error)?;
        drop(opened);
        remove_migration_backup_file_if_exists(matching_backup)?;
        remove_migration_backup_file_if_exists(&identity_path)?;
        workflow
            .revoke_privacy_backup(&identity.privacy_backup_id)
            .map_err(workflow_error)?;
        consumed.insert(matching_backup.clone());
    }
    for backup_path in staged_backups {
        if retained.contains(&backup_path) || consumed.contains(&backup_path) {
            continue;
        }
        let bytes = SensitiveBytes(read_local_file(&backup_path, MAX_APPLICATION_BACKUP_BYTES)?);
        let opened = open_current_application_backup(bytes.as_slice(), workflow)?;
        let metadata = validate_opened_five_component_backup(bytes.as_slice(), opened)?;
        remove_migration_backup_file_if_exists(&backup_path)?;
        workflow
            .revoke_privacy_backup(&metadata.privacy_backup_id)
            .map_err(workflow_error)?;
    }
    Ok(())
}

fn migration_backup_identity(
    migration_id: &str,
    source_fingerprint: &str,
    backup_file_name: &str,
    workflow: &PrivacyWorkflowManager,
    metadata: &ApplicationBackupMetadata,
    built: &BuiltMigrationComponentIdentity,
) -> Result<MigrationBackupIdentityV1, IpcError> {
    let approved_bundle_sha256 = metadata
        .approved_workspace_bundle_sha256
        .clone()
        .ok_or_else(five_component_backup_error)?;
    let approved_manifest_sha256 = metadata
        .approved_workspace_manifest_sha256
        .clone()
        .ok_or_else(five_component_backup_error)?;
    let work_products_bundle_sha256 = metadata
        .work_products_bundle_sha256
        .clone()
        .ok_or_else(five_component_backup_error)?;
    let work_products_manifest_sha256 = metadata
        .work_products_manifest_sha256
        .clone()
        .ok_or_else(five_component_backup_error)?;
    if metadata.user_database_sha256 != built.current.user_database_sha256
        || metadata.vault_manifest_sha256 != built.current.vault_manifest_sha256
        || approved_manifest_sha256 != built.current.approved_workspace_manifest_sha256
        || work_products_manifest_sha256 != built.current.work_products_manifest_sha256
    {
        return Err(five_component_backup_error());
    }
    let identity = MigrationBackupIdentityV1 {
        schema_version: MIGRATION_BACKUP_IDENTITY_SCHEMA_VERSION.to_owned(),
        migration_id: migration_id.to_owned(),
        source_fingerprint: source_fingerprint.to_owned(),
        workspace_instance_id: workflow.workspace_instance_id().as_str().to_owned(),
        backup_file_name: backup_file_name.to_owned(),
        backup_bundle_sha256: metadata.bundle_sha256.clone(),
        backup_id: metadata.backup_id.clone(),
        privacy_backup_id: metadata.privacy_backup_id.clone(),
        app_version: metadata.app_version.clone(),
        user_schema_version: metadata.user_schema_version,
        created_at_unix: metadata.created_at_unix,
        expires_at_unix: metadata.expires_at_unix,
        components: MigrationComponentIdentityV1 {
            user_database_sha256: built.current.user_database_sha256.clone(),
            privacy_store_schema_version: built.current.privacy_store_schema_version,
            privacy_store_manifest_sha256: built.current.privacy_store_manifest_sha256.clone(),
            privacy_database_sha256: built.privacy_database_sha256.clone(),
            encrypted_privacy_bundle_sha256: metadata.encrypted_privacy_bundle_sha256.clone(),
            vault_store_schema_version: built.current.vault_store_schema_version,
            vault_content_manifest_sha256: built.current.vault_content_manifest_sha256.clone(),
            vault_manifest_sha256: built.current.vault_manifest_sha256.clone(),
            encrypted_vault_bundle_sha256: metadata.encrypted_vault_bundle_sha256.clone(),
            approved_workspace_manifest_sha256: approved_manifest_sha256,
            approved_workspace_bundle_sha256: approved_bundle_sha256,
            work_products_manifest_sha256,
            work_products_bundle_sha256,
        },
    };
    validate_migration_backup_identity(&identity, workflow, migration_id, source_fingerprint)?;
    Ok(identity)
}

fn validate_migration_backup_identity(
    identity: &MigrationBackupIdentityV1,
    workflow: &PrivacyWorkflowManager,
    migration_id: &str,
    source_fingerprint: &str,
) -> Result<(), IpcError> {
    migration_backup_file_name(migration_id, source_fingerprint)?;
    let component_hashes = [
        identity.backup_bundle_sha256.as_str(),
        identity.components.user_database_sha256.as_str(),
        identity.components.privacy_store_manifest_sha256.as_str(),
        identity.components.privacy_database_sha256.as_str(),
        identity.components.encrypted_privacy_bundle_sha256.as_str(),
        identity.components.vault_content_manifest_sha256.as_str(),
        identity.components.vault_manifest_sha256.as_str(),
        identity.components.encrypted_vault_bundle_sha256.as_str(),
        identity
            .components
            .approved_workspace_manifest_sha256
            .as_str(),
        identity
            .components
            .approved_workspace_bundle_sha256
            .as_str(),
        identity.components.work_products_manifest_sha256.as_str(),
        identity.components.work_products_bundle_sha256.as_str(),
    ];
    if identity.schema_version != MIGRATION_BACKUP_IDENTITY_SCHEMA_VERSION
        || identity.migration_id != migration_id
        || identity.source_fingerprint != source_fingerprint
        || identity.workspace_instance_id != workflow.workspace_instance_id().as_str()
        || identity.user_schema_version != database::USER_SCHEMA_VERSION
        || identity.created_at_unix == 0
        || identity.created_at_unix >= identity.expires_at_unix
        || !(1..=PRIVACY_STORE_SCHEMA_VERSION)
            .contains(&identity.components.privacy_store_schema_version)
        || !(1..=privacy::vault_store::VAULT_STORE_SCHEMA_VERSION)
            .contains(&identity.components.vault_store_schema_version)
        || !identity.backup_id.starts_with("appbkp_")
        || !identity.privacy_backup_id.starts_with("bkp_")
        || identity.backup_file_name.is_empty()
        || identity.backup_file_name.len() > 240
        || !identity.backup_file_name.is_ascii()
        || identity.backup_file_name.contains(['/', '\\'])
        || !identity
            .backup_file_name
            .ends_with(&format!(".{FULL_BACKUP_EXTENSION}"))
        || component_hashes.iter().any(|value| !is_hash(value))
    {
        return Err(ipc_error(
            "migration_backup_identity_invalid",
            "The authenticated migration-backup identity manifest is invalid.",
        ));
    }
    Ok(())
}

fn migration_backup_file_name_for_components(
    migration_id: &str,
    source_fingerprint: &str,
    component_fingerprint: &str,
) -> Result<String, IpcError> {
    let canonical = migration_backup_file_name(migration_id, source_fingerprint)?;
    if !is_hash(component_fingerprint) {
        return Err(ipc_error(
            "migration_backup_component_mismatch",
            "The migration component identity is not a canonical SHA-256 value.",
        ));
    }
    let stem = canonical
        .strip_suffix(&format!(".{FULL_BACKUP_EXTENSION}"))
        .ok_or_else(five_component_backup_error)?;
    Ok(format!(
        "{stem}-{}.{FULL_BACKUP_EXTENSION}",
        &component_fingerprint[..24]
    ))
}

fn migration_backup_identity_path(backup: &Path) -> Result<PathBuf, IpcError> {
    let file_name = backup
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            ipc_error(
                "migration_backup_unsafe_path",
                "The migration backup file name is not canonical local text.",
            )
        })?;
    if !file_name.is_ascii() || !file_name.ends_with(&format!(".{FULL_BACKUP_EXTENSION}")) {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "The migration backup file name is not canonical.",
        ));
    }
    Ok(backup.with_file_name(format!("{file_name}{MIGRATION_BACKUP_IDENTITY_SUFFIX}")))
}

fn migration_component_fingerprint(identity: &CurrentMigrationComponentIdentity) -> String {
    let mut digest = Sha256::new();
    digest.update(b"migration-five-component-identity-v1\0");
    for value in [
        identity.user_database_sha256.as_str(),
        &identity.privacy_store_schema_version.to_string(),
        identity.privacy_store_manifest_sha256.as_str(),
        &identity.vault_store_schema_version.to_string(),
        identity.vault_content_manifest_sha256.as_str(),
        identity.vault_manifest_sha256.as_str(),
        identity.approved_workspace_manifest_sha256.as_str(),
        identity.work_products_manifest_sha256.as_str(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn identity_matches_current(
    stored: &MigrationComponentIdentityV1,
    current: &CurrentMigrationComponentIdentity,
) -> bool {
    stored.user_database_sha256 == current.user_database_sha256
        && stored.privacy_store_schema_version == current.privacy_store_schema_version
        && stored.privacy_store_manifest_sha256 == current.privacy_store_manifest_sha256
        && stored.vault_store_schema_version == current.vault_store_schema_version
        && stored.vault_content_manifest_sha256 == current.vault_content_manifest_sha256
        && stored.vault_manifest_sha256 == current.vault_manifest_sha256
        && stored.approved_workspace_manifest_sha256 == current.approved_workspace_manifest_sha256
        && stored.work_products_manifest_sha256 == current.work_products_manifest_sha256
}

fn identity_is_recovery_compatible(
    stored: &MigrationComponentIdentityV1,
    current: &CurrentMigrationComponentIdentity,
) -> bool {
    let privacy_is_exact = stored.privacy_store_schema_version
        == current.privacy_store_schema_version
        && stored.privacy_store_manifest_sha256 == current.privacy_store_manifest_sha256;
    let privacy_is_owned_upgrade = (1..PRIVACY_STORE_SCHEMA_VERSION)
        .contains(&stored.privacy_store_schema_version)
        && current.privacy_store_schema_version == PRIVACY_STORE_SCHEMA_VERSION;
    let vault_is_exact = stored.vault_store_schema_version == current.vault_store_schema_version
        && stored.vault_manifest_sha256 == current.vault_manifest_sha256
        && stored.vault_content_manifest_sha256 == current.vault_content_manifest_sha256;
    let vault_is_owned_upgrade = stored.vault_store_schema_version == 1
        && current.vault_store_schema_version == privacy::vault_store::VAULT_STORE_SCHEMA_VERSION
        && stored.vault_content_manifest_sha256 == current.vault_content_manifest_sha256;
    stored.user_database_sha256 == current.user_database_sha256
        && stored.approved_workspace_manifest_sha256 == current.approved_workspace_manifest_sha256
        && stored.work_products_manifest_sha256 == current.work_products_manifest_sha256
        && (privacy_is_exact || privacy_is_owned_upgrade)
        && (vault_is_exact || vault_is_owned_upgrade)
}

fn stage_migration_backup_pair(
    backup_staging: &Path,
    identity_staging: &Path,
    bytes: &[u8],
    identity: &MigrationBackupIdentityV1,
    workflow: &PrivacyWorkflowManager,
    expected_metadata: &ApplicationBackupMetadata,
) -> Result<(), IpcError> {
    validate_new_local_file(backup_staging)?;
    validate_new_migration_identity_file(identity_staging)?;
    write_new_file(backup_staging, bytes)?;
    let staged_metadata = verify_migration_application_backup(
        backup_staging,
        workflow,
        Some(&identity.backup_bundle_sha256),
    )?;
    if staged_metadata != *expected_metadata {
        return Err(five_component_backup_error());
    }
    let plaintext =
        privacy::vnext::canonical_json_v1(identity).map_err(|_| five_component_backup_error())?;
    let protected = protect_local(&plaintext).map_err(|_| {
        ipc_error(
            "migration_backup_identity_protection_failed",
            "The migration-backup identity manifest could not be protected for this Windows user.",
        )
    })?;
    if protected.is_empty() || protected.len() > MAX_MIGRATION_BACKUP_IDENTITY_BYTES {
        return Err(five_component_backup_error());
    }
    write_new_file(identity_staging, &protected)?;
    let staged_identity = read_migration_backup_identity(identity_staging)?;
    if staged_identity != *identity {
        return Err(ipc_error(
            "migration_backup_identity_tampered",
            "The staged migration-backup identity changed before install.",
        ));
    }
    Ok(())
}

fn validate_new_migration_identity_file(path: &Path) -> Result<(), IpcError> {
    let file_name = path.file_name().and_then(|value| value.to_str());
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || path.parent().is_none_or(|parent| !parent.is_dir())
        || path.exists()
        || file_name.is_none_or(|name| {
            !name.is_ascii()
                || !(name.ends_with(MIGRATION_BACKUP_IDENTITY_SUFFIX)
                    || name.ends_with(".staged.identity.dpapi"))
        })
    {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "The migration-backup identity destination is not a new controlled local file.",
        ));
    }
    Ok(())
}

fn read_migration_backup_identity(path: &Path) -> Result<MigrationBackupIdentityV1, IpcError> {
    if !ordinary_single_link_file(path) {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "The migration-backup identity is not an ordinary single-link fixed-local file.",
        ));
    }
    let protected = SensitiveBytes(read_local_file(path, MAX_MIGRATION_BACKUP_IDENTITY_BYTES)?);
    let plaintext = SensitiveBytes(unprotect_local(protected.as_slice()).map_err(|_| {
        ipc_error(
            "migration_backup_identity_tampered",
            "The migration-backup identity could not be authenticated for this Windows user.",
        )
    })?);
    let identity: MigrationBackupIdentityV1 =
        privacy::vnext::strict_json_v1_from_slice(plaintext.as_slice()).map_err(|_| {
            ipc_error(
                "migration_backup_identity_tampered",
                "The authenticated migration-backup identity has an invalid schema.",
            )
        })?;
    let canonical =
        privacy::vnext::canonical_json_v1(&identity).map_err(|_| five_component_backup_error())?;
    if canonical != plaintext.as_slice() {
        return Err(ipc_error(
            "migration_backup_identity_tampered",
            "The authenticated migration-backup identity is not canonically encoded.",
        ));
    }
    Ok(identity)
}

fn verify_migration_backup_pair(
    backup_path: &Path,
    identity_path: &Path,
    workflow: &PrivacyWorkflowManager,
    expected_bundle_sha256: Option<&str>,
    expected: Option<(&MigrationBackupIdentityV1, &ApplicationBackupMetadata)>,
) -> Result<VerifiedMigrationBackupCandidate, IpcError> {
    if !ordinary_single_link_file(backup_path) || !ordinary_single_link_file(identity_path) {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "The migration backup pair is not ordinary single-link fixed-local files.",
        ));
    }
    let identity = read_migration_backup_identity(identity_path)?;
    let bytes = SensitiveBytes(read_local_file(backup_path, MAX_APPLICATION_BACKUP_BYTES)?);
    if expected_bundle_sha256
        .is_some_and(|expected_hash| sha256_hex(bytes.as_slice()) != expected_hash)
        || sha256_hex(bytes.as_slice()) != identity.backup_bundle_sha256
    {
        return Err(ipc_error(
            "migration_backup_tampered",
            "The migration backup no longer matches its authenticated identity.",
        ));
    }
    let opened = open_application_backup_for_migration_recovery(
        bytes.as_slice(),
        &MigrationApplicationBackupOpenContext {
            expected_workspace_instance_id: &workflow.workspace_instance_id(),
            expected_user_schema_version: identity.user_schema_version,
            expected_backup_id: &identity.backup_id,
            expected_privacy_backup_id: &identity.privacy_backup_id,
            expected_app_version: &identity.app_version,
            expected_created_at_unix: identity.created_at_unix,
            expected_expires_at_unix: identity.expires_at_unix,
            expected_bundle_sha256: &identity.backup_bundle_sha256,
        },
    )
    .map_err(application_backup_error)?;
    let metadata = validate_opened_five_component_backup(bytes.as_slice(), opened)?;
    let maximum_privacy_bundle_bytes = privacy::lifecycle::max_portable_backup_bytes_for_schema(
        identity.components.privacy_store_schema_version,
    )
    .and_then(|maximum| u64::try_from(maximum).ok())
    .ok_or_else(five_component_backup_error)?;
    if metadata.encrypted_privacy_bundle_bytes > maximum_privacy_bundle_bytes
        || metadata.user_database_sha256 != identity.components.user_database_sha256
        || metadata.encrypted_privacy_bundle_sha256
            != identity.components.encrypted_privacy_bundle_sha256
        || metadata.vault_manifest_sha256 != identity.components.vault_manifest_sha256
        || metadata.encrypted_vault_bundle_sha256
            != identity.components.encrypted_vault_bundle_sha256
        || metadata.approved_workspace_manifest_sha256.as_deref()
            != Some(
                identity
                    .components
                    .approved_workspace_manifest_sha256
                    .as_str(),
            )
        || metadata.approved_workspace_bundle_sha256.as_deref()
            != Some(
                identity
                    .components
                    .approved_workspace_bundle_sha256
                    .as_str(),
            )
        || metadata.work_products_manifest_sha256.as_deref()
            != Some(identity.components.work_products_manifest_sha256.as_str())
        || metadata.work_products_bundle_sha256.as_deref()
            != Some(identity.components.work_products_bundle_sha256.as_str())
    {
        return Err(five_component_backup_error());
    }
    if let Some((expected_identity, expected_metadata)) = expected {
        if identity != *expected_identity || metadata != *expected_metadata {
            return Err(five_component_backup_error());
        }
    }
    Ok(VerifiedMigrationBackupCandidate {
        path: backup_path.to_path_buf(),
        identity,
        metadata,
    })
}

fn load_migration_backup_candidates(
    directory: &Path,
    workflow: &PrivacyWorkflowManager,
    migration_id: &str,
    source_fingerprint: &str,
) -> Result<Vec<VerifiedMigrationBackupCandidate>, IpcError> {
    let canonical = migration_backup_file_name(migration_id, source_fingerprint)?;
    let prefix = canonical
        .strip_suffix(&format!(".{FULL_BACKUP_EXTENSION}"))
        .ok_or_else(five_component_backup_error)?;
    let mut identity_paths = Vec::new();
    let mut backup_paths = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| {
        ipc_error(
            "migration_backup_io",
            "The migration backup directory could not be enumerated.",
        )
    })? {
        let entry = entry.map_err(|_| {
            ipc_error(
                "migration_backup_io",
                "A migration backup directory entry could not be inspected.",
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(prefix) || name.starts_with('.') {
            continue;
        }
        if name.ends_with(&format!(
            ".{FULL_BACKUP_EXTENSION}{MIGRATION_BACKUP_IDENTITY_SUFFIX}"
        )) {
            identity_paths.push(entry.path());
        } else if name.ends_with(&format!(".{FULL_BACKUP_EXTENSION}")) {
            backup_paths.push(entry.path());
        }
    }
    if identity_paths.len() > MAX_MIGRATION_BACKUP_CANDIDATES
        || backup_paths.len() > MAX_MIGRATION_BACKUP_CANDIDATES
    {
        return Err(ipc_error(
            "migration_backup_candidate_limit",
            "Too many fixed migration backup candidates require manual inspection.",
        ));
    }
    identity_paths.sort();
    backup_paths.sort();
    let mut candidates = Vec::with_capacity(identity_paths.len());
    for identity_path in identity_paths {
        let identity = read_migration_backup_identity(&identity_path)?;
        validate_migration_backup_identity(&identity, workflow, migration_id, source_fingerprint)?;
        let backup_path = directory.join(&identity.backup_file_name);
        if migration_backup_identity_path(&backup_path)? != identity_path {
            return Err(ipc_error(
                "migration_backup_identity_invalid",
                "The migration-backup identity does not name its exact sibling bundle.",
            ));
        }
        if !path_is_present(&backup_path)? {
            recover_incomplete_migration_backup_install(
                directory,
                migration_id,
                source_fingerprint,
                &identity,
                &backup_path,
            )?;
        }
        candidates.push(verify_migration_backup_pair(
            &backup_path,
            &identity_path,
            workflow,
            None,
            None,
        )?);
    }
    for backup_path in backup_paths {
        if !path_is_present(&migration_backup_identity_path(&backup_path)?)? {
            return Err(ipc_error(
                "migration_backup_identity_missing",
                "A fixed migration backup has no authenticated component identity; it was preserved and not overwritten.",
            ));
        }
    }
    Ok(candidates)
}

fn recover_incomplete_migration_backup_install(
    directory: &Path,
    migration_id: &str,
    source_fingerprint: &str,
    identity: &MigrationBackupIdentityV1,
    destination: &Path,
) -> Result<(), IpcError> {
    let staging_prefix = format!(".{migration_id}-{source_fingerprint}-");
    let staging_suffix = format!(".staged.{FULL_BACKUP_EXTENSION}");
    let mut matching = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| {
        ipc_error(
            "migration_backup_io",
            "Incomplete migration backup staging could not be enumerated.",
        )
    })? {
        let entry = entry.map_err(|_| {
            ipc_error(
                "migration_backup_io",
                "An incomplete migration backup staging entry could not be inspected.",
            )
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.starts_with(&staging_prefix) && name.ends_with(&staging_suffix) {
            let path = entry.path();
            if !ordinary_single_link_file(&path) {
                return Err(ipc_error(
                    "migration_backup_unsafe_path",
                    "An incomplete migration backup staging file is unsafe.",
                ));
            }
            let bytes = SensitiveBytes(read_local_file(&path, MAX_APPLICATION_BACKUP_BYTES)?);
            if sha256_hex(bytes.as_slice()) == identity.backup_bundle_sha256 {
                matching.push(path);
            }
        }
    }
    if matching.len() != 1 {
        return Err(ipc_error(
            "migration_backup_install_incomplete",
            "The authenticated migration backup identity was preserved, but its exact staged bundle could not be recovered automatically.",
        ));
    }
    atomic_install_new_migration_backup(&matching[0], destination)
}

fn capture_current_migration_components(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<CurrentMigrationComponentIdentity, IpcError> {
    let guard = workflow.begin_application_backup_pair();
    let (user_connection, mut user_file) =
        open_coherent_user_snapshot(app_local_data_dir, state.user_database_path())?;
    let result = (|| {
        let approved = approved_workspace
            .snapshot_for_application_backup()
            .map_err(approved_mcp_error)?;
        let (privacy_store_schema_version, privacy_store_manifest_sha256) =
            privacy_store_identity(app_local_data_dir, workflow)?;
        let (vault_bundle, vault_summary) = workflow
            .export_encrypted_vault_backup_locked(&guard)
            .map_err(vault_backup_error)?;
        drop(vault_bundle);
        let (vault_store_schema_version, vault_content_manifest_sha256) =
            vault_content_identity(app_local_data_dir, workflow)?;
        let user_database = snapshot_user_database(
            app_local_data_dir,
            state.user_database_path(),
            &mut user_file,
        )?;
        Ok(CurrentMigrationComponentIdentity {
            user_database_sha256: sha256_hex(user_database.as_slice()),
            privacy_store_schema_version,
            privacy_store_manifest_sha256,
            vault_store_schema_version,
            vault_content_manifest_sha256,
            vault_manifest_sha256: vault_summary.manifest_sha256.as_str().to_owned(),
            approved_workspace_manifest_sha256: approved.approved_workspace_manifest_sha256,
            work_products_manifest_sha256: approved.work_products_manifest_sha256,
        })
    })();
    let rollback = rollback_user_snapshot(&user_connection);
    drop(user_connection);
    drop(user_file);
    drop(guard);
    rollback?;
    result
}

fn privacy_store_identity(
    app_local_data_dir: &Path,
    workflow: &PrivacyWorkflowManager,
) -> Result<(i64, String), IpcError> {
    let path = app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE);
    let connection = open_read_only_identity_database(&path)?;
    connection.execute_batch("BEGIN DEFERRED").map_err(|_| {
        ipc_error(
            "migration_backup_component_invalid",
            "The Privacy store identity snapshot could not begin.",
        )
    })?;
    let result = (|| {
        validate_identity_database(&connection)?;
        let schema_version = match PrivacyStore::preflight_schema(&connection)
            .map_err(|_| five_component_backup_error())?
        {
            PrivacyStoreSchemaStatus::Current => PRIVACY_STORE_SCHEMA_VERSION,
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version } => found_version,
            PrivacyStoreSchemaStatus::Empty => return Err(five_component_backup_error()),
        };
        validate_privacy_database_page_bound(&connection, schema_version)?;
        let workspace: String = connection
            .query_row(
                "SELECT workspace_instance_id FROM privacy_lifecycle_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| five_component_backup_error())?;
        if workspace != workflow.workspace_instance_id().as_str() {
            return Err(five_component_backup_error());
        }
        let excluded = BTreeSet::from(["privacy_backup_registry"]);
        let manifest = logical_database_manifest(&connection, &excluded)?;
        Ok((schema_version, manifest))
    })();
    let rollback = connection.execute_batch("ROLLBACK").map_err(|_| {
        ipc_error(
            "migration_backup_component_invalid",
            "The Privacy store identity snapshot could not be closed.",
        )
    });
    rollback?;
    result
}

fn validate_privacy_database_page_bound(
    connection: &Connection,
    schema_version: i64,
) -> Result<(), IpcError> {
    let page_count = connection
        .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(five_component_backup_error)?;
    let page_size = connection
        .pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))
        .ok()
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(five_component_backup_error)?;
    validate_privacy_database_page_values(schema_version, page_count, page_size)
}

fn validate_privacy_database_page_values(
    schema_version: i64,
    page_count: u64,
    page_size: u64,
) -> Result<(), IpcError> {
    let maximum = privacy_database_backup_maximum(schema_version)?;
    let database_bytes = page_count
        .checked_mul(page_size)
        .ok_or_else(five_component_backup_error)?;
    if database_bytes == 0
        || database_bytes > u64::try_from(maximum).map_err(|_| five_component_backup_error())?
    {
        return Err(ipc_error(
            "migration_backup_privacy_source_too_large",
            "The Privacy migration source exceeds its schema-specific raw database limit.",
        ));
    }
    Ok(())
}

fn vault_content_identity(
    app_local_data_dir: &Path,
    workflow: &PrivacyWorkflowManager,
) -> Result<(u32, String), IpcError> {
    let root = app_local_data_dir.join(VAULT_DIRECTORY_NAME);
    let database_path = root.join("vault-state.sqlite");
    let connection = open_read_only_identity_database(&database_path)?;
    connection.execute_batch("BEGIN DEFERRED").map_err(|_| {
        ipc_error(
            "migration_backup_component_invalid",
            "The Vault identity snapshot could not begin.",
        )
    })?;
    let result = (|| {
        validate_identity_database(&connection)?;
        let (schema_version, workspace): (u32, String) = connection
            .query_row(
                "SELECT schema_version,workspace_instance_id FROM vault_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| five_component_backup_error())?;
        if !matches!(
            schema_version,
            1 | privacy::vault_store::VAULT_STORE_SCHEMA_VERSION
        ) || workspace != workflow.workspace_instance_id().as_str()
        {
            return Err(five_component_backup_error());
        }
        let mut digest = Sha256::new();
        digest.update(b"vault-content-manifest-v1\0");
        for table in ["object_journal", "nonce_reservations"] {
            digest.update(table.as_bytes());
            digest.update(table_rows_manifest(&connection, table)?.as_bytes());
        }
        for (relative, hash) in vault_non_database_file_manifest(&root)? {
            digest.update((relative.len() as u64).to_be_bytes());
            digest.update(relative.as_bytes());
            digest.update(hash.as_bytes());
        }
        Ok((schema_version, format!("{:x}", digest.finalize())))
    })();
    let rollback = connection.execute_batch("ROLLBACK").map_err(|_| {
        ipc_error(
            "migration_backup_component_invalid",
            "The Vault identity snapshot could not be closed.",
        )
    });
    rollback?;
    result
}

fn open_read_only_identity_database(path: &Path) -> Result<Connection, IpcError> {
    if !ordinary_single_link_file(path) {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "A migration backup component database is not an ordinary single-link local file.",
        ));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| five_component_backup_error())?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| five_component_backup_error())?;
    connection
        .execute_batch(
            "PRAGMA query_only=ON;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| five_component_backup_error())?;
    Ok(connection)
}

fn validate_identity_database(connection: &Connection) -> Result<(), IpcError> {
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| five_component_backup_error())?;
    if integrity != "ok" {
        return Err(five_component_backup_error());
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| five_component_backup_error())?;
    let mut rows = foreign_keys
        .query([])
        .map_err(|_| five_component_backup_error())?;
    let has_foreign_key_error = rows
        .next()
        .map_err(|_| five_component_backup_error())?
        .is_some();
    if has_foreign_key_error {
        return Err(five_component_backup_error());
    }
    Ok(())
}

fn logical_database_manifest(
    connection: &Connection,
    excluded_data_tables: &BTreeSet<&str>,
) -> Result<String, IpcError> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,COALESCE(sql,'')
             FROM sqlite_master
             WHERE name NOT LIKE 'sqlite_%'
             ORDER BY type,name",
        )
        .map_err(|_| five_component_backup_error())?;
    let objects = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| five_component_backup_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| five_component_backup_error())?;
    drop(statement);
    let mut digest = Sha256::new();
    digest.update(b"sqlite-logical-manifest-v1\0");
    for (object_type, name, sql) in objects {
        for value in [&object_type, &name, &sql] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        if object_type == "table" && !excluded_data_tables.contains(name.as_str()) {
            digest.update(table_rows_manifest(connection, &name)?.as_bytes());
        }
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn table_rows_manifest(connection: &Connection, table: &str) -> Result<String, IpcError> {
    let quoted = table.replace('"', "\"\"");
    let mut statement = connection
        .prepare(&format!("SELECT * FROM \"{quoted}\""))
        .map_err(|_| five_component_backup_error())?;
    let column_count = statement.column_count();
    let mut rows = statement
        .query([])
        .map_err(|_| five_component_backup_error())?;
    let mut row_hashes = Vec::new();
    while let Some(row) = rows.next().map_err(|_| five_component_backup_error())? {
        let mut digest = Sha256::new();
        digest.update(b"sqlite-row-v1\0");
        for index in 0..column_count {
            match row
                .get_ref(index)
                .map_err(|_| five_component_backup_error())?
            {
                ValueRef::Null => digest.update([0]),
                ValueRef::Integer(value) => {
                    digest.update([1]);
                    digest.update(value.to_be_bytes());
                }
                ValueRef::Real(value) => {
                    digest.update([2]);
                    digest.update(value.to_bits().to_be_bytes());
                }
                ValueRef::Text(value) => {
                    digest.update([3]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value);
                }
                ValueRef::Blob(value) => {
                    digest.update([4]);
                    digest.update((value.len() as u64).to_be_bytes());
                    digest.update(value);
                }
            }
        }
        row_hashes.push(digest.finalize().to_vec());
    }
    row_hashes.sort();
    let mut digest = Sha256::new();
    digest.update(b"sqlite-table-rows-v1\0");
    digest.update((row_hashes.len() as u64).to_be_bytes());
    for hash in row_hashes {
        digest.update(hash);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn vault_non_database_file_manifest(root: &Path) -> Result<Vec<(String, String)>, IpcError> {
    fn visit(
        root: &Path,
        current: &Path,
        output: &mut Vec<(String, String)>,
    ) -> Result<(), IpcError> {
        let metadata = fs::symlink_metadata(current).map_err(|_| five_component_backup_error())?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !privacy_manager::local_path_chain_is_ordinary(current)
        {
            return Err(ipc_error(
                "migration_backup_unsafe_path",
                "The Vault component identity encountered an unsafe path.",
            ));
        }
        if metadata.is_dir() {
            let mut entries = fs::read_dir(current)
                .map_err(|_| five_component_backup_error())?
                .map(|entry| entry.map(|value| value.path()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| five_component_backup_error())?;
            entries.sort();
            for path in entries {
                visit(root, &path, output)?;
            }
            return Ok(());
        }
        if !metadata.is_file() || !ordinary_single_link_file(current) {
            return Err(five_component_backup_error());
        }
        let relative = current
            .strip_prefix(root)
            .map_err(|_| five_component_backup_error())?
            .to_string_lossy()
            .replace('\\', "/");
        if matches!(
            relative.as_str(),
            "vault-state.sqlite"
                | "vault-state.sqlite-wal"
                | "vault-state.sqlite-shm"
                | "vault-state.sqlite-journal"
        ) {
            return Ok(());
        }
        output.push((relative, stream_sha256(current)?));
        Ok(())
    }
    let mut output = Vec::new();
    visit(root, root, &mut output)?;
    output.sort();
    Ok(output)
}

fn stream_sha256(path: &Path) -> Result<String, IpcError> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| five_component_backup_error())?;
    if !ordinary_single_link_handle(&file) {
        return Err(five_component_backup_error());
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| five_component_backup_error())?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    if !ordinary_single_link_handle(&file) {
        return Err(five_component_backup_error());
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_current_migration_source_fingerprint(
    workflow: &PrivacyWorkflowManager,
    migration_id: &str,
    expected: &str,
) -> Result<(), IpcError> {
    let current = match migration_id {
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID | PROJECT_PRIVACY_CASE_BINDING_MIGRATION_ID => {
            workflow
                .case_material_migration_source_fingerprint()
                .map_err(workflow_error)?
        }
        APPROVED_CASE_PROJECTION_MIGRATION_ID => workflow
            .approved_projection_migration_source_fingerprint()
            .map_err(workflow_error)?,
        _ => {
            return Err(ipc_error(
                "migration_backup_invalid_id",
                "The migration backup identifier is not in the fixed application allowlist.",
            ))
        }
    };
    if current != expected {
        return Err(ipc_error(
            "migration_backup_source_changed",
            "The user-database migration source changed outside the source-bound backup window.",
        ));
    }
    Ok(())
}

fn migration_backup_file_name(
    migration_id: &str,
    source_fingerprint: &str,
) -> Result<String, IpcError> {
    if !is_hash(source_fingerprint) {
        return Err(ipc_error(
            "migration_backup_invalid_source_fingerprint",
            "The migration backup source fingerprint is not a canonical SHA-256 value.",
        ));
    }
    let stem = match migration_id {
        CASE_MATERIAL_UNIFICATION_MIGRATION_ID => "case-material-unification-v1",
        PROJECT_PRIVACY_CASE_BINDING_MIGRATION_ID => "project-privacy-case-binding-v1",
        APPROVED_CASE_PROJECTION_MIGRATION_ID => "approved-case-projection-v1",
        _ => {
            return Err(ipc_error(
                "migration_backup_invalid_id",
                "The migration backup identifier is not in the fixed application allowlist.",
            ))
        }
    };
    Ok(format!(
        "{stem}-{source_fingerprint}.{FULL_BACKUP_EXTENSION}"
    ))
}

fn ensure_migration_backup_directory(app_local_data_dir: &Path) -> Result<PathBuf, IpcError> {
    validate_migration_backup_directory(app_local_data_dir)?;
    let directory = app_local_data_dir.join(MIGRATION_BACKUP_DIRECTORY_NAME);
    if directory.parent() != Some(app_local_data_dir) {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "The migration backup directory escaped App LocalData.",
        ));
    }
    match fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(ipc_error(
                "migration_backup_io",
                "The controlled migration backup directory could not be created.",
            ));
        }
    }
    validate_migration_backup_directory(&directory)?;
    Ok(directory)
}

fn validate_migration_backup_directory(path: &Path) -> Result<(), IpcError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ipc_error(
            "migration_backup_unsafe_path",
            "The migration backup directory could not be inspected.",
        )
    })?;
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || privacy_manager::has_cloud_recall_attributes(&metadata)
    {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "The migration backup directory is not an ordinary fixed-local directory.",
        ));
    }
    Ok(())
}

fn path_is_present(path: &Path) -> Result<bool, IpcError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ipc_error(
            "migration_backup_io",
            "A fixed migration backup path could not be inspected.",
        )),
    }
}

fn atomic_install_new_migration_backup(staging: &Path, destination: &Path) -> Result<(), IpcError> {
    atomic_install_new_migration_file(staging, destination)
}

fn atomic_install_new_migration_file(staging: &Path, destination: &Path) -> Result<(), IpcError> {
    let parent = destination.parent().ok_or_else(|| {
        ipc_error(
            "migration_backup_unsafe_path",
            "The fixed migration backup destination has no controlled parent.",
        )
    })?;
    if staging.parent() != Some(parent)
        || !ordinary_single_link_file(staging)
        || path_is_present(destination)?
    {
        return Err(ipc_error(
            "migration_backup_install_conflict",
            "The fixed migration backup could not be atomically installed without replacement.",
        ));
    }
    fs::rename(staging, destination).map_err(|_| {
        ipc_error(
            "migration_backup_install_failed",
            "The staged migration backup could not be atomically installed.",
        )
    })
}

fn verify_migration_application_backup(
    path: &Path,
    workflow: &PrivacyWorkflowManager,
    expected_bundle_sha256: Option<&str>,
) -> Result<ApplicationBackupMetadata, IpcError> {
    if !ordinary_single_link_file(path) {
        return Err(ipc_error(
            "migration_backup_unsafe_path",
            "The migration backup is not an ordinary single-link fixed-local file.",
        ));
    }
    let bytes = SensitiveBytes(read_local_file(path, MAX_APPLICATION_BACKUP_BYTES)?);
    if expected_bundle_sha256.is_some_and(|expected| sha256_hex(bytes.as_slice()) != expected) {
        return Err(ipc_error(
            "migration_backup_tampered",
            "The installed migration backup hash does not match the staged backup.",
        ));
    }
    let opened = open_current_application_backup(bytes.as_slice(), workflow)?;
    validate_opened_five_component_backup(bytes.as_slice(), opened)
}

fn validate_five_component_application_backup(
    bytes: &[u8],
    workflow: &PrivacyWorkflowManager,
    expected_metadata: &ApplicationBackupMetadata,
) -> Result<(), IpcError> {
    let opened = open_current_application_backup(bytes, workflow)?;
    let metadata = validate_opened_five_component_backup(bytes, opened)?;
    if metadata != *expected_metadata {
        return Err(ipc_error(
            "migration_backup_component_mismatch",
            "The newly built migration backup metadata is inconsistent.",
        ));
    }
    Ok(())
}

fn validate_opened_five_component_backup(
    bytes: &[u8],
    mut opened: privacy::OpenedApplicationBackup,
) -> Result<ApplicationBackupMetadata, IpcError> {
    let validation = (|| {
        let metadata = &opened.metadata;
        let approved = opened
            .approved_workspace_bundle
            .as_ref()
            .ok_or_else(five_component_backup_error)?;
        let work_products = opened
            .work_products_bundle
            .as_ref()
            .ok_or_else(five_component_backup_error)?;
        let approved_bytes = metadata
            .approved_workspace_bundle_bytes
            .ok_or_else(five_component_backup_error)?;
        let approved_sha256 = metadata
            .approved_workspace_bundle_sha256
            .as_deref()
            .ok_or_else(five_component_backup_error)?;
        let approved_chunks = metadata
            .approved_workspace_bundle_chunk_count
            .ok_or_else(five_component_backup_error)?;
        let work_products_bytes = metadata
            .work_products_bundle_bytes
            .ok_or_else(five_component_backup_error)?;
        let work_products_sha256 = metadata
            .work_products_bundle_sha256
            .as_deref()
            .ok_or_else(five_component_backup_error)?;
        let work_products_chunks = metadata
            .work_products_bundle_chunk_count
            .ok_or_else(five_component_backup_error)?;
        let expected_chunks = metadata
            .user_database_chunk_count
            .checked_add(metadata.privacy_bundle_chunk_count)
            .and_then(|count| count.checked_add(metadata.vault_bundle_chunk_count))
            .and_then(|count| count.checked_add(approved_chunks))
            .and_then(|count| count.checked_add(work_products_chunks))
            .ok_or_else(five_component_backup_error)?;
        if metadata.bundle_sha256 != sha256_hex(bytes)
            || metadata.chunk_count != expected_chunks
            || [
                metadata.user_database_chunk_count,
                metadata.privacy_bundle_chunk_count,
                metadata.vault_bundle_chunk_count,
                approved_chunks,
                work_products_chunks,
            ]
            .contains(&0)
            || !component_matches(
                &opened.user_database,
                metadata.user_database_bytes,
                &metadata.user_database_sha256,
            )
            || !component_matches(
                &opened.encrypted_privacy_bundle,
                metadata.encrypted_privacy_bundle_bytes,
                &metadata.encrypted_privacy_bundle_sha256,
            )
            || !component_matches(
                &opened.encrypted_vault_bundle,
                metadata.encrypted_vault_bundle_bytes,
                &metadata.encrypted_vault_bundle_sha256,
            )
            || !component_matches(approved, approved_bytes, approved_sha256)
            || !component_matches(work_products, work_products_bytes, work_products_sha256)
        {
            return Err(five_component_backup_error());
        }
        Ok(metadata.clone())
    })();
    opened.user_database.fill(0);
    opened.encrypted_privacy_bundle.fill(0);
    opened.encrypted_vault_bundle.fill(0);
    if let Some(bytes) = opened.approved_workspace_bundle.as_mut() {
        bytes.fill(0);
    }
    if let Some(bytes) = opened.work_products_bundle.as_mut() {
        bytes.fill(0);
    }
    validation
}

fn component_matches(bytes: &[u8], expected_bytes: u64, expected_sha256: &str) -> bool {
    u64::try_from(bytes.len()).ok() == Some(expected_bytes) && sha256_hex(bytes) == expected_sha256
}

fn five_component_backup_error() -> IpcError {
    ipc_error(
        "migration_backup_component_mismatch",
        "The migration gate requires one authenticated five-component V3 application backup.",
    )
}

fn abort_built_migration_backup(
    workflow: &PrivacyWorkflowManager,
    privacy_backup_id: &str,
    staging: Option<&Path>,
    destination: Option<&Path>,
    original: IpcError,
) -> IpcError {
    let mut result = original;
    if let Some(staging) = staging {
        if let Err(error) = remove_migration_backup_file_if_exists(staging) {
            result = error;
        }
    }
    if let Some(destination) = destination {
        if let Err(error) = remove_migration_backup_file_if_exists(destination) {
            result = error;
        }
    }
    if let Err(error) = workflow.revoke_privacy_backup(privacy_backup_id) {
        result = workflow_error(error);
    }
    result
}

fn remove_migration_backup_file_if_exists(path: &Path) -> Result<(), IpcError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(ipc_error(
                "migration_backup_cleanup_failed",
                "A migration backup transaction file could not be inspected for cleanup.",
            ));
        }
    };
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_file()
        || !ordinary_single_link_file(path)
    {
        return Err(ipc_error(
            "migration_backup_unsafe_cleanup",
            "Cleanup refused a migration backup path that is not an ordinary single-link file.",
        ));
    }
    fs::remove_file(path).map_err(|_| {
        ipc_error(
            "migration_backup_cleanup_failed",
            "A failed migration backup transaction file could not be removed.",
        )
    })?;
    if path_is_present(path)? {
        return Err(ipc_error(
            "migration_backup_cleanup_failed",
            "A failed migration backup transaction file remains after cleanup.",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn build_application_backup_with_lock_hook<Hook>(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    lock_hook: Hook,
) -> Result<(Vec<u8>, ApplicationBackupMetadata, String), IpcError>
where
    Hook: FnOnce(),
{
    let (bytes, metadata, privacy_backup_id, _) =
        build_application_backup_internal(app_local_data_dir, state, workflow, None, lock_hook)?;
    Ok((bytes, metadata, privacy_backup_id))
}

fn build_application_backup_internal<Hook>(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    lock_hook: Hook,
) -> Result<
    (
        Vec<u8>,
        ApplicationBackupMetadata,
        String,
        Option<BuiltMigrationComponentIdentity>,
    ),
    IpcError,
>
where
    Hook: FnOnce(),
{
    let guard = workflow.begin_application_backup_pair();
    let (user_connection, mut user_file) =
        open_coherent_user_snapshot(app_local_data_dir, state.user_database_path())?;
    lock_hook();

    let approved_snapshot = match approved_workspace {
        Some(workspace) => match workspace.snapshot_for_application_backup() {
            Ok(snapshot) => Some(snapshot),
            Err(error) => {
                return Err(abort_application_backup_pair(
                    &user_connection,
                    workflow,
                    &guard,
                    None,
                    approved_mcp_error(error),
                ));
            }
        },
        None => None,
    };

    let privacy_store_identity = match approved_workspace {
        Some(_) => Some(privacy_store_identity(app_local_data_dir, workflow)?),
        None => None,
    };
    let privacy_backup = match workflow.create_privacy_backup_locked(&guard) {
        Ok(backup) => backup,
        Err(error) => {
            return Err(abort_application_backup_pair(
                &user_connection,
                workflow,
                &guard,
                None,
                workflow_error(error),
            ));
        }
    };
    let privacy_bundle =
        match workflow.export_privacy_backup_bundle_locked(&guard, &privacy_backup.backup_id) {
            Ok(bundle) => bundle,
            Err(error) => {
                return Err(abort_application_backup_pair(
                    &user_connection,
                    workflow,
                    &guard,
                    Some(&privacy_backup.backup_id),
                    workflow_error(error),
                ));
            }
        };
    let (vault_bundle, vault_summary) = match workflow.export_encrypted_vault_backup_locked(&guard)
    {
        Ok(bundle) => bundle,
        Err(error) => {
            return Err(abort_application_backup_pair(
                &user_connection,
                workflow,
                &guard,
                Some(&privacy_backup.backup_id),
                vault_backup_error(error),
            ));
        }
    };
    let vault_content_identity = match approved_workspace {
        Some(_) => match vault_content_identity(app_local_data_dir, workflow) {
            Ok(identity) => Some(identity),
            Err(error) => {
                return Err(abort_application_backup_pair(
                    &user_connection,
                    workflow,
                    &guard,
                    Some(&privacy_backup.backup_id),
                    error,
                ));
            }
        },
        None => None,
    };
    let user_database = match snapshot_user_database(
        app_local_data_dir,
        state.user_database_path(),
        &mut user_file,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(abort_application_backup_pair(
                &user_connection,
                workflow,
                &guard,
                Some(&privacy_backup.backup_id),
                error,
            ));
        }
    };
    if !ordinary_single_link_file(state.user_database_path())
        || !ordinary_single_link_handle(&user_file)
    {
        return Err(abort_application_backup_pair(
            &user_connection,
            workflow,
            &guard,
            Some(&privacy_backup.backup_id),
            ipc_error(
                "application_backup_environment_mismatch",
                "The fixed user database changed identity during the coherent backup window.",
            ),
        ));
    }
    if let Err(rollback_error) = rollback_user_snapshot(&user_connection) {
        if let Err(revoke_error) =
            workflow.revoke_privacy_backup_locked(&guard, &privacy_backup.backup_id)
        {
            return Err(workflow_error(revoke_error));
        }
        return Err(rollback_error);
    }
    drop(user_connection);
    drop(user_file);
    drop(guard);

    let backup_id = format!("appbkp_{}", Uuid::new_v4().simple());
    let workspace_instance_id = workflow.workspace_instance_id();
    let result = match approved_snapshot.as_ref() {
        Some(snapshot) => seal_application_backup_v3(&ApplicationBackupCreateRequestV3 {
            backup_id: &backup_id,
            privacy_backup_id: &privacy_backup.backup_id,
            workspace_instance_id: &workspace_instance_id,
            app_version: env!("CARGO_PKG_VERSION"),
            user_schema_version: database::USER_SCHEMA_VERSION,
            created_at_unix: privacy_backup.created_at_unix,
            expires_at_unix: privacy_backup.expires_at_unix,
            user_database: user_database.as_slice(),
            encrypted_privacy_bundle: &privacy_bundle,
            encrypted_vault_bundle: &vault_bundle,
            vault_manifest_sha256: vault_summary.manifest_sha256.as_str(),
            approved_workspace_bundle: &snapshot.approved_workspace_bundle,
            approved_workspace_manifest_sha256: &snapshot.approved_workspace_manifest_sha256,
            work_products_bundle: &snapshot.work_products_bundle,
            work_products_manifest_sha256: &snapshot.work_products_manifest_sha256,
        }),
        None => seal_application_backup(&ApplicationBackupCreateRequest {
            backup_id: &backup_id,
            privacy_backup_id: &privacy_backup.backup_id,
            workspace_instance_id: &workspace_instance_id,
            app_version: env!("CARGO_PKG_VERSION"),
            user_schema_version: database::USER_SCHEMA_VERSION,
            created_at_unix: privacy_backup.created_at_unix,
            expires_at_unix: privacy_backup.expires_at_unix,
            user_database: user_database.as_slice(),
            encrypted_privacy_bundle: &privacy_bundle,
            encrypted_vault_bundle: &vault_bundle,
            vault_manifest_sha256: vault_summary.manifest_sha256.as_str(),
        }),
    }
    .map_err(application_backup_error);
    match result {
        Ok((bytes, metadata)) => {
            let migration_identity = match (
                approved_snapshot.as_ref(),
                privacy_store_identity,
                vault_content_identity,
            ) {
                (
                    Some(snapshot),
                    Some((privacy_store_schema_version, privacy_store_manifest_sha256)),
                    Some((vault_store_schema_version, vault_content_manifest_sha256)),
                ) => Some(BuiltMigrationComponentIdentity {
                    current: CurrentMigrationComponentIdentity {
                        user_database_sha256: metadata.user_database_sha256.clone(),
                        privacy_store_schema_version,
                        privacy_store_manifest_sha256,
                        vault_store_schema_version,
                        vault_content_manifest_sha256,
                        vault_manifest_sha256: vault_summary.manifest_sha256.as_str().to_owned(),
                        approved_workspace_manifest_sha256: snapshot
                            .approved_workspace_manifest_sha256
                            .clone(),
                        work_products_manifest_sha256: snapshot
                            .work_products_manifest_sha256
                            .clone(),
                    },
                    privacy_database_sha256: privacy_backup.database_sha256.clone(),
                }),
                (None, None, None) => None,
                _ => {
                    if let Err(revoke_error) =
                        workflow.revoke_privacy_backup(&privacy_backup.backup_id)
                    {
                        return Err(workflow_error(revoke_error));
                    }
                    return Err(five_component_backup_error());
                }
            };
            Ok((
                bytes,
                metadata,
                privacy_backup.backup_id,
                migration_identity,
            ))
        }
        Err(error) => {
            if let Err(revoke_error) = workflow.revoke_privacy_backup(&privacy_backup.backup_id) {
                return Err(workflow_error(revoke_error));
            }
            Err(error)
        }
    }
}

fn open_coherent_user_snapshot(
    app_local_data_dir: &Path,
    source_path: &Path,
) -> Result<(Connection, File), IpcError> {
    if source_path != database::user_database_path(app_local_data_dir)
        || !privacy_manager::is_normal_local_absolute(source_path)
        || !privacy_manager::local_path_chain_is_ordinary(source_path)
    {
        return Err(ipc_error(
            "application_backup_environment_mismatch",
            "The user database is not the fixed ordinary local application database.",
        ));
    }
    let source_file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(source_path)
        .map_err(|_| {
            ipc_error(
                "application_backup_invalid",
                "The fixed user database could not be pinned against replacement.",
            )
        })?;
    if !ordinary_single_link_handle(&source_file) {
        return Err(ipc_error(
            "application_backup_environment_mismatch",
            "The fixed user database is not an ordinary single-link local file.",
        ));
    }
    let connection = database::open_user_database_read_only(source_path).map_err(|_| {
        ipc_error(
            "application_backup_invalid",
            "The fixed user database could not be opened with read-only query authority.",
        )
    })?;
    let journal_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(|_| {
            ipc_error(
                "application_backup_invalid",
                "The user database journal mode could not be verified.",
            )
        })?;
    if !journal_mode.eq_ignore_ascii_case("delete") {
        return Err(ipc_error(
            "application_backup_environment_mismatch",
            "Coherent backup requires the canonical DELETE rollback-journal mode.",
        ));
    }
    connection.execute_batch("BEGIN DEFERRED").map_err(|_| {
        ipc_error(
            "application_backup_busy",
            "The user database could not enter the read-only coherent backup window.",
        )
    })?;
    let locked_journal_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(|_| {
            ipc_error(
                "application_backup_invalid",
                "The locked user database journal mode could not be verified.",
            )
        })?;
    if !locked_journal_mode.eq_ignore_ascii_case("delete") {
        let original = ipc_error(
            "application_backup_environment_mismatch",
            "The user database left canonical DELETE journal mode before the coherent read snapshot.",
        );
        return match rollback_user_snapshot(&connection) {
            Ok(()) => Err(original),
            Err(rollback_error) => Err(rollback_error),
        };
    }
    database::validate_open_user_database(&connection).map_err(|_| {
        ipc_error(
            "application_backup_invalid",
            "The read-only user database snapshot failed canonical schema and integrity validation.",
        )
    })?;
    if !ordinary_single_link_handle(&source_file) {
        return Err(ipc_error(
            "application_backup_environment_mismatch",
            "The pinned user database changed identity during validation.",
        ));
    }
    Ok((connection, source_file))
}
fn rollback_user_snapshot(connection: &Connection) -> Result<(), IpcError> {
    connection.execute_batch("ROLLBACK").map_err(|_| {
        ipc_error(
            "application_backup_rollback_failed",
            "The coherent user-database backup transaction could not be rolled back.",
        )
    })
}

fn abort_application_backup_pair(
    user_connection: &Connection,
    workflow: &PrivacyWorkflowManager,
    guard: &ApplicationBackupPrivacyGuard<'_>,
    backup_id: Option<&str>,
    original: IpcError,
) -> IpcError {
    if let Err(error) = rollback_user_snapshot(user_connection) {
        return error;
    }
    if let Some(backup_id) = backup_id {
        if let Err(error) = workflow.revoke_privacy_backup_locked(guard, backup_id) {
            return workflow_error(error);
        }
    }
    original
}

#[cfg(test)]
fn stage_application_restore_bytes(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    bytes: &[u8],
) -> Result<ApplicationBackupMetadata, IpcError> {
    stage_application_restore_bytes_internal(
        app_local_data_dir,
        expected_user_database_path,
        workflow,
        None,
        bytes,
    )
}

fn stage_selected_application_restore_with_approved(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    source: &Path,
    bytes: &[u8],
) -> Result<ApplicationBackupMetadata, IpcError> {
    match open_current_application_backup(bytes, workflow) {
        Ok(_) => stage_application_restore_bytes_with_approved(
            app_local_data_dir,
            expected_user_database_path,
            workflow,
            approved_workspace,
            bytes,
        ),
        Err(normal_error) => {
            let identity_path = migration_backup_identity_path(source)?;
            if !path_is_present(&identity_path)? {
                return Err(normal_error);
            }
            stage_migration_application_restore_with_approved(
                app_local_data_dir,
                expected_user_database_path,
                workflow,
                approved_workspace,
                source,
                &identity_path,
                bytes,
            )
        }
    }
}

fn stage_migration_application_restore_with_approved(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    source: &Path,
    identity_path: &Path,
    bytes: &[u8],
) -> Result<ApplicationBackupMetadata, IpcError> {
    let identity = read_migration_backup_identity(identity_path)?;
    validate_migration_backup_identity(
        &identity,
        workflow,
        &identity.migration_id,
        &identity.source_fingerprint,
    )?;
    verify_current_migration_source_fingerprint(
        workflow,
        &identity.migration_id,
        &identity.source_fingerprint,
    )?;
    let candidate = verify_migration_backup_pair(source, identity_path, workflow, None, None)?;
    let current = capture_current_migration_components(
        app_local_data_dir,
        &AppState::new(
            app_local_data_dir.join("migration-restore-unused-legal.sqlite"),
            expected_user_database_path.to_path_buf(),
        ),
        workflow,
        approved_workspace,
    )?;
    if !identity_matches_current(&candidate.identity.components, &current)
        && !identity_is_recovery_compatible(&candidate.identity.components, &current)
    {
        return Err(ipc_error(
            "migration_backup_component_mismatch",
            "The selected migration rollback point is not bound to the current five-component lineage.",
        ));
    }
    let opened = open_application_backup_for_migration_recovery(
        bytes,
        &MigrationApplicationBackupOpenContext {
            expected_workspace_instance_id: &workflow.workspace_instance_id(),
            expected_user_schema_version: identity.user_schema_version,
            expected_backup_id: &identity.backup_id,
            expected_privacy_backup_id: &identity.privacy_backup_id,
            expected_app_version: &identity.app_version,
            expected_created_at_unix: identity.created_at_unix,
            expected_expires_at_unix: identity.expires_at_unix,
            expected_bundle_sha256: &identity.backup_bundle_sha256,
        },
    )
    .map_err(application_backup_error)?;
    stage_application_restore_opened_with_hook(
        app_local_data_dir,
        expected_user_database_path,
        workflow,
        Some(approved_workspace),
        opened,
        Some(identity.created_at_unix),
        |_| Ok(()),
    )
}

fn stage_application_restore_bytes_with_approved(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    bytes: &[u8],
) -> Result<ApplicationBackupMetadata, IpcError> {
    stage_application_restore_bytes_internal(
        app_local_data_dir,
        expected_user_database_path,
        workflow,
        Some(approved_workspace),
        bytes,
    )
}

fn stage_application_restore_bytes_internal(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    bytes: &[u8],
) -> Result<ApplicationBackupMetadata, IpcError> {
    stage_application_restore_bytes_with_hook(
        app_local_data_dir,
        expected_user_database_path,
        workflow,
        approved_workspace,
        bytes,
        |_| Ok(()),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplicationRestoreStagePoint {
    VaultStaging,
    ApprovedAndWorkProductsStaging,
    BeforeProtectedMarker,
}

fn stage_application_restore_bytes_with_hook<Hook>(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    bytes: &[u8],
    hook: Hook,
) -> Result<ApplicationBackupMetadata, IpcError>
where
    Hook: FnMut(ApplicationRestoreStagePoint) -> Result<(), IpcError>,
{
    let opened = open_current_application_backup(bytes, workflow)?;
    stage_application_restore_opened_with_hook(
        app_local_data_dir,
        expected_user_database_path,
        workflow,
        approved_workspace,
        opened,
        None,
        hook,
    )
}

fn stage_application_restore_opened_with_hook<Hook>(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    opened: privacy::OpenedApplicationBackup,
    migration_recovery_created_at_unix: Option<u64>,
    mut hook: Hook,
) -> Result<ApplicationBackupMetadata, IpcError>
where
    Hook: FnMut(ApplicationRestoreStagePoint) -> Result<(), IpcError>,
{
    let paths = application_restore_paths(app_local_data_dir);
    if paths.user_active != expected_user_database_path {
        return Err(ipc_error(
            "application_restore_environment_mismatch",
            "主案件数据库固定路径与当前进程状态不一致。",
        ));
    }
    ensure_pair_restore_slot_empty(&paths)?;
    let coordinated_pre_migration_restore = match (
        opened.approved_workspace_bundle.as_ref(),
        opened.work_products_bundle.as_ref(),
        opened.metadata.approved_workspace_bundle_sha256.as_ref(),
        opened.metadata.approved_workspace_manifest_sha256.as_ref(),
        opened.metadata.work_products_bundle_sha256.as_ref(),
        opened.metadata.work_products_manifest_sha256.as_ref(),
    ) {
        (Some(_), Some(_), Some(_), Some(_), Some(_), Some(_)) => true,
        (None, None, None, None, None, None) => false,
        _ => {
            return Err(ipc_error(
                "application_backup_component_mismatch",
                "The authenticated application backup has an incomplete workspace component set.",
            ));
        }
    };
    if !coordinated_pre_migration_restore {
        ensure_legacy_three_component_restore_is_lineage_safe(&paths)?;
    }
    let result = (|| {
        write_sensitive_new_file(&paths.user_incoming, &opened.user_database)?;
        validate_user_component(&paths.user_incoming, &opened.metadata.user_database_sha256)?;
        let (privacy, privacy_store_schema_version) = if coordinated_pre_migration_restore {
            let staged = match migration_recovery_created_at_unix {
                Some(created_at_unix) => workflow
                    .stage_pre_migration_application_privacy_component_for_migration_recovery(
                        &opened.metadata.privacy_backup_id,
                        &opened.encrypted_privacy_bundle,
                        created_at_unix,
                    ),
                None => workflow.stage_pre_migration_application_privacy_component(
                    &opened.metadata.privacy_backup_id,
                    &opened.encrypted_privacy_bundle,
                ),
            }
            .map_err(workflow_error)?;
            (staged.verified, Some(staged.privacy_store_schema_version))
        } else {
            (
                workflow
                    .stage_application_privacy_component(
                        &opened.metadata.privacy_backup_id,
                        &opened.encrypted_privacy_bundle,
                    )
                    .map_err(workflow_error)?,
                None,
            )
        };
        if privacy.database_sha256.is_empty()
            || privacy.workspace_instance_id != opened.metadata.workspace_instance_id.as_str()
        {
            return Err(ipc_error(
                "application_backup_component_mismatch",
                "隐私备份组件与完整备份清单不一致。",
            ));
        }
        hook(ApplicationRestoreStagePoint::VaultStaging)?;
        let vault = stage_encrypted_vault_backup(
            &opened.encrypted_vault_bundle,
            &opened.metadata.workspace_instance_id,
            &paths.vault_incoming,
        )
        .map_err(vault_backup_error)?;
        if vault.manifest_sha256.as_str() != opened.metadata.vault_manifest_sha256
            || vault.archive_sha256.as_str() != opened.metadata.encrypted_vault_bundle_sha256
        {
            return Err(ipc_error(
                "application_backup_component_mismatch",
                "The authenticated Vault component does not match the complete-backup manifest.",
            ));
        }
        // These bits are part of the protected marker, not inferred from a
        // later ambiguous `(active, incoming, rollback)` tuple.  In
        // particular, `(present, absent, absent)` can then be distinguished
        // as either a legitimately installed absent-original component or a
        // cleaned present-original component.
        let original_user_present = restore_path_is_present(&paths.user_active)?;
        let original_privacy_present = restore_path_is_present(&paths.privacy_active)?;
        let original_vault_present = restore_path_is_present(&paths.vault_active)?;
        let original_approved_workspace_present = restore_path_is_present(&paths.approved_active)?;
        let original_work_products_present = restore_path_is_present(&paths.work_products_active)?;
        let marker = match (
            opened.approved_workspace_bundle.as_deref(),
            opened.work_products_bundle.as_deref(),
            opened.metadata.approved_workspace_bundle_sha256.as_deref(),
            opened
                .metadata
                .approved_workspace_manifest_sha256
                .as_deref(),
            opened.metadata.work_products_bundle_sha256.as_deref(),
            opened.metadata.work_products_manifest_sha256.as_deref(),
        ) {
            (
                Some(approved_bundle),
                Some(work_products_bundle),
                Some(approved_bundle_sha256),
                Some(approved_manifest_sha256),
                Some(work_products_bundle_sha256),
                Some(work_products_manifest_sha256),
            ) => {
                let approved_workspace = approved_workspace.ok_or_else(|| {
                    ipc_error(
                        "application_restore_environment_mismatch",
                        "The approved workspace restore manager is unavailable.",
                    )
                })?;
                hook(ApplicationRestoreStagePoint::ApprovedAndWorkProductsStaging)?;
                approved_workspace
                    .stage_application_backup_components(
                        approved_bundle,
                        approved_manifest_sha256,
                        work_products_bundle,
                        work_products_manifest_sha256,
                        &paths.approved_incoming,
                        &paths.work_products_incoming,
                    )
                    .map_err(approved_mcp_error)?;
                PendingApplicationRestore::V3(PendingApplicationRestoreV3 {
                    format_version: FULL_RESTORE_V3_FORMAT_VERSION,
                    backup_id: opened.metadata.backup_id.clone(),
                    privacy_backup_id: opened.metadata.privacy_backup_id.clone(),
                    workspace_instance_id: opened
                        .metadata
                        .workspace_instance_id
                        .as_str()
                        .to_owned(),
                    original_user_present: Some(original_user_present),
                    original_privacy_present: Some(original_privacy_present),
                    original_vault_present: Some(original_vault_present),
                    original_approved_workspace_present: Some(original_approved_workspace_present),
                    original_work_products_present: Some(original_work_products_present),
                    app_version: migration_recovery_created_at_unix
                        .map(|_| env!("CARGO_PKG_VERSION").to_owned())
                        .unwrap_or_else(|| opened.metadata.app_version.clone()),
                    user_schema_version: opened.metadata.user_schema_version,
                    privacy_store_schema_version,
                    user_database_sha256: opened.metadata.user_database_sha256.clone(),
                    privacy_database_sha256: privacy.database_sha256,
                    privacy_key_epoch: privacy.key_epoch,
                    vault_manifest_sha256: opened.metadata.vault_manifest_sha256.clone(),
                    vault_archive_sha256: opened.metadata.encrypted_vault_bundle_sha256.clone(),
                    approved_workspace_bundle_sha256: approved_bundle_sha256.to_owned(),
                    approved_workspace_manifest_sha256: approved_manifest_sha256.to_owned(),
                    work_products_bundle_sha256: work_products_bundle_sha256.to_owned(),
                    work_products_manifest_sha256: work_products_manifest_sha256.to_owned(),
                })
            }
            (None, None, None, None, None, None) => {
                PendingApplicationRestore::V2(PendingApplicationRestoreV2 {
                    format_version: FULL_RESTORE_FORMAT_VERSION,
                    backup_id: opened.metadata.backup_id.clone(),
                    privacy_backup_id: opened.metadata.privacy_backup_id.clone(),
                    workspace_instance_id: opened
                        .metadata
                        .workspace_instance_id
                        .as_str()
                        .to_owned(),
                    original_user_present: Some(original_user_present),
                    original_privacy_present: Some(original_privacy_present),
                    original_vault_present: Some(original_vault_present),
                    app_version: migration_recovery_created_at_unix
                        .map(|_| env!("CARGO_PKG_VERSION").to_owned())
                        .unwrap_or_else(|| opened.metadata.app_version.clone()),
                    user_schema_version: opened.metadata.user_schema_version,
                    user_database_sha256: opened.metadata.user_database_sha256.clone(),
                    privacy_database_sha256: privacy.database_sha256,
                    privacy_key_epoch: privacy.key_epoch,
                    vault_manifest_sha256: opened.metadata.vault_manifest_sha256.clone(),
                    vault_archive_sha256: opened.metadata.encrypted_vault_bundle_sha256.clone(),
                })
            }
            _ => {
                return Err(ipc_error(
                    "application_backup_component_mismatch",
                    "The authenticated application backup has an incomplete workspace component set.",
                ));
            }
        };
        hook(ApplicationRestoreStagePoint::BeforeProtectedMarker)?;
        write_pair_marker(&paths.marker, &marker)
    })();
    finish_pair_restore_stage(&paths, result)?;
    Ok(opened.metadata.clone())
}

/// Enumerates and authenticates the complete full-application restore namespace
/// before any current manager, schema initializer, credential creator, cleanup,
/// or writer is allowed to run.  Absence is accepted only when every full-
/// restore transaction slot is absent; unmarked residue is never repaired here.
pub(crate) fn observe_pending_application_restore_read_only(
    app_local_data_dir: &Path,
) -> Result<PendingApplicationRestoreObservation, IpcError> {
    observe_pending_application_restore_read_only_with_approved(app_local_data_dir, None)
}

fn observe_pending_application_restore_read_only_with_approved(
    app_local_data_dir: &Path,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
) -> Result<PendingApplicationRestoreObservation, IpcError> {
    match fs::symlink_metadata(app_local_data_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PendingApplicationRestoreObservation::Absent);
        }
        Err(_) => {
            return Err(ipc_error(
                "application_restore_io",
                "The fixed application data directory could not be inspected.",
            ));
        }
        Ok(_) => {}
    }
    validate_application_restore_observation_root(app_local_data_dir)?;
    let paths = application_restore_paths(app_local_data_dir);
    reject_unknown_application_restore_siblings(app_local_data_dir, &paths)?;

    if !restore_path_is_present(&paths.marker)? {
        ensure_full_restore_residue_absent(&paths)?;
        return Ok(PendingApplicationRestoreObservation::Absent);
    }
    ensure_no_mixed_application_restore(&paths, app_local_data_dir)?;

    let (marker, marker_file) = read_pair_marker_with_proof(&paths.marker)?;
    let workspace_instance_id = marker_workspace_instance_id(&marker)?;
    validate_pair_marker(&marker, &workspace_instance_id)?;
    let workspace_identity = match approved_workspace {
        Some(workspace) => workspace
            .observe_application_restore_workspace_identity_read_only(&workspace_instance_id),
        None => observe_application_restore_workspace_identity_read_only(
            app_local_data_dir,
            &workspace_instance_id,
        ),
    }
    .map_err(approved_mcp_error)?;
    if workspace_identity.workspace_instance_id() != &workspace_instance_id {
        return Err(ipc_error(
            "application_restore_environment_mismatch",
            "The authenticated restore marker is not bound to this application workspace.",
        ));
    }
    let slots_before = capture_application_restore_slots(&paths)?;
    let phase = classify_pending_application_restore(&marker, &slots_before)?;
    let approved_components = validate_observed_application_restore_components(
        app_local_data_dir,
        &paths,
        &marker,
        &workspace_instance_id,
        &slots_before,
        approved_workspace,
    )?;
    let slots_after = capture_application_restore_slots(&paths)?;
    if slots_after != slots_before {
        return Err(application_restore_observation_changed());
    }
    let (marker_after, marker_file_after) = read_pair_marker_with_proof(&paths.marker)?;
    if marker_after != marker || marker_file_after != marker_file {
        return Err(application_restore_observation_changed());
    }

    Ok(PendingApplicationRestoreObservation::Authenticated(
        PendingApplicationRestoreGate {
            marker,
            marker_file,
            workspace_instance_id,
            phase,
            slots: slots_before,
            workspace_identity,
            approved_components,
        },
    ))
}

fn marker_workspace_instance_id(
    marker: &PendingApplicationRestore,
) -> Result<privacy::vnext::WorkspaceInstanceId, IpcError> {
    let value = match marker {
        PendingApplicationRestore::V2(marker) => &marker.workspace_instance_id,
        PendingApplicationRestore::V3(marker) => &marker.workspace_instance_id,
    };
    privacy::vnext::WorkspaceInstanceId::parse(value.clone()).map_err(|_| {
        ipc_error(
            "application_restore_environment_mismatch",
            "The authenticated application restore workspace identifier is invalid.",
        )
    })
}

fn validate_application_restore_observation_root(path: &Path) -> Result<(), IpcError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "The fixed application data directory could not be inspected.",
        )
    })?;
    if !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "The application restore root is not an ordinary fixed local directory.",
        ));
    }
    Ok(())
}

fn application_restore_observation_changed() -> IpcError {
    ipc_error(
        "application_restore_observation_changed",
        "The authenticated application restore namespace changed during read-only observation.",
    )
}

fn classify_pending_application_restore(
    marker: &PendingApplicationRestore,
    slots: &ApplicationRestoreSlotsProof,
) -> Result<PendingApplicationRestorePhase, IpcError> {
    let original_presence = marker_original_presence(marker)?;
    let mut states = vec![
        classify_restore_slot_progress(
            &slots.user_active,
            &slots.user_incoming,
            &slots.user_rollback,
            original_presence.as_ref().map(|values| values[0]),
        )?,
        classify_restore_slot_progress(
            &slots.privacy_active,
            &slots.privacy_incoming,
            &slots.privacy_rollback,
            original_presence.as_ref().map(|values| values[1]),
        )?,
        classify_restore_slot_progress(
            &slots.vault_active,
            &slots.vault_incoming,
            &slots.vault_rollback,
            original_presence.as_ref().map(|values| values[2]),
        )?,
    ];
    let mut kinds = vec![
        RestoreComponentKind::User,
        RestoreComponentKind::Privacy,
        RestoreComponentKind::Vault,
    ];
    match marker {
        PendingApplicationRestore::V2(_) => {
            if slots.approved_incoming.is_present()
                || slots.approved_rollback.is_present()
                || slots.work_products_incoming.is_present()
                || slots.work_products_rollback.is_present()
            {
                return Err(application_restore_crash_state_error());
            }
        }
        PendingApplicationRestore::V3(_) => {
            states.push(classify_restore_slot_progress(
                &slots.approved_active,
                &slots.approved_incoming,
                &slots.approved_rollback,
                original_presence.as_ref().map(|values| values[3]),
            )?);
            states.push(classify_restore_slot_progress(
                &slots.work_products_active,
                &slots.work_products_incoming,
                &slots.work_products_rollback,
                original_presence.as_ref().map(|values| values[4]),
            )?);
            kinds.push(RestoreComponentKind::ApprovedWorkspace);
            kinds.push(RestoreComponentKind::WorkProducts);
        }
    }
    classify_restore_progress_sequence(&states, &kinds, original_presence.as_deref())
}

fn marker_original_presence(
    marker: &PendingApplicationRestore,
) -> Result<Option<Vec<bool>>, IpcError> {
    let values = match marker {
        PendingApplicationRestore::V2(marker) => vec![
            marker.original_user_present,
            marker.original_privacy_present,
            marker.original_vault_present,
        ],
        PendingApplicationRestore::V3(marker) => vec![
            marker.original_user_present,
            marker.original_privacy_present,
            marker.original_vault_present,
            marker.original_approved_workspace_present,
            marker.original_work_products_present,
        ],
    };
    if values.iter().all(Option::is_none) {
        return Ok(None);
    }
    values
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .map(Some)
        .ok_or_else(application_restore_crash_state_error)
}

impl RestorePathProof {
    fn is_present(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

fn classify_restore_slot_progress(
    active: &RestorePathProof,
    incoming: &RestorePathProof,
    rollback: &RestorePathProof,
    original_present: Option<bool>,
) -> Result<RestoreSlotProgress, IpcError> {
    let tuple = (
        active.is_present(),
        incoming.is_present(),
        rollback.is_present(),
    );
    match original_present {
        Some(true) => match tuple {
            (true, true, false) => Ok(RestoreSlotProgress::PreparedWithOriginal),
            (false, true, true) => Ok(RestoreSlotProgress::MovedToRollback),
            (true, false, true) => Ok(RestoreSlotProgress::InstalledWithRollback),
            (true, false, false) => Ok(RestoreSlotProgress::Cleaned),
            _ => Err(application_restore_crash_state_error()),
        },
        Some(false) => match tuple {
            (false, true, false) => Ok(RestoreSlotProgress::PreparedFromAbsent),
            (true, false, false) => Ok(RestoreSlotProgress::InstalledFromAbsent),
            _ => Err(application_restore_crash_state_error()),
        },
        None => match tuple {
            (true, true, false) => Ok(RestoreSlotProgress::PreparedWithOriginal),
            (false, true, false) => Ok(RestoreSlotProgress::PreparedFromAbsent),
            (false, true, true) => Ok(RestoreSlotProgress::MovedToRollback),
            (true, false, true) => Ok(RestoreSlotProgress::InstalledWithRollback),
            (true, false, false) => Ok(RestoreSlotProgress::LegacyInstalledWithoutRollback),
            _ => Err(application_restore_crash_state_error()),
        },
    }
}

fn restore_slot_is_prepared(state: RestoreSlotProgress) -> bool {
    matches!(
        state,
        RestoreSlotProgress::PreparedWithOriginal | RestoreSlotProgress::PreparedFromAbsent
    )
}

fn restore_slot_is_installed(state: RestoreSlotProgress) -> bool {
    matches!(
        state,
        RestoreSlotProgress::InstalledWithRollback
            | RestoreSlotProgress::InstalledFromAbsent
            | RestoreSlotProgress::LegacyInstalledWithoutRollback
    )
}

fn classify_restore_progress_sequence(
    states: &[RestoreSlotProgress],
    kinds: &[RestoreComponentKind],
    original_presence: Option<&[bool]>,
) -> Result<PendingApplicationRestorePhase, IpcError> {
    if states.len() != kinds.len()
        || original_presence.is_some_and(|values| states.len() != values.len())
        || states.is_empty()
    {
        return Err(application_restore_crash_state_error());
    }
    if states.iter().all(|state| restore_slot_is_prepared(*state)) {
        return Ok(PendingApplicationRestorePhase::Prepared);
    }

    for index in 0..states.len() {
        if states[..index]
            .iter()
            .all(|state| restore_slot_is_installed(*state))
            && states[index] == RestoreSlotProgress::MovedToRollback
            && states[index + 1..]
                .iter()
                .all(|state| restore_slot_is_prepared(*state))
        {
            return moved_restore_phase(kinds[index]);
        }
        if index + 1 < states.len()
            && states[..=index]
                .iter()
                .all(|state| restore_slot_is_installed(*state))
            && states[index + 1..]
                .iter()
                .all(|state| restore_slot_is_prepared(*state))
        {
            return installed_restore_phase(kinds[index]);
        }
    }

    if original_presence.is_none() {
        if states.iter().all(|state| restore_slot_is_installed(*state)) {
            let removed = states
                .iter()
                .position(|state| *state == RestoreSlotProgress::InstalledWithRollback)
                .unwrap_or(states.len());
            return Ok(PendingApplicationRestorePhase::InstalledPendingCleanup {
                removed_rollback_prefix: u8::try_from(removed)
                    .map_err(|_| application_restore_crash_state_error())?,
            });
        }
        return Err(application_restore_crash_state_error());
    }

    let original_presence = original_presence.ok_or_else(application_restore_crash_state_error)?;
    // New markers carry a disk-authenticated canonical cleanup position even when
    // absent-original slots are interspersed: every present-original before
    // the first surviving rollback must be cleaned, every one after it must
    // still have its rollback, and absent-original slots remain installed.
    let mut first_surviving_rollback = None;
    let mut surviving_rollback_seen = false;
    for (index, (state, original_present)) in
        states.iter().zip(original_presence.iter()).enumerate()
    {
        if *original_present {
            match state {
                RestoreSlotProgress::Cleaned if !surviving_rollback_seen => {}
                RestoreSlotProgress::InstalledWithRollback => {
                    surviving_rollback_seen = true;
                    first_surviving_rollback.get_or_insert(index);
                }
                _ => return Err(application_restore_crash_state_error()),
            }
        } else if *state != RestoreSlotProgress::InstalledFromAbsent {
            return Err(application_restore_crash_state_error());
        }
    }
    let removed = first_surviving_rollback.unwrap_or(states.len());
    Ok(PendingApplicationRestorePhase::InstalledPendingCleanup {
        removed_rollback_prefix: u8::try_from(removed)
            .map_err(|_| application_restore_crash_state_error())?,
    })
}

fn moved_restore_phase(
    component: RestoreComponentKind,
) -> Result<PendingApplicationRestorePhase, IpcError> {
    Ok(match component {
        RestoreComponentKind::User => PendingApplicationRestorePhase::UserMovedToRollback,
        RestoreComponentKind::Privacy => PendingApplicationRestorePhase::PrivacyMovedToRollback,
        RestoreComponentKind::Vault => PendingApplicationRestorePhase::VaultMovedToRollback,
        RestoreComponentKind::ApprovedWorkspace => {
            PendingApplicationRestorePhase::ApprovedWorkspaceMovedToRollback
        }
        RestoreComponentKind::WorkProducts => {
            PendingApplicationRestorePhase::WorkProductsMovedToRollback
        }
    })
}

fn installed_restore_phase(
    component: RestoreComponentKind,
) -> Result<PendingApplicationRestorePhase, IpcError> {
    match component {
        RestoreComponentKind::User => Ok(PendingApplicationRestorePhase::UserInstalled),
        RestoreComponentKind::Privacy => Ok(PendingApplicationRestorePhase::PrivacyInstalled),
        RestoreComponentKind::Vault => Ok(PendingApplicationRestorePhase::VaultInstalled),
        RestoreComponentKind::ApprovedWorkspace => {
            Ok(PendingApplicationRestorePhase::ApprovedWorkspaceInstalled)
        }
        RestoreComponentKind::WorkProducts => Err(application_restore_crash_state_error()),
    }
}

fn application_restore_crash_state_error() -> IpcError {
    ipc_error(
        "application_restore_conflict",
        "The full application restore slots do not match one exact authenticated crash phase.",
    )
}

fn ensure_full_restore_residue_absent(paths: &ApplicationRestorePaths) -> Result<(), IpcError> {
    for path in [
        &paths.user_incoming,
        &paths.user_rollback,
        &paths.privacy_incoming,
        &paths.privacy_rollback,
    ] {
        ensure_restore_database_slot_absent(path)?;
    }
    for path in [
        &paths.vault_incoming,
        &paths.vault_rollback,
        &paths.approved_incoming,
        &paths.approved_rollback,
        &paths.work_products_incoming,
        &paths.work_products_rollback,
    ] {
        if restore_path_is_present(path)? {
            return Err(ipc_error(
                "application_restore_conflict",
                "An unmarked full-application restore residue requires explicit recovery.",
            ));
        }
    }
    Ok(())
}

fn ensure_restore_database_slot_absent(path: &Path) -> Result<(), IpcError> {
    for candidate in [
        path.to_path_buf(),
        sqlite_sidecar_path(path, "-journal"),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ] {
        if restore_path_is_present(&candidate)? {
            return Err(ipc_error(
                "application_restore_conflict",
                "An unmarked database restore residue requires explicit recovery.",
            ));
        }
    }
    Ok(())
}

fn ensure_no_mixed_application_restore(
    paths: &ApplicationRestorePaths,
    app_local_data_dir: &Path,
) -> Result<(), IpcError> {
    let privacy_directory = app_local_data_dir.join("privacy");
    for path in [
        paths.legacy_user_incoming.clone(),
        paths.legacy_user_marker.clone(),
        paths.legacy_user_rollback.clone(),
        privacy_directory.join("privacy-workflow.sqlite.restore-incoming"),
        privacy_directory.join("privacy-workflow.sqlite.restore-pending.dpapi"),
        privacy_directory.join("privacy-workflow.sqlite.restore-rollback"),
        app_local_data_dir.join("v031-migration-recovery-pending.dpapi"),
    ] {
        if restore_path_is_present(&path)? {
            return Err(ipc_error(
                "application_restore_conflict",
                "A full restore cannot coexist with a legacy, standalone, or migration-recovery transaction.",
            ));
        }
    }
    Ok(())
}

fn reject_unknown_application_restore_siblings(
    app_local_data_dir: &Path,
    paths: &ApplicationRestorePaths,
) -> Result<(), IpcError> {
    let privacy_directory = app_local_data_dir.join("privacy");
    let approved_parent = paths
        .approved_active
        .parent()
        .ok_or_else(application_restore_crash_state_error)?;
    reject_unknown_restore_names_in_directory(
        app_local_data_dir,
        &["application", "user.sqlite", VAULT_DIRECTORY_NAME],
        &[
            FULL_RESTORE_MARKER_NAME,
            "v031-migration-recovery-pending.dpapi",
            "user.sqlite.application-restore-incoming",
            "user.sqlite.application-restore-incoming-journal",
            "user.sqlite.application-restore-incoming-wal",
            "user.sqlite.application-restore-incoming-shm",
            "user.sqlite.application-restore-rollback",
            "user.sqlite.application-restore-rollback-journal",
            "user.sqlite.application-restore-rollback-wal",
            "user.sqlite.application-restore-rollback-shm",
            "user.sqlite.restore-incoming",
            "user.sqlite.restore-pending.json",
            "user.sqlite.restore-rollback",
            "case-vault-v2.application-restore-incoming",
            "case-vault-v2.application-restore-rollback",
        ],
    )?;
    if restore_path_is_present(&privacy_directory)? {
        reject_unknown_restore_names_in_directory(
            &privacy_directory,
            &["privacy-workflow.sqlite"],
            &[
                "privacy-workflow.sqlite.application-restore-incoming",
                "privacy-workflow.sqlite.application-restore-incoming-journal",
                "privacy-workflow.sqlite.application-restore-incoming-wal",
                "privacy-workflow.sqlite.application-restore-incoming-shm",
                "privacy-workflow.sqlite.application-restore-rollback",
                "privacy-workflow.sqlite.application-restore-rollback-journal",
                "privacy-workflow.sqlite.application-restore-rollback-wal",
                "privacy-workflow.sqlite.application-restore-rollback-shm",
                "privacy-workflow.sqlite.restore-incoming",
                "privacy-workflow.sqlite.restore-pending.dpapi",
                "privacy-workflow.sqlite.restore-rollback",
            ],
        )?;
    }
    if restore_path_is_present(approved_parent)? {
        reject_unknown_restore_names_in_directory(
            approved_parent,
            &[APPROVED_DIRECTORY_NAME, WORK_PRODUCTS_DIRECTORY_NAME],
            &[
                "approved-generations.application-restore-incoming",
                "approved-generations.application-restore-rollback",
                "work-products.application-restore-incoming",
                "work-products.application-restore-rollback",
            ],
        )?;
    }
    Ok(())
}

fn reject_unknown_restore_names_in_directory(
    directory: &Path,
    target_stems: &[&str],
    allowed_restore_names: &[&str],
) -> Result<(), IpcError> {
    validate_restore_directory_identity(directory)?;
    for entry in fs::read_dir(directory).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "A full-restore sibling directory could not be enumerated.",
        )
    })? {
        let entry = entry.map_err(|_| {
            ipc_error(
                "application_restore_io",
                "A full-restore sibling entry could not be inspected.",
            )
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let looks_related = target_stems.iter().any(|stem| name.starts_with(stem))
            && (name.contains("restore")
                || name.contains("pending")
                || name.contains(".incoming")
                || name.contains(".rollback")
                || name.contains(".staging"));
        if looks_related && !allowed_restore_names.contains(&name.as_str()) {
            return Err(ipc_error(
                "application_restore_unknown_state",
                "An unknown full-application restore sibling was found.",
            ));
        }
    }
    Ok(())
}

fn capture_application_restore_slots(
    paths: &ApplicationRestorePaths,
) -> Result<ApplicationRestoreSlotsProof, IpcError> {
    for path in [
        &paths.user_active,
        &paths.user_incoming,
        &paths.user_rollback,
        &paths.privacy_active,
        &paths.privacy_incoming,
        &paths.privacy_rollback,
    ] {
        ensure_no_database_sidecars(path)?;
    }
    Ok(ApplicationRestoreSlotsProof {
        user_active: capture_optional_restore_file(
            &paths.user_active,
            MAX_USER_DATABASE_BACKUP_BYTES,
        )?,
        user_incoming: capture_optional_restore_file(
            &paths.user_incoming,
            MAX_USER_DATABASE_BACKUP_BYTES,
        )?,
        user_rollback: capture_optional_restore_file(
            &paths.user_rollback,
            MAX_USER_DATABASE_BACKUP_BYTES,
        )?,
        privacy_active: capture_optional_restore_file(
            &paths.privacy_active,
            privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES,
        )?,
        privacy_incoming: capture_optional_restore_file(
            &paths.privacy_incoming,
            privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES,
        )?,
        privacy_rollback: capture_optional_restore_file(
            &paths.privacy_rollback,
            privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES,
        )?,
        vault_active: capture_optional_restore_directory(&paths.vault_active)?,
        vault_incoming: capture_optional_restore_directory(&paths.vault_incoming)?,
        vault_rollback: capture_optional_restore_directory(&paths.vault_rollback)?,
        approved_active: capture_optional_restore_directory(&paths.approved_active)?,
        approved_incoming: capture_optional_restore_directory(&paths.approved_incoming)?,
        approved_rollback: capture_optional_restore_directory(&paths.approved_rollback)?,
        work_products_active: capture_optional_restore_directory(&paths.work_products_active)?,
        work_products_incoming: capture_optional_restore_directory(&paths.work_products_incoming)?,
        work_products_rollback: capture_optional_restore_directory(&paths.work_products_rollback)?,
    })
}

fn capture_optional_restore_file(
    path: &Path,
    maximum: usize,
) -> Result<RestorePathProof, IpcError> {
    if !restore_path_is_present(path)? {
        return Ok(RestorePathProof::Absent);
    }
    let (_, proof) = read_restore_file_with_proof(path, maximum, false)?;
    Ok(RestorePathProof::File(proof))
}

fn capture_optional_restore_directory(path: &Path) -> Result<RestorePathProof, IpcError> {
    if !restore_path_is_present(path)? {
        return Ok(RestorePathProof::Absent);
    }
    capture_restore_directory_proof(path).map(RestorePathProof::Directory)
}

fn read_pair_marker_with_proof(
    path: &Path,
) -> Result<(PendingApplicationRestore, RestoreFileProof), IpcError> {
    let (protected, proof) =
        read_restore_file_with_proof(path, FULL_RESTORE_MARKER_MAX_BYTES, false)?;
    let plaintext = SensitiveBytes(unprotect_local(protected.as_slice()).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "The full application restore marker failed DPAPI authentication.",
        )
    })?);
    let marker: PendingApplicationRestore =
        privacy::vnext::strict_json_v1_from_slice(plaintext.as_slice()).map_err(|_| {
            ipc_error(
                "application_restore_invalid",
                "The full application restore marker has an invalid strict encoding.",
            )
        })?;
    if privacy::vnext::canonical_json_v1(&marker).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "The full application restore marker could not be canonically encoded.",
        )
    })? != plaintext.as_slice()
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "The full application restore marker is not canonical JSON.",
        ));
    }
    Ok((marker, proof))
}

fn read_restore_file_with_proof(
    path: &Path,
    maximum: usize,
    allow_empty: bool,
) -> Result<(SensitiveBytes, RestoreFileProof), IpcError> {
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore proof file is not on an ordinary fixed local path.",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| {
            ipc_error(
                "application_restore_io",
                "A restore proof file could not be opened.",
            )
        })?;
    if !ordinary_single_link_handle(&file) {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore proof file is not an ordinary single-link file.",
        ));
    }
    let before = file.metadata().map_err(|_| {
        ipc_error(
            "application_restore_io",
            "A restore proof file's metadata could not be read.",
        )
    })?;
    if (!allow_empty && before.len() == 0) || before.len() > maximum as u64 {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore proof file has an invalid length for its fixed bound.",
        ));
    }
    let identity_sha256 = opened_file_identity_sha256(&file)?;
    let capacity = usize::try_from(before.len()).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "A restore proof file length is unsupported.",
        )
    })?;
    let mut bytes = SensitiveBytes(Vec::with_capacity(capacity));
    (&mut file)
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes.0)
        .map_err(|_| {
            ipc_error(
                "application_restore_io",
                "A restore proof file could not be read.",
            )
        })?;
    let after = file.metadata().map_err(|_| {
        ipc_error(
            "application_restore_io",
            "A restore proof file's final metadata could not be read.",
        )
    })?;
    if bytes.0.len() != capacity
        || !same_restore_metadata(&before, &after)
        || opened_file_identity_sha256(&file)? != identity_sha256
        || !ordinary_single_link_handle(&file)
    {
        return Err(application_restore_observation_changed());
    }
    let proof = RestoreFileProof {
        identity_sha256,
        bytes: before.len(),
        created: before.creation_time(),
        modified: before.last_write_time(),
        attributes: before.file_attributes(),
        sha256: sha256_hex(bytes.as_slice()),
    };
    Ok((bytes, proof))
}

fn opened_file_identity_sha256(file: &File) -> Result<String, IpcError> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if handle.is_null()
        || unsafe { GetFileInformationByHandle(handle, &mut information) } == 0
        || information.nNumberOfLinks != 1
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore proof file identity could not be authenticated.",
        ));
    }
    let mut value = Vec::with_capacity(20);
    value.extend_from_slice(b"restore-file-identity-v1\0");
    value.extend_from_slice(&information.dwVolumeSerialNumber.to_be_bytes());
    value.extend_from_slice(&information.nFileIndexHigh.to_be_bytes());
    value.extend_from_slice(&information.nFileIndexLow.to_be_bytes());
    Ok(sha256_hex(&value))
}

fn same_restore_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file() == right.is_file()
        && left.is_dir() == right.is_dir()
        && left.len() == right.len()
        && left.creation_time() == right.creation_time()
        && left.last_write_time() == right.last_write_time()
        && left.file_attributes() == right.file_attributes()
}

fn capture_restore_directory_proof(root: &Path) -> Result<RestoreDirectoryProof, IpcError> {
    validate_restore_directory_identity(root)?;
    let root_metadata = fs::symlink_metadata(root).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "A restore proof directory could not be inspected.",
        )
    })?;
    let root_proof = restore_directory_entry_proof(root, Path::new(""), &root_metadata)?;
    let mut entries = Vec::new();
    let mut total_file_bytes = 0_u64;
    capture_restore_directory_entries(root, root, &mut entries, &mut total_file_bytes)?;
    entries.sort_by(|left, right| {
        left.relative_path_sha256
            .cmp(&right.relative_path_sha256)
            .then_with(|| (left.kind as u8).cmp(&(right.kind as u8)))
    });
    if entries
        .windows(2)
        .any(|pair| pair[0].relative_path_sha256 == pair[1].relative_path_sha256)
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore directory contains an ambiguous recursive entry identity.",
        ));
    }
    let root_after =
        fs::symlink_metadata(root).map_err(|_| application_restore_observation_changed())?;
    if !same_restore_metadata(&root_metadata, &root_after)
        || restore_directory_entry_proof(root, Path::new(""), &root_after)? != root_proof
    {
        return Err(application_restore_observation_changed());
    }
    Ok(RestoreDirectoryProof {
        root: root_proof,
        entries,
        total_file_bytes,
    })
}

fn capture_restore_directory_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<RestoreTreeEntryProof>,
    total_file_bytes: &mut u64,
) -> Result<(), IpcError> {
    validate_restore_directory_identity(current)?;
    for entry in fs::read_dir(current).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "A restore proof directory could not be enumerated.",
        )
    })? {
        if entries.len() >= MAX_APPLICATION_RESTORE_TREE_ENTRIES {
            return Err(ipc_error(
                "application_restore_invalid",
                "A restore proof directory exceeds its fixed entry bound.",
            ));
        }
        let entry = entry.map_err(|_| {
            ipc_error(
                "application_restore_io",
                "A recursive restore proof entry could not be inspected.",
            )
        })?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| application_restore_crash_state_error())?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| {
            ipc_error(
                "application_restore_io",
                "A recursive restore proof entry's metadata could not be read.",
            )
        })?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(ipc_error(
                "application_restore_invalid",
                "A restore directory contains a reparse point.",
            ));
        }
        if metadata.is_dir() {
            entries.push(restore_directory_entry_proof(&path, relative, &metadata)?);
            capture_restore_directory_entries(root, &path, entries, total_file_bytes)?;
        } else if metadata.is_file() {
            let remaining = MAX_APPLICATION_RESTORE_TREE_BYTES
                .checked_sub(*total_file_bytes)
                .ok_or_else(application_restore_crash_state_error)?;
            let maximum = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(MAX_APPLICATION_BACKUP_BYTES);
            let (_, file) = read_restore_file_with_proof(&path, maximum, true)?;
            *total_file_bytes = total_file_bytes
                .checked_add(file.bytes)
                .filter(|value| *value <= MAX_APPLICATION_RESTORE_TREE_BYTES)
                .ok_or_else(|| {
                    ipc_error(
                        "application_restore_invalid",
                        "A restore proof directory exceeds its fixed byte bound.",
                    )
                })?;
            entries.push(RestoreTreeEntryProof {
                relative_path_sha256: restore_relative_path_sha256(
                    relative,
                    RestoreTreeEntryKind::File,
                )?,
                kind: RestoreTreeEntryKind::File,
                identity_sha256: file.identity_sha256,
                bytes: file.bytes,
                created: file.created,
                modified: file.modified,
                attributes: file.attributes,
                content_sha256: Some(file.sha256),
            });
        } else {
            return Err(ipc_error(
                "application_restore_invalid",
                "A restore proof directory contains an unsupported entry type.",
            ));
        }
    }
    Ok(())
}

fn restore_directory_entry_proof(
    path: &Path,
    relative: &Path,
    metadata: &fs::Metadata,
) -> Result<RestoreTreeEntryProof, IpcError> {
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore proof directory entry is not an ordinary directory.",
        ));
    }
    Ok(RestoreTreeEntryProof {
        relative_path_sha256: restore_relative_path_sha256(
            relative,
            RestoreTreeEntryKind::Directory,
        )?,
        kind: RestoreTreeEntryKind::Directory,
        identity_sha256: opened_directory_identity_sha256(path)?,
        bytes: 0,
        created: metadata.creation_time(),
        modified: metadata.last_write_time(),
        attributes: metadata.file_attributes(),
        content_sha256: None,
    })
}

fn opened_directory_identity_sha256(path: &Path) -> Result<String, IpcError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|_| {
            ipc_error(
                "application_restore_invalid",
                "A restore proof directory identity could not be opened.",
            )
        })?;
    let handle = directory.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if handle.is_null() || unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore proof directory identity could not be authenticated.",
        ));
    }
    let mut value = Vec::new();
    value.extend_from_slice(b"restore-directory-identity-v1\0");
    value.extend_from_slice(&information.dwVolumeSerialNumber.to_be_bytes());
    value.extend_from_slice(&information.nFileIndexHigh.to_be_bytes());
    value.extend_from_slice(&information.nFileIndexLow.to_be_bytes());
    Ok(sha256_hex(&value))
}

fn restore_relative_path_sha256(
    relative: &Path,
    kind: RestoreTreeEntryKind,
) -> Result<String, IpcError> {
    let components = relative.components().collect::<Vec<_>>();
    let mut value = Vec::new();
    value.extend_from_slice(b"lawyer-assistance-restore-tree-entry-v1\0");
    value.push(match kind {
        RestoreTreeEntryKind::Directory => 0,
        RestoreTreeEntryKind::File => 1,
    });
    value.extend_from_slice(
        &u32::try_from(components.len())
            .map_err(|_| application_restore_crash_state_error())?
            .to_be_bytes(),
    );
    for component in components {
        let Component::Normal(component) = component else {
            return Err(application_restore_crash_state_error());
        };
        let component = component.to_str().ok_or_else(|| {
            ipc_error(
                "application_restore_invalid",
                "A restore tree contains a non-Unicode relative path.",
            )
        })?;
        value.extend_from_slice(
            &u32::try_from(component.len())
                .map_err(|_| application_restore_crash_state_error())?
                .to_be_bytes(),
        );
        value.extend_from_slice(component.as_bytes());
    }
    Ok(sha256_hex(&value))
}

fn validate_observed_application_restore_components(
    app_local_data_dir: &Path,
    paths: &ApplicationRestorePaths,
    marker: &PendingApplicationRestore,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    slots: &ApplicationRestoreSlotsProof,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
) -> Result<Option<ApplicationRestoreApprovedComponentsProof>, IpcError> {
    let original_presence = marker_original_presence(marker)?;
    let user_state = classify_restore_slot_progress(
        &slots.user_active,
        &slots.user_incoming,
        &slots.user_rollback,
        original_presence.as_ref().map(|values| values[0]),
    )?;
    let privacy_state = classify_restore_slot_progress(
        &slots.privacy_active,
        &slots.privacy_incoming,
        &slots.privacy_rollback,
        original_presence.as_ref().map(|values| values[1]),
    )?;
    let vault_state = classify_restore_slot_progress(
        &slots.vault_active,
        &slots.vault_incoming,
        &slots.vault_rollback,
        original_presence.as_ref().map(|values| values[2]),
    )?;
    let (user_sha256, privacy_sha256, privacy_epoch, privacy_schema, vault_manifest, vault_archive) =
        match marker {
            PendingApplicationRestore::V2(marker) => (
                marker.user_database_sha256.as_str(),
                marker.privacy_database_sha256.as_str(),
                marker.privacy_key_epoch,
                PRIVACY_STORE_SCHEMA_VERSION,
                marker.vault_manifest_sha256.as_str(),
                marker.vault_archive_sha256.as_str(),
            ),
            PendingApplicationRestore::V3(marker) => (
                marker.user_database_sha256.as_str(),
                marker.privacy_database_sha256.as_str(),
                marker.privacy_key_epoch,
                marker
                    .privacy_store_schema_version
                    .unwrap_or(PRIVACY_STORE_SCHEMA_VERSION),
                marker.vault_manifest_sha256.as_str(),
                marker.vault_archive_sha256.as_str(),
            ),
        };
    let user_replacement =
        restore_replacement_path(user_state, &paths.user_active, &paths.user_incoming);
    validate_user_component(user_replacement, user_sha256)?;
    ensure_no_database_sidecars(user_replacement)?;
    let privacy_replacement = restore_replacement_path(
        privacy_state,
        &paths.privacy_active,
        &paths.privacy_incoming,
    );
    validate_privacy_component(
        privacy_replacement,
        workspace_instance_id,
        privacy_epoch,
        privacy_schema,
        privacy_sha256,
    )?;
    ensure_no_database_sidecars(privacy_replacement)?;
    validate_vault_component(
        restore_replacement_path(vault_state, &paths.vault_active, &paths.vault_incoming),
        workspace_instance_id,
        vault_manifest,
        vault_archive,
    )?;

    if let Some(original) =
        restore_original_path(user_state, &paths.user_active, &paths.user_rollback)
    {
        database::validate_user_database_migration_source_read_only(original).map_err(|_| {
            ipc_error(
                "application_restore_lineage_unverifiable",
                "The original user database restore lineage is not an exact supported profile.",
            )
        })?;
    }
    if let Some(original) = restore_original_path(
        privacy_state,
        &paths.privacy_active,
        &paths.privacy_rollback,
    ) {
        validate_original_privacy_restore_component(original, workspace_instance_id)?;
    }
    if let Some(original) =
        restore_original_path(vault_state, &paths.vault_active, &paths.vault_rollback)
    {
        validate_original_vault_restore_component(original, workspace_instance_id)?;
    }

    match marker {
        PendingApplicationRestore::V2(_) => {
            ensure_observed_legacy_three_component_lineage_safe(paths, user_state, privacy_state)?;
            Ok(None)
        }
        PendingApplicationRestore::V3(marker) => {
            let approved_state = classify_restore_slot_progress(
                &slots.approved_active,
                &slots.approved_incoming,
                &slots.approved_rollback,
                original_presence.as_ref().map(|values| values[3]),
            )?;
            let work_products_state = classify_restore_slot_progress(
                &slots.work_products_active,
                &slots.work_products_incoming,
                &slots.work_products_rollback,
                original_presence.as_ref().map(|values| values[4]),
            )?;
            let approved_root = restore_replacement_path(
                approved_state,
                &paths.approved_active,
                &paths.approved_incoming,
            );
            let work_products_root = restore_replacement_path(
                work_products_state,
                &paths.work_products_active,
                &paths.work_products_incoming,
            );
            let proof = match approved_workspace {
                Some(workspace) => workspace.validate_application_restore_components_read_only(
                    approved_root,
                    work_products_root,
                    workspace_instance_id,
                    &marker.approved_workspace_manifest_sha256,
                    &marker.work_products_manifest_sha256,
                ),
                None => validate_application_restore_components_read_only(
                    app_local_data_dir,
                    approved_root,
                    work_products_root,
                    workspace_instance_id,
                    &marker.approved_workspace_manifest_sha256,
                    &marker.work_products_manifest_sha256,
                ),
            }
            .map_err(approved_mcp_error)?;
            if proof.workspace_instance_id() != workspace_instance_id {
                return Err(ipc_error(
                    "application_restore_environment_mismatch",
                    "The restored Approved/work-products pair has a different workspace lineage.",
                ));
            }
            Ok(Some(proof))
        }
    }
}

fn restore_replacement_path<'a>(
    state: RestoreSlotProgress,
    active: &'a Path,
    incoming: &'a Path,
) -> &'a Path {
    match state {
        RestoreSlotProgress::PreparedWithOriginal
        | RestoreSlotProgress::PreparedFromAbsent
        | RestoreSlotProgress::MovedToRollback => incoming,
        RestoreSlotProgress::InstalledWithRollback
        | RestoreSlotProgress::InstalledFromAbsent
        | RestoreSlotProgress::Cleaned
        | RestoreSlotProgress::LegacyInstalledWithoutRollback => active,
    }
}

fn restore_original_path<'a>(
    state: RestoreSlotProgress,
    active: &'a Path,
    rollback: &'a Path,
) -> Option<&'a Path> {
    match state {
        RestoreSlotProgress::PreparedWithOriginal => Some(active),
        RestoreSlotProgress::PreparedFromAbsent
        | RestoreSlotProgress::InstalledFromAbsent
        | RestoreSlotProgress::Cleaned
        | RestoreSlotProgress::LegacyInstalledWithoutRollback => None,
        RestoreSlotProgress::MovedToRollback | RestoreSlotProgress::InstalledWithRollback => {
            Some(rollback)
        }
    }
}

fn validate_original_privacy_restore_component(
    path: &Path,
    expected_workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<(), IpcError> {
    validate_restore_file_identity(path)?;
    ensure_no_database_sidecars(path)?;
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        ipc_error(
            "application_restore_lineage_unverifiable",
            "The original Privacy restore component could not be opened read-only.",
        )
    })?;
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; BEGIN DEFERRED;")
        .map_err(|_| {
            ipc_error(
                "application_restore_lineage_unverifiable",
                "The original Privacy restore snapshot could not be fixed read-only.",
            )
        })?;
    let result = (|| {
        let integrity: String = connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .map_err(|_| application_restore_crash_state_error())?;
        let foreign_keys = match connection.query_row("PRAGMA foreign_key_check", [], |_| Ok(1_i64))
        {
            Ok(_) => 1_i64,
            Err(rusqlite::Error::QueryReturnedNoRows) => 0_i64,
            Err(_) => return Err(application_restore_crash_state_error()),
        };
        let workspace: String = connection
            .query_row(
                "SELECT workspace_instance_id FROM privacy_lifecycle_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| application_restore_crash_state_error())?;
        let lifecycle = PrivacyLifecycle::open(&connection, expected_workspace_instance_id.clone())
            .map_err(|_| application_restore_crash_state_error())?;
        let key_epoch = lifecycle
            .current_key_epoch(&connection)
            .map_err(|_| application_restore_crash_state_error())?;
        if integrity != "ok"
            || foreign_keys != 0
            || workspace != expected_workspace_instance_id.as_str()
            || key_epoch == 0
        {
            return Err(application_restore_crash_state_error());
        }
        Ok(())
    })();
    connection
        .execute_batch("ROLLBACK")
        .map_err(|_| application_restore_crash_state_error())?;
    result
}

fn ensure_observed_legacy_three_component_lineage_safe(
    paths: &ApplicationRestorePaths,
    user_state: RestoreSlotProgress,
    privacy_state: RestoreSlotProgress,
) -> Result<(), IpcError> {
    const UNIFIED_USER_STATE_TABLES: &[&str] = &["case_assistant_pending_outputs"];
    const UNIFIED_PRIVACY_STATE_TABLES: &[&str] = &[
        "privacy_materials",
        "privacy_redactions",
        "privacy_vault_material_refs",
        "case_material_selections",
        "case_material_migration_ledger",
        "case_material_migration_events",
        "case_material_legacy_references",
        "project_privacy_case_bindings",
        "project_privacy_case_binding_audit",
        "project_deletion_journal",
        "case_material_assignment_audit",
    ];
    let user_has_state =
        match restore_original_path(user_state, &paths.user_active, &paths.user_rollback) {
            Some(path) => restore_database_has_rows(path, UNIFIED_USER_STATE_TABLES, false)?,
            None => false,
        };
    let privacy_has_state = match restore_original_path(
        privacy_state,
        &paths.privacy_active,
        &paths.privacy_rollback,
    ) {
        Some(path) => restore_database_has_rows(path, UNIFIED_PRIVACY_STATE_TABLES, false)?,
        None => false,
    };
    let approved_state = restore_workspace_component_has_state(
        &paths.approved_active,
        APPROVED_DATABASE_FILE_NAME,
        "publication_journal",
    )?;
    let work_product_state = restore_workspace_component_has_state(
        &paths.work_products_active,
        WORK_PRODUCTS_DATABASE_FILE_NAME,
        "work_product_versions",
    )?;
    if user_has_state || privacy_has_state || approved_state || work_product_state {
        return Err(ipc_error(
            "application_restore_requires_five_components",
            "A legacy three-component restore cannot replace a five-component lineage.",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn apply_pending_application_restore_with_approved(
    app_local_data_dir: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(), IpcError> {
    apply_pending_application_restore_internal(
        app_local_data_dir,
        workspace_instance_id,
        Some(approved_workspace),
    )
}

#[cfg(test)]
fn apply_pending_application_restore_internal(
    app_local_data_dir: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
) -> Result<(), IpcError> {
    let observation = observe_pending_application_restore_read_only_with_approved(
        app_local_data_dir,
        approved_workspace,
    )?;
    let PendingApplicationRestoreObservation::Authenticated(gate) = observation else {
        return Ok(());
    };
    if gate.workspace_instance_id() != workspace_instance_id {
        return Err(ipc_error(
            "application_restore_environment_mismatch",
            "The observed full restore is bound to a different workspace.",
        ));
    }
    apply_observed_pending_application_restore_with_hook(
        app_local_data_dir,
        &gate,
        approved_workspace,
        |_| Ok(()),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplicationRestoreCommitPoint {
    UserMovedToRollback,
    UserInstalled,
    PrivacyMovedToRollback,
    PrivacyInstalled,
    VaultMovedToRollback,
    VaultInstalled,
    ApprovedWorkspaceMovedToRollback,
    ApprovedWorkspaceInstalled,
    WorkProductsMovedToRollback,
    WorkProductsInstalled,
    CredentialsInvalidated,
    UserRollbackCleaned,
    PrivacyRollbackCleaned,
    VaultRollbackCleaned,
    ApprovedWorkspaceRollbackCleaned,
    WorkProductsRollbackCleaned,
}

pub(crate) fn apply_observed_pending_application_restore(
    app_local_data_dir: &Path,
    gate: &PendingApplicationRestoreGate,
) -> Result<(), IpcError> {
    let approved_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
    apply_observed_pending_application_restore_with_hook(
        app_local_data_dir,
        gate,
        Some(&approved_workspace),
        |_| Ok(()),
    )
}

#[cfg(test)]
fn apply_pending_application_restore_with_hook<Hook>(
    app_local_data_dir: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    mut hook: Hook,
) -> Result<(), IpcError>
where
    Hook: FnMut(ApplicationRestoreCommitPoint) -> Result<(), IpcError>,
{
    let PendingApplicationRestoreObservation::Authenticated(gate) =
        observe_pending_application_restore_read_only_with_approved(
            app_local_data_dir,
            approved_workspace,
        )?
    else {
        return Ok(());
    };
    if gate.workspace_instance_id() != workspace_instance_id {
        return Err(ipc_error(
            "application_restore_environment_mismatch",
            "The observed full restore is bound to a different workspace.",
        ));
    }
    apply_observed_pending_application_restore_with_hook(
        app_local_data_dir,
        &gate,
        approved_workspace,
        &mut hook,
    )
}

fn apply_observed_pending_application_restore_with_hook<Hook>(
    app_local_data_dir: &Path,
    expected_gate: &PendingApplicationRestoreGate,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    mut hook: Hook,
) -> Result<(), IpcError>
where
    Hook: FnMut(ApplicationRestoreCommitPoint) -> Result<(), IpcError>,
{
    let owned_workspace;
    let approved_workspace = match approved_workspace {
        Some(workspace) => workspace,
        None => {
            owned_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
            &owned_workspace
        }
    };
    let mut gate = reobserve_exact_application_restore_gate(
        app_local_data_dir,
        expected_gate,
        approved_workspace,
    )?;
    let paths = application_restore_paths(app_local_data_dir);
    let v3 = matches!(gate.marker, PendingApplicationRestore::V3(_));
    let initial_cleanup = matches!(
        gate.phase,
        PendingApplicationRestorePhase::InstalledPendingCleanup { .. }
    );
    let original_absent = observed_original_absence(&gate)?;

    if !initial_cleanup {
        let swap_result = (|| {
            install_observed_restore_component(
                app_local_data_dir,
                &mut gate,
                &paths.user_active,
                &paths.user_incoming,
                &paths.user_rollback,
                false,
                approved_workspace,
                ApplicationRestoreCommitPoint::UserMovedToRollback,
                ApplicationRestoreCommitPoint::UserInstalled,
                &mut hook,
            )?;
            install_observed_restore_component(
                app_local_data_dir,
                &mut gate,
                &paths.privacy_active,
                &paths.privacy_incoming,
                &paths.privacy_rollback,
                false,
                approved_workspace,
                ApplicationRestoreCommitPoint::PrivacyMovedToRollback,
                ApplicationRestoreCommitPoint::PrivacyInstalled,
                &mut hook,
            )?;
            install_observed_restore_component(
                app_local_data_dir,
                &mut gate,
                &paths.vault_active,
                &paths.vault_incoming,
                &paths.vault_rollback,
                true,
                approved_workspace,
                ApplicationRestoreCommitPoint::VaultMovedToRollback,
                ApplicationRestoreCommitPoint::VaultInstalled,
                &mut hook,
            )?;
            if v3 {
                install_observed_restore_component(
                    app_local_data_dir,
                    &mut gate,
                    &paths.approved_active,
                    &paths.approved_incoming,
                    &paths.approved_rollback,
                    true,
                    approved_workspace,
                    ApplicationRestoreCommitPoint::ApprovedWorkspaceMovedToRollback,
                    ApplicationRestoreCommitPoint::ApprovedWorkspaceInstalled,
                    &mut hook,
                )?;
                install_observed_restore_component(
                    app_local_data_dir,
                    &mut gate,
                    &paths.work_products_active,
                    &paths.work_products_incoming,
                    &paths.work_products_rollback,
                    true,
                    approved_workspace,
                    ApplicationRestoreCommitPoint::WorkProductsMovedToRollback,
                    ApplicationRestoreCommitPoint::WorkProductsInstalled,
                    &mut hook,
                )?;
            }
            Ok(())
        })();
        if let Err(error) = swap_result {
            rollback_observed_application_restore(&paths, &original_absent, v3)?;
            remove_if_exists(&paths.marker)?;
            return Err(error);
        }
    }

    gate = observe_authenticated_application_restore_gate(app_local_data_dir, approved_workspace)?;
    if v3 && !observed_present_original_cleanup_exists(&gate)? {
        reobserve_exact_application_restore_gate(app_local_data_dir, &gate, approved_workspace)?;
        approved_workspace
            .invalidate_after_application_restore()
            .map_err(approved_mcp_error)?;
        gate =
            observe_authenticated_application_restore_gate(app_local_data_dir, approved_workspace)?;
        hook(ApplicationRestoreCommitPoint::CredentialsInvalidated)?;
    }

    cleanup_observed_restore_file(
        app_local_data_dir,
        &mut gate,
        &paths.user_rollback,
        approved_workspace,
        ApplicationRestoreCommitPoint::UserRollbackCleaned,
        &mut hook,
    )?;
    cleanup_observed_restore_file(
        app_local_data_dir,
        &mut gate,
        &paths.privacy_rollback,
        approved_workspace,
        ApplicationRestoreCommitPoint::PrivacyRollbackCleaned,
        &mut hook,
    )?;
    cleanup_observed_restore_directory(
        app_local_data_dir,
        &mut gate,
        &paths.vault_rollback,
        true,
        approved_workspace,
        ApplicationRestoreCommitPoint::VaultRollbackCleaned,
        &mut hook,
    )?;
    if v3 {
        cleanup_observed_restore_directory(
            app_local_data_dir,
            &mut gate,
            &paths.approved_rollback,
            false,
            approved_workspace,
            ApplicationRestoreCommitPoint::ApprovedWorkspaceRollbackCleaned,
            &mut hook,
        )?;
        cleanup_observed_restore_directory(
            app_local_data_dir,
            &mut gate,
            &paths.work_products_rollback,
            false,
            approved_workspace,
            ApplicationRestoreCommitPoint::WorkProductsRollbackCleaned,
            &mut hook,
        )?;
    }
    reobserve_exact_application_restore_gate(app_local_data_dir, &gate, approved_workspace)?;
    remove_if_exists(&paths.marker)
}

fn observed_present_original_cleanup_exists(
    gate: &PendingApplicationRestoreGate,
) -> Result<bool, IpcError> {
    let Some(original_presence) = marker_original_presence(&gate.marker)? else {
        // Pre-presence V3 markers cannot distinguish a cleaned present original
        // from an installed absent original. Replaying the monotonic revocation
        // is safer than treating an unauthenticated numeric prefix as proof.
        return Ok(false);
    };
    let mut states = vec![
        classify_restore_slot_progress(
            &gate.slots.user_active,
            &gate.slots.user_incoming,
            &gate.slots.user_rollback,
            Some(original_presence[0]),
        )?,
        classify_restore_slot_progress(
            &gate.slots.privacy_active,
            &gate.slots.privacy_incoming,
            &gate.slots.privacy_rollback,
            Some(original_presence[1]),
        )?,
        classify_restore_slot_progress(
            &gate.slots.vault_active,
            &gate.slots.vault_incoming,
            &gate.slots.vault_rollback,
            Some(original_presence[2]),
        )?,
    ];
    if matches!(gate.marker, PendingApplicationRestore::V3(_)) {
        states.push(classify_restore_slot_progress(
            &gate.slots.approved_active,
            &gate.slots.approved_incoming,
            &gate.slots.approved_rollback,
            Some(original_presence[3]),
        )?);
        states.push(classify_restore_slot_progress(
            &gate.slots.work_products_active,
            &gate.slots.work_products_incoming,
            &gate.slots.work_products_rollback,
            Some(original_presence[4]),
        )?);
    }
    Ok(original_presence
        .iter()
        .zip(states)
        .any(|(present, state)| *present && state == RestoreSlotProgress::Cleaned))
}

fn observe_authenticated_application_restore_gate(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<PendingApplicationRestoreGate, IpcError> {
    match observe_pending_application_restore_read_only_with_approved(
        app_local_data_dir,
        Some(approved_workspace),
    )? {
        PendingApplicationRestoreObservation::Authenticated(gate) => Ok(gate),
        PendingApplicationRestoreObservation::Absent => {
            Err(application_restore_observation_changed())
        }
    }
}

fn reobserve_exact_application_restore_gate(
    app_local_data_dir: &Path,
    expected_gate: &PendingApplicationRestoreGate,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<PendingApplicationRestoreGate, IpcError> {
    let observed =
        observe_authenticated_application_restore_gate(app_local_data_dir, approved_workspace)?;
    if &observed != expected_gate {
        return Err(application_restore_observation_changed());
    }
    Ok(observed)
}

#[allow(clippy::too_many_arguments)]
fn install_observed_restore_component<Hook>(
    app_local_data_dir: &Path,
    gate: &mut PendingApplicationRestoreGate,
    active: &Path,
    incoming: &Path,
    rollback: &Path,
    directory: bool,
    approved_workspace: &ApprovedMcpWorkspace,
    moved_point: ApplicationRestoreCommitPoint,
    installed_point: ApplicationRestoreCommitPoint,
    hook: &mut Hook,
) -> Result<(), IpcError>
where
    Hook: FnMut(ApplicationRestoreCommitPoint) -> Result<(), IpcError>,
{
    let state = restore_component_state_from_gate(gate, active)?;
    if state == RestoreSlotProgress::PreparedWithOriginal {
        perform_observed_restore_rename(
            app_local_data_dir,
            gate,
            active,
            rollback,
            directory,
            approved_workspace,
        )?;
        hook(moved_point)?;
    }
    let state = restore_component_state_from_gate(gate, active)?;
    if matches!(
        state,
        RestoreSlotProgress::PreparedFromAbsent | RestoreSlotProgress::MovedToRollback
    ) {
        perform_observed_restore_rename(
            app_local_data_dir,
            gate,
            incoming,
            active,
            directory,
            approved_workspace,
        )?;
        hook(installed_point)?;
    }
    Ok(())
}

fn perform_observed_restore_rename(
    app_local_data_dir: &Path,
    gate: &mut PendingApplicationRestoreGate,
    from: &Path,
    to: &Path,
    directory: bool,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(), IpcError> {
    reobserve_exact_application_restore_gate(app_local_data_dir, gate, approved_workspace)?;
    if restore_path_is_present(to)? || !restore_path_is_present(from)? {
        return Err(application_restore_crash_state_error());
    }
    if directory {
        validate_restore_directory_identity(from)?;
    } else {
        validate_restore_file_identity(from)?;
        ensure_no_database_sidecars(from)?;
    }
    fs::rename(from, to).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "An authenticated full-restore component could not enter its next fixed slot.",
        )
    })?;
    *gate = observe_authenticated_application_restore_gate(app_local_data_dir, approved_workspace)?;
    Ok(())
}

fn restore_component_state_from_gate(
    gate: &PendingApplicationRestoreGate,
    active: &Path,
) -> Result<RestoreSlotProgress, IpcError> {
    let paths = application_restore_paths_from_active(active)?;
    let original_presence = marker_original_presence(&gate.marker)?;
    let (active, incoming, rollback, index) = match paths {
        RestoreGateSlotRefs::User => (
            &gate.slots.user_active,
            &gate.slots.user_incoming,
            &gate.slots.user_rollback,
            0,
        ),
        RestoreGateSlotRefs::Privacy => (
            &gate.slots.privacy_active,
            &gate.slots.privacy_incoming,
            &gate.slots.privacy_rollback,
            1,
        ),
        RestoreGateSlotRefs::Vault => (
            &gate.slots.vault_active,
            &gate.slots.vault_incoming,
            &gate.slots.vault_rollback,
            2,
        ),
        RestoreGateSlotRefs::Approved => (
            &gate.slots.approved_active,
            &gate.slots.approved_incoming,
            &gate.slots.approved_rollback,
            3,
        ),
        RestoreGateSlotRefs::WorkProducts => (
            &gate.slots.work_products_active,
            &gate.slots.work_products_incoming,
            &gate.slots.work_products_rollback,
            4,
        ),
    };
    classify_restore_slot_progress(
        active,
        incoming,
        rollback,
        original_presence.as_ref().map(|values| values[index]),
    )
}

enum RestoreGateSlotRefs {
    User,
    Privacy,
    Vault,
    Approved,
    WorkProducts,
}

fn application_restore_paths_from_active(active: &Path) -> Result<RestoreGateSlotRefs, IpcError> {
    let name = active
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    match name {
        "user.sqlite" => Ok(RestoreGateSlotRefs::User),
        "privacy-workflow.sqlite" => Ok(RestoreGateSlotRefs::Privacy),
        VAULT_DIRECTORY_NAME => Ok(RestoreGateSlotRefs::Vault),
        APPROVED_DIRECTORY_NAME => Ok(RestoreGateSlotRefs::Approved),
        WORK_PRODUCTS_DIRECTORY_NAME => Ok(RestoreGateSlotRefs::WorkProducts),
        _ => Err(application_restore_crash_state_error()),
    }
}

fn observed_original_absence(gate: &PendingApplicationRestoreGate) -> Result<[bool; 5], IpcError> {
    if let Some(original_presence) = marker_original_presence(&gate.marker)? {
        let mut absent = [false; 5];
        for (index, present) in original_presence.into_iter().enumerate() {
            absent[index] = !present;
        }
        return Ok(absent);
    }
    let mut states = vec![
        classify_restore_slot_progress(
            &gate.slots.user_active,
            &gate.slots.user_incoming,
            &gate.slots.user_rollback,
            None,
        )?,
        classify_restore_slot_progress(
            &gate.slots.privacy_active,
            &gate.slots.privacy_incoming,
            &gate.slots.privacy_rollback,
            None,
        )?,
        classify_restore_slot_progress(
            &gate.slots.vault_active,
            &gate.slots.vault_incoming,
            &gate.slots.vault_rollback,
            None,
        )?,
    ];
    if matches!(gate.marker, PendingApplicationRestore::V3(_)) {
        states.push(classify_restore_slot_progress(
            &gate.slots.approved_active,
            &gate.slots.approved_incoming,
            &gate.slots.approved_rollback,
            None,
        )?);
        states.push(classify_restore_slot_progress(
            &gate.slots.work_products_active,
            &gate.slots.work_products_incoming,
            &gate.slots.work_products_rollback,
            None,
        )?);
    }
    let mut absent = [false; 5];
    for (index, state) in states.into_iter().enumerate() {
        absent[index] = matches!(
            state,
            RestoreSlotProgress::PreparedFromAbsent
                | RestoreSlotProgress::LegacyInstalledWithoutRollback
        );
    }
    Ok(absent)
}

fn rollback_observed_application_restore(
    paths: &ApplicationRestorePaths,
    original_absent: &[bool; 5],
    v3: bool,
) -> Result<(), IpcError> {
    if v3 {
        rollback_observed_restore_directory(
            &paths.work_products_active,
            &paths.work_products_incoming,
            &paths.work_products_rollback,
            original_absent[4],
            false,
        )?;
        rollback_observed_restore_directory(
            &paths.approved_active,
            &paths.approved_incoming,
            &paths.approved_rollback,
            original_absent[3],
            false,
        )?;
    }
    rollback_observed_restore_directory(
        &paths.vault_active,
        &paths.vault_incoming,
        &paths.vault_rollback,
        original_absent[2],
        true,
    )?;
    rollback_observed_restore_file(
        &paths.privacy_active,
        &paths.privacy_incoming,
        &paths.privacy_rollback,
        original_absent[1],
    )?;
    rollback_observed_restore_file(
        &paths.user_active,
        &paths.user_incoming,
        &paths.user_rollback,
        original_absent[0],
    )
}

fn rollback_observed_restore_file(
    active: &Path,
    incoming: &Path,
    rollback: &Path,
    original_absent: bool,
) -> Result<(), IpcError> {
    if restore_path_is_present(rollback)? {
        remove_database_restore_files(active)?;
        fs::rename(rollback, active).map_err(|_| {
            ipc_error(
                "application_restore_rollback_failed",
                "An original database component could not be restored.",
            )
        })?;
    } else if original_absent && !restore_path_is_present(incoming)? {
        remove_database_restore_files(active)?;
    }
    remove_database_restore_files(incoming)
}

fn rollback_observed_restore_directory(
    active: &Path,
    incoming: &Path,
    rollback: &Path,
    original_absent: bool,
    vault: bool,
) -> Result<(), IpcError> {
    let remove = |path: &Path| {
        if vault {
            remove_vault_restore_directory(path)
        } else {
            remove_restore_directory(path)
        }
    };
    if restore_path_is_present(rollback)? {
        remove(active)?;
        fs::rename(rollback, active).map_err(|_| {
            ipc_error(
                "application_restore_rollback_failed",
                "An original directory component could not be restored.",
            )
        })?;
    } else if original_absent && !restore_path_is_present(incoming)? {
        remove(active)?;
    }
    remove(incoming)
}

fn cleanup_observed_restore_file<Hook>(
    app_local_data_dir: &Path,
    gate: &mut PendingApplicationRestoreGate,
    rollback: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
    point: ApplicationRestoreCommitPoint,
    hook: &mut Hook,
) -> Result<(), IpcError>
where
    Hook: FnMut(ApplicationRestoreCommitPoint) -> Result<(), IpcError>,
{
    if !restore_path_is_present(rollback)? {
        return Ok(());
    }
    reobserve_exact_application_restore_gate(app_local_data_dir, gate, approved_workspace)?;
    remove_database_restore_files(rollback)?;
    *gate = observe_authenticated_application_restore_gate(app_local_data_dir, approved_workspace)?;
    hook(point)
}

fn cleanup_observed_restore_directory<Hook>(
    app_local_data_dir: &Path,
    gate: &mut PendingApplicationRestoreGate,
    rollback: &Path,
    vault: bool,
    approved_workspace: &ApprovedMcpWorkspace,
    point: ApplicationRestoreCommitPoint,
    hook: &mut Hook,
) -> Result<(), IpcError>
where
    Hook: FnMut(ApplicationRestoreCommitPoint) -> Result<(), IpcError>,
{
    if !restore_path_is_present(rollback)? {
        return Ok(());
    }
    reobserve_exact_application_restore_gate(app_local_data_dir, gate, approved_workspace)?;
    if vault {
        remove_vault_restore_directory(rollback)?;
    } else {
        remove_restore_directory(rollback)?;
    }
    *gate = observe_authenticated_application_restore_gate(app_local_data_dir, approved_workspace)?;
    hook(point)
}

fn snapshot_user_database(
    app_local_data_dir: &Path,
    source_path: &Path,
    source: &mut File,
) -> Result<SensitiveBytes, IpcError> {
    if source_path != database::user_database_path(app_local_data_dir)
        || !ordinary_single_link_handle(source)
    {
        return Err(ipc_error(
            "application_backup_environment_mismatch",
            "The pinned user database is not the fixed ordinary application file.",
        ));
    }
    let expected_bytes = source
        .metadata()
        .map_err(|_| {
            ipc_error(
                "application_backup_io",
                "The pinned user database metadata could not be read.",
            )
        })?
        .len();
    let maximum = u64::try_from(MAX_USER_DATABASE_BACKUP_BYTES).map_err(|_| {
        ipc_error(
            "application_backup_io",
            "The user-database backup bound is invalid.",
        )
    })?;
    if expected_bytes == 0 || expected_bytes > maximum {
        return Err(ipc_error(
            "application_backup_invalid",
            "The pinned user database is empty or exceeds the backup limit.",
        ));
    }
    let capacity = usize::try_from(expected_bytes).map_err(|_| {
        ipc_error(
            "application_backup_invalid",
            "The pinned user database length is unsupported.",
        )
    })?;
    source.seek(SeekFrom::Start(0)).map_err(|_| {
        ipc_error(
            "application_backup_io",
            "The pinned user database could not be rewound.",
        )
    })?;
    let mut bytes = SensitiveBytes(Vec::with_capacity(capacity));
    (&mut *source)
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes.0)
        .map_err(|_| {
            ipc_error(
                "application_backup_io",
                "The pinned user database could not be read completely.",
            )
        })?;
    source.seek(SeekFrom::Start(0)).map_err(|_| {
        ipc_error(
            "application_backup_io",
            "The pinned user database could not be reset after reading.",
        )
    })?;
    if bytes.0.len() != capacity
        || !bytes.0.starts_with(b"SQLite format 3\0")
        || !ordinary_single_link_handle(source)
    {
        return Err(ipc_error(
            "application_backup_invalid",
            "The pinned user database changed or is not a canonical SQLite file.",
        ));
    }
    Ok(bytes)
}
pub(crate) fn cleanup_stale_application_backup_snapshots(
    app_local_data_dir: &Path,
) -> Result<(), IpcError> {
    if !app_local_data_dir.exists() {
        return Ok(());
    }
    if !privacy_manager::is_normal_local_absolute(app_local_data_dir)
        || !privacy_manager::local_path_chain_is_ordinary(app_local_data_dir)
    {
        return Err(ipc_error(
            "application_backup_unsafe_temporary",
            "The application data directory is not an ordinary fixed local directory.",
        ));
    }
    for entry in fs::read_dir(app_local_data_dir).map_err(|_| {
        ipc_error(
            "application_backup_cleanup_failed",
            "Application backup temporaries could not be enumerated.",
        )
    })? {
        let entry = entry.map_err(|_| {
            ipc_error(
                "application_backup_cleanup_failed",
                "An application backup temporary could not be inspected.",
            )
        })?;
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !is_application_backup_snapshot_name(&file_name) {
            continue;
        }
        let path = entry.path();
        if path.parent() != Some(app_local_data_dir) || !ordinary_single_link_file(&path) {
            return Err(ipc_error(
                "application_backup_unsafe_temporary",
                "A matching application backup temporary failed identity validation.",
            ));
        }
        fs::remove_file(path).map_err(|_| {
            ipc_error(
                "application_backup_cleanup_failed",
                "A stale sensitive application backup temporary could not be removed.",
            )
        })?;
    }
    Ok(())
}

fn is_application_backup_snapshot_name(file_name: &str) -> bool {
    if !file_name.is_ascii() {
        return false;
    }
    let base = ["-journal", "-wal", "-shm"]
        .into_iter()
        .find_map(|suffix| file_name.strip_suffix(suffix))
        .unwrap_or(file_name);
    let Some(id) = base
        .strip_prefix(".application-backup-user-")
        .and_then(|value| value.strip_suffix(".sqlite"))
    else {
        return false;
    };
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn install_and_verify_backup(
    destination: &Path,
    bytes: &[u8],
    workflow: &PrivacyWorkflowManager,
) -> Result<(), IpcError> {
    validate_new_local_file(destination)?;
    write_new_file(destination, bytes)?;
    let installed = read_local_file(destination, MAX_APPLICATION_BACKUP_BYTES)?;
    if installed.len() != bytes.len() || sha256_hex(&installed) != sha256_hex(bytes) {
        return Err(ipc_error(
            "application_backup_verify_failed",
            "完整加密备份安装后重读哈希不一致。",
        ));
    }
    let opened = open_current_application_backup(&installed, workflow)?;
    if opened.metadata.bundle_sha256 != sha256_hex(bytes) {
        return Err(ipc_error(
            "application_backup_verify_failed",
            "完整加密备份安装后认证摘要不一致。",
        ));
    }
    Ok(())
}

fn open_current_application_backup(
    bytes: &[u8],
    workflow: &PrivacyWorkflowManager,
) -> Result<privacy::OpenedApplicationBackup, IpcError> {
    open_application_backup(
        bytes,
        &ApplicationBackupOpenContext {
            expected_workspace_instance_id: &workflow.workspace_instance_id(),
            expected_app_version: env!("CARGO_PKG_VERSION"),
            expected_user_schema_version: database::USER_SCHEMA_VERSION,
            now_unix: unix_now()?,
        },
    )
    .map_err(application_backup_error)
}

fn application_restore_paths(app_local_data_dir: &Path) -> ApplicationRestorePaths {
    let approved_active = app_local_data_dir.join(APPROVED_DIRECTORY_RELATIVE);
    let work_products_active = app_local_data_dir.join(WORK_PRODUCTS_DIRECTORY_RELATIVE);
    ApplicationRestorePaths {
        marker: app_local_data_dir.join(FULL_RESTORE_MARKER_NAME),
        user_active: database::user_database_path(app_local_data_dir),
        user_incoming: app_local_data_dir.join("user.sqlite.application-restore-incoming"),
        user_rollback: app_local_data_dir.join("user.sqlite.application-restore-rollback"),
        legacy_user_incoming: app_local_data_dir.join("user.sqlite.restore-incoming"),
        legacy_user_marker: app_local_data_dir.join("user.sqlite.restore-pending.json"),
        legacy_user_rollback: app_local_data_dir.join("user.sqlite.restore-rollback"),
        privacy_active: app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE),
        privacy_incoming: app_local_data_dir.join(PRIVACY_INCOMING_RELATIVE),
        privacy_rollback: app_local_data_dir
            .join("privacy/privacy-workflow.sqlite.application-restore-rollback"),
        vault_active: app_local_data_dir.join(VAULT_DIRECTORY_NAME),
        vault_incoming: app_local_data_dir.join(format!(
            "{VAULT_DIRECTORY_NAME}.application-restore-incoming"
        )),
        vault_rollback: app_local_data_dir.join(format!(
            "{VAULT_DIRECTORY_NAME}.application-restore-rollback"
        )),
        approved_incoming: sibling_restore_path(&approved_active, "incoming"),
        approved_rollback: sibling_restore_path(&approved_active, "rollback"),
        approved_active,
        work_products_incoming: sibling_restore_path(&work_products_active, "incoming"),
        work_products_rollback: sibling_restore_path(&work_products_active, "rollback"),
        work_products_active,
    }
}

pub(crate) fn ensure_standalone_restore_is_lineage_safe(
    app_local_data_dir: &Path,
) -> Result<(), IpcError> {
    ensure_legacy_three_component_restore_is_lineage_safe(&application_restore_paths(
        app_local_data_dir,
    ))
}

fn ensure_legacy_three_component_restore_is_lineage_safe(
    paths: &ApplicationRestorePaths,
) -> Result<(), IpcError> {
    const UNIFIED_USER_STATE_TABLES: &[&str] = &["case_assistant_pending_outputs"];
    const UNIFIED_PRIVACY_STATE_TABLES: &[&str] = &[
        "privacy_materials",
        "privacy_redactions",
        "privacy_vault_material_refs",
        "case_material_selections",
        "case_material_migration_ledger",
        "case_material_migration_events",
        "case_material_legacy_references",
        "project_privacy_case_bindings",
        "project_privacy_case_binding_audit",
        "project_deletion_journal",
        "case_material_assignment_audit",
    ];
    let pending_output_state =
        restore_database_has_rows_if_present(&paths.user_active, UNIFIED_USER_STATE_TABLES, false)?;
    let unified_state = restore_database_has_rows_if_present(
        &paths.privacy_active,
        UNIFIED_PRIVACY_STATE_TABLES,
        false,
    )?;
    let approved_state = restore_workspace_component_has_state(
        &paths.approved_active,
        APPROVED_DATABASE_FILE_NAME,
        "publication_journal",
    )?;
    let work_product_state = restore_workspace_component_has_state(
        &paths.work_products_active,
        WORK_PRODUCTS_DATABASE_FILE_NAME,
        "work_product_versions",
    )?;
    if pending_output_state || unified_state || approved_state || work_product_state {
        return Err(ipc_error(
            "application_restore_requires_five_components",
            "A legacy three-component backup cannot replace a workspace that already has unified case-material, approved-generation, or work-product state. Restore an authenticated five-component backup instead.",
        ));
    }
    Ok(())
}

fn restore_database_has_rows_if_present(
    path: &Path,
    tables: &[&str],
    require_tables: bool,
) -> Result<bool, IpcError> {
    match fs::symlink_metadata(path) {
        Ok(_) => restore_database_has_rows(path, tables, require_tables),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ipc_error(
            "application_restore_lineage_unverifiable",
            "The current application lineage database could not be inspected.",
        )),
    }
}

fn restore_workspace_component_has_state(
    root: &Path,
    database_file_name: &str,
    state_table: &str,
) -> Result<bool, IpcError> {
    match fs::symlink_metadata(root) {
        Ok(_) => validate_restore_directory_identity(root)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => {
            return Err(ipc_error(
                "application_restore_lineage_unverifiable",
                "The current application workspace lineage could not be inspected.",
            ));
        }
    }
    let database_path = root.join(database_file_name);
    if !restore_path_is_present(&database_path)? {
        let is_empty = fs::read_dir(root)
            .map_err(|_| {
                ipc_error(
                    "application_restore_lineage_unverifiable",
                    "The current application workspace lineage could not be enumerated.",
                )
            })?
            .next()
            .is_none();
        return if is_empty {
            Ok(false)
        } else {
            Err(ipc_error(
                "application_restore_lineage_unverifiable",
                "The current application workspace has state but no verifiable lineage database.",
            ))
        };
    }
    if restore_database_has_rows(&database_path, &[state_table], true)? {
        return Ok(true);
    }
    let database_sidecars = [
        database_file_name.to_owned(),
        format!("{database_file_name}-journal"),
        format!("{database_file_name}-wal"),
        format!("{database_file_name}-shm"),
    ];
    for entry in fs::read_dir(root).map_err(|_| {
        ipc_error(
            "application_restore_lineage_unverifiable",
            "The current application workspace lineage could not be enumerated.",
        )
    })? {
        let entry = entry.map_err(|_| {
            ipc_error(
                "application_restore_lineage_unverifiable",
                "The current application workspace lineage contains an unreadable entry.",
            )
        })?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !database_sidecars
            .iter()
            .any(|candidate| candidate == &file_name)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn restore_database_has_rows(
    path: &Path,
    tables: &[&str],
    require_tables: bool,
) -> Result<bool, IpcError> {
    if !ordinary_single_link_file(path) {
        return Err(ipc_error(
            "application_restore_lineage_unverifiable",
            "The current application lineage database is not an ordinary single-link local file.",
        ));
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| {
        ipc_error(
            "application_restore_lineage_unverifiable",
            "The current application lineage database could not be opened read-only.",
        )
    })?;
    connection
        .execute_batch(
            "PRAGMA query_only=ON;
             PRAGMA trusted_schema=OFF;
             BEGIN DEFERRED;",
        )
        .map_err(|_| {
            ipc_error(
                "application_restore_lineage_unverifiable",
                "The current application lineage snapshot could not begin.",
            )
        })?;
    let result = (|| {
        for table in tables {
            let exists: i64 = connection
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM sqlite_master
                         WHERE type='table' AND name=?1
                     )",
                    [table],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ipc_error(
                        "application_restore_lineage_unverifiable",
                        "The current application lineage schema could not be inspected.",
                    )
                })?;
            if exists == 0 {
                if require_tables {
                    return Err(ipc_error(
                        "application_restore_lineage_unverifiable",
                        "The current application lineage database is missing a required state table.",
                    ));
                }
                continue;
            }
            let quoted = table.replace('"', "\"\"");
            let has_rows: i64 = connection
                .query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM \"{quoted}\" LIMIT 1)"),
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| {
                    ipc_error(
                        "application_restore_lineage_unverifiable",
                        "The current application lineage state could not be inspected.",
                    )
                })?;
            if has_rows != 0 {
                return Ok(true);
            }
        }
        Ok(false)
    })();
    let rollback = connection.execute_batch("ROLLBACK").map_err(|_| {
        ipc_error(
            "application_restore_lineage_unverifiable",
            "The current application lineage snapshot could not be closed.",
        )
    });
    rollback?;
    result
}

fn sibling_restore_path(active: &Path, suffix: &str) -> PathBuf {
    let mut value = active.as_os_str().to_os_string();
    value.push(format!(".application-restore-{suffix}"));
    PathBuf::from(value)
}

fn exact_vault_replacement_summary(
    path: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<privacy::VaultBackupSummaryV1, IpcError> {
    validate_restore_directory_identity(path)?;
    ensure_no_vault_database_sidecars(path)?;
    let (store, _schema_upgrade_required) =
        VaultStore::open_for_application_startup(path, workspace_instance_id.clone())
            .map_err(vault_store_error)?;
    let isolation = store.isolation_status().map_err(vault_store_error)?;
    if !isolation.private_acl_enforced
        || !isolation.content_indexing_disabled
        || !isolation.encrypted_at_rest
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "The staged Vault did not retain its private ACL, no-index, and encryption controls.",
        ));
    }
    let (_archive, summary) =
        privacy::export_encrypted_vault_backup_read_only(&store).map_err(vault_backup_error)?;
    Ok(summary)
}

fn validate_original_vault_restore_component(
    path: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<(), IpcError> {
    validate_restore_directory_identity(path)?;
    let (store, _schema_upgrade_required) =
        VaultStore::open_for_application_startup(path, workspace_instance_id.clone())
            .map_err(vault_store_error)?;
    let isolation = store.isolation_status().map_err(vault_store_error)?;
    if !isolation.private_acl_enforced
        || !isolation.content_indexing_disabled
        || !isolation.encrypted_at_rest
    {
        return Err(ipc_error(
            "application_restore_lineage_unverifiable",
            "The original Vault lineage did not retain its private ACL, no-index, and encryption controls.",
        ));
    }
    privacy::validate_encrypted_vault_lineage_read_only(&store).map_err(|_| {
        ipc_error(
            "application_restore_lineage_unverifiable",
            "The original Vault restore lineage is not an exact supported profile.",
        )
    })
}

fn ensure_no_vault_database_sidecars(path: &Path) -> Result<(), IpcError> {
    for name in [
        "vault-state.sqlite-journal",
        "vault-state.sqlite-wal",
        "vault-state.sqlite-shm",
    ] {
        if restore_path_is_present(&path.join(name))? {
            return Err(ipc_error(
                "application_restore_conflict",
                "A staged Vault replacement has an unexpected journal or WAL sidecar.",
            ));
        }
    }
    Ok(())
}

fn validate_vault_component(
    path: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    expected_manifest_sha256: &str,
    expected_archive_sha256: &str,
) -> Result<(), IpcError> {
    let summary = exact_vault_replacement_summary(path, workspace_instance_id)?;
    if summary.manifest_sha256.as_str() != expected_manifest_sha256
        || summary.archive_sha256.as_str() != expected_archive_sha256
    {
        return Err(ipc_error(
            "application_restore_tampered",
            "The staged Vault manifest or encrypted archive hash changed.",
        ));
    }
    Ok(())
}

fn ensure_pair_restore_slot_empty(paths: &ApplicationRestorePaths) -> Result<(), IpcError> {
    for path in [
        &paths.marker,
        &paths.user_incoming,
        &paths.user_rollback,
        &paths.legacy_user_incoming,
        &paths.legacy_user_marker,
        &paths.legacy_user_rollback,
        &paths.privacy_incoming,
        &paths.privacy_rollback,
        &paths.vault_incoming,
        &paths.vault_rollback,
        &paths.approved_incoming,
        &paths.approved_rollback,
        &paths.work_products_incoming,
        &paths.work_products_rollback,
    ] {
        if restore_path_is_present(path)? {
            return Err(ipc_error(
                "application_restore_conflict",
                "A fixed application restore transaction slot is already occupied.",
            ));
        }
    }
    Ok(())
}

fn finish_pair_restore_stage(
    paths: &ApplicationRestorePaths,
    result: Result<(), IpcError>,
) -> Result<(), IpcError> {
    match result {
        Ok(()) => Ok(()),
        Err(original) => match cleanup_pair_incoming(paths) {
            Ok(()) => Err(original),
            Err(cleanup_error) => Err(cleanup_error),
        },
    }
}

fn cleanup_pair_incoming(paths: &ApplicationRestorePaths) -> Result<(), IpcError> {
    let mut cleanup_error = None;
    record_cleanup_error(
        &mut cleanup_error,
        remove_database_restore_files(&paths.user_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_database_restore_files(&paths.privacy_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_vault_restore_directory(&paths.vault_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_restore_directory(&paths.approved_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_restore_directory(&paths.work_products_incoming),
    );
    record_cleanup_error(&mut cleanup_error, remove_if_exists(&paths.marker));
    cleanup_error.map_or(Ok(()), Err)
}

#[cfg(test)]
fn cleanup_unmarked_pair_incoming(paths: &ApplicationRestorePaths) -> Result<(), IpcError> {
    if restore_path_is_present(&paths.user_rollback)?
        || restore_path_is_present(&paths.privacy_rollback)?
        || restore_path_is_present(&paths.vault_rollback)?
        || restore_path_is_present(&paths.approved_rollback)?
        || restore_path_is_present(&paths.work_products_rollback)?
    {
        return Err(ipc_error(
            "application_restore_conflict",
            "An unmarked application restore rollback residue requires explicit recovery.",
        ));
    }
    let mut cleanup_error = None;
    record_cleanup_error(
        &mut cleanup_error,
        remove_database_restore_files(&paths.user_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_database_restore_files(&paths.privacy_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_vault_restore_directory(&paths.vault_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_restore_directory(&paths.approved_incoming),
    );
    record_cleanup_error(
        &mut cleanup_error,
        remove_restore_directory(&paths.work_products_incoming),
    );
    cleanup_error.map_or(Ok(()), Err)
}

fn record_cleanup_error(slot: &mut Option<IpcError>, result: Result<(), IpcError>) {
    if let Err(error) = result {
        if slot.is_none() {
            *slot = Some(error);
        }
    }
}

fn remove_database_restore_files(path: &Path) -> Result<(), IpcError> {
    let mut cleanup_error = None;
    for candidate in [
        sqlite_sidecar_path(path, "-journal"),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
        path.to_path_buf(),
    ] {
        record_cleanup_error(&mut cleanup_error, remove_if_exists(&candidate));
    }
    cleanup_error.map_or(Ok(()), Err)
}

fn ensure_no_database_sidecars(path: &Path) -> Result<(), IpcError> {
    for candidate in [
        sqlite_sidecar_path(path, "-journal"),
        sqlite_sidecar_path(path, "-wal"),
        sqlite_sidecar_path(path, "-shm"),
    ] {
        if restore_path_is_present(&candidate)? {
            return Err(ipc_error(
                "application_restore_conflict",
                "A SQLite restore component has an unexpected journal or WAL sidecar.",
            ));
        }
    }
    Ok(())
}

fn sqlite_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}
fn validate_pair_marker(
    marker: &PendingApplicationRestore,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<(), IpcError> {
    let valid = match marker {
        PendingApplicationRestore::V2(marker) => {
            marker.format_version == FULL_RESTORE_FORMAT_VERSION
                && validate_pair_marker_common(
                    &marker.backup_id,
                    &marker.privacy_backup_id,
                    &marker.workspace_instance_id,
                    &marker.app_version,
                    marker.user_schema_version,
                    &marker.user_database_sha256,
                    &marker.privacy_database_sha256,
                    marker.privacy_key_epoch,
                    &marker.vault_manifest_sha256,
                    &marker.vault_archive_sha256,
                    workspace_instance_id,
                )
        }
        PendingApplicationRestore::V3(marker) => {
            marker.format_version == FULL_RESTORE_V3_FORMAT_VERSION
                && validate_pair_marker_common(
                    &marker.backup_id,
                    &marker.privacy_backup_id,
                    &marker.workspace_instance_id,
                    &marker.app_version,
                    marker.user_schema_version,
                    &marker.user_database_sha256,
                    &marker.privacy_database_sha256,
                    marker.privacy_key_epoch,
                    &marker.vault_manifest_sha256,
                    &marker.vault_archive_sha256,
                    workspace_instance_id,
                )
                && marker
                    .privacy_store_schema_version
                    .is_none_or(supported_restored_privacy_schema)
                && is_hash(&marker.approved_workspace_bundle_sha256)
                && is_hash(&marker.approved_workspace_manifest_sha256)
                && is_hash(&marker.work_products_bundle_sha256)
                && is_hash(&marker.work_products_manifest_sha256)
        }
    };
    if !valid {
        return Err(ipc_error(
            "application_restore_environment_mismatch",
            "完整恢复标记与当前应用、schema 或工作区不匹配。",
        ));
    }
    Ok(())
}

fn supported_restored_privacy_schema(schema_version: i64) -> bool {
    (1..=5).contains(&schema_version) || schema_version == PRIVACY_STORE_SCHEMA_VERSION
}

#[allow(clippy::too_many_arguments)]
fn validate_pair_marker_common(
    backup_id: &str,
    privacy_backup_id: &str,
    marker_workspace_instance_id: &str,
    app_version: &str,
    user_schema_version: i64,
    user_database_sha256: &str,
    privacy_database_sha256: &str,
    privacy_key_epoch: u64,
    vault_manifest_sha256: &str,
    vault_archive_sha256: &str,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> bool {
    marker_workspace_instance_id == workspace_instance_id.as_str()
        && app_version == env!("CARGO_PKG_VERSION")
        && user_schema_version == database::USER_SCHEMA_VERSION
        && privacy_key_epoch > 0
        && backup_id.starts_with("appbkp_")
        && privacy_backup_id.starts_with("bkp_")
        && is_hash(user_database_sha256)
        && is_hash(privacy_database_sha256)
        && is_hash(vault_manifest_sha256)
        && is_hash(vault_archive_sha256)
}

fn write_pair_marker(path: &Path, marker: &PendingApplicationRestore) -> Result<(), IpcError> {
    let plaintext = privacy::vnext::canonical_json_v1(marker)
        .map_err(|_| ipc_error("application_restore_invalid", "完整恢复标记无法编码。"))?;
    let protected = protect_local(&plaintext).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "完整恢复标记无法通过 DPAPI 保护。",
        )
    })?;
    if protected.is_empty() || protected.len() > FULL_RESTORE_MARKER_MAX_BYTES {
        return Err(ipc_error(
            "application_restore_invalid",
            "完整恢复标记大小无效。",
        ));
    }
    write_new_file(path, &protected)
}

#[cfg(test)]
fn read_pair_marker(path: &Path) -> Result<PendingApplicationRestore, IpcError> {
    let protected = read_local_file(path, FULL_RESTORE_MARKER_MAX_BYTES)?;
    let plaintext = SensitiveBytes(unprotect_local(&protected).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "完整恢复标记 DPAPI 认证失败。",
        )
    })?);
    let marker: PendingApplicationRestore =
        privacy::vnext::strict_json_v1_from_slice(plaintext.as_slice())
            .map_err(|_| ipc_error("application_restore_invalid", "完整恢复标记格式无效。"))?;
    if privacy::vnext::canonical_json_v1(&marker)
        .map_err(|_| ipc_error("application_restore_invalid", "完整恢复标记格式无效。"))?
        != plaintext.as_slice()
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "完整恢复标记不是规范编码。",
        ));
    }
    Ok(marker)
}

fn validate_user_component(path: &Path, expected_sha256: &str) -> Result<(), IpcError> {
    if file_sha256(path, MAX_USER_DATABASE_BACKUP_BYTES)? != expected_sha256 {
        return Err(ipc_error(
            "application_restore_tampered",
            "主案件数据库恢复组件哈希不匹配。",
        ));
    }
    database::validate_user_database_read_only(path).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "主案件数据库恢复组件未通过 schema、完整性或外键验证。",
        )
    })
}

fn validate_privacy_component(
    path: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    expected_key_epoch: u64,
    expected_privacy_store_schema_version: i64,
    expected_sha256: &str,
) -> Result<(), IpcError> {
    let maximum_bytes = privacy_database_backup_maximum(expected_privacy_store_schema_version)?;
    if file_sha256(path, maximum_bytes)? != expected_sha256 {
        return Err(ipc_error(
            "application_restore_tampered",
            "隐私数据库恢复组件哈希不匹配。",
        ));
    }
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| ipc_error("application_restore_invalid", "隐私恢复组件无法只读打开。"))?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| {
            ipc_error(
                "application_restore_invalid",
                "隐私恢复组件完整性检查失败。",
            )
        })?;
    let foreign_keys: i64 = connection
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|_| ipc_error("application_restore_invalid", "隐私恢复组件外键检查失败。"))?;
    let lifecycle =
        PrivacyLifecycle::open(&connection, workspace_instance_id.clone()).map_err(|_| {
            ipc_error(
                "application_restore_invalid",
                "隐私恢复组件工作区绑定无效。",
            )
        })?;
    let schema_matches = match PrivacyStore::preflight_schema(&connection) {
        Ok(PrivacyStoreSchemaStatus::Current) => {
            expected_privacy_store_schema_version == PRIVACY_STORE_SCHEMA_VERSION
        }
        Ok(PrivacyStoreSchemaStatus::UpgradeRequired { found_version }) => {
            supported_restored_privacy_schema(found_version)
                && found_version == expected_privacy_store_schema_version
        }
        Ok(PrivacyStoreSchemaStatus::Empty) | Err(_) => false,
    };
    if integrity != "ok"
        || foreign_keys != 0
        || !schema_matches
        || lifecycle
            .current_key_epoch(&connection)
            .map_err(|_| ipc_error("application_restore_invalid", "隐私恢复组件 epoch 无效。"))?
            != expected_key_epoch
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "隐私恢复组件未通过完整性、外键或密钥 epoch 验证。",
        ));
    }
    Ok(())
}

fn privacy_database_backup_maximum(schema_version: i64) -> Result<usize, IpcError> {
    privacy::lifecycle::max_backup_database_bytes_for_schema(schema_version).ok_or_else(|| {
        ipc_error(
            "application_restore_invalid",
            "隐私数据库恢复组件 schema 不受当前版本支持。",
        )
    })
}

fn validate_new_local_file(path: &Path) -> Result<(), IpcError> {
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || path.extension().and_then(|value| value.to_str()) != Some(FULL_BACKUP_EXTENSION)
        || path.exists()
    {
        return Err(ipc_error(
            "application_backup_invalid_destination",
            "完整备份目标必须是本机固定磁盘上的新 .lavbackup 文件，且不会覆盖现有文件。",
        ));
    }
    Ok(())
}

fn read_local_file(path: &Path, maximum: usize) -> Result<Vec<u8>, IpcError> {
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(ipc_error(
            "application_backup_invalid_source",
            "完整备份来源必须是本机固定磁盘普通文件。",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ipc_error("application_backup_io", "完整备份文件无法读取。"))?;
    if !ordinary_single_link_handle(&file) {
        return Err(ipc_error(
            "application_backup_invalid_source",
            "完整备份文件不能是链接、reparse point、云占位或硬链接。",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((maximum as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ipc_error("application_backup_io", "完整备份文件读取失败。"))?;
    if bytes.is_empty() || bytes.len() > maximum || !ordinary_single_link_handle(&file) {
        return Err(ipc_error(
            "application_backup_too_large",
            "完整备份文件为空、超出上限或读取期间身份变化。",
        ));
    }
    Ok(bytes)
}

fn write_sensitive_new_file(path: &Path, bytes: &[u8]) -> Result<(), IpcError> {
    write_new_file(path, bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), IpcError> {
    let parent = path.parent().ok_or_else(|| {
        ipc_error(
            "application_backup_invalid_destination",
            "完整备份文件缺少父目录。",
        )
    })?;
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !parent.is_dir()
    {
        return Err(ipc_error(
            "application_backup_invalid_destination",
            "完整备份写入路径不是本机固定磁盘普通目录。",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| ipc_error("application_backup_io", "完整备份目标无法以新文件创建。"))?;
    if !ordinary_single_link_handle(&file) {
        return Err(ipc_error(
            "application_backup_invalid_destination",
            "完整备份目标不是本机单链接普通文件。",
        ));
    }
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ipc_error("application_backup_io", "完整备份文件无法完整同步。"))?;
    if !ordinary_single_link_handle(&file) {
        return Err(ipc_error(
            "application_backup_invalid_destination",
            "完整备份文件写入期间身份变化。",
        ));
    }
    Ok(())
}

fn ordinary_single_link_file(path: &Path) -> bool {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .is_ok_and(|file| ordinary_single_link_handle(&file))
}

fn ordinary_single_link_handle(file: &File) -> bool {
    if !privacy_manager::opened_file_resolves_to_ordinary_local(file) {
        return false;
    }
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || privacy_manager::has_cloud_recall_attributes(&metadata)
    {
        return false;
    }
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    !handle.is_null()
        && unsafe { GetFileInformationByHandle(handle, &mut information) } != 0
        && information.nNumberOfLinks == 1
}

fn file_sha256(path: &Path, maximum: usize) -> Result<String, IpcError> {
    let bytes = SensitiveBytes(read_local_file(path, maximum)?);
    Ok(sha256_hex(bytes.as_slice()))
}

fn force_extension(path: &mut PathBuf) {
    if path.extension().and_then(|value| value.to_str()) != Some(FULL_BACKUP_EXTENSION) {
        path.set_extension(FULL_BACKUP_EXTENSION);
    }
}

fn safe_file_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .unwrap_or(FULL_BACKUP_DEFAULT_NAME)
        .to_owned()
}

fn restore_path_is_present(path: &Path) -> Result<bool, IpcError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(ipc_error(
            "application_restore_io",
            "A fixed restore transaction path could not be inspected.",
        )),
    }
}

fn validate_restore_file_identity(path: &Path) -> Result<(), IpcError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "A fixed restore transaction file could not be inspected.",
        )
    })?;
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_file()
        || !ordinary_single_link_file(path)
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "A restore transaction file is not an ordinary single-link fixed local file.",
        ));
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<(), IpcError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(ipc_error(
                "application_restore_cleanup_failed",
                "A fixed restore transaction path could not be inspected for cleanup.",
            ));
        }
    };
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_file()
        || !ordinary_single_link_file(path)
    {
        return Err(ipc_error(
            "application_restore_unsafe_cleanup",
            "Cleanup refused a restore transaction path that is not an ordinary single-link local file.",
        ));
    }
    fs::remove_file(path).map_err(|_| {
        ipc_error(
            "application_restore_cleanup_failed",
            "A sensitive restore transaction file could not be removed.",
        )
    })?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(ipc_error(
            "application_restore_cleanup_failed",
            "A sensitive restore transaction path remains after cleanup.",
        )),
    }
}
fn validate_restore_directory_identity(path: &Path) -> Result<(), IpcError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ipc_error(
            "application_restore_invalid",
            "A fixed Vault restore directory could not be inspected.",
        )
    })?;
    if !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
        || !metadata.is_dir()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(ipc_error(
            "application_restore_invalid",
            "A Vault restore path is not an ordinary fixed local directory.",
        ));
    }
    Ok(())
}

fn validate_vault_cleanup_tree(root: &Path, current: &Path) -> Result<(), IpcError> {
    let metadata = fs::symlink_metadata(current).map_err(|_| {
        ipc_error(
            "application_restore_cleanup_failed",
            "A Vault restore cleanup path could not be inspected.",
        )
    })?;
    if !current.starts_with(root) || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(ipc_error(
            "application_restore_unsafe_cleanup",
            "Vault cleanup refused a reparse point or path outside its fixed slot.",
        ));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(current).map_err(|_| {
            ipc_error(
                "application_restore_cleanup_failed",
                "A Vault restore directory could not be enumerated for cleanup.",
            )
        })? {
            let entry = entry.map_err(|_| {
                ipc_error(
                    "application_restore_cleanup_failed",
                    "A Vault restore entry could not be inspected for cleanup.",
                )
            })?;
            validate_vault_cleanup_tree(root, &entry.path())?;
        }
        Ok(())
    } else if metadata.is_file() && ordinary_single_link_file(current) {
        Ok(())
    } else {
        Err(ipc_error(
            "application_restore_unsafe_cleanup",
            "Vault cleanup refused a non-ordinary or hardlinked file.",
        ))
    }
}

fn remove_vault_restore_directory(path: &Path) -> Result<(), IpcError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(ipc_error(
                "application_restore_cleanup_failed",
                "A fixed Vault restore path could not be inspected for cleanup.",
            ));
        }
    };
    let allowed_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                VAULT_DIRECTORY_NAME
                    | "case-vault-v2.application-restore-incoming"
                    | "case-vault-v2.application-restore-rollback"
            )
        });
    if !allowed_name || !metadata.is_dir() {
        return Err(ipc_error(
            "application_restore_unsafe_cleanup",
            "Vault cleanup refused a path outside the three exact restore slots.",
        ));
    }
    validate_restore_directory_identity(path)?;
    validate_vault_cleanup_tree(path, path)?;
    fs::remove_dir_all(path).map_err(|_| {
        ipc_error(
            "application_restore_cleanup_failed",
            "The fixed Vault restore directory could not be removed.",
        )
    })?;
    if restore_path_is_present(path)? {
        return Err(ipc_error(
            "application_restore_cleanup_failed",
            "A Vault restore directory remains after cleanup.",
        ));
    }
    Ok(())
}

fn remove_restore_directory(path: &Path) -> Result<(), IpcError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(ipc_error(
                "application_restore_cleanup_failed",
                "A fixed application restore directory could not be inspected for cleanup.",
            ));
        }
    };
    let allowed_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                APPROVED_DIRECTORY_NAME
                    | "approved-generations.application-restore-incoming"
                    | "approved-generations.application-restore-rollback"
                    | WORK_PRODUCTS_DIRECTORY_NAME
                    | "work-products.application-restore-incoming"
                    | "work-products.application-restore-rollback"
            )
        });
    if !allowed_name || !metadata.is_dir() {
        return Err(ipc_error(
            "application_restore_unsafe_cleanup",
            "Application restore cleanup refused a directory outside its exact fixed slots.",
        ));
    }
    validate_restore_directory_identity(path)?;
    validate_vault_cleanup_tree(path, path)?;
    fs::remove_dir_all(path).map_err(|_| {
        ipc_error(
            "application_restore_cleanup_failed",
            "A fixed application restore directory could not be removed.",
        )
    })?;
    if restore_path_is_present(path)? {
        return Err(ipc_error(
            "application_restore_cleanup_failed",
            "An application restore directory remains after cleanup.",
        ));
    }
    Ok(())
}
fn cancelled_response() -> ApplicationBackupResponse {
    ApplicationBackupResponse {
        cancelled: true,
        file_name: None,
        metadata: None,
        restart_required: false,
    }
}

fn unix_now() -> Result<u64, IpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ipc_error("application_backup_clock", "系统时钟早于 Unix epoch。"))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn workflow_error(error: crate::privacy_workflow::PrivacyWorkflowError) -> IpcError {
    ipc_error(error.code(), error.message())
}

fn vault_backup_error(error: privacy::VaultBackupError) -> IpcError {
    ipc_error(
        error.code(),
        "The encrypted Vault backup failed authentication, bounds, or fixed-local-storage checks.",
    )
}

fn vault_store_error(error: privacy::vault_store::VaultStoreError) -> IpcError {
    ipc_error(
        error.code(),
        "The restored Vault failed database, key, object, ACL, or filesystem verification.",
    )
}

fn approved_mcp_error(error: crate::approved_mcp::ApprovedMcpError) -> IpcError {
    ipc_error(error.code(), error.message())
}
fn application_backup_error(error: privacy::ApplicationBackupError) -> IpcError {
    ipc_error(error.code(), "完整加密备份认证、环境绑定或有效期验证失败。")
}

fn ipc_error(error_type: &str, message: &str) -> IpcError {
    IpcError {
        error_type: error_type.to_owned(),
        message: providers::redact_sensitive(message),
    }
}

#[cfg(all(test, windows))]
#[path = "application_backup_tests.rs"]
mod tests;
