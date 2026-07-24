#![allow(unsafe_code)]

use super::privacy_workflow::IpcError;
use crate::{
    approved_mcp::ApprovedMcpWorkspace,
    privacy_manager,
    privacy_workflow::{ApplicationBackupPrivacyGuard, PrivacyWorkflowManager},
    state::AppState,
};
use privacy::vault_store::VaultStore;
use privacy::{
    open_application_backup, protect_local, seal_application_backup, seal_application_backup_v3,
    sha256_hex, stage_encrypted_vault_backup, unprotect_local, ApplicationBackupCreateRequest,
    ApplicationBackupCreateRequestV3, ApplicationBackupMetadata, ApplicationBackupOpenContext,
    PrivacyLifecycle, MAX_APPLICATION_BACKUP_BYTES, MAX_USER_DATABASE_BACKUP_BYTES,
};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
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
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
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
const APPROVED_DIRECTORY_RELATIVE: &str = "privacy/approved-mcp/approved-generations";
const WORK_PRODUCTS_DIRECTORY_RELATIVE: &str = "privacy/approved-mcp/work-products";
pub const FULL_RESTORE_CONFIRMATION: &str = "恢复完整应用备份";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationBackupResponse {
    pub cancelled: bool,
    pub file_name: Option<String>,
    pub metadata: Option<ApplicationBackupMetadata>,
    pub restart_required: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageApplicationRestoreRequest {
    pub confirmation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingApplicationRestoreV2 {
    format_version: u16,
    backup_id: String,
    privacy_backup_id: String,
    workspace_instance_id: String,
    app_version: String,
    user_schema_version: i64,
    user_database_sha256: String,
    privacy_database_sha256: String,
    privacy_key_epoch: u64,
    vault_manifest_sha256: String,
    vault_archive_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PendingApplicationRestoreV3 {
    format_version: u16,
    backup_id: String,
    privacy_backup_id: String,
    workspace_instance_id: String,
    app_version: String,
    user_schema_version: i64,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let metadata = stage_application_restore_bytes_with_approved(
            &app_local_data_dir,
            state.user_database_path(),
            &workflow,
            &approved_workspace,
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
    build_application_backup_internal(
        app_local_data_dir,
        state,
        workflow,
        Some(approved_workspace),
        || {},
    )
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
    build_application_backup_internal(app_local_data_dir, state, workflow, None, lock_hook)
}

fn build_application_backup_internal<Hook>(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    lock_hook: Hook,
) -> Result<(Vec<u8>, ApplicationBackupMetadata, String), IpcError>
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
    let result = match approved_snapshot {
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
        Ok((bytes, metadata)) => Ok((bytes, metadata, privacy_backup.backup_id)),
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
    let connection = database::open_existing_user_database(source_path).map_err(|_| {
        ipc_error(
            "application_backup_invalid",
            "The fixed user database could not be opened without creating a replacement.",
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
    connection.execute_batch("BEGIN IMMEDIATE").map_err(|_| {
        ipc_error(
            "application_backup_busy",
            "The user database could not enter the coherent backup window.",
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
            "The user database left canonical DELETE journal mode before the coherent lock.",
        );
        return match rollback_user_snapshot(&connection) {
            Ok(()) => Err(original),
            Err(rollback_error) => Err(rollback_error),
        };
    }
    database::validate_open_user_database(&connection).map_err(|_| {
        ipc_error(
            "application_backup_invalid",
            "The locked user database failed canonical schema and integrity validation.",
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
    BeforeProtectedMarker,
}

fn stage_application_restore_bytes_with_hook<Hook>(
    app_local_data_dir: &Path,
    expected_user_database_path: &Path,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    bytes: &[u8],
    mut hook: Hook,
) -> Result<ApplicationBackupMetadata, IpcError>
where
    Hook: FnMut(ApplicationRestoreStagePoint) -> Result<(), IpcError>,
{
    let opened = open_current_application_backup(bytes, workflow)?;
    let paths = application_restore_paths(app_local_data_dir);
    if paths.user_active != expected_user_database_path {
        return Err(ipc_error(
            "application_restore_environment_mismatch",
            "主案件数据库固定路径与当前进程状态不一致。",
        ));
    }
    ensure_pair_restore_slot_empty(&paths)?;
    let result = (|| {
        write_sensitive_new_file(&paths.user_incoming, &opened.user_database)?;
        validate_user_component(&paths.user_incoming, &opened.metadata.user_database_sha256)?;
        let privacy = workflow
            .stage_application_privacy_component(
                &opened.metadata.privacy_backup_id,
                &opened.encrypted_privacy_bundle,
            )
            .map_err(workflow_error)?;
        if privacy.database_sha256.is_empty()
            || privacy.workspace_instance_id != opened.metadata.workspace_instance_id.as_str()
        {
            return Err(ipc_error(
                "application_backup_component_mismatch",
                "隐私备份组件与完整备份清单不一致。",
            ));
        }
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
                    app_version: opened.metadata.app_version.clone(),
                    user_schema_version: opened.metadata.user_schema_version,
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
                    app_version: opened.metadata.app_version.clone(),
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

#[cfg(test)]
pub(crate) fn apply_pending_application_restore(
    app_local_data_dir: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<(), IpcError> {
    apply_pending_application_restore_internal(app_local_data_dir, workspace_instance_id, None)
}

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

fn apply_pending_application_restore_internal(
    app_local_data_dir: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
) -> Result<(), IpcError> {
    apply_pending_application_restore_with_hook(
        app_local_data_dir,
        workspace_instance_id,
        approved_workspace,
        |_| Ok(()),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplicationRestoreCommitPoint {
    UserInstalled,
    PrivacyInstalled,
    VaultInstalled,
    ApprovedWorkspaceInstalled,
    WorkProductsInstalled,
    CredentialsInvalidated,
}

fn apply_pending_application_restore_with_hook<Hook>(
    app_local_data_dir: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    approved_workspace: Option<&ApprovedMcpWorkspace>,
    mut hook: Hook,
) -> Result<(), IpcError>
where
    Hook: FnMut(ApplicationRestoreCommitPoint) -> Result<(), IpcError>,
{
    let paths = application_restore_paths(app_local_data_dir);
    if !restore_path_is_present(&paths.marker)? {
        cleanup_unmarked_pair_incoming(&paths)?;
        return Ok(());
    }
    ensure_no_legacy_user_restore(&paths)?;
    let marker = read_pair_marker(&paths.marker)?;
    validate_pair_marker(&marker, workspace_instance_id)?;
    let (
        user_database_sha256,
        privacy_database_sha256,
        privacy_key_epoch,
        vault_manifest_sha256,
        vault_archive_sha256,
    ) = match &marker {
        PendingApplicationRestore::V2(marker) => (
            marker.user_database_sha256.as_str(),
            marker.privacy_database_sha256.as_str(),
            marker.privacy_key_epoch,
            marker.vault_manifest_sha256.as_str(),
            marker.vault_archive_sha256.as_str(),
        ),
        PendingApplicationRestore::V3(marker) => (
            marker.user_database_sha256.as_str(),
            marker.privacy_database_sha256.as_str(),
            marker.privacy_key_epoch,
            marker.vault_manifest_sha256.as_str(),
            marker.vault_archive_sha256.as_str(),
        ),
    };
    let result = (|| {
        if let PendingApplicationRestore::V3(marker) = &marker {
            let approved_candidate = pending_directory_candidate(
                &paths.approved_active,
                &paths.approved_incoming,
                &paths.approved_rollback,
            )?;
            let work_products_candidate = pending_directory_candidate(
                &paths.work_products_active,
                &paths.work_products_incoming,
                &paths.work_products_rollback,
            )?;
            approved_workspace
                .ok_or_else(|| {
                    ipc_error(
                        "application_restore_environment_mismatch",
                        "The approved workspace restore manager is unavailable.",
                    )
                })?
                .validate_staged_application_backup_manifests(
                    approved_candidate,
                    &marker.approved_workspace_manifest_sha256,
                    work_products_candidate,
                    &marker.work_products_manifest_sha256,
                )
                .map_err(approved_mcp_error)?;
        }
        advance_component(
            &paths.user_active,
            &paths.user_incoming,
            &paths.user_rollback,
            user_database_sha256,
            |path| validate_user_component(path, user_database_sha256),
        )?;
        hook(ApplicationRestoreCommitPoint::UserInstalled)?;
        advance_component(
            &paths.privacy_active,
            &paths.privacy_incoming,
            &paths.privacy_rollback,
            privacy_database_sha256,
            |path| {
                validate_privacy_component(
                    path,
                    workspace_instance_id,
                    privacy_key_epoch,
                    privacy_database_sha256,
                )
            },
        )?;
        hook(ApplicationRestoreCommitPoint::PrivacyInstalled)?;
        advance_vault_component(
            &paths.vault_active,
            &paths.vault_incoming,
            &paths.vault_rollback,
            workspace_instance_id,
            vault_manifest_sha256,
            vault_archive_sha256,
        )?;
        hook(ApplicationRestoreCommitPoint::VaultInstalled)?;
        if let PendingApplicationRestore::V3(marker) = &marker {
            advance_restore_directory(
                &paths.approved_active,
                &paths.approved_incoming,
                &paths.approved_rollback,
            )?;
            hook(ApplicationRestoreCommitPoint::ApprovedWorkspaceInstalled)?;
            advance_restore_directory(
                &paths.work_products_active,
                &paths.work_products_incoming,
                &paths.work_products_rollback,
            )?;
            hook(ApplicationRestoreCommitPoint::WorkProductsInstalled)?;
            let approved_workspace = approved_workspace.ok_or_else(|| {
                ipc_error(
                    "application_restore_environment_mismatch",
                    "The approved workspace restore manager is unavailable.",
                )
            })?;
            approved_workspace
                .validate_staged_application_backup_manifests(
                    &paths.approved_active,
                    &marker.approved_workspace_manifest_sha256,
                    &paths.work_products_active,
                    &marker.work_products_manifest_sha256,
                )
                .map_err(approved_mcp_error)?;
            approved_workspace
                .invalidate_after_application_restore()
                .map_err(approved_mcp_error)?;
            hook(ApplicationRestoreCommitPoint::CredentialsInvalidated)?;
            if !is_hash(&marker.approved_workspace_bundle_sha256)
                || !is_hash(&marker.work_products_bundle_sha256)
            {
                return Err(ipc_error(
                    "application_restore_tampered",
                    "The approved workspace restore binding is invalid.",
                ));
            }
        }
        validate_user_component(&paths.user_active, user_database_sha256)?;
        validate_privacy_component(
            &paths.privacy_active,
            workspace_instance_id,
            privacy_key_epoch,
            privacy_database_sha256,
        )?;
        validate_vault_component(
            &paths.vault_active,
            workspace_instance_id,
            vault_manifest_sha256,
            vault_archive_sha256,
        )
    })();
    if let Err(error) = result {
        let mut cleanup_error = None;
        record_cleanup_error(
            &mut cleanup_error,
            rollback_restore_directory(
                &paths.work_products_active,
                &paths.work_products_incoming,
                &paths.work_products_rollback,
            ),
        );
        record_cleanup_error(
            &mut cleanup_error,
            rollback_restore_directory(
                &paths.approved_active,
                &paths.approved_incoming,
                &paths.approved_rollback,
            ),
        );
        record_cleanup_error(
            &mut cleanup_error,
            rollback_component(
                &paths.user_active,
                &paths.user_incoming,
                &paths.user_rollback,
            ),
        );
        record_cleanup_error(
            &mut cleanup_error,
            rollback_vault_component(
                &paths.vault_active,
                &paths.vault_incoming,
                &paths.vault_rollback,
            ),
        );
        record_cleanup_error(
            &mut cleanup_error,
            rollback_component(
                &paths.privacy_active,
                &paths.privacy_incoming,
                &paths.privacy_rollback,
            ),
        );
        if let Some(cleanup_error) = cleanup_error {
            return Err(cleanup_error);
        }
        remove_if_exists(&paths.marker)?;
        return Err(error);
    }
    remove_database_restore_files(&paths.user_rollback)?;
    remove_database_restore_files(&paths.privacy_rollback)?;
    remove_vault_restore_directory(&paths.vault_rollback)?;
    remove_restore_directory(&paths.approved_rollback)?;
    remove_restore_directory(&paths.work_products_rollback)?;
    remove_database_restore_files(&paths.user_incoming)?;
    remove_database_restore_files(&paths.privacy_incoming)?;
    remove_vault_restore_directory(&paths.vault_incoming)?;
    remove_restore_directory(&paths.approved_incoming)?;
    remove_restore_directory(&paths.work_products_incoming)?;
    remove_if_exists(&paths.marker)?;
    Ok(())
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

fn sibling_restore_path(active: &Path, suffix: &str) -> PathBuf {
    let mut value = active.as_os_str().to_os_string();
    value.push(format!(".application-restore-{suffix}"));
    PathBuf::from(value)
}

fn vault_component_summary(
    path: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<privacy::VaultBackupSummaryV1, IpcError> {
    validate_restore_directory_identity(path)?;
    let store = VaultStore::open(path, workspace_instance_id.clone()).map_err(vault_store_error)?;
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
    store
        .verify_all_committed_objects()
        .map_err(vault_store_error)?;
    let (_archive, summary) =
        privacy::export_encrypted_vault_backup(&store).map_err(vault_backup_error)?;
    Ok(summary)
}

fn validate_vault_component(
    path: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    expected_manifest_sha256: &str,
    expected_archive_sha256: &str,
) -> Result<(), IpcError> {
    let summary = vault_component_summary(path, workspace_instance_id)?;
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

fn advance_vault_component(
    active: &Path,
    incoming: &Path,
    rollback: &Path,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    expected_manifest_sha256: &str,
    expected_archive_sha256: &str,
) -> Result<(), IpcError> {
    if restore_path_is_present(active)? {
        let summary = vault_component_summary(active, workspace_instance_id)?;
        if summary.manifest_sha256.as_str() == expected_manifest_sha256
            && summary.archive_sha256.as_str() == expected_archive_sha256
        {
            if restore_path_is_present(incoming)? {
                validate_vault_component(
                    incoming,
                    workspace_instance_id,
                    expected_manifest_sha256,
                    expected_archive_sha256,
                )?;
            }
            return Ok(());
        }
    }
    if !restore_path_is_present(incoming)? {
        return Err(ipc_error(
            "application_restore_incomplete",
            "The authenticated incoming Vault restore component is missing.",
        ));
    }
    validate_vault_component(
        incoming,
        workspace_instance_id,
        expected_manifest_sha256,
        expected_archive_sha256,
    )?;
    if !restore_path_is_present(rollback)? {
        if !restore_path_is_present(active)? {
            return Err(ipc_error(
                "application_restore_incomplete",
                "The active and rollback Vault components are both missing.",
            ));
        }
        validate_restore_directory_identity(active)?;
        fs::rename(active, rollback).map_err(|_| {
            ipc_error(
                "application_restore_io",
                "The active Vault could not enter its fixed rollback slot.",
            )
        })?;
        validate_restore_directory_identity(rollback)?;
    } else {
        validate_restore_directory_identity(rollback)?;
    }
    fs::rename(incoming, active).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "The authenticated Vault could not be atomically installed.",
        )
    })?;
    validate_vault_component(
        active,
        workspace_instance_id,
        expected_manifest_sha256,
        expected_archive_sha256,
    )
}

fn rollback_vault_component(
    active: &Path,
    incoming: &Path,
    rollback: &Path,
) -> Result<(), IpcError> {
    if restore_path_is_present(rollback)? {
        validate_restore_directory_identity(rollback)?;
        if restore_path_is_present(active)? {
            remove_vault_restore_directory(active)?;
        }
        fs::rename(rollback, active).map_err(|_| {
            ipc_error(
                "application_restore_rollback_failed",
                "The original Vault could not be restored from its fixed rollback slot.",
            )
        })?;
        validate_restore_directory_identity(active)?;
    }
    remove_vault_restore_directory(incoming)
}

fn pending_directory_candidate<'a>(
    active: &'a Path,
    incoming: &'a Path,
    rollback: &'a Path,
) -> Result<&'a Path, IpcError> {
    let active_present = restore_path_is_present(active)?;
    let incoming_present = restore_path_is_present(incoming)?;
    let rollback_present = restore_path_is_present(rollback)?;
    if active_present && incoming_present && rollback_present {
        return Err(ipc_error(
            "application_restore_conflict",
            "An application restore directory occupies active, incoming, and rollback slots simultaneously.",
        ));
    }
    let candidate = if incoming_present {
        incoming
    } else if active_present {
        active
    } else {
        return Err(ipc_error(
            "application_restore_incomplete",
            "An authenticated application restore directory is missing.",
        ));
    };
    validate_restore_directory_identity(candidate)?;
    if rollback_present {
        validate_restore_directory_identity(rollback)?;
    }
    Ok(candidate)
}

fn advance_restore_directory(
    active: &Path,
    incoming: &Path,
    rollback: &Path,
) -> Result<(), IpcError> {
    let active_present = restore_path_is_present(active)?;
    let incoming_present = restore_path_is_present(incoming)?;
    let rollback_present = restore_path_is_present(rollback)?;
    if rollback_present {
        validate_restore_directory_identity(rollback)?;
        return match (active_present, incoming_present) {
            (true, false) => validate_restore_directory_identity(active),
            (false, true) => {
                validate_restore_directory_identity(incoming)?;
                fs::rename(incoming, active).map_err(|_| {
                    ipc_error(
                        "application_restore_io",
                        "The authenticated restore directory could not be installed after a crash.",
                    )
                })?;
                validate_restore_directory_identity(active)
            }
            _ => Err(ipc_error(
                "application_restore_conflict",
                "The restore directory transaction has an ambiguous crash-recovery state.",
            )),
        };
    }
    if !incoming_present {
        if !active_present {
            return Err(ipc_error(
                "application_restore_incomplete",
                "The active and incoming restore directories are both missing.",
            ));
        }
        return validate_restore_directory_identity(active);
    }
    if !active_present {
        return Err(ipc_error(
            "application_restore_incomplete",
            "The active and rollback restore directories are both missing.",
        ));
    }
    validate_restore_directory_identity(active)?;
    validate_restore_directory_identity(incoming)?;
    fs::rename(active, rollback).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "The active restore directory could not enter its fixed rollback slot.",
        )
    })?;
    validate_restore_directory_identity(rollback)?;
    fs::rename(incoming, active).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "The authenticated restore directory could not be atomically installed.",
        )
    })?;
    validate_restore_directory_identity(active)
}

fn rollback_restore_directory(
    active: &Path,
    incoming: &Path,
    rollback: &Path,
) -> Result<(), IpcError> {
    if restore_path_is_present(rollback)? {
        validate_restore_directory_identity(rollback)?;
        if restore_path_is_present(active)? {
            remove_restore_directory(active)?;
        }
        fs::rename(rollback, active).map_err(|_| {
            ipc_error(
                "application_restore_rollback_failed",
                "The original application restore directory could not be restored.",
            )
        })?;
        validate_restore_directory_identity(active)?;
    }
    remove_restore_directory(incoming)
}

fn advance_component<Validate>(
    active: &Path,
    incoming: &Path,
    rollback: &Path,
    expected_sha256: &str,
    validate: Validate,
) -> Result<(), IpcError>
where
    Validate: Fn(&Path) -> Result<(), IpcError>,
{
    if restore_path_is_present(active)?
        && file_sha256(active, MAX_USER_DATABASE_BACKUP_BYTES.max(96 * 1024 * 1024))?
            == expected_sha256
    {
        validate(active)?;
        if restore_path_is_present(incoming)? {
            validate(incoming)?;
            ensure_no_database_sidecars(incoming)?;
        }
        return Ok(());
    }
    if !restore_path_is_present(incoming)? {
        return Err(ipc_error(
            "application_restore_incomplete",
            "The authenticated incoming restore component is missing.",
        ));
    }
    validate(incoming)?;
    ensure_no_database_sidecars(incoming)?;
    if !restore_path_is_present(rollback)? {
        if !restore_path_is_present(active)? {
            return Err(ipc_error(
                "application_restore_incomplete",
                "The active and rollback database components are both missing.",
            ));
        }
        validate_restore_file_identity(active)?;
        ensure_no_database_sidecars(active)?;
        fs::rename(active, rollback).map_err(|_| {
            ipc_error(
                "application_restore_io",
                "The active database could not enter the fixed rollback slot.",
            )
        })?;
        validate_restore_file_identity(rollback)?;
    } else {
        validate_restore_file_identity(rollback)?;
        ensure_no_database_sidecars(rollback)?;
    }
    fs::rename(incoming, active).map_err(|_| {
        ipc_error(
            "application_restore_io",
            "The authenticated restore component could not be atomically installed.",
        )
    })?;
    validate(active)
}

fn rollback_component(active: &Path, incoming: &Path, rollback: &Path) -> Result<(), IpcError> {
    if restore_path_is_present(rollback)? {
        validate_restore_file_identity(rollback)?;
        ensure_no_database_sidecars(rollback)?;
        if restore_path_is_present(active)? {
            remove_database_restore_files(active)?;
        }
        fs::rename(rollback, active).map_err(|_| {
            ipc_error(
                "application_restore_rollback_failed",
                "The original database could not be restored from the fixed rollback slot.",
            )
        })?;
        validate_restore_file_identity(active)?;
    }
    remove_database_restore_files(incoming)
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

fn ensure_no_legacy_user_restore(paths: &ApplicationRestorePaths) -> Result<(), IpcError> {
    for path in [
        &paths.legacy_user_incoming,
        &paths.legacy_user_marker,
        &paths.legacy_user_rollback,
    ] {
        if restore_path_is_present(path)? {
            return Err(ipc_error(
                "application_restore_conflict",
                "A legacy user-database restore transaction is still present.",
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
    expected_sha256: &str,
) -> Result<(), IpcError> {
    if file_sha256(path, 96 * 1024 * 1024)? != expected_sha256 {
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
    if integrity != "ok"
        || foreign_keys != 0
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
