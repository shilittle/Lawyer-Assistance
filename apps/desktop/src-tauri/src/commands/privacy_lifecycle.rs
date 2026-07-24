use super::privacy_workflow::IpcError;
use crate::{
    privacy_manager,
    privacy_workflow::{
        BackupIdRequest, CleanupReportView, DestroyMappingKeyRequest, LifecycleStatusRequest,
        LifecycleStatusView, PrivacyWorkflowManager, RetentionPolicyView, RevealMappingRequest,
        RevealMappingResponse, RevokeMappingRequest, RotateMappingKeyRequest,
        RunRetentionSweepRequest, SetLegalHoldRequest, SetRetentionPolicyRequest,
        StagePrivacyRestoreRequest, VerifiedBackupView,
    },
};
use privacy::{lifecycle::MAX_PORTABLE_BACKUP_BYTES, sha256_hex};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
};
use tauri::State;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT,
    },
};

const PORTABLE_BACKUP_EXTENSION: &str = "lavprivacy";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortablePrivacyBackupExportResponse {
    pub cancelled: bool,
    pub backup_id: String,
    pub bundle_sha256: Option<String>,
    pub bytes_written: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortablePrivacyBackupImportResponse {
    pub cancelled: bool,
    pub bundle_sha256: Option<String>,
    pub backup: Option<VerifiedBackupView>,
}

fn runtime_error(message: &str) -> IpcError {
    IpcError {
        error_type: "runtime_failure".to_owned(),
        message: message.to_owned(),
    }
}

#[tauri::command]
pub async fn get_privacy_lifecycle_status(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: LifecycleStatusRequest,
) -> Result<LifecycleStatusView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.lifecycle_status(request))
        .await
        .map_err(|_| runtime_error("隐私生命周期状态读取任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn set_privacy_retention_policy(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: SetRetentionPolicyRequest,
) -> Result<RetentionPolicyView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.set_retention_policy(request))
        .await
        .map_err(|_| runtime_error("隐私保留策略保存任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn set_privacy_legal_hold(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: SetLegalHoldRequest,
) -> Result<(), IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.set_redaction_legal_hold(request))
        .await
        .map_err(|_| runtime_error("隐私法律保留设置任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn reveal_privacy_mapping(
    app: tauri::AppHandle,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: RevealMappingRequest,
) -> Result<RevealMappingResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let confirmed = app
            .dialog()
            .message(
                "即将仅在本机界面单次解密并显示敏感映射。请确认屏幕未共享、周围无无关人员；窗口失焦、页面隐藏或离开页面后会立即隐藏。",
            )
            .title("确认单次显示敏感映射")
            .kind(MessageDialogKind::Warning)
            .buttons(MessageDialogButtons::OkCancelCustom(
                "单次显示".to_owned(),
                "取消".to_owned(),
            ))
            .blocking_show();
        if !confirmed {
            return Err(IpcError {
                error_type: "privacy_mapping_reveal_cancelled".to_owned(),
                message: "已取消敏感映射显示；未解密任何映射内容。".to_owned(),
            });
        }
        let authorization = workflow
            .issue_mapping_reveal_authorization()
            .map_err(IpcError::from)?;
        workflow
            .reveal_mapping(request, authorization)
            .map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("敏感映射单次显示任务未完成。"))?
}

#[tauri::command]
pub async fn revoke_privacy_mapping(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: RevokeMappingRequest,
) -> Result<(), IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.revoke_mapping(request))
        .await
        .map_err(|_| runtime_error("敏感映射撤销任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn rotate_privacy_mapping_key(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: RotateMappingKeyRequest,
) -> Result<u64, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.rotate_mapping_key(request))
        .await
        .map_err(|_| runtime_error("敏感映射密钥轮换任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn destroy_privacy_mapping_key(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: DestroyMappingKeyRequest,
) -> Result<(), IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.destroy_mapping_key(request))
        .await
        .map_err(|_| runtime_error("敏感映射密钥销毁任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn run_privacy_retention_sweep(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: RunRetentionSweepRequest,
) -> Result<CleanupReportView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.run_retention_sweep(request))
        .await
        .map_err(|_| runtime_error("隐私到期清理任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn create_privacy_backup(
    workflow: State<'_, PrivacyWorkflowManager>,
) -> Result<VerifiedBackupView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.create_privacy_backup())
        .await
        .map_err(|_| runtime_error("加密隐私备份创建任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn verify_privacy_backup(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: BackupIdRequest,
) -> Result<VerifiedBackupView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.verify_privacy_backup(&request.backup_id))
        .await
        .map_err(|_| runtime_error("加密隐私备份验证任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn revoke_privacy_backup(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: BackupIdRequest,
) -> Result<(), IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.revoke_privacy_backup(&request.backup_id))
        .await
        .map_err(|_| runtime_error("加密隐私备份撤销任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn stage_privacy_restore(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: StagePrivacyRestoreRequest,
) -> Result<VerifiedBackupView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.stage_privacy_restore(request))
        .await
        .map_err(|_| runtime_error("隐私备份恢复暂存任务未完成。"))?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn export_privacy_backup_bundle(
    app: tauri::AppHandle,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: BackupIdRequest,
) -> Result<PortablePrivacyBackupExportResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selected = app
            .dialog()
            .file()
            .set_title("导出本机加密隐私备份")
            .set_file_name(format!(
                "{}.{}",
                request.backup_id, PORTABLE_BACKUP_EXTENSION
            ))
            .add_filter(
                "Lawyer Assistance 加密隐私备份",
                &[PORTABLE_BACKUP_EXTENSION],
            )
            .blocking_save_file();
        let Some(selected) = selected else {
            return Ok(PortablePrivacyBackupExportResponse {
                cancelled: true,
                backup_id: request.backup_id,
                bundle_sha256: None,
                bytes_written: 0,
            });
        };
        let mut path = selected.into_path().map_err(|_| invalid_path_error())?;
        force_portable_extension(&mut path);
        validate_new_portable_destination(&path)?;
        let bytes = workflow
            .export_privacy_backup_bundle(&request.backup_id)
            .map_err(IpcError::from)?;
        let expected_sha256 = sha256_hex(&bytes);
        install_portable_bundle(&path, &bytes, &expected_sha256)?;
        Ok(PortablePrivacyBackupExportResponse {
            cancelled: false,
            backup_id: request.backup_id,
            bundle_sha256: Some(expected_sha256),
            bytes_written: bytes.len() as u64,
        })
    })
    .await
    .map_err(|_| runtime_error("加密隐私备份导出任务未完成。"))?
}

#[tauri::command]
pub async fn import_privacy_backup_bundle(
    app: tauri::AppHandle,
    workflow: State<'_, PrivacyWorkflowManager>,
) -> Result<PortablePrivacyBackupImportResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selected = app
            .dialog()
            .file()
            .set_title("导入本机加密隐私备份")
            .add_filter(
                "Lawyer Assistance 加密隐私备份",
                &[PORTABLE_BACKUP_EXTENSION],
            )
            .blocking_pick_file();
        let Some(selected) = selected else {
            return Ok(PortablePrivacyBackupImportResponse {
                cancelled: true,
                bundle_sha256: None,
                backup: None,
            });
        };
        let path = selected.into_path().map_err(|_| invalid_path_error())?;
        let bytes = read_portable_bundle(&path)?;
        let bundle_sha256 = sha256_hex(&bytes);
        let backup = workflow
            .import_privacy_backup_bundle(&bytes)
            .map_err(IpcError::from)?;
        Ok(PortablePrivacyBackupImportResponse {
            cancelled: false,
            bundle_sha256: Some(bundle_sha256),
            backup: Some(backup),
        })
    })
    .await
    .map_err(|_| runtime_error("加密隐私备份导入任务未完成。"))?
}

fn invalid_path_error() -> IpcError {
    IpcError {
        error_type: "privacy_backup_path_invalid".to_owned(),
        message: "隐私备份文件必须位于本机固定磁盘，且不能经过网络、链接、重解析点或云端占位节点。"
            .to_owned(),
    }
}

fn force_portable_extension(path: &mut PathBuf) {
    if !has_portable_extension(path) {
        path.set_extension(PORTABLE_BACKUP_EXTENSION);
    }
}

fn has_portable_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(PORTABLE_BACKUP_EXTENSION))
}

fn validate_local_portable_path(path: &Path) -> Result<(), IpcError> {
    if !has_portable_extension(path)
        || !privacy_manager::is_normal_local_absolute(path)
        || !privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(invalid_path_error());
    }
    Ok(())
}

fn validate_new_portable_destination(path: &Path) -> Result<(), IpcError> {
    validate_local_portable_path(path)?;
    let parent = path.parent().ok_or_else(invalid_path_error)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| invalid_path_error())?;
    if !metadata.is_dir() || is_reparse_or_cloud(&metadata) {
        return Err(invalid_path_error());
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(IpcError {
            error_type: "privacy_backup_target_exists".to_owned(),
            message: "隐私备份导出不会覆盖现有文件；请选择新的文件名。".to_owned(),
        }),
        Err(_) => Err(invalid_path_error()),
    }
}

fn install_portable_bundle(
    path: &Path,
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), IpcError> {
    if bytes.is_empty() || bytes.len() > MAX_PORTABLE_BACKUP_BYTES {
        return Err(IpcError {
            error_type: "privacy_backup_invalid".to_owned(),
            message: "隐私备份包大小无效。".to_owned(),
        });
    }
    validate_new_portable_destination(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| IpcError {
            error_type: "privacy_backup_write_failed".to_owned(),
            message: "隐私备份文件无法以不覆盖模式创建。".to_owned(),
        })?;
    let result = (|| {
        if !opened_file_is_ordinary_single_link(&file) {
            return Err(invalid_path_error());
        }
        file.write_all(bytes).map_err(|_| IpcError {
            error_type: "privacy_backup_write_failed".to_owned(),
            message: "隐私备份文件无法完整写入。".to_owned(),
        })?;
        file.sync_all().map_err(|_| IpcError {
            error_type: "privacy_backup_write_failed".to_owned(),
            message: "隐私备份文件无法同步到磁盘。".to_owned(),
        })?;
        if !opened_file_is_ordinary_single_link(&file) {
            return Err(invalid_path_error());
        }
        drop(file);
        let installed = read_portable_bundle(path)?;
        if installed.len() != bytes.len() || sha256_hex(&installed) != expected_sha256 {
            return Err(IpcError {
                error_type: "privacy_backup_verify_failed".to_owned(),
                message: "隐私备份文件保存后重读哈希不一致。".to_owned(),
            });
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn read_portable_bundle(path: &Path) -> Result<Vec<u8>, IpcError> {
    validate_local_portable_path(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_path_error())?;
    if !metadata.is_file()
        || is_reparse_or_cloud(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_PORTABLE_BACKUP_BYTES as u64
    {
        return Err(invalid_path_error());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| invalid_path_error())?;
    if !opened_file_is_ordinary_single_link(&file) {
        return Err(invalid_path_error());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take((MAX_PORTABLE_BACKUP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| IpcError {
            error_type: "privacy_backup_read_failed".to_owned(),
            message: "隐私备份文件无法完整读取。".to_owned(),
        })?;
    if bytes.is_empty()
        || bytes.len() > MAX_PORTABLE_BACKUP_BYTES
        || bytes.len() as u64 != metadata.len()
        || !opened_file_is_ordinary_single_link(&file)
    {
        return Err(invalid_path_error());
    }
    Ok(bytes)
}

fn is_reparse_or_cloud(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || privacy_manager::has_cloud_recall_attributes(metadata)
}

fn opened_file_is_ordinary_single_link(file: &File) -> bool {
    if !privacy_manager::opened_file_resolves_to_ordinary_local(file) {
        return false;
    }
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file() || is_reparse_or_cloud(&metadata) {
        return false;
    }
    let handle = file.as_raw_handle() as HANDLE;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    !handle.is_null()
        && unsafe { GetFileInformationByHandle(handle, &mut information) } != 0
        && information.nNumberOfLinks == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_destination_rejects_existing_file_and_unc() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("existing.lavprivacy");
        fs::write(&path, b"existing").expect("fixture");
        assert_eq!(
            validate_new_portable_destination(&path)
                .expect_err("existing path rejected")
                .error_type,
            "privacy_backup_target_exists"
        );
        assert_eq!(fs::read(&path).expect("unchanged"), b"existing");
        assert_eq!(
            validate_new_portable_destination(Path::new(r"\\server\share\backup.lavprivacy"))
                .expect_err("UNC rejected")
                .error_type,
            "privacy_backup_path_invalid"
        );
    }

    #[test]
    fn import_rejects_hardlinks() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let original = directory.path().join("original.lavprivacy");
        let hardlink = directory.path().join("hardlink.lavprivacy");
        fs::write(&original, b"synthetic encrypted backup").expect("fixture");
        fs::hard_link(&original, &hardlink).expect("hardlink");
        assert_eq!(
            read_portable_bundle(&hardlink)
                .expect_err("hardlink rejected")
                .error_type,
            "privacy_backup_path_invalid"
        );
    }

    #[test]
    fn create_new_export_reopens_and_hashes_exact_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("synthetic.lavprivacy");
        let bytes = b"synthetic encrypted privacy bundle";
        install_portable_bundle(&path, bytes, &sha256_hex(bytes)).expect("secure install");
        assert_eq!(read_portable_bundle(&path).expect("reopen"), bytes);
    }

    #[test]
    fn request_contracts_reject_frontend_paths_and_secrets() {
        assert!(
            serde_json::from_value::<BackupIdRequest>(serde_json::json!({
                "backupId": "bkp_0123456789abcdef0123456789abcdef",
                "path": "C:/case/raw.pdf"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<LifecycleStatusRequest>(serde_json::json!({
                "redactionId": null,
                "receiptToken": "secret"
            }))
            .is_err()
        );
    }
}
