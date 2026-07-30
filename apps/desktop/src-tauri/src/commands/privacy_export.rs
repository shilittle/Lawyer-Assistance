use super::privacy_workflow::IpcError;
use crate::{
    privacy_manager,
    privacy_workflow::{
        export_reason, ExportApprovedCaseRedactionRequest, ExportApprovedPrivacyReviewRequest,
        PrivacyWorkflowManager, SafeExportFormat,
    },
};
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
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT,
    },
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportApprovedPrivacyReviewResponse {
    pub cancelled: bool,
    pub format: SafeExportFormat,
    pub file_name: Option<String>,
    pub media_type: String,
    pub artifact_sha256: Option<String>,
    pub approved_text_sha256: Option<String>,
    pub reopened_text_sha256: Option<String>,
    pub source_page_count: u32,
    pub output_page_count: u32,
}

// Phase 3 keeps this compatibility adapter for one release cycle, but it must not be registered
// with the renderer after the project-scoped cutover.
#[allow(dead_code)]
#[tauri::command]
pub async fn export_approved_privacy_review(
    app: tauri::AppHandle,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ExportApprovedPrivacyReviewRequest,
) -> Result<ExportApprovedPrivacyReviewResponse, IpcError> {
    export_approved_privacy_review_internal(app, workflow.inner().clone(), request, None).await
}

async fn export_approved_privacy_review_internal(
    app: tauri::AppHandle,
    workflow: PrivacyWorkflowManager,
    request: ExportApprovedPrivacyReviewRequest,
    case_scope: Option<ExportApprovedCaseRedactionRequest>,
) -> Result<ExportApprovedPrivacyReviewResponse, IpcError> {
    tauri::async_runtime::spawn_blocking(move || {
        let format = request.format;
        let selected = app
            .dialog()
            .file()
            .set_title(format!("保存已验证的脱敏 {}", format.code().to_uppercase()))
            .set_file_name(format.default_file_name())
            .add_filter(format.dialog_filter_label(), &[format.file_extension()])
            .blocking_save_file();
        let Some(selected) = selected else {
            if let Some(case_request) = case_scope.as_ref() {
                workflow
                    .validate_case_export_scope(case_request)
                    .map_err(IpcError::from)?;
            }
            workflow
                .record_safe_export_cancellation(&request)
                .map_err(IpcError::from)?;
            return Ok(ExportApprovedPrivacyReviewResponse {
                cancelled: true,
                format,
                file_name: None,
                media_type: format.media_type().to_owned(),
                artifact_sha256: None,
                approved_text_sha256: None,
                reopened_text_sha256: None,
                source_page_count: 0,
                output_page_count: 0,
            });
        };

        let mut path = selected.into_path().map_err(|_| IpcError {
            error_type: "invalid_export_destination".to_owned(),
            message: "所选导出目标不是本地文件。".to_owned(),
        })?;
        force_fixed_extension(&mut path, format);

        // Build first as required: only a fully re-opened artifact advances to
        // target validation. No output path is persisted in workflow state.
        let built = workflow
            .build_safe_export(&request)
            .map_err(IpcError::from)?;
        validate_safe_export_destination(&path, format)?;

        let pending_reason = export_reason(format, "attempt_pending");
        workflow
            .record_safe_export_event(&built, false, &pending_reason)
            .map_err(IpcError::from)?;
        let install_result = if let Some(case_request) = case_scope.as_ref() {
            workflow.with_case_safe_export_authorization(case_request, &built, || {
                install_safe_export(
                    &path,
                    format,
                    &built.bytes,
                    || Ok(()),
                    |_| Ok(()),
                    |installed| {
                        workflow
                            .verify_installed_safe_export(&built, installed)
                            .map_err(IpcError::from)
                    },
                )
            })
        } else {
            install_safe_export(
                &path,
                format,
                &built.bytes,
                || {
                    workflow
                        .verify_safe_export_authorization(&built)
                        .map_err(IpcError::from)
                },
                |_| Ok(()),
                |installed| {
                    workflow
                        .verify_installed_safe_export(&built, installed)
                        .map_err(IpcError::from)
                },
            )
        };
        if let Err(error) = install_result {
            let failure = export_reason(
                format,
                &format!("failed_{}", sanitize_reason_component(&error.error_type)),
            );
            let _ = workflow.record_safe_export_event(&built, false, &failure);
            if error.error_type == "export_verify_failed"
                || error.error_type == "safe_export_failed"
            {
                return Err(IpcError {
                    error_type: "export_installed_verify_failed".to_owned(),
                    message: "安全派生文书已原子安装，但保存后严格重读复核失败；请将该文件视为已导出且不可继续使用，并人工核验。".to_owned(),
                });
            }
            return Err(error);
        }

        let success_reason = export_reason(format, "succeeded");
        if workflow
            .record_safe_export_event(&built, true, &success_reason)
            .is_err()
        {
            return Err(IpcError {
                error_type: "export_succeeded_audit_failed".to_owned(),
                message:
                    "安全派生文书已保存并复核，但成功结果未能写入本机隐私审计；文件仍应视为已导出。"
                        .to_owned(),
            });
        }
        let file_name = safe_file_name(&path, format.default_file_name());
        Ok(ExportApprovedPrivacyReviewResponse {
            cancelled: false,
            format,
            file_name: Some(file_name),
            media_type: built.media_type.clone(),
            artifact_sha256: Some(built.artifact_sha256.clone()),
            approved_text_sha256: Some(built.approved_text_sha256.clone()),
            reopened_text_sha256: Some(built.reopened_text_sha256.clone()),
            source_page_count: built.source_page_count,
            output_page_count: built.output_page_count,
        })
    })
    .await
    .map_err(|_| IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "安全派生文书重建、保存与严格复核任务未完成。".to_owned(),
    })?
}

#[tauri::command]
pub async fn export_approved_case_redaction(
    app: tauri::AppHandle,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ExportApprovedCaseRedactionRequest,
) -> Result<ExportApprovedPrivacyReviewResponse, IpcError> {
    let manager = workflow.inner().clone();
    manager
        .validate_case_export_scope(&request)
        .map_err(IpcError::from)?;
    let legacy_request = request.legacy_request();
    export_approved_privacy_review_internal(app, manager, legacy_request, Some(request)).await
}

fn force_fixed_extension(path: &mut PathBuf, format: SafeExportFormat) {
    if !path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(format.file_extension()))
    {
        path.set_extension(format.file_extension());
    }
}

fn safe_file_name(path: &Path, fallback: &str) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .unwrap_or(fallback)
        .to_owned()
}

fn sanitize_reason_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .take(64)
        .collect()
}

fn validate_safe_export_destination(path: &Path, format: SafeExportFormat) -> Result<(), IpcError> {
    if !privacy_manager::is_normal_local_absolute(path)
        || !path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case(format.file_extension()))
    {
        return Err(IpcError {
            error_type: "invalid_export_destination".to_owned(),
            message:
                "安全导出目标必须使用后端固定扩展名，且位于本机固定磁盘；UNC 与映射网络盘已拒绝。"
                    .to_owned(),
        });
    }
    if !privacy_manager::local_path_chain_is_ordinary(path) {
        return Err(IpcError {
            error_type: "filesystem_rejected".to_owned(),
            message: "安全导出路径不能包含链接、reparse point 或云端占位/召回节点。".to_owned(),
        });
    }
    let parent = path.parent().ok_or_else(|| IpcError {
        error_type: "invalid_export_destination".to_owned(),
        message: "安全导出目标缺少父目录。".to_owned(),
    })?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| IpcError {
        error_type: "invalid_export_destination".to_owned(),
        message: "安全导出父目录无法核验。".to_owned(),
    })?;
    if !parent_metadata.is_dir() || is_reparse_or_cloud(&parent_metadata) {
        return Err(IpcError {
            error_type: "filesystem_rejected".to_owned(),
            message: "安全导出父目录不能是链接、reparse point 或云端占位/召回目录。".to_owned(),
        });
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || is_reparse_or_cloud(&metadata) {
                return Err(IpcError {
                    error_type: "filesystem_rejected".to_owned(),
                    message: "安全导出目标必须是非链接、非云端占位的本地普通文件。".to_owned(),
                });
            }
            let file = open_no_follow_read(path)?;
            if !opened_file_is_ordinary_single_link(&file) {
                return Err(IpcError {
                    error_type: "filesystem_rejected".to_owned(),
                    message: "安全导出目标是硬链接、重解析点或非本机普通文件。".to_owned(),
                });
            }
            Err(IpcError {
                error_type: "export_target_exists".to_owned(),
                message: "安全导出不会覆盖现有文件；请选择新的文件名。".to_owned(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(IpcError {
            error_type: "invalid_export_destination".to_owned(),
            message: "安全导出目标无法核验。".to_owned(),
        }),
    }
}

fn is_reparse_or_cloud(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || privacy_manager::has_cloud_recall_attributes(metadata)
}

fn open_no_follow_read(path: &Path) -> Result<File, IpcError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| IpcError {
            error_type: "filesystem_rejected".to_owned(),
            message: "安全导出文件句柄无法打开或核验。".to_owned(),
        })
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
    if handle.is_null() {
        return false;
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file owns a live Windows handle for the duration of this call.
    (unsafe { GetFileInformationByHandle(handle, &mut information) }) != 0
        && information.nNumberOfLinks == 1
}

fn install_safe_export<Authorize, AfterInstall, Verify>(
    path: &Path,
    format: SafeExportFormat,
    bytes: &[u8],
    final_authorize: Authorize,
    after_install: AfterInstall,
    verify_installed: Verify,
) -> Result<(), IpcError>
where
    Authorize: FnOnce() -> Result<(), IpcError>,
    AfterInstall: FnOnce(&Path) -> Result<(), IpcError>,
    Verify: FnOnce(&[u8]) -> Result<(), IpcError>,
{
    validate_safe_export_destination(path, format)?;
    let parent = path.parent().ok_or_else(|| IpcError {
        error_type: "invalid_export_destination".to_owned(),
        message: "安全导出目标缺少父目录。".to_owned(),
    })?;
    let staged = parent.join(format!(
        ".lawyer-assistance-safe-export-{}.incoming",
        Uuid::new_v4().simple()
    ));

    let result = (|| -> Result<(), IpcError> {
        // Recheck the active receipt (and, for case exports, the exact
        // ProjectId scope) before creating even the zero-byte staging file.
        // The case-scoped caller keeps the workflow gate held through install.
        final_authorize()?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&staged)
            .map_err(|_| IpcError {
                error_type: "export_write_failed".to_owned(),
                message: "安全派生文书临时文件无法创建。".to_owned(),
            })?;
        if !opened_file_is_ordinary_single_link(&file) {
            return Err(IpcError {
                error_type: "filesystem_rejected".to_owned(),
                message: "安全导出临时文件不是本机单链接普通文件。".to_owned(),
            });
        }

        file.write_all(bytes).map_err(|_| IpcError {
            error_type: "export_write_failed".to_owned(),
            message: "安全派生文书临时文件无法完整写入。".to_owned(),
        })?;
        file.sync_all().map_err(|_| IpcError {
            error_type: "export_write_failed".to_owned(),
            message: "安全派生文书临时文件无法同步到磁盘。".to_owned(),
        })?;
        if !opened_file_is_ordinary_single_link(&file) {
            return Err(IpcError {
                error_type: "filesystem_rejected".to_owned(),
                message: "安全导出临时文件写入期间发生身份变化。".to_owned(),
            });
        }
        drop(file);

        let staged_file = open_no_follow_read(&staged)?;
        if !opened_file_is_ordinary_single_link(&staged_file) {
            return Err(IpcError {
                error_type: "filesystem_rejected".to_owned(),
                message: "安全导出临时文件在原子安装前不再是单链接普通文件。".to_owned(),
            });
        }
        drop(staged_file);

        // A second validation closes the target-selection/write interval.
        // fs::rename on Windows is same-directory atomic and fails rather than
        // replacing a destination that appeared during the race window.
        validate_safe_export_destination(path, format)?;
        fs::rename(&staged, path).map_err(|_| IpcError {
            error_type: "export_install_failed".to_owned(),
            message: "安全派生文书无法原子安装；不会覆盖已存在文件。".to_owned(),
        })?;

        after_install(path)?;
        let installed = read_installed_file(path, bytes.len())?;
        verify_installed(&installed)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

fn read_installed_file(path: &Path, expected_len: usize) -> Result<Vec<u8>, IpcError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| IpcError {
        error_type: "export_verify_failed".to_owned(),
        message: "安全导出文件安装后无法读取元数据。".to_owned(),
    })?;
    if !metadata.is_file() || is_reparse_or_cloud(&metadata) {
        return Err(IpcError {
            error_type: "export_verify_failed".to_owned(),
            message: "安全导出文件安装后变成链接、云端占位或非普通文件。".to_owned(),
        });
    }
    let mut file = open_no_follow_read(path).map_err(|_| IpcError {
        error_type: "export_verify_failed".to_owned(),
        message: "安全导出文件安装后无法以不跟随链接的方式打开。".to_owned(),
    })?;
    if !opened_file_is_ordinary_single_link(&file) {
        return Err(IpcError {
            error_type: "export_verify_failed".to_owned(),
            message: "安全导出文件安装后不是本机单链接普通文件。".to_owned(),
        });
    }
    let limit = expected_len.checked_add(1).ok_or_else(|| IpcError {
        error_type: "export_verify_failed".to_owned(),
        message: "安全导出文件大小复核溢出。".to_owned(),
    })?;
    let mut bytes = Vec::with_capacity(expected_len);
    (&mut file)
        .take(limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| IpcError {
            error_type: "export_verify_failed".to_owned(),
            message: "安全导出文件安装后无法完整重读。".to_owned(),
        })?;
    if bytes.len() != expected_len || !opened_file_is_ordinary_single_link(&file) {
        return Err(IpcError {
            error_type: "export_verify_failed".to_owned(),
            message: "安全导出文件安装后大小或文件身份不一致。".to_owned(),
        });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_error(error_type: &str, message: &str) -> IpcError {
        IpcError {
            error_type: error_type.to_owned(),
            message: message.to_owned(),
        }
    }

    #[test]
    fn case_export_request_requires_project_id_and_denies_private_or_unknown_identity_fields() {
        let valid = serde_json::json!({
            "projectId": "case-export-contract",
            "redactionId": "red_export_contract",
            "format": "pdf"
        });
        let request: ExportApprovedCaseRedactionRequest =
            serde_json::from_value(valid.clone()).expect("valid case export request");
        assert_eq!(request.project_id, "case-export-contract");
        assert_eq!(request.redaction_id, "red_export_contract");

        let mut missing_project_id = valid.clone();
        missing_project_id
            .as_object_mut()
            .expect("request object")
            .remove("projectId");
        assert!(
            serde_json::from_value::<ExportApprovedCaseRedactionRequest>(missing_project_id)
                .is_err()
        );

        for private_or_unknown_key in ["caseId", "privacyCaseId", "unexpected"] {
            let mut with_unknown = valid.clone();
            with_unknown
                .as_object_mut()
                .expect("request object")
                .insert(
                    private_or_unknown_key.to_owned(),
                    serde_json::Value::String("case_88888888888888888888888888888888".to_owned()),
                );
            assert!(
                serde_json::from_value::<ExportApprovedCaseRedactionRequest>(with_unknown).is_err(),
                "case export request must deny {private_or_unknown_key}"
            );
        }

        let serialized = serde_json::to_value(&request).expect("serialize case export request");
        assert_eq!(
            serialized
                .get("projectId")
                .and_then(serde_json::Value::as_str),
            Some("case-export-contract")
        );
        assert!(serialized.get("caseId").is_none());
        assert!(serialized.get("privacyCaseId").is_none());
        let legacy = request.legacy_request();
        assert_eq!(legacy.redaction_id, "red_export_contract");
        assert_eq!(legacy.format, SafeExportFormat::Pdf);
    }

    #[test]
    fn fixed_extension_is_backend_selected_for_every_format() {
        for format in SafeExportFormat::ALL {
            let mut path = PathBuf::from("attacker-selected.exe");
            force_fixed_extension(&mut path, format);
            assert_eq!(
                path.extension().and_then(|value| value.to_str()),
                Some(format.file_extension())
            );
        }
    }

    #[test]
    fn existing_destination_and_hardlink_are_rejected_without_overwrite() {
        let directory = tempfile::tempdir().expect("temp export directory");
        let existing = directory.path().join("existing.txt");
        fs::write(&existing, b"existing").expect("existing file");
        let error = validate_safe_export_destination(&existing, SafeExportFormat::Txt)
            .expect_err("existing target rejected");
        assert_eq!(error.error_type, "export_target_exists");
        assert_eq!(fs::read(&existing).expect("unchanged"), b"existing");

        let original = directory.path().join("original.bin");
        let hardlink = directory.path().join("hardlink.txt");
        fs::write(&original, b"original").expect("hardlink source");
        fs::hard_link(&original, &hardlink).expect("create hardlink");
        let error = validate_safe_export_destination(&hardlink, SafeExportFormat::Txt)
            .expect_err("hardlink rejected");
        assert_eq!(error.error_type, "filesystem_rejected");
        assert_eq!(fs::read(&original).expect("source unchanged"), b"original");
    }

    #[test]
    fn reparse_point_destination_is_rejected_when_platform_allows_creation() {
        let directory = tempfile::tempdir().expect("temp export directory");
        let source = directory.path().join("source.txt");
        let link = directory.path().join("linked.txt");
        fs::write(&source, b"source").expect("symlink source");
        if std::os::windows::fs::symlink_file(&source, &link).is_err() {
            return;
        }
        let error = validate_safe_export_destination(&link, SafeExportFormat::Txt)
            .expect_err("reparse point rejected");
        assert_eq!(error.error_type, "filesystem_rejected");
    }

    #[test]
    fn post_install_tampering_fails_final_reread_verification() {
        let directory = tempfile::tempdir().expect("temp export directory");
        let destination = directory.path().join("safe.txt");
        let expected = b"approved-redacted-text";
        let error = install_safe_export(
            &destination,
            SafeExportFormat::Txt,
            expected,
            || Ok(()),
            |path| {
                fs::write(path, b"tampered").map_err(|_| test_error("test_hook", "tamper failed"))
            },
            |installed| {
                if installed == expected {
                    Ok(())
                } else {
                    Err(test_error("export_verify_failed", "tamper detected"))
                }
            },
        )
        .expect_err("post-install tamper rejected");
        assert_eq!(error.error_type, "export_verify_failed");
        assert_eq!(
            fs::read(&destination).expect("installed remains"),
            b"tampered"
        );
    }

    #[test]
    fn post_install_hardlink_fails_final_handle_verification() {
        let directory = tempfile::tempdir().expect("temp export directory");
        let destination = directory.path().join("safe.txt");
        let alias = directory.path().join("alias.bin");
        let error = install_safe_export(
            &destination,
            SafeExportFormat::Txt,
            b"approved-redacted-text",
            || Ok(()),
            |path| {
                fs::hard_link(path, &alias).map_err(|_| test_error("test_hook", "hardlink failed"))
            },
            |_| Ok(()),
        )
        .expect_err("post-install hardlink rejected");
        assert_eq!(error.error_type, "export_verify_failed");
    }

    #[test]
    fn final_authorization_failure_writes_no_artifact_bytes() {
        let directory = tempfile::tempdir().expect("temp export directory");
        let destination = directory.path().join("safe.txt");
        let error = install_safe_export(
            &destination,
            SafeExportFormat::Txt,
            b"approved-redacted-text",
            || Err(test_error("redaction_receipt_revoked", "revoked")),
            |_| Ok(()),
            |_| Ok(()),
        )
        .expect_err("revoked receipt fails closed");
        assert_eq!(error.error_type, "redaction_receipt_revoked");
        assert!(!destination.exists());
        assert!(fs::read_dir(directory.path())
            .expect("list temp directory")
            .all(|entry| !entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".incoming")));
    }

    #[test]
    fn command_orders_build_validate_install_reread_and_success_audit() {
        let source = include_str!("privacy_export.rs");
        let command = source
            .split("async fn export_approved_privacy_review_internal")
            .nth(1)
            .expect("export command source");
        let build = command.find(".build_safe_export(&request)").expect("build");
        let validate = command
            .find("validate_safe_export_destination(&path, format)")
            .expect("target validation");
        let install = command
            .find("install_safe_export(")
            .expect("atomic install");
        let final_verify = command
            .find(".verify_installed_safe_export(&built, installed)")
            .expect("installed reparse");
        let success = command
            .find("record_safe_export_event(&built, true")
            .expect("success audit");
        assert!(build < validate && validate < install);
        assert!(install < final_verify && final_verify < success);
        assert!(command.contains("record_safe_export_cancellation(&request)"));

        let installer = source
            .split("fn install_safe_export")
            .nth(1)
            .expect("safe installer source");
        let final_authorize = installer
            .find("final_authorize()?")
            .expect("final authorization");
        let staged_create = installer
            .find("OpenOptions::new()")
            .expect("staging file creation");
        assert!(
            final_authorize < staged_create,
            "final authorization must precede every staging-file creation"
        );

        let case_branch = command
            .find(".with_case_safe_export_authorization")
            .expect("case scope and receipt authorization");
        assert!(
            case_branch < install,
            "case scope authorization must wrap atomic installation"
        );
    }
}
