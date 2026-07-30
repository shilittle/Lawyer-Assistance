use crate::{
    privacy_manager::{OcrMode, PrivacyManager, PrivacyManagerError},
    privacy_workflow::{
        ApplyCaseRedactionRiskReviewActionRequest, ApplyPrivacyRiskReviewActionRequest,
        ApproveCaseRedactionReviewRequest, ApprovePrivacyReviewRequest,
        ApprovePrivacyReviewResponse, AssignUnassignedCaseMaterialRequest,
        AssignUnassignedCaseMaterialResponse, BuiltSafePdf, CaseMaterialSummary,
        CaseRedactionGenerationSummary, CaseRedactionReviewView,
        CaseRedactionRiskReviewRevisionRequest, DeleteCaseRedactionReviewRequest,
        DeletePrivacyReviewRequest, DeletePrivacyReviewResponse, ExportApprovedReviewPdfRequest,
        ListCaseMaterialsRequest, ListCaseRedactionGenerationsRequest,
        ListUnassignedCaseMaterialsRequest, LoadCaseRedactionReviewRequest,
        LoadPrivacyReviewRequest, LocalOcrExecutionContext, PrepareCaseMaterialRequest,
        PrepareCaseMaterialResponse, PreparePrivacyMaterialRequest, PreparePrivacyMaterialResponse,
        PrivacyReviewView, PrivacyRiskReviewRevisionRequest, PrivacyWorkflowError,
        PrivacyWorkflowManager, UnassignedCaseMaterialSummary,
    },
};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use tauri::State;
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl From<PrivacyManagerError> for IpcError {
    fn from(error: PrivacyManagerError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

impl From<PrivacyWorkflowError> for IpcError {
    fn from(error: PrivacyWorkflowError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

#[tauri::command]
pub async fn prepare_privacy_material(
    app: tauri::AppHandle,
    configuration: State<'_, PrivacyManager>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: PreparePrivacyMaterialRequest,
) -> Result<PreparePrivacyMaterialResponse, IpcError> {
    let configuration = configuration.inner().clone();
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selected = app
            .dialog()
            .file()
            .set_title("选择要在本机脱敏的材料")
            .add_filter(
                "支持的材料",
                &["pdf", "png", "jpg", "jpeg", "docx", "txt", "md", "markdown"],
            )
            .blocking_pick_file();
        let Some(selected) = selected else {
            return Ok(PreparePrivacyMaterialResponse {
                cancelled: true,
                review: None,
            });
        };
        let path = selected.into_path().map_err(|_| IpcError {
            error_type: "invalid_material".to_owned(),
            message: "所选材料不是本地文件。".to_owned(),
        })?;
        let config = configuration.current_config();
        let ocr_status = configuration.local_ocr_status().map_err(IpcError::from)?;
        let mineru_config = match config.ocr.mode {
            OcrMode::Off => None,
            OcrMode::ForceLocal => configuration
                .local_mineru_config()
                .map_err(IpcError::from)?,
            OcrMode::AutoLocal => match configuration.local_mineru_config() {
                Ok(value) => value,
                Err(error) if error.code() == "ocr_derived_publication_invalidation_failed" => {
                    return Err(error.into());
                }
                Err(_) => None,
            },
        };
        let ocr_qualification = mineru_config
            .as_ref()
            .map(|_| configuration.local_ocr_qualification_snapshot())
            .transpose()
            .map_err(IpcError::from)?;
        let project_id = request.project_id;
        let review = match workflow.prepare_case_selected_material_with_qualification(
            &path,
            &config,
            &ocr_status,
            LocalOcrExecutionContext {
                mineru_config: mineru_config.as_ref(),
                qualification: ocr_qualification.as_ref(),
            },
            project_id.clone(),
            request.custom_terms,
        ) {
            Ok(review) => review,
            Err(error) => {
                if local_ocr_error_revokes_qualification(error.code()) {
                    configuration
                        .revoke_local_mineru_qualification()
                        .map_err(IpcError::from)?;
                }
                return Err(error.into());
            }
        };
        let review = workflow
            .case_redaction_review_view(project_id, review)
            .map_err(IpcError::from)?;
        Ok(PreparePrivacyMaterialResponse {
            cancelled: false,
            review: Some(review),
        })
    })
    .await
    .map_err(|_| IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "本地材料处理任务未完成。".to_owned(),
    })?
}

#[tauri::command]
pub async fn prepare_case_material(
    app: tauri::AppHandle,
    configuration: State<'_, PrivacyManager>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: PrepareCaseMaterialRequest,
) -> Result<PrepareCaseMaterialResponse, IpcError> {
    prepare_privacy_material(app, configuration, workflow, request).await
}

#[tauri::command]
pub async fn list_case_materials(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ListCaseMaterialsRequest,
) -> Result<Vec<CaseMaterialSummary>, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.list_case_materials(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "案件材料目录读取任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn list_unassigned_case_materials(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ListUnassignedCaseMaterialsRequest,
) -> Result<Vec<UnassignedCaseMaterialSummary>, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.list_unassigned_case_materials(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "未归属材料目录读取任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn assign_unassigned_case_material(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: AssignUnassignedCaseMaterialRequest,
) -> Result<AssignUnassignedCaseMaterialResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.assign_unassigned_case_material(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "未归属材料归入任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn list_case_redaction_generations(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ListCaseRedactionGenerationsRequest,
) -> Result<Vec<CaseRedactionGenerationSummary>, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.list_case_redaction_generations(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "案件脱敏代次目录读取任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn load_case_redaction_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: LoadCaseRedactionReviewRequest,
) -> Result<CaseRedactionReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.load_case_redaction_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "案件脱敏审阅读取任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn apply_case_redaction_risk_review_action(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ApplyCaseRedactionRiskReviewActionRequest,
) -> Result<CaseRedactionReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workflow.apply_case_redaction_risk_review_action(request)
    })
    .await
    .map_err(|_| IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "案件脱敏风险审阅任务未完成。".to_owned(),
    })?
    .map_err(Into::into)
}

#[tauri::command]
pub async fn undo_case_redaction_risk_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: CaseRedactionRiskReviewRevisionRequest,
) -> Result<CaseRedactionReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.undo_case_redaction_risk_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "案件脱敏风险审阅撤销任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn redo_case_redaction_risk_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: CaseRedactionRiskReviewRevisionRequest,
) -> Result<CaseRedactionReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.redo_case_redaction_risk_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "案件脱敏风险审阅重做任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn approve_case_redaction_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ApproveCaseRedactionReviewRequest,
) -> Result<ApprovePrivacyReviewResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.approve_case_redaction_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "案件脱敏批准任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn delete_case_redaction_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: DeleteCaseRedactionReviewRequest,
) -> Result<DeletePrivacyReviewResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.delete_case_redaction_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "案件脱敏审阅删除任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

fn local_ocr_error_revokes_qualification(code: &str) -> bool {
    matches!(
        code,
        "ocr_worker_untrusted"
            | "ocr_worker_isolation_unverified"
            | "ocr_process_containment_unavailable"
            | "ocr_config_unsafe"
            | "ocr_runtime_untrusted"
            | "ocr_runtime_changed"
            | "ocr_worker_protocol_violation"
            | "ocr_worker_unhealthy"
            | "ocr_worker_identity_mismatch"
            | "ocr_model_untrusted"
    )
}

// Phase 3 retains the unscoped adapters for compatibility qualification only. The renderer
// registration is intentionally limited to the project-scoped commands above.
#[allow(dead_code)]
#[tauri::command]
pub async fn load_privacy_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: LoadPrivacyReviewRequest,
) -> Result<PrivacyReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.load_review(&request.redaction_id))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "本地审阅读取任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[allow(dead_code)]
#[tauri::command]
pub async fn load_latest_privacy_review(
    workflow: State<'_, PrivacyWorkflowManager>,
) -> Result<Option<PrivacyReviewView>, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.load_latest_review())
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "最近的本地审阅读取任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[allow(dead_code)]
#[tauri::command]
pub async fn load_privacy_risk_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: LoadPrivacyReviewRequest,
) -> Result<privacy::ReviewStateViewV1, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.load_risk_review(&request.redaction_id))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "Local risk review load task did not complete.".to_owned(),
        })?
        .map_err(Into::into)
}

#[allow(dead_code)]
#[tauri::command]
pub async fn apply_privacy_risk_review_action(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ApplyPrivacyRiskReviewActionRequest,
) -> Result<PrivacyReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.apply_risk_review_action(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "Local risk review action task did not complete.".to_owned(),
        })?
        .map_err(Into::into)
}

#[allow(dead_code)]
#[tauri::command]
pub async fn undo_privacy_risk_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: PrivacyRiskReviewRevisionRequest,
) -> Result<PrivacyReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.undo_risk_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "Local risk review undo task did not complete.".to_owned(),
        })?
        .map_err(Into::into)
}

#[allow(dead_code)]
#[tauri::command]
pub async fn redo_privacy_risk_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: PrivacyRiskReviewRevisionRequest,
) -> Result<PrivacyReviewView, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.redo_risk_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "Local risk review redo task did not complete.".to_owned(),
        })?
        .map_err(Into::into)
}
#[allow(dead_code)]
#[tauri::command]
pub async fn delete_privacy_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: DeletePrivacyReviewRequest,
) -> Result<DeletePrivacyReviewResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.delete_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "本机审阅删除任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[allow(dead_code)]
#[tauri::command]
pub async fn approve_privacy_review(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ApprovePrivacyReviewRequest,
) -> Result<ApprovePrivacyReviewResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.approve_local_safe_export_review(request))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "本地审阅批准与回执签发任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportApprovedReviewPdfResponse {
    pub cancelled: bool,
    pub file_name: Option<String>,
    pub pdf_sha256: Option<String>,
    pub approved_text_sha256: Option<String>,
    pub extracted_text_sha256: Option<String>,
    pub output_page_count: u32,
}

#[allow(dead_code)]
#[tauri::command]
pub async fn export_approved_review_pdf(
    app: tauri::AppHandle,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ExportApprovedReviewPdfRequest,
) -> Result<ExportApprovedReviewPdfResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let selected = app
            .dialog()
            .file()
            .set_title("保存已验证的脱敏 PDF")
            .set_file_name("已脱敏材料.pdf")
            .add_filter("PDF 文档", &["pdf"])
            .blocking_save_file();
        let Some(selected) = selected else {
            workflow
                .record_safe_pdf_export_cancellation(&request)
                .map_err(IpcError::from)?;
            return Ok(ExportApprovedReviewPdfResponse {
                cancelled: true,
                file_name: None,
                pdf_sha256: None,
                approved_text_sha256: None,
                extracted_text_sha256: None,
                output_page_count: 0,
            });
        };
        let mut path = selected.into_path().map_err(|_| IpcError {
            error_type: "invalid_export_destination".to_owned(),
            message: "所选导出目标不是本地文件。".to_owned(),
        })?;
        if !path
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
        {
            path.set_extension("pdf");
        }
        validate_safe_pdf_destination(&path)?;
        let built = workflow
            .build_safe_pdf(request.clone())
            .map_err(IpcError::from)?;
        let install_result = install_safe_pdf(&path, &built, || {
            workflow
                .record_safe_pdf_export_event(
                    &request,
                    &built,
                    false,
                    "local_safe_pdf_export_attempt_pending",
                )
                .map_err(IpcError::from)?;
            workflow
                .verify_safe_pdf_authorization(&request)
                .map_err(IpcError::from)
        });
        if let Err(error) = install_result {
            let reason_code = format!("local_safe_pdf_export_failed_{}", error.error_type);
            let _ = workflow.record_safe_pdf_export_event(&request, &built, false, &reason_code);
            if error.error_type == "export_verify_failed" {
                return Err(IpcError {
                    error_type: "export_installed_verify_failed".to_owned(),
                    message:
                        "安全 PDF 已执行安装，但保存后复核失败；请将该文件视为已导出并人工核验。"
                            .to_owned(),
                });
            }
            return Err(error);
        }
        if workflow
            .record_safe_pdf_export_event(&request, &built, true, "local_safe_pdf_export_succeeded")
            .is_err()
        {
            return Err(IpcError {
                error_type: "export_succeeded_audit_failed".to_owned(),
                message: "安全 PDF 已保存，但成功结果未能写入本机隐私审计；文件仍应视为已导出。"
                    .to_owned(),
            });
        }
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
            .unwrap_or("已脱敏材料.pdf")
            .to_owned();
        Ok(ExportApprovedReviewPdfResponse {
            cancelled: false,
            file_name: Some(file_name),
            pdf_sha256: Some(built.sha256),
            approved_text_sha256: Some(built.approved_text_sha256),
            extracted_text_sha256: Some(built.extracted_text_sha256),
            output_page_count: built.output_page_count,
        })
    })
    .await
    .map_err(|_| IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "安全 PDF 重建与保存任务未完成。".to_owned(),
    })?
}

#[allow(dead_code)]
fn validate_safe_pdf_destination(path: &Path) -> Result<(), IpcError> {
    if !crate::privacy_manager::is_normal_local_absolute(path)
        || !crate::privacy_manager::local_path_chain_is_ordinary(path)
    {
        return Err(IpcError {
            error_type: "invalid_export_destination".to_owned(),
            message: "安全导出目标必须位于本机非网络磁盘；UNC 与映射网络盘已拒绝。".to_owned(),
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
    if !parent_metadata.is_dir()
        || parent_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || crate::privacy_manager::has_cloud_recall_attributes(&parent_metadata)
    {
        return Err(IpcError {
            error_type: "filesystem_rejected".to_owned(),
            message: "安全导出父目录不能是链接、reparse point 或云端占位/召回目录。".to_owned(),
        });
    }
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if !metadata.is_file()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || crate::privacy_manager::has_cloud_recall_attributes(&metadata) =>
        {
            return Err(IpcError {
                error_type: "filesystem_rejected".to_owned(),
                message: "安全导出目标必须是非云端占位的本地普通文件。".to_owned(),
            });
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(IpcError {
                error_type: "invalid_export_destination".to_owned(),
                message: "安全导出目标无法核验。".to_owned(),
            });
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn install_safe_pdf<Authorize>(
    path: &Path,
    built: &BuiltSafePdf,
    final_authorize: Authorize,
) -> Result<(), IpcError>
where
    Authorize: FnOnce() -> Result<(), IpcError>,
{
    validate_safe_pdf_destination(path)?;
    let parent = path.parent().ok_or_else(|| IpcError {
        error_type: "invalid_export_destination".to_owned(),
        message: "安全导出目标缺少父目录。".to_owned(),
    })?;

    let staged = parent.join(format!(
        ".lawyer-assistance-safe-export-{}.incoming",
        Uuid::new_v4().simple()
    ));
    let result = (|| -> Result<(), IpcError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&staged)
            .map_err(|_| IpcError {
                error_type: "export_write_failed".to_owned(),
                message: "安全 PDF 临时文件无法创建。".to_owned(),
            })?;
        if !crate::privacy_manager::opened_file_resolves_to_ordinary_local(&file) {
            return Err(IpcError {
                error_type: "filesystem_rejected".to_owned(),
                message: "安全 PDF 临时文件没有解析到本机固定磁盘普通文件。".to_owned(),
            });
        }
        final_authorize()?;
        file.write_all(&built.bytes).map_err(|_| IpcError {
            error_type: "export_write_failed".to_owned(),
            message: "安全 PDF 临时文件无法完整写入。".to_owned(),
        })?;
        file.sync_all().map_err(|_| IpcError {
            error_type: "export_write_failed".to_owned(),
            message: "安全 PDF 临时文件无法同步到磁盘。".to_owned(),
        })?;
        drop(file);
        crate::atomic_file::install(&staged, path, None).map_err(|_| IpcError {
            error_type: "export_install_failed".to_owned(),
            message: "安全 PDF 无法原子安装到所选目标。".to_owned(),
        })?;
        let installed = fs::read(path).map_err(|_| IpcError {
            error_type: "export_verify_failed".to_owned(),
            message: "安全 PDF 保存后无法复核。".to_owned(),
        })?;
        if installed != built.bytes {
            return Err(IpcError {
                error_type: "export_verify_failed".to_owned(),
                message: "安全 PDF 保存后字节不一致。".to_owned(),
            });
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_project_scoped_contract<T>(valid: serde_json::Value)
    where
        T: serde::de::DeserializeOwned,
    {
        assert!(
            serde_json::from_value::<T>(valid.clone()).is_ok(),
            "valid project-scoped request must deserialize"
        );

        let mut missing_project_id = valid.clone();
        missing_project_id
            .as_object_mut()
            .expect("request object")
            .remove("projectId");
        assert!(
            serde_json::from_value::<T>(missing_project_id).is_err(),
            "projectId must be required"
        );

        for private_or_unknown_key in ["caseId", "privacyCaseId", "unexpected"] {
            let mut with_unknown = valid.clone();
            with_unknown
                .as_object_mut()
                .expect("request object")
                .insert(
                    private_or_unknown_key.to_owned(),
                    serde_json::Value::String("case_99999999999999999999999999999999".to_owned()),
                );
            assert!(
                serde_json::from_value::<T>(with_unknown).is_err(),
                "request must deny unknown field {private_or_unknown_key}"
            );
        }
    }

    #[test]
    fn every_case_material_workflow_request_requires_project_id_and_denies_unknown_fields() {
        assert_project_scoped_contract::<PrepareCaseMaterialRequest>(serde_json::json!({
            "projectId": "case-request-contract",
            "customTerms": []
        }));
        assert_project_scoped_contract::<ListCaseMaterialsRequest>(serde_json::json!({
            "projectId": "case-request-contract"
        }));
        assert_project_scoped_contract::<ListUnassignedCaseMaterialsRequest>(serde_json::json!({
            "projectId": "case-request-contract"
        }));
        assert_project_scoped_contract::<AssignUnassignedCaseMaterialRequest>(serde_json::json!({
            "projectId": "case-request-contract",
            "materialId": "mat_request_contract",
            "expectedRowVersion": 2,
            "actor": "local-reviewer"
        }));
        assert_project_scoped_contract::<ListCaseRedactionGenerationsRequest>(serde_json::json!({
            "projectId": "case-request-contract",
            "materialId": "mat_request_contract"
        }));
        assert_project_scoped_contract::<LoadCaseRedactionReviewRequest>(serde_json::json!({
            "projectId": "case-request-contract",
            "redactionId": "red_request_contract"
        }));
        assert_project_scoped_contract::<ApplyCaseRedactionRiskReviewActionRequest>(
            serde_json::json!({
                "projectId": "case-request-contract",
                "redactionId": "red_request_contract",
                "expectedRevision": 1,
                "actor": "local-reviewer",
                "editedPages": [],
                "action": {
                    "kind": "confirm_edited_output"
                }
            }),
        );
        assert_project_scoped_contract::<CaseRedactionRiskReviewRevisionRequest>(
            serde_json::json!({
                "projectId": "case-request-contract",
                "redactionId": "red_request_contract",
                "expectedRevision": 1
            }),
        );
        assert_project_scoped_contract::<ApproveCaseRedactionReviewRequest>(serde_json::json!({
            "projectId": "case-request-contract",
            "redactionId": "red_request_contract",
            "expectedRiskRevision": 1,
            "expectedSuggestedRedactedSha256": "a".repeat(64),
            "editedPages": [],
            "reviewer": "local-reviewer",
            "destination": {
                "kind": "verified_local_provider",
                "identifier": "local-safe-pdf-export-v1"
            },
            "purpose": "local_safe_pdf_export",
            "ttlSeconds": 600
        }));
        assert_project_scoped_contract::<DeleteCaseRedactionReviewRequest>(serde_json::json!({
            "projectId": "case-request-contract",
            "redactionId": "red_request_contract",
            "expectedSourceSha256": "b".repeat(64),
            "expectedExtractionSha256": "c".repeat(64)
        }));
    }

    #[test]
    fn prepare_request_has_no_path_field() {
        let request: PreparePrivacyMaterialRequest = serde_json::from_value(serde_json::json!({
            "projectId": "case-privacy-command-test",
            "customTerms": ["内部代号"]
        }))
        .expect("custom terms parse");
        assert_eq!(request.project_id, "case-privacy-command-test");
        assert_eq!(request.custom_terms, ["内部代号"]);

        assert!(
            serde_json::from_value::<PreparePrivacyMaterialRequest>(serde_json::json!({
                "projectId": "case-privacy-command-test",
                "customTerms": [],
                "path": "C:/case/raw.pdf"
            }))
            .is_err()
        );
    }
    #[test]
    fn safe_export_verifies_after_the_blocking_dialog_and_before_install() {
        let source = include_str!("privacy_workflow.rs");
        let export = source
            .split("pub async fn export_approved_review_pdf")
            .nth(1)
            .expect("safe export command source");
        let dialog = export
            .find(".blocking_save_file()")
            .expect("blocking save dialog");
        let cancelled_audit = export
            .find("record_safe_pdf_export_cancellation(&request)")
            .expect("hash-only cancelled export audit");
        let validate = export
            .find("validate_safe_pdf_destination(&path)")
            .expect("local destination validation");
        let build = export
            .find(".build_safe_pdf(request.clone())")
            .expect("active receipt verification/build");
        let install = export
            .find("install_safe_pdf(&path, &built, ||")
            .expect("atomic safe install");
        let pending_audit = export
            .find("local_safe_pdf_export_attempt_pending")
            .expect("pending export audit before final authorization");
        let final_verify = export
            .find(".verify_safe_pdf_authorization(&request)")
            .expect("final persisted active-receipt verification");
        assert!(install < pending_audit && pending_audit < final_verify);
        assert!(dialog < cancelled_audit && cancelled_audit < validate);
        assert!(validate < build && build < install);

        let installer = source
            .split("fn install_safe_pdf")
            .nth(1)
            .expect("safe installer source");
        let final_authorize = installer
            .find("final_authorize()?")
            .expect("final active receipt verification");
        let write = installer
            .find("file.write_all(&built.bytes)")
            .expect("safe PDF byte write");
        assert!(final_authorize < write);
    }

    #[test]
    fn sensitive_paths_guard_ancestors_and_resolved_handles_before_io() {
        let workflow_source = include_str!("../privacy_workflow.rs");
        let reader = workflow_source
            .split("fn read_bounded_selected_material")
            .nth(1)
            .and_then(|source| source.split("fn validate_selected_file_metadata").next())
            .expect("bounded source reader");
        let source_ancestors = reader
            .find("local_path_chain_is_ordinary(path)")
            .expect("source ancestor-chain guard");
        let source_open = reader.find("OpenOptions::new()").expect("source open");
        let source_resolved = reader
            .find("opened_file_resolves_to_ordinary_local(&file)")
            .expect("source resolved-handle guard");
        let source_read = reader.find(".read_to_end").expect("source byte read");
        assert!(
            source_ancestors < source_open
                && source_open < source_resolved
                && source_resolved < source_read
        );

        let command_source = include_str!("privacy_workflow.rs");
        let destination_validator = command_source
            .split("fn validate_safe_pdf_destination")
            .nth(1)
            .and_then(|source| source.split("fn install_safe_pdf").next())
            .expect("destination validator");
        assert!(destination_validator.contains("local_path_chain_is_ordinary(path)"));

        let installer = command_source
            .split("fn install_safe_pdf")
            .nth(1)
            .expect("safe installer");
        let destination_recheck = installer
            .find("validate_safe_pdf_destination(path)?")
            .expect("destination ancestor recheck");
        let staged_open = installer.find("OpenOptions::new()").expect("staged open");
        let staged_resolved = installer
            .find("opened_file_resolves_to_ordinary_local(&file)")
            .expect("staged resolved-handle guard");
        let staged_write = installer
            .find("file.write_all(&built.bytes)")
            .expect("staged byte write");
        assert!(
            destination_recheck < staged_open
                && staged_open < staged_resolved
                && staged_resolved < staged_write
        );
    }
    #[test]
    fn final_authorization_failure_after_build_writes_zero_bytes() {
        let directory = tempfile::tempdir().expect("temporary local export directory");
        let target = directory.path().join("redacted.pdf");
        let artifact = BuiltSafePdf {
            bytes: b"%PDF-1.7\nredacted".to_vec(),
            sha256: "a".repeat(64),
            approved_text_sha256: "b".repeat(64),
            extracted_text_sha256: "c".repeat(64),
            output_page_count: 1,
        };
        let error = install_safe_pdf(&target, &artifact, || {
            Err(IpcError {
                error_type: "redaction_receipt_expired".to_owned(),
                message: "expired during build".to_owned(),
            })
        })
        .expect_err("expired final authorization must fail");
        assert_eq!(error.error_type, "redaction_receipt_expired");
        assert!(!target.exists());
        assert_eq!(
            fs::read_dir(directory.path())
                .expect("read export directory")
                .count(),
            0
        );
    }

    #[test]
    fn safe_export_rejects_unc_before_writing() {
        let artifact = BuiltSafePdf {
            bytes: b"%PDF-1.7".to_vec(),
            sha256: "a".repeat(64),
            approved_text_sha256: "b".repeat(64),
            extracted_text_sha256: "c".repeat(64),
            output_page_count: 1,
        };
        let error = install_safe_pdf(
            Path::new(r"\\server\share\approved-redacted.pdf"),
            &artifact,
            || Ok(()),
        )
        .expect_err("UNC safe export must be rejected");
        assert_eq!(error.error_type, "invalid_export_destination");
    }
}
