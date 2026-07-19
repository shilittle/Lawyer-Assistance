use crate::{commands::case::IpcError, state::AppState};
use domain::document::{
    generate_standalone_document, template_catalog, DocumentTemplateId, DocumentTemplateMetadata,
    GeneratedDocument, StandaloneDocumentInput,
};
use font_subset::{Font, FontReader, TableTag};
use lopdf::{Object as PdfObject, ObjectId as PdfObjectId, StringFormat as PdfStringFormat};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File},
    io::{Read, Write},
    os::windows::ffi::OsStrExt,
    path::{Component, Path, PathBuf},
};
use tauri::State;
use tauri_plugin_dialog::DialogExt;
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
};

const MAX_PROJECT_ID_BYTES: usize = 256;
const MAX_MODEL_DRAFT_BYTES: usize = 1024 * 1024;
const MAX_EXPORT_PATH_BYTES: usize = 32 * 1024;
const MAX_RECOVERABLE_PDF_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PDF_ASCII_TOKEN_CHARS: usize = 12;
const PDF_TABLE_BODY_FONT_SIZE: u8 = 11;
const PDF_TABLE_SEQUENCE_HEADER_FONT_SIZE: u8 = 10;
const PDF_TABLE_CELL_VERTICAL_PADDING_MM: f32 = 1.0;
const PDF_TABLE_CELL_HORIZONTAL_PADDING_MM: f32 = 1.0;
const PDF_TABLE_FIT_GUARD_MM: f32 = 0.5;
const EXPORT_MARKER_PREFIX: &str = "pending-document-export-";

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PdfTablePageTrace {
    headers: Vec<String>,
    row_start: usize,
    row_end: usize,
    oversized_continuation: bool,
}

#[cfg(test)]
std::thread_local! {
    static PDF_TABLE_PAGE_TRACE: std::cell::RefCell<Option<Vec<PdfTablePageTrace>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn begin_pdf_table_page_trace() {
    PDF_TABLE_PAGE_TRACE.with(|trace| *trace.borrow_mut() = Some(Vec::new()));
}

#[cfg(test)]
fn record_pdf_table_page_trace(trace_entry: PdfTablePageTrace) {
    PDF_TABLE_PAGE_TRACE.with(|trace| {
        if let Some(entries) = trace.borrow_mut().as_mut() {
            entries.push(trace_entry);
        }
    });
}

#[cfg(test)]
fn take_pdf_table_page_trace() -> Vec<PdfTablePageTrace> {
    PDF_TABLE_PAGE_TRACE.with(|trace| trace.borrow_mut().take().unwrap_or_default())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ExportMarkerPhase {
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportMarker {
    format_version: u8,
    phase: ExportMarkerPhase,
    #[serde(default)]
    audit_id: Option<String>,
    record_id: String,
    export_path: PathBuf,
    staged_path: PathBuf,
    rollback_path: PathBuf,
    destination_existed: bool,
    destination_sha256: Option<String>,
    staged_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviewDocumentRequest {
    pub project_id: Option<String>,
    pub standalone_input: Option<StandaloneDocumentInput>,
    pub template_id: DocumentTemplateId,
    pub model_draft: Option<String>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TemplateCatalogResponse {
    pub templates: Vec<DocumentTemplateMetadata>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewDocumentResponse {
    pub document: GeneratedDocument,
    pub case_revision: Option<String>,
    pub generation_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportDocumentPdfRequest {
    pub project_id: Option<String>,
    pub standalone_input: Option<StandaloneDocumentInput>,
    pub template_id: DocumentTemplateId,
    pub model_draft: Option<String>,
    pub expected_revision: Option<String>,
    pub generation_hash: String,
    pub confirmed: bool,
    pub idempotency_key: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportDocumentPdfResponse {
    pub cancelled: bool,
    pub replayed: bool,
    pub record_id: Option<String>,
    pub file_name: Option<String>,
    pub citation_count: usize,
}

#[derive(Debug)]
struct GeneratedPreview {
    document: GeneratedDocument,
    case_revision: Option<String>,
    generation_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PdfExportAuditDetails {
    schema_version: u16,
    record_id: String,
    export_path: PathBuf,
    file_sha256: String,
    citation_count: usize,
    case_revision: Option<String>,
    generation_hash: String,
}

struct LockedDirectory(HANDLE);

impl Drop for LockedDirectory {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

#[tauri::command]
pub fn list_document_templates() -> TemplateCatalogResponse {
    TemplateCatalogResponse {
        templates: template_catalog(),
    }
}

#[tauri::command]
pub fn preview_document(
    state: State<'_, AppState>,
    request: PreviewDocumentRequest,
) -> Result<PreviewDocumentResponse, IpcError> {
    let generated = load_and_generate(
        &state,
        request.project_id.as_deref(),
        request.standalone_input.as_ref(),
        request.template_id,
        request.model_draft.as_deref(),
    )?;
    Ok(PreviewDocumentResponse {
        document: generated.document,
        case_revision: generated.case_revision,
        generation_hash: generated.generation_hash,
    })
}

fn require_privacy_safe_document_export() -> Result<(), IpcError> {
    Err(IpcError::new(
        "privacy_required",
        "Legacy document PDF export is disabled; use export_approved_review_pdf with an active exact redaction receipt.",
    ))
}
#[tauri::command]
pub async fn export_document_pdf(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    request: ExportDocumentPdfRequest,
) -> Result<ExportDocumentPdfResponse, IpcError> {
    require_privacy_safe_document_export()?;
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        export_document_pdf_blocking(&app, &state, request)
    })
    .await
    .map_err(|_| IpcError::new("runtime", "PDF export worker failed"))?
}

fn export_document_pdf_blocking(
    app: &tauri::AppHandle,
    state: &AppState,
    request: ExportDocumentPdfRequest,
) -> Result<ExportDocumentPdfResponse, IpcError> {
    validate_pdf_export_request(&request)?;
    let _export_guard = state.begin_document_export();
    let request_hash = sha256_serialized(&request)?;
    let idempotency_key_hash = sha256_bytes(request.idempotency_key.as_bytes());
    let connection = database::open_user_database(state.user_database_path())?;
    if let Some(existing) = database::get_operation_audit_by_idempotency_key_hash(
        &connection,
        "desktop",
        "document_export_pdf",
        &idempotency_key_hash,
    )? {
        return replay_pdf_export(&existing, &request_hash);
    }
    drop(connection);

    let generated = load_and_generate(
        state,
        request.project_id.as_deref(),
        request.standalone_input.as_ref(),
        request.template_id,
        request.model_draft.as_deref(),
    )?;
    verify_generation_seal(&request, &generated)?;
    let case_revision = generated.case_revision.clone();
    let generation_hash = generated.generation_hash.clone();
    let document = generated.document;
    let selected = app
        .dialog()
        .file()
        .set_title("导出已复核 PDF")
        .set_file_name(format!("{}.pdf", request.template_id.as_str()))
        .add_filter("PDF 文档", &["pdf"])
        .blocking_save_file();
    let Some(selected) = selected else {
        return Ok(ExportDocumentPdfResponse {
            cancelled: true,
            replayed: false,
            record_id: None,
            file_name: None,
            citation_count: 0,
        });
    };
    let mut export_path = selected
        .into_path()
        .map_err(|_| IpcError::new("validation", "selected destination is not a local file"))?;
    if !export_path
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
    {
        export_path.set_extension("pdf");
    }
    let (validated_path, _parent_lock) = validate_selected_pdf_destination(state, &export_path)?;
    export_path = validated_path;
    let staged_path = sibling_path(&export_path, "export-incoming")?;
    let rollback_path = sibling_path(&export_path, "export-previous")?;
    let audit_id = format!("audit:{}", Uuid::new_v4());
    let record_id = Uuid::new_v4().to_string();
    let source_ids = document
        .sections
        .iter()
        .flat_map(|s| s.source_ids.iter().cloned())
        .collect::<Vec<_>>();
    let mut source_ids = source_ids;
    source_ids.sort();
    source_ids.dedup();
    let citation_ids = document
        .citations
        .iter()
        .map(|c| c.source_id.clone())
        .collect::<Vec<_>>();
    let mut citation_ids = citation_ids;
    citation_ids.sort();
    citation_ids.dedup();
    let source_ids_json = serde_json::to_string(&source_ids)?;
    let citation_ids_json = serde_json::to_string(&citation_ids)?;
    // A native save-dialog selection is required and existing destinations
    // are rejected. This avoids treating a renderer-originated boolean as
    // proof that the user approved an overwrite.
    let destination_existed = false;
    let destination_sha256 = None;
    write_pdf(&staged_path, &document)?;
    let staged_sha256 = file_sha256(&staged_path).inspect_err(|_| {
        let _ = fs::remove_file(&staged_path);
    })?;
    let marker_path = export_marker_path(state.user_database_path(), &record_id)?;
    let mut marker = ExportMarker {
        format_version: 1,
        phase: ExportMarkerPhase::Prepared,
        audit_id: Some(audit_id.clone()),
        record_id: record_id.clone(),
        export_path: export_path.clone(),
        staged_path: staged_path.clone(),
        rollback_path: rollback_path.clone(),
        destination_existed,
        destination_sha256,
        staged_sha256,
    };
    if let Err(error) = write_export_marker(&marker_path, &marker) {
        return Err(combine_cleanup_error(
            error,
            cleanup_prepared_export(&marker_path, &marker, None),
        ));
    }
    let mut connection = match database::open_user_database(state.user_database_path()) {
        Ok(connection) => connection,
        Err(error) => {
            let primary = error.into();
            return Err(combine_cleanup_error(
                primary,
                cleanup_prepared_export(&marker_path, &marker, None),
            ));
        }
    };
    let transaction =
        match connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
            Ok(transaction) => transaction,
            Err(error) => {
                let primary = error.into();
                return Err(combine_cleanup_error(
                    primary,
                    cleanup_prepared_export(&marker_path, &marker, None),
                ));
            }
        };
    if let Err(error) = database::create_operation_audit(
        &transaction,
        &database::NewOperationAuditRow {
            audit_id: audit_id.clone(),
            origin: "desktop".to_owned(),
            operation: "document_export_pdf".to_owned(),
            project_id: request.project_id.clone(),
            request_hash: request_hash.clone(),
            idempotency_key_hash: Some(idempotency_key_hash),
            details_json: serde_json::json!({
                "schemaVersion": legal_services::SERVICE_SCHEMA_VERSION,
                "generationHash": generation_hash,
                "caseRevision": case_revision,
                "state": "prepared"
            })
            .to_string(),
        },
    ) {
        let primary = IpcError::from(error);
        return Err(combine_cleanup_error(
            primary,
            cleanup_prepared_export(&marker_path, &marker, None),
        ));
    }
    if let Some(project_id) = request
        .project_id
        .filter(|project_id| !project_id.trim().is_empty())
    {
        if let Err(error) = database::insert_document_generation_record(
            &transaction,
            &database::DocumentGenerationRecordRow {
                record_id: record_id.clone(),
                project_id,
                template_id: request.template_id.as_str().to_owned(),
                template_version: document.template.version.clone(),
                source_ids_json,
                citation_ids_json,
                export_path: export_path.to_string_lossy().into_owned(),
                exported_at: current_timestamp(),
            },
        ) {
            let primary = error.into();
            return Err(combine_cleanup_error(
                primary,
                cleanup_prepared_export(&marker_path, &marker, None),
            ));
        }
    }
    if let Err(error) = transaction.commit() {
        let primary = error.into();
        return Err(combine_cleanup_error(
            primary,
            cleanup_prepared_export(&marker_path, &marker, Some(&connection)),
        ));
    }
    if let Err(error) = crate::atomic_file::install(
        &staged_path,
        &export_path,
        destination_existed.then_some(rollback_path.as_path()),
    ) {
        return Err(combine_cleanup_error(
            IpcError::new("io", error.to_string()),
            cleanup_prepared_export(&marker_path, &marker, Some(&connection)),
        ));
    }
    let completed = PdfExportAuditDetails {
        schema_version: legal_services::SERVICE_SCHEMA_VERSION,
        record_id: record_id.clone(),
        export_path: export_path.clone(),
        file_sha256: marker.staged_sha256.clone(),
        citation_count: document.citations.len(),
        case_revision,
        generation_hash,
    };
    match database::compare_and_set_operation_audit_status(
        &connection,
        &audit_id,
        "succeeded",
        &serde_json::to_string(&completed)?,
    ) {
        Ok(database::OperationAuditStatusUpdateResult::Updated(_)) => {}
        Ok(database::OperationAuditStatusUpdateResult::Conflict(_))
        | Ok(database::OperationAuditStatusUpdateResult::NotFound) => {
            return Err(combine_cleanup_error(
                IpcError::new("audit_conflict", "PDF export audit could not be finalized"),
                cleanup_prepared_export(&marker_path, &marker, Some(&connection)),
            ));
        }
        Err(error) => {
            return Err(combine_cleanup_error(
                IpcError::from(error),
                cleanup_prepared_export(&marker_path, &marker, Some(&connection)),
            ));
        }
    }
    marker.phase = ExportMarkerPhase::Committed;
    // Once the audit is durably succeeded, a stale prepared marker is safe:
    // startup recovery verifies the file hash and completes cleanup.
    let _ = write_export_marker(&marker_path, &marker);
    if rollback_path.exists() {
        fs::remove_file(&rollback_path).map_err(|error| IpcError::new("io", error.to_string()))?;
    }
    let _ = remove_file_if_exists(&marker_path);
    let file_name = export_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| IpcError::new("validation", "selected file name is not valid UTF-8"))?
        .to_owned();
    Ok(ExportDocumentPdfResponse {
        cancelled: false,
        replayed: false,
        record_id: Some(record_id),
        file_name: Some(file_name),
        citation_count: document.citations.len(),
    })
}

fn load_and_generate(
    state: &AppState,
    project_id: Option<&str>,
    standalone_input: Option<&StandaloneDocumentInput>,
    template_id: DocumentTemplateId,
    model_draft: Option<&str>,
) -> Result<GeneratedPreview, IpcError> {
    if model_draft.is_some_and(|draft| draft.len() > MAX_MODEL_DRAFT_BYTES) {
        return Err(IpcError::new(
            "validation",
            "modelDraft exceeds the 1 MiB safety limit",
        ));
    }
    if standalone_input.is_some_and(|input| {
        serde_json::to_vec(input).is_ok_and(|value| value.len() > MAX_MODEL_DRAFT_BYTES)
    }) {
        return Err(IpcError::new(
            "validation",
            "standaloneInput exceeds the 1 MiB safety limit",
        ));
    }

    let project_id = project_id.filter(|value| !value.trim().is_empty());
    let generated = match (project_id, standalone_input) {
        (Some(_), Some(_)) => {
            return Err(IpcError::new(
                "validation",
                "choose either a case project or standalone input",
            ));
        }
        (Some(project_id), None) => {
            if project_id.len() > MAX_PROJECT_ID_BYTES {
                return Err(IpcError::new("validation", "projectId is too long"));
            }
            let generated = state
                .legal_services()?
                .document_generate(legal_services::DocumentGenerateRequest {
                    schema_version: legal_services::SERVICE_SCHEMA_VERSION,
                    project_id: project_id.to_owned(),
                    template_id,
                    model_draft: model_draft.map(str::to_owned),
                })
                .map_err(document_service_error)?;
            return Ok(GeneratedPreview {
                document: generated.document,
                case_revision: Some(generated.case_revision),
                generation_hash: generated.generation_hash,
            });
        }
        (None, Some(input)) => generate_standalone_document(input, template_id, model_draft),
        (None, None) => {
            return Err(IpcError::new(
                "validation",
                "case project or standalone input is required",
            ));
        }
    };
    let document = generated.map_err(|error| {
        IpcError::new(
            "document_validation",
            serde_json::to_string(&error).unwrap_or_else(|_| "document validation failed".into()),
        )
    })?;
    let generation_hash = sha256_serialized(&document)?;
    Ok(GeneratedPreview {
        document,
        case_revision: None,
        generation_hash,
    })
}

fn document_service_error(error: legal_services::ServiceError) -> IpcError {
    if error.code != "document_validation_failed" {
        return error.into();
    }

    const PUBLIC_DOCUMENT_FIELDS: &[&str] = &[
        "plaintiff",
        "defendant",
        "sender",
        "recipient",
        "claims",
        "facts",
        "dated_facts",
        "evidence",
        "issues",
        "valid_citations",
        "case_date",
        "model_draft",
        "standalone_content",
    ];
    let missing_fields = error
        .details
        .get("missingFields")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .filter(|field| PUBLIC_DOCUMENT_FIELDS.contains(field))
        .collect::<Vec<_>>();
    let invalid_citation_count = error
        .details
        .get("invalidCitationIds")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    let code = error
        .details
        .get("code")
        .and_then(serde_json::Value::as_str)
        .filter(|code| *code == "missing_required_fields")
        .unwrap_or("citation_validation_failed");
    let public_payload = serde_json::json!({
        "code": code,
        "missingFields": missing_fields,
        // The UI needs only a count. Never forward source identifiers across
        // the renderer boundary as part of a user-visible validation error.
        "invalidCitationIds": vec!["待重新核验"; invalid_citation_count],
    });
    IpcError::new("document_validation", public_payload.to_string())
}

fn validate_pdf_export_request(request: &ExportDocumentPdfRequest) -> Result<(), IpcError> {
    if !request.confirmed {
        return Err(IpcError::new(
            "confirmation_required",
            "explicit confirmation is required before PDF export",
        ));
    }
    if request.idempotency_key.len() < 16
        || request.idempotency_key.len() > 128
        || !request
            .idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.'))
    {
        return Err(IpcError::new(
            "validation",
            "idempotencyKey must contain 16-128 safe ASCII characters",
        ));
    }
    validate_sha256_text("generationHash", &request.generation_hash)?;
    let project_id = request
        .project_id
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    match (project_id, request.standalone_input.as_ref()) {
        (Some(_), None) => {
            let revision = request.expected_revision.as_deref().ok_or_else(|| {
                IpcError::new(
                    "validation",
                    "expectedRevision is required for a case-backed PDF",
                )
            })?;
            validate_sha256_text("expectedRevision", revision)?;
        }
        (None, Some(_)) if request.expected_revision.is_none() => {}
        (Some(_), Some(_)) => {
            return Err(IpcError::new(
                "validation",
                "choose either a case project or standalone input",
            ));
        }
        (None, Some(_)) => {
            return Err(IpcError::new(
                "validation",
                "standalone PDF export must not carry a case revision",
            ));
        }
        (None, None) => {
            return Err(IpcError::new(
                "validation",
                "case project or standalone input is required",
            ));
        }
    }
    Ok(())
}

fn verify_generation_seal(
    request: &ExportDocumentPdfRequest,
    generated: &GeneratedPreview,
) -> Result<(), IpcError> {
    if request.expected_revision != generated.case_revision {
        return Err(IpcError::new(
            "revision_conflict",
            "case changed after PDF preview; regenerate and review the preview",
        ));
    }
    if request.generation_hash != generated.generation_hash {
        return Err(IpcError::new(
            "generation_hash_mismatch",
            "regenerated PDF content does not match the reviewed preview",
        ));
    }
    Ok(())
}

fn validate_sha256_text(field: &str, value: &str) -> Result<(), IpcError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(IpcError::new(
            "validation",
            format!("{field} must be a lowercase SHA-256 digest"),
        ));
    }
    Ok(())
}

fn sha256_serialized<T: Serialize>(value: &T) -> Result<String, IpcError> {
    let bytes = serde_json::to_vec(value)?;
    Ok(sha256_bytes(&bytes))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn replay_pdf_export(
    existing: &database::OperationAuditRow,
    request_hash: &str,
) -> Result<ExportDocumentPdfResponse, IpcError> {
    if existing.request_hash != request_hash {
        return Err(IpcError::new(
            "idempotency_conflict",
            "idempotencyKey was already used for a different PDF export request",
        ));
    }
    if existing.status == "prepared" {
        return Err(IpcError::new(
            "operation_in_progress",
            "the original PDF export is still being finalized; retry with the same key",
        ));
    }
    if existing.status != "succeeded" {
        return Err(IpcError::new(
            "idempotency_conflict",
            "the original PDF export failed; review the state and use a new key",
        ));
    }
    let details: PdfExportAuditDetails = serde_json::from_str(&existing.details_json)
        .map_err(|_| IpcError::new("audit_corrupt", "PDF export audit details are invalid"))?;
    if details.schema_version != legal_services::SERVICE_SCHEMA_VERSION
        || !path_is_normal_absolute(&details.export_path)
    {
        return Err(IpcError::new(
            "audit_corrupt",
            "PDF export audit details are incompatible",
        ));
    }
    let metadata = fs::symlink_metadata(&details.export_path)
        .map_err(|_| IpcError::new("export_missing", "the previously exported PDF is missing"))?;
    if !metadata.is_file()
        || is_reparse_point(&metadata)
        || metadata.len() > MAX_RECOVERABLE_PDF_BYTES
    {
        return Err(IpcError::new(
            "export_changed",
            "the previously exported PDF is no longer a bounded regular file",
        ));
    }
    if file_sha256(&details.export_path)? != details.file_sha256 {
        return Err(IpcError::new(
            "export_changed",
            "the previously exported PDF no longer matches its audit digest",
        ));
    }
    let file_name = details
        .export_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| IpcError::new("audit_corrupt", "audited PDF file name is invalid"))?
        .to_owned();
    Ok(ExportDocumentPdfResponse {
        cancelled: false,
        replayed: true,
        record_id: Some(details.record_id),
        file_name: Some(file_name),
        citation_count: details.citation_count,
    })
}

fn validate_selected_pdf_destination(
    state: &AppState,
    destination: &Path,
) -> Result<(PathBuf, LockedDirectory), IpcError> {
    if !path_is_normal_absolute(destination)
        || destination.as_os_str().to_string_lossy().len() > MAX_EXPORT_PATH_BYTES
        || !destination
            .extension()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
    {
        return Err(IpcError::new(
            "validation",
            "the selected destination must be an absolute normal .pdf path",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| IpcError::new("validation", "selected destination has no parent"))?;
    reject_reparse_chain(parent)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| IpcError::new("validation", "selected parent directory is unavailable"))?;
    let parent_metadata = fs::symlink_metadata(&canonical_parent)
        .map_err(|_| IpcError::new("validation", "selected parent metadata is unavailable"))?;
    if !parent_metadata.is_dir() || is_reparse_point(&parent_metadata) {
        return Err(IpcError::new(
            "validation",
            "selected parent must be a non-reparse directory",
        ));
    }
    let file_name = destination
        .file_name()
        .ok_or_else(|| IpcError::new("validation", "selected destination has no file name"))?;
    let normalized = canonical_parent.join(file_name);
    let app_data = state
        .user_database_path()
        .parent()
        .ok_or_else(|| IpcError::new("validation", "application data directory is unavailable"))?;
    if path_is_within_directory(&canonical_parent, app_data)
        || [
            state.user_database_path(),
            state.legal_core_path(),
            state.crash_log_path(),
        ]
        .iter()
        .any(|protected| crate::commands::release::paths_refer_to_same_file(protected, &normalized))
    {
        return Err(IpcError::new(
            "protected_path",
            "PDF files cannot be exported into application-managed storage",
        ));
    }
    let parent_lock = lock_directory(&canonical_parent)?;
    match fs::symlink_metadata(&normalized) {
        Ok(_) => {
            return Err(IpcError::new(
                "output_exists",
                "PDF export never overwrites an existing destination; choose a new file name",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(IpcError::new(
                "validation",
                "selected destination metadata is unavailable",
            ));
        }
    }
    Ok((normalized, parent_lock))
}

fn path_is_normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn path_is_within_directory(path: &Path, directory: &Path) -> bool {
    let path = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let directory = fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    let path = path.to_string_lossy().to_lowercase();
    let mut directory = directory.to_string_lossy().to_lowercase();
    if !directory.ends_with(std::path::MAIN_SEPARATOR) {
        directory.push(std::path::MAIN_SEPARATOR);
    }
    path == directory.trim_end_matches(std::path::MAIN_SEPARATOR) || path.starts_with(&directory)
}

fn reject_reparse_chain(path: &Path) -> Result<(), IpcError> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|_| IpcError::new("validation", "selected path metadata is unavailable"))?;
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            return Err(IpcError::new(
                "path_escape",
                "selected path contains a symlink or reparse point",
            ));
        }
    }
    Ok(())
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn lock_directory(path: &Path) -> Result<LockedDirectory, IpcError> {
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(IpcError::new(
            "path_lock_failed",
            "selected parent directory could not be locked for export",
        ));
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        unsafe {
            CloseHandle(handle);
        }
        return Err(IpcError::new(
            "path_lock_failed",
            "selected parent directory identity could not be verified",
        ));
    }
    Ok(LockedDirectory(handle))
}

fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

fn sibling_path(path: &Path, role: &str) -> Result<PathBuf, IpcError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| IpcError::new("validation", "exportPath must name a file"))?;
    Ok(parent.join(format!(
        ".{file_name}.lawyer-assistance-{role}-{}",
        Uuid::new_v4()
    )))
}

fn absolute_file_path(path: &Path) -> Result<PathBuf, IpcError> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(path))
            .map_err(|error| IpcError::new("io", error.to_string()))
    }
}

fn export_marker_path(user_database_path: &Path, record_id: &str) -> Result<PathBuf, IpcError> {
    let directory = user_database_path
        .parent()
        .ok_or_else(|| IpcError::new("io", "user database path has no parent directory"))?;
    Ok(directory.join(format!("{EXPORT_MARKER_PREFIX}{record_id}.json")))
}

fn write_export_marker(path: &Path, marker: &ExportMarker) -> Result<(), IpcError> {
    let incoming = sibling_path(path, "marker-incoming")?;
    let result = (|| {
        let mut file =
            File::create(&incoming).map_err(|error| IpcError::new("io", error.to_string()))?;
        file.write_all(&serde_json::to_vec(marker)?)
            .map_err(|error| IpcError::new("io", error.to_string()))?;
        file.sync_all()
            .map_err(|error| IpcError::new("io", error.to_string()))?;
        drop(file);
        // Replacing the tiny marker needs no rollback copy: ReplaceFileW leaves
        // either the old or new complete JSON, and both phases are recoverable.
        crate::atomic_file::install(&incoming, path, None)
            .map_err(|error| IpcError::new("io", error.to_string()))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(incoming);
    }
    result
}

fn delete_generation_record(
    connection: &rusqlite::Connection,
    record_id: &str,
) -> Result<(), IpcError> {
    connection
        .execute(
            "DELETE FROM document_generation_records WHERE record_id = ?1",
            [record_id],
        )
        .map(|_| ())
        .map_err(IpcError::from)
}

fn rollback_export_files(marker: &ExportMarker) -> Result<(), IpcError> {
    if marker.destination_existed {
        if marker.rollback_path.exists() {
            if marker.export_path.exists() {
                crate::atomic_file::install(&marker.rollback_path, &marker.export_path, None)
                    .map_err(|error| IpcError::new("io", error.to_string()))?;
            } else {
                fs::rename(&marker.rollback_path, &marker.export_path)
                    .map_err(|error| IpcError::new("io", error.to_string()))?;
            }
        } else if !marker.staged_path.exists() && !original_destination_is_restored(marker)? {
            return Err(IpcError::new(
                "document_recovery",
                "the previous destination journal is missing; automatic rollback is unsafe",
            ));
        } else if marker.staged_path.exists() && !original_destination_is_restored(marker)? {
            return Err(IpcError::new(
                "document_recovery",
                "the original export destination changed before installation",
            ));
        }
    } else if marker.staged_path.exists() {
        if marker.export_path.exists() {
            return Err(IpcError::new(
                "document_recovery",
                "a new destination appeared before document installation",
            ));
        }
    } else if marker.export_path.exists() {
        if file_sha256(&marker.export_path)? != marker.staged_sha256 {
            return Err(IpcError::new(
                "document_recovery",
                "the export destination no longer matches the staged document",
            ));
        }
        fs::remove_file(&marker.export_path)
            .map_err(|error| IpcError::new("io", error.to_string()))?;
    }
    remove_file_if_exists(&marker.staged_path)?;
    remove_file_if_exists(&marker.rollback_path)?;
    Ok(())
}

fn original_destination_is_restored(marker: &ExportMarker) -> Result<bool, IpcError> {
    if !marker.destination_existed {
        return Ok(!marker.export_path.exists());
    }
    let Some(expected) = marker.destination_sha256.as_deref() else {
        return Ok(false);
    };
    if !marker.export_path.is_file() {
        return Ok(false);
    }
    Ok(file_sha256(&marker.export_path)? == expected)
}

fn file_sha256(path: &Path) -> Result<String, IpcError> {
    let mut file = File::open(path).map_err(|error| IpcError::new("io", error.to_string()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| IpcError::new("io", error.to_string()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn remove_file_if_exists(path: &Path) -> Result<(), IpcError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(IpcError::new("io", error.to_string())),
    }
}

fn cleanup_prepared_export(
    marker_path: &Path,
    marker: &ExportMarker,
    connection: Option<&rusqlite::Connection>,
) -> Result<(), IpcError> {
    if let Some(connection) = connection {
        if let Some(audit_id) = marker.audit_id.as_deref() {
            if database::get_operation_audit(connection, audit_id)?
                .is_some_and(|audit| audit.status == "succeeded")
            {
                return Err(IpcError::new(
                    "document_cleanup",
                    "a succeeded PDF audit cannot be rolled back automatically",
                ));
            }
        }
        delete_generation_record(connection, &marker.record_id)?;
    }
    rollback_export_files(marker)?;
    if let (Some(connection), Some(audit_id)) = (connection, marker.audit_id.as_deref()) {
        match database::compare_and_set_operation_audit_status(
            connection,
            audit_id,
            "failed",
            &serde_json::json!({
                "schemaVersion": legal_services::SERVICE_SCHEMA_VERSION,
                "reason": "pdf_export_rolled_back"
            })
            .to_string(),
        )? {
            database::OperationAuditStatusUpdateResult::Updated(_)
            | database::OperationAuditStatusUpdateResult::NotFound => {}
            database::OperationAuditStatusUpdateResult::Conflict(audit)
                if audit.status == "failed" => {}
            database::OperationAuditStatusUpdateResult::Conflict(_) => {
                return Err(IpcError::new(
                    "audit_conflict",
                    "PDF export audit changed during rollback",
                ));
            }
        }
    }
    let mut completed = marker.clone();
    completed.phase = ExportMarkerPhase::RolledBack;
    write_export_marker(marker_path, &completed)?;
    remove_file_if_exists(marker_path)
}

fn combine_cleanup_error(primary: IpcError, cleanup: Result<(), IpcError>) -> IpcError {
    match cleanup {
        Ok(()) => primary,
        Err(cleanup) => IpcError::new(
            "document_cleanup",
            format!(
                "{}; recovery marker was retained because automatic cleanup failed: {}",
                primary.message, cleanup.message
            ),
        ),
    }
}

/// Repairs the small two-phase journal used to keep exported PDF files and
/// their database audit records consistent across a process or power loss.
pub fn recover_pending_document_exports(
    app_local_data_dir: &Path,
    user_database_path: &Path,
) -> Result<(), IpcError> {
    if !app_local_data_dir.is_dir() {
        return Ok(());
    }
    let connection = database::open_user_database(user_database_path)?;
    for entry in
        fs::read_dir(app_local_data_dir).map_err(|error| IpcError::new("io", error.to_string()))?
    {
        let entry = entry.map_err(|error| IpcError::new("io", error.to_string()))?;
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        if !file_name.starts_with(EXPORT_MARKER_PREFIX) || !file_name.ends_with(".json") {
            continue;
        }
        let bytes =
            fs::read(entry.path()).map_err(|error| IpcError::new("io", error.to_string()))?;
        if bytes.len() > 64 * 1024 {
            return Err(IpcError::new(
                "document_recovery",
                "export marker is too large",
            ));
        }
        let marker: ExportMarker = serde_json::from_slice(&bytes)?;
        validate_export_marker(&marker, &entry.path())?;
        let record_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM document_generation_records WHERE record_id = ?1)",
                [&marker.record_id],
                |row| row.get(0),
            )
            .map_err(IpcError::from)?;
        let audit = marker
            .audit_id
            .as_deref()
            .map(|audit_id| database::get_operation_audit(&connection, audit_id))
            .transpose()?
            .flatten();
        let durable_success = audit.as_ref().is_some_and(|audit| {
            audit.status == "succeeded" && (audit.project_id.is_none() || record_exists)
        }) || (audit.is_none()
            && marker.phase == ExportMarkerPhase::Committed
            && record_exists);
        if durable_success
            && marker.export_path.is_file()
            && file_sha256(&marker.export_path)? == marker.staged_sha256
        {
            remove_file_if_exists(&marker.staged_path)?;
            remove_file_if_exists(&marker.rollback_path)?;
        } else {
            if audit
                .as_ref()
                .is_some_and(|audit| audit.status == "succeeded")
            {
                return Err(IpcError::new(
                    "document_recovery",
                    "a succeeded PDF audit no longer matches its file or generation record",
                ));
            }
            delete_generation_record(&connection, &marker.record_id)?;
            rollback_export_files(&marker)?;
            if let (Some(audit), Some(audit_id)) = (audit.as_ref(), marker.audit_id.as_deref()) {
                if audit.status == "prepared" {
                    match database::compare_and_set_operation_audit_status(
                        &connection,
                        audit_id,
                        "failed",
                        &serde_json::json!({
                            "schemaVersion": legal_services::SERVICE_SCHEMA_VERSION,
                            "reason": "recovered_incomplete_pdf_export"
                        })
                        .to_string(),
                    )? {
                        database::OperationAuditStatusUpdateResult::Updated(_) => {}
                        _ => {
                            return Err(IpcError::new(
                                "audit_conflict",
                                "PDF export audit changed during recovery",
                            ));
                        }
                    }
                }
            }
            if marker.phase != ExportMarkerPhase::RolledBack {
                let mut completed = marker.clone();
                completed.phase = ExportMarkerPhase::RolledBack;
                write_export_marker(&entry.path(), &completed)?;
            }
        }
        fs::remove_file(entry.path()).map_err(|error| IpcError::new("io", error.to_string()))?;
    }
    Ok(())
}

fn validate_export_marker(marker: &ExportMarker, marker_path: &Path) -> Result<(), IpcError> {
    if marker.format_version != 1
        || Uuid::parse_str(&marker.record_id).is_err()
        || marker.audit_id.as_deref().is_some_and(|audit_id| {
            audit_id
                .strip_prefix("audit:")
                .is_none_or(|value| Uuid::parse_str(value).is_err())
        })
        || marker.staged_sha256.len() != 64
        || marker
            .destination_sha256
            .as_deref()
            .is_some_and(|digest| digest.len() != 64)
        || marker.destination_existed != marker.destination_sha256.is_some()
    {
        return Err(IpcError::new(
            "document_recovery",
            "export marker is invalid",
        ));
    }
    if export_marker_path(
        marker_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(database::USER_DB_FILE_NAME)
            .as_path(),
        &marker.record_id,
    )? != marker_path
    {
        return Err(IpcError::new(
            "document_recovery",
            "export marker filename does not match its record",
        ));
    }
    let parent = marker.export_path.parent();
    if marker.staged_path.parent() != parent || marker.rollback_path.parent() != parent {
        return Err(IpcError::new(
            "document_recovery",
            "export recovery files must be siblings",
        ));
    }
    let staged_name = marker
        .staged_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let rollback_name = marker
        .rollback_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !staged_name.contains("lawyer-assistance-export-incoming-")
        || !rollback_name.contains("lawyer-assistance-export-previous-")
    {
        return Err(IpcError::new(
            "document_recovery",
            "export recovery filenames are invalid",
        ));
    }
    Ok(())
}

fn write_pdf(path: &Path, document: &GeneratedDocument) -> Result<(), IpcError> {
    let path = absolute_file_path(path)?;
    let path = path.as_path();
    validate_pdf_structure(document)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| IpcError::new("io", e.to_string()))?;
    }
    if let Err(error) = write_pdf_payload(path, document) {
        let _ = fs::remove_file(path);
        return Err(error);
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let _ = fs::remove_file(path);
        IpcError::new("io", error.to_string())
    })?;
    if !metadata.is_file()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_RECOVERABLE_PDF_BYTES
    {
        let _ = fs::remove_file(path);
        return Err(IpcError::new(
            "pdf_size",
            "generated PDF is empty or exceeds the recoverable export limit",
        ));
    }
    Ok(())
}

fn write_pdf_payload(path: &Path, document: &GeneratedDocument) -> Result<(), IpcError> {
    use genpdf::{elements, style, Alignment, Element as _, PaperSize};

    let all_characters = collect_pdf_characters(document);
    // Use one reviewed, hash-pinned TrueType face for every family slot. The
    // generated PDF embeds only the glyph subset it needs, so output no longer
    // depends on optional Windows FangSong/Song/Hei font installations.
    let bundled = load_bundled_legal_font(&all_characters)?;
    let fang = bundled.clone();
    let song = bundled.clone();
    let bold = bundled.clone();
    let title_bold = bundled;

    validate_pdf_font_coverage(
        "内置标题字体",
        &song,
        std::iter::once(document.title.as_str()),
    )?;
    validate_pdf_font_coverage(
        "内置强调字体",
        &bold,
        document
            .sections
            .iter()
            .map(|section| section.heading.as_str())
            .chain(
                document
                    .tables
                    .iter()
                    .flat_map(|table| table.headers.iter().map(String::as_str)),
            ),
    )?;
    validate_pdf_font_coverage(
        "内置正文字体",
        &fang,
        document
            .sections
            .iter()
            .flat_map(|section| section.paragraphs.iter().map(String::as_str))
            .chain(document.tables.iter().flat_map(|table| {
                table
                    .rows
                    .iter()
                    .flat_map(|row| row.cells.iter().map(String::as_str))
            })),
    )?;

    let body_family = genpdf::fonts::FontFamily {
        regular: fang.clone(),
        bold: bold.clone(),
        italic: fang,
        bold_italic: bold,
    };
    let title_family = genpdf::fonts::FontFamily {
        regular: song.clone(),
        bold: title_bold.clone(),
        italic: song,
        bold_italic: title_bold,
    };

    let mut pdf = genpdf::Document::new(body_family);
    let title_family = pdf.add_font_family(title_family);
    pdf.set_title(&document.title);
    pdf.set_paper_size(PaperSize::A4);
    pdf.set_font_size(16);
    pdf.set_line_spacing(1.5);
    pdf.set_minimal_conformance();
    let mut decorator = genpdf::SimplePageDecorator::new();
    decorator.set_margins((25, 25, 25, 28));
    pdf.set_page_decorator(decorator);

    let title_style = style::Style::new()
        .with_font_family(title_family)
        .with_font_size(18)
        .with_line_spacing(1.25)
        .bold();
    pdf.push(
        breakable_paragraph(&document.title)
            .aligned(Alignment::Center)
            .styled(title_style),
    );
    pdf.push(elements::Break::new(1.5));

    for (section_index, section) in document.sections.iter().enumerate() {
        // The public citation appendix must stay visually independent from the
        // preceding pleading.  Starting it on a fresh page also gives its
        // widest rows enough room to remain intact.
        if section_index > 0 && section.heading == "法律依据与案例引用表" {
            pdf.push(elements::PageBreak::new());
        }
        let heading_size = match section.level {
            0 | 1 => 17,
            2 => 16,
            _ => 15,
        };
        pdf.push(
            breakable_paragraph(&section.heading)
                .styled(style::Style::new().with_font_size(heading_size).bold()),
        );
        pdf.push(elements::Break::new(0.5));

        for paragraph in &section.paragraphs {
            for line in paragraph.lines() {
                pdf.push(indented_legal_paragraph(line));
            }
            pdf.push(elements::Break::new(0.65));
        }

        for source_table in document
            .tables
            .iter()
            .filter(|table| table.section_heading == section.heading)
        {
            let weights = source_table
                .column_widths_dxa
                .iter()
                .map(|width| usize::try_from(*width).unwrap_or(1).max(1))
                .collect();
            pdf.push(PaginatedPdfTable::new(
                weights,
                source_table.headers.clone(),
                source_table
                    .rows
                    .iter()
                    .map(|row| row.cells.clone())
                    .collect(),
            ));
            pdf.push(elements::Break::new(0.8));
        }
    }

    pdf.render_to_file(path)
        .map_err(|error| IpcError::new("pdf", format!("PDF rendering failed: {error}")))?;
    optimize_pdf_file(path, &document.title)?;
    File::options()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| IpcError::new("io", error.to_string()))
}

/// A table renderer with row-level pagination.
///
/// `genpdf`'s stock `TableLayout` resumes a partially rendered row on the next
/// page without repeating the header.  That is unsuitable for legal citation
/// appendices: a reader must always be able to identify every continued
/// column, and an ordinary row must not be cut merely because it began in the
/// last few lines of a page.  This element measures the wrapped cell content,
/// emits only complete rows that fit, and reconstructs the header on every
/// continuation page.  A single row taller than a full page is the sole case
/// in which the row itself is continued; even then, each continuation receives
/// a fresh header.
struct PaginatedPdfTable {
    column_weights: Vec<usize>,
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
    next_row: usize,
    next_render_is_fresh_page: bool,
    oversized_row: Option<genpdf::elements::TableLayout>,
}

impl PaginatedPdfTable {
    fn new(column_weights: Vec<usize>, headers: Vec<String>, rows: Vec<Vec<String>>) -> Self {
        Self {
            column_weights,
            headers,
            rows,
            next_row: 0,
            next_render_is_fresh_page: false,
            oversized_row: None,
        }
    }

    fn render_oversized_row(
        &mut self,
        context: &genpdf::Context,
        mut area: genpdf::render::Area<'_>,
        style: genpdf::style::Style,
    ) -> Result<genpdf::RenderResult, genpdf::error::Error> {
        let mut header = build_pdf_table_layout(&self.column_weights, &self.headers, &[], true)?;
        let header_result = genpdf::Element::render(&mut header, context, area.clone(), style)?;
        if header_result.has_more {
            return Err(genpdf::error::Error::new(
                "PDF table header exceeds the writable page area",
                genpdf::error::ErrorKind::PageSizeExceeded,
            ));
        }

        area.add_offset(genpdf::Position::new(0, header_result.size.height));
        let row_result = genpdf::Element::render(
            self.oversized_row
                .as_mut()
                .expect("oversized table row must exist while rendering"),
            context,
            area,
            style,
        )?;
        #[cfg(test)]
        record_pdf_table_page_trace(PdfTablePageTrace {
            headers: self.headers.clone(),
            row_start: self.next_row,
            row_end: self.next_row + 1,
            oversized_continuation: true,
        });
        let mut result = genpdf::RenderResult {
            size: header_result.size.stack_vertical(row_result.size),
            has_more: row_result.has_more,
        };

        if row_result.has_more {
            self.next_render_is_fresh_page = true;
        } else {
            self.oversized_row = None;
            self.next_row += 1;
            result.has_more = self.next_row < self.rows.len();
            self.next_render_is_fresh_page = result.has_more;
        }
        Ok(result)
    }
}

impl genpdf::Element for PaginatedPdfTable {
    fn render(
        &mut self,
        context: &genpdf::Context,
        area: genpdf::render::Area<'_>,
        style: genpdf::style::Style,
    ) -> Result<genpdf::RenderResult, genpdf::error::Error> {
        let is_fresh_page = self.next_render_is_fresh_page;
        self.next_render_is_fresh_page = false;

        if self.oversized_row.is_some() {
            return self.render_oversized_row(context, area, style);
        }

        if self.rows.is_empty() {
            let mut header =
                build_pdf_table_layout(&self.column_weights, &self.headers, &[], true)?;
            return genpdf::Element::render(&mut header, context, area, style);
        }

        let header_height = measure_pdf_table_row_height(
            context,
            &area,
            style,
            &self.column_weights,
            &self.headers,
            true,
        );
        let available_height = area.size().height;
        let fit_guard = genpdf::Mm::from(PDF_TABLE_FIT_GUARD_MM);
        let mut planned_height = header_height + fit_guard;
        let mut end_row = self.next_row;
        while end_row < self.rows.len() {
            let row_height = measure_pdf_table_row_height(
                context,
                &area,
                style,
                &self.column_weights,
                &self.rows[end_row],
                false,
            );
            if planned_height + row_height + fit_guard > available_height {
                break;
            }
            planned_height += row_height + fit_guard;
            end_row += 1;
        }

        if end_row == self.next_row {
            if !is_fresh_page {
                // Consume no vertical space but return a non-zero width, like
                // genpdf's PageBreak, so the root renderer safely advances to
                // a clean page and retries this same row.
                self.next_render_is_fresh_page = true;
                return Ok(genpdf::RenderResult {
                    size: genpdf::Size::new(1, 0),
                    has_more: true,
                });
            }

            self.oversized_row = Some(build_pdf_table_layout(
                &self.column_weights,
                &self.headers,
                &self.rows[self.next_row..=self.next_row],
                false,
            )?);
            return self.render_oversized_row(context, area, style);
        }

        let mut table = build_pdf_table_layout(
            &self.column_weights,
            &self.headers,
            &self.rows[self.next_row..end_row],
            true,
        )?;
        let mut result = genpdf::Element::render(&mut table, context, area, style)?;
        if result.has_more {
            return Err(genpdf::error::Error::new(
                "PDF table row fit calculation did not preserve a complete row",
                genpdf::error::ErrorKind::PageSizeExceeded,
            ));
        }

        #[cfg(test)]
        record_pdf_table_page_trace(PdfTablePageTrace {
            headers: self.headers.clone(),
            row_start: self.next_row,
            row_end: end_row,
            oversized_continuation: false,
        });

        self.next_row = end_row;
        result.has_more = self.next_row < self.rows.len();
        self.next_render_is_fresh_page = result.has_more;
        Ok(result)
    }
}

fn build_pdf_table_layout(
    column_weights: &[usize],
    headers: &[String],
    rows: &[Vec<String>],
    include_header: bool,
) -> Result<genpdf::elements::TableLayout, genpdf::error::Error> {
    use genpdf::{elements, style, Element as _};

    let mut table = elements::TableLayout::new(column_weights.to_vec());
    table.set_cell_decorator(elements::FrameCellDecorator::new(true, true, false));

    if include_header {
        let mut header = table.row();
        for value in headers {
            let font_size = if value == "序号" {
                PDF_TABLE_SEQUENCE_HEADER_FONT_SIZE
            } else {
                PDF_TABLE_BODY_FONT_SIZE
            };
            header.push_element(
                breakable_table_header(value)
                    .styled(style::Style::new().with_font_size(font_size).bold())
                    .padded((
                        PDF_TABLE_CELL_VERTICAL_PADDING_MM,
                        PDF_TABLE_CELL_HORIZONTAL_PADDING_MM,
                    )),
            );
        }
        header.push()?;
    }

    for values in rows {
        let mut row = table.row();
        for value in values {
            row.push_element(
                breakable_table_cell(value)
                    .styled(style::Style::new().with_font_size(PDF_TABLE_BODY_FONT_SIZE))
                    .padded((
                        PDF_TABLE_CELL_VERTICAL_PADDING_MM,
                        PDF_TABLE_CELL_HORIZONTAL_PADDING_MM,
                    )),
            );
        }
        row.push()?;
    }
    Ok(table)
}

fn measure_pdf_table_row_height(
    context: &genpdf::Context,
    area: &genpdf::render::Area<'_>,
    parent_style: genpdf::style::Style,
    column_weights: &[usize],
    values: &[String],
    is_header: bool,
) -> genpdf::Mm {
    let column_areas = area.split_horizontally(column_weights);
    column_areas
        .iter()
        .zip(values)
        .map(|(column_area, value)| {
            let font_size = if is_header && value == "序号" {
                PDF_TABLE_SEQUENCE_HEADER_FONT_SIZE
            } else {
                PDF_TABLE_BODY_FONT_SIZE
            };
            let cell_style = parent_style.and({
                let style = genpdf::style::Style::new().with_font_size(font_size);
                if is_header {
                    style.bold()
                } else {
                    style
                }
            });
            let content_width = (column_area.size().width
                - genpdf::Mm::from(2.0 * PDF_TABLE_CELL_HORIZONTAL_PADDING_MM))
            .max(genpdf::Mm::from(0.1_f32));
            let line_count = pdf_table_lines(value)
                .iter()
                .map(|tokens| {
                    if tokens.is_empty() {
                        1
                    } else {
                        measure_pdf_wrapped_lines(context, tokens, content_width, cell_style)
                    }
                })
                .sum::<usize>();
            let content_height = cell_style.line_height(&context.font_cache) * line_count as f64;
            content_height + genpdf::Mm::from(2.0 * PDF_TABLE_CELL_VERTICAL_PADDING_MM)
        })
        .fold(genpdf::Mm::from(0), |height, cell_height| {
            height.max(cell_height)
        })
}

fn measure_pdf_wrapped_lines(
    context: &genpdf::Context,
    tokens: &[String],
    max_width: genpdf::Mm,
    style: genpdf::style::Style,
) -> usize {
    let mut lines = 0_usize;
    let mut occupied = genpdf::Mm::from(0);
    let mut has_word = false;

    for token in tokens {
        let mut remaining = token.as_str();
        while !remaining.is_empty() {
            let split_at = remaining
                .find(' ')
                .map(|index| index + 1)
                .unwrap_or(remaining.len());
            let word = &remaining[..split_at];
            remaining = &remaining[split_at..];
            let word_width = style.str_width(&context.font_cache, word);
            if has_word && occupied + word_width > max_width {
                lines += 1;
                occupied = word_width;
            } else {
                occupied += word_width;
            }
            has_word = true;
        }
    }

    lines + usize::from(has_word)
}

/// genpdf 0.2 only wraps at `StyledString` boundaries without a hyphenator.
/// These tokens keep Chinese closing punctuation, ISO dates and file extensions
/// attached to their neighbours while still bounding long opaque identifiers.
fn breakable_paragraph(value: &str) -> genpdf::elements::Paragraph {
    pdf_break_tokens(value).into_iter().collect()
}

fn indented_legal_paragraph(value: &str) -> genpdf::elements::Paragraph {
    if value.trim().is_empty() || value.starts_with("　　") {
        breakable_paragraph(value)
    } else {
        breakable_paragraph(&format!("　　{value}"))
    }
}

fn breakable_table_cell(value: &str) -> genpdf::elements::LinearLayout {
    let mut layout = genpdf::elements::LinearLayout::vertical();
    for line in pdf_table_lines(value) {
        if line.is_empty() {
            layout.push(genpdf::elements::Break::new(1));
        } else {
            layout.push(line.into_iter().collect::<genpdf::elements::Paragraph>());
        }
    }
    layout
}

fn breakable_table_header(value: &str) -> genpdf::elements::LinearLayout {
    if value == "序号" {
        let mut layout = genpdf::elements::LinearLayout::vertical();
        layout.push(genpdf::elements::Paragraph::new(value));
        layout
    } else {
        breakable_table_cell(value)
    }
}

fn pdf_table_lines(value: &str) -> Vec<Vec<String>> {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(pdf_break_tokens)
        .collect()
}

fn pdf_break_tokens(value: &str) -> Vec<String> {
    const CLOSING_PUNCTUATION: &str = "，。！？；：、）》】」』”’〉〕］｝…";
    const OPENING_PUNCTUATION: &str = "（《【「『“‘〈〔［｛";

    let characters = value.chars().collect::<Vec<_>>();
    let mut tokens = Vec::<String>::new();
    let mut opening = String::new();
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if character.is_ascii() && !character.is_ascii_whitespace() {
            let start = index;
            index += 1;
            while index < characters.len()
                && characters[index].is_ascii()
                && !characters[index].is_ascii_whitespace()
            {
                index += 1;
            }
            let ascii = characters[start..index].iter().collect::<String>();
            for (piece_index, piece) in split_pdf_ascii_token(&ascii).into_iter().enumerate() {
                if piece_index == 0 && piece.starts_with('.') && piece.len() <= 5 {
                    if let Some(previous) = tokens.last_mut() {
                        previous.push_str(&opening);
                        opening.clear();
                        previous.push_str(&piece);
                        continue;
                    }
                }
                let mut token = String::new();
                token.push_str(&opening);
                opening.clear();
                token.push_str(&piece);
                tokens.push(token);
            }
            continue;
        }
        index += 1;

        if character.is_whitespace() {
            let mut whitespace = String::new();
            whitespace.push_str(&opening);
            opening.clear();
            whitespace.push(character);
            while index < characters.len() && characters[index].is_whitespace() {
                whitespace.push(characters[index]);
                index += 1;
            }
            tokens.push(whitespace);
        } else if OPENING_PUNCTUATION.contains(character) {
            opening.push(character);
        } else if CLOSING_PUNCTUATION.contains(character) {
            if let Some(previous) = tokens.last_mut() {
                previous.push_str(&opening);
                opening.clear();
                previous.push(character);
            } else {
                opening.push(character);
            }
        } else {
            let mut token = String::new();
            token.push_str(&opening);
            opening.clear();
            token.push(character);
            tokens.push(token);
        }
    }
    if !opening.is_empty() {
        if let Some(previous) = tokens.last_mut() {
            previous.push_str(&opening);
        } else {
            tokens.push(opening);
        }
    }
    tokens
}

fn split_pdf_ascii_token(value: &str) -> Vec<String> {
    if value.chars().count() <= MAX_PDF_ASCII_TOKEN_CHARS {
        return vec![value.to_owned()];
    }
    let mut remaining = value;
    let mut pieces = Vec::new();
    while remaining.len() > MAX_PDF_ASCII_TOKEN_CHARS {
        let window = &remaining[..MAX_PDF_ASCII_TOKEN_CHARS];
        let cut = window
            .char_indices()
            .rev()
            .find_map(|(index, character)| {
                matches!(character, ':' | '/' | '\\' | '-' | '_' | '.')
                    .then_some(index + character.len_utf8())
            })
            .filter(|cut| *cut >= 4)
            .unwrap_or(MAX_PDF_ASCII_TOKEN_CHARS);
        pieces.push(remaining[..cut].to_owned());
        remaining = &remaining[cut..];
    }
    if !remaining.is_empty() {
        pieces.push(remaining.to_owned());
    }
    pieces
}

fn collect_pdf_characters(document: &GeneratedDocument) -> BTreeSet<char> {
    // U+3000 is inserted by `indented_legal_paragraph` even when it is not
    // present in the generated document model.
    let mut characters = BTreeSet::from([' ', '-', '\u{3000}']);
    extend_pdf_characters(&mut characters, &document.title);
    for section in &document.sections {
        extend_pdf_characters(&mut characters, &section.heading);
        for paragraph in &section.paragraphs {
            extend_pdf_characters(&mut characters, paragraph);
        }
    }
    for table in &document.tables {
        for header in &table.headers {
            extend_pdf_characters(&mut characters, header);
        }
        for row in &table.rows {
            for cell in &row.cells {
                extend_pdf_characters(&mut characters, cell);
            }
        }
    }
    characters
}

fn extend_pdf_characters(characters: &mut BTreeSet<char>, value: &str) {
    characters.extend(
        value
            .chars()
            .filter(|character| pdf_character_requires_glyph(*character)),
    );
}

fn pdf_character_requires_glyph(character: char) -> bool {
    // Paragraph and table renderers consume CR/LF as line boundaries. Other
    // whitespace, including tabs and narrow no-break spaces, is handed to the
    // font renderer and must therefore have a real glyph or fail closed.
    !matches!(character, '\r' | '\n')
}

fn load_bundled_legal_font(
    retained_characters: &BTreeSet<char>,
) -> Result<genpdf::fonts::FontData, IpcError> {
    const ROLE: &str = "内置 Noto Sans SC";
    const SOURCE_LABEL: &str = "NotoSansSC-Regular.ttf";
    let bytes = material_processing::bundled_pdf_font_bytes();
    let reader = FontReader::new(bytes).map_err(|error| {
        IpcError::new(
            "pdf_font",
            format!("无法解析{ROLE}字体 {SOURCE_LABEL}：{error}"),
        )
    })?;

    let os2 = reader
        .raw_tables()
        .find_map(|(tag, bytes)| (tag == TableTag::OS2).then_some(bytes))
        .ok_or_else(|| IpcError::new("pdf_font", format!("{ROLE}字体缺少 OS/2 许可表。")))?;
    if os2.len() < 10 {
        return Err(IpcError::new(
            "pdf_font",
            format!("{ROLE}字体的 OS/2 许可表不完整。"),
        ));
    }
    let fs_type = u16::from_be_bytes([os2[8], os2[9]]);
    let embedding = fs_type & 0x000f;
    if !matches!(embedding, 0 | 8) || fs_type & 0x0200 != 0 {
        return Err(IpcError::new(
            "pdf_font_license",
            format!("{ROLE}字体的许可证不允许可编辑的轮廓嵌入，已拒绝生成 PDF。"),
        ));
    }

    let font: Font<'_> = reader.read().map_err(|error| {
        IpcError::new(
            "pdf_font",
            format!("无法解析{ROLE}字体 {SOURCE_LABEL}：{error}"),
        )
    })?;
    let permissions = font.permissions();
    if !permissions.embedding.is_lenient()
        || !permissions.allow_subsetting
        || permissions.embed_only_bitmaps
    {
        return Err(IpcError::new(
            "pdf_font_license",
            format!("{ROLE}字体的许可证不允许嵌入并子集化，已拒绝生成 PDF。"),
        ));
    }
    if let Some(character) = retained_characters.iter().copied().find(|character| {
        pdf_character_requires_glyph(*character) && !font.contains_char(*character)
    }) {
        return Err(IpcError::new(
            "pdf_font",
            format!(
                "{ROLE}字体缺少 U+{:04X} 字形，已拒绝生成包含方框缺字的 PDF。",
                u32::from(character)
            ),
        ));
    }
    let supported_characters = retained_characters
        .iter()
        .copied()
        .filter(|character| font.contains_char(*character))
        .collect::<BTreeSet<_>>();
    if supported_characters.is_empty() {
        return Err(IpcError::new(
            "pdf_font",
            format!("{ROLE}字体不包含文书所需的任何字形。"),
        ));
    }
    let subset = font.subset(&supported_characters).map_err(|error| {
        IpcError::new(
            "pdf_font",
            format!("无法子集化{ROLE}字体 {SOURCE_LABEL}：{error}"),
        )
    })?;
    genpdf::fonts::FontData::new(subset.to_opentype(), None).map_err(|error| {
        IpcError::new(
            "pdf_font",
            format!("无法加载子集化的{ROLE}字体 {SOURCE_LABEL}：{error}"),
        )
    })
}

fn optimize_pdf_file(path: &Path, title: &str) -> Result<(), IpcError> {
    let mut document = lopdf::Document::load(path)
        .map_err(|error| IpcError::new("pdf", format!("PDF post-processing failed: {error}")))?;
    deduplicate_pdf_font_streams(&mut document);
    set_pdf_title_metadata(&mut document, title)?;
    document.prune_objects();
    document.compress();
    let file = document
        .save(path)
        .map_err(|error| IpcError::new("pdf", format!("PDF optimization failed: {error}")))?;
    file.sync_all()
        .map_err(|error| IpcError::new("io", error.to_string()))
}

fn deduplicate_pdf_font_streams(document: &mut lopdf::Document) {
    let mut canonical = HashMap::<(i64, [u8; 32]), PdfObjectId>::new();
    let mut replacements = HashMap::<PdfObjectId, PdfObjectId>::new();
    for (object_id, object) in &document.objects {
        let PdfObject::Stream(stream) = object else {
            continue;
        };
        let Ok(length) = stream.dict.get(b"Length1").and_then(PdfObject::as_i64) else {
            continue;
        };
        if length < 0 || usize::try_from(length).ok() != Some(stream.content.len()) {
            continue;
        }
        let digest: [u8; 32] = Sha256::digest(&stream.content).into();
        if let Some(canonical_id) = canonical.get(&(length, digest)) {
            replacements.insert(*object_id, *canonical_id);
        } else {
            canonical.insert((length, digest), *object_id);
        }
    }
    if replacements.is_empty() {
        return;
    }
    for object in document.objects.values_mut() {
        replace_pdf_references(object, &replacements);
    }
    for (_, object) in document.trailer.iter_mut() {
        replace_pdf_references(object, &replacements);
    }
}

fn replace_pdf_references(
    object: &mut PdfObject,
    replacements: &HashMap<PdfObjectId, PdfObjectId>,
) {
    match object {
        PdfObject::Reference(object_id) => {
            if let Some(replacement) = replacements.get(object_id) {
                *object_id = *replacement;
            }
        }
        PdfObject::Array(objects) => {
            for object in objects {
                replace_pdf_references(object, replacements);
            }
        }
        PdfObject::Dictionary(dictionary) => {
            for (_, object) in dictionary.iter_mut() {
                replace_pdf_references(object, replacements);
            }
        }
        PdfObject::Stream(stream) => {
            for (_, object) in stream.dict.iter_mut() {
                replace_pdf_references(object, replacements);
            }
        }
        _ => {}
    }
}

fn set_pdf_title_metadata(document: &mut lopdf::Document, title: &str) -> Result<(), IpcError> {
    let info_id = match document
        .trailer
        .get(b"Info")
        .and_then(PdfObject::as_reference)
    {
        Ok(info_id) => info_id,
        Err(_) => {
            let info_id = document.add_object(lopdf::Dictionary::new());
            document.trailer.set("Info", PdfObject::Reference(info_id));
            info_id
        }
    };
    let info = document
        .objects
        .get_mut(&info_id)
        .and_then(|object| object.as_dict_mut().ok())
        .ok_or_else(|| IpcError::new("pdf", "PDF metadata dictionary is invalid"))?;
    info.set(
        "Title",
        PdfObject::String(pdf_utf16be(title), PdfStringFormat::Hexadecimal),
    );
    Ok(())
}

fn pdf_utf16be(value: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len().saturating_mul(2).saturating_add(2));
    bytes.extend_from_slice(&[0xFE, 0xFF]);
    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    bytes
}

fn validate_pdf_font_coverage<'a>(
    role: &str,
    font: &genpdf::fonts::FontData,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<(), IpcError> {
    let family = genpdf::fonts::FontFamily {
        regular: font.clone(),
        bold: font.clone(),
        italic: font.clone(),
        bold_italic: font.clone(),
    };
    let cache = genpdf::fonts::FontCache::new(family);
    let cached_font = cache.default_font_family().regular;

    for value in values {
        let glyph_ids = cached_font.glyph_ids(&cache, value.chars());
        if let Some(character) = value
            .chars()
            .zip(glyph_ids)
            .find_map(|(character, glyph_id)| {
                (pdf_character_requires_glyph(character) && glyph_id == 0).then_some(character)
            })
        {
            return Err(IpcError::new(
                "pdf_font",
                format!(
                    "{role}字体缺少 U+{:04X} 字形，已拒绝生成包含方框缺字的 PDF。",
                    u32::from(character)
                ),
            ));
        }
    }
    Ok(())
}

fn validate_pdf_structure(document: &GeneratedDocument) -> Result<(), IpcError> {
    for table in &document.tables {
        if table.headers.is_empty()
            || table.headers.len() != table.column_widths_dxa.len()
            || table.column_widths_dxa.contains(&0)
            || table
                .rows
                .iter()
                .any(|row| row.cells.len() != table.headers.len())
        {
            return Err(IpcError::new(
                "pdf_structure",
                format!(
                    "table '{}' must have matching non-empty headers, widths and cells",
                    table.section_heading
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::document::generate_document;
    use domain::{
        case::{
            CaseFact, CaseParty, CaseProject, CaseProjectStatus, CaseWorkspace, ConfirmationStatus,
            EvidenceItem, EvidenceLink, LegalBasis, LegalIssue, LegalIssueStatus, PartyRole,
        },
        qa::CitationStatus,
    };

    #[test]
    fn case_document_validation_error_preserves_only_safe_missing_field_details() {
        let error = legal_services::ServiceError::new(
            "document_validation_failed",
            "case is incomplete for the requested document template",
            false,
        )
        .with_details(serde_json::json!({
            "code": "missing_required_fields",
            "missingFields": ["claims", "facts", "private_internal_field"],
            "invalidCitationIds": ["law:secret-source"],
        }));

        let ipc = document_service_error(error);
        assert_eq!(ipc.error_type, "document_validation");
        let payload: serde_json::Value = serde_json::from_str(&ipc.message).unwrap();
        assert_eq!(
            payload["missingFields"],
            serde_json::json!(["claims", "facts"])
        );
        assert_eq!(
            payload["invalidCitationIds"],
            serde_json::json!(["待重新核验"])
        );
        assert!(!ipc.message.contains("private_internal_field"));
        assert!(!ipc.message.contains("law:secret-source"));
    }

    fn acceptance_workspace() -> CaseWorkspace {
        CaseWorkspace {
            project: CaseProject {
                project_id: "qa-case-2026-001".into(),
                title: "软件采购合同价款及逾期交付纠纷".into(),
                case_type: "民事·买卖合同纠纷".into(),
                status: CaseProjectStatus::Active,
                opened_on: Some("2026-06-18".into()),
                summary: "采购方已经支付首期款，供货方交付的软件许可数量不足，并对剩余价款提出请求。".into(),
                created_at: "2026-06-18T09:00:00+08:00".into(),
                updated_at: "2026-07-15T09:00:00+08:00".into(),
            },
            files: vec![],
            parties: vec![
                CaseParty {
                    party_id: "party-purchaser".into(),
                    project_id: "qa-case-2026-001".into(),
                    name: "华辰信息技术有限公司".into(),
                    normalized_name: "华辰信息技术有限公司".into(),
                    role: PartyRole::Plaintiff,
                    contact: "法务部 010-5555 1200".into(),
                    notes: "采购方、发函方".into(),
                },
                CaseParty {
                    party_id: "party-supplier".into(),
                    project_id: "qa-case-2026-001".into(),
                    name: "远景软件服务有限公司".into(),
                    normalized_name: "远景软件服务有限公司".into(),
                    role: PartyRole::Defendant,
                    contact: "合同管理部 021-5555 3400".into(),
                    notes: "供货方、收函方".into(),
                },
            ],
            facts: vec![
                CaseFact {
                    fact_id: "fact-contract".into(),
                    project_id: "qa-case-2026-001".into(),
                    occurred_on: Some("2025-09-08".into()),
                    title: "签署采购合同".into(),
                    description: "双方约定采购 500 套软件许可，合同总价为 120 万元，分两期支付。".into(),
                    source: "《软件采购合同》及签章页".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
                CaseFact {
                    fact_id: "fact-payment".into(),
                    project_id: "qa-case-2026-001".into(),
                    occurred_on: Some("2025-09-15".into()),
                    title: "支付首期款".into(),
                    description: "采购方依约支付首期合同款 72 万元。".into(),
                    source: "银行电子回单".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
                CaseFact {
                    fact_id: "fact-delivery".into(),
                    project_id: "qa-case-2026-001".into(),
                    occurred_on: Some("2025-11-03".into()),
                    title: "交付数量不足".into(),
                    description: "供货方仅开通 320 套许可，双方在联合验收单中记录了 180 套缺口。".into(),
                    source: "联合验收单、系统许可清单".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
                CaseFact {
                    fact_id: "fact-notice".into(),
                    project_id: "qa-case-2026-001".into(),
                    occurred_on: Some("2025-11-10".into()),
                    title: "书面催告".into(),
                    description: "采购方向供货方发出补充交付通知，要求在十个工作日内完成剩余许可交付。".into(),
                    source: "补充交付通知及送达回执".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
            ],
            evidence: vec![
                EvidenceItem {
                    evidence_id: "evidence-contract".into(),
                    project_id: "qa-case-2026-001".into(),
                    evidence_number: "1".into(),
                    title: "软件采购合同及签章页".into(),
                    source: "双方签署的合同正本".into(),
                    formed_on: Some("2025-09-08".into()),
                    summary: "证明合同主体、软件许可数量、价款、交付期限及付款安排。".into(),
                    storage_reference: "案件材料/01-合同.pdf".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
                EvidenceItem {
                    evidence_id: "evidence-payment".into(),
                    project_id: "qa-case-2026-001".into(),
                    evidence_number: "2".into(),
                    title: "银行电子回单".into(),
                    source: "采购方开户银行".into(),
                    formed_on: Some("2025-09-15".into()),
                    summary: "证明采购方已经支付首期合同款 72 万元。".into(),
                    storage_reference: "案件材料/02-付款回单.pdf".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
                EvidenceItem {
                    evidence_id: "evidence-acceptance".into(),
                    project_id: "qa-case-2026-001".into(),
                    evidence_number: "3".into(),
                    title: "联合验收单与许可清单".into(),
                    source: "双方项目负责人共同确认".into(),
                    formed_on: Some("2025-11-03".into()),
                    summary: "证明实际开通 320 套许可，尚缺 180 套。".into(),
                    storage_reference: "案件材料/03-联合验收资料.pdf".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
                EvidenceItem {
                    evidence_id: "evidence-notice".into(),
                    project_id: "qa-case-2026-001".into(),
                    evidence_number: "4".into(),
                    title: "补充交付通知及送达回执".into(),
                    source: "采购方法务部寄送并签收".into(),
                    formed_on: Some("2025-11-10".into()),
                    summary: "证明采购方已经催告供货方履行剩余交付义务。".into(),
                    storage_reference: "案件材料/04-催告及回执.pdf".into(),
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
            ],
            evidence_links: vec![
                EvidenceLink {
                    link_id: "link-contract".into(),
                    project_id: "qa-case-2026-001".into(),
                    fact_id: "fact-contract".into(),
                    evidence_id: "evidence-contract".into(),
                },
                EvidenceLink {
                    link_id: "link-payment".into(),
                    project_id: "qa-case-2026-001".into(),
                    fact_id: "fact-payment".into(),
                    evidence_id: "evidence-payment".into(),
                },
                EvidenceLink {
                    link_id: "link-delivery".into(),
                    project_id: "qa-case-2026-001".into(),
                    fact_id: "fact-delivery".into(),
                    evidence_id: "evidence-acceptance".into(),
                },
                EvidenceLink {
                    link_id: "link-notice".into(),
                    project_id: "qa-case-2026-001".into(),
                    fact_id: "fact-notice".into(),
                    evidence_id: "evidence-notice".into(),
                },
            ],
            fact_issue_links: vec![],
            legal_issues: vec![
                LegalIssue {
                    issue_id: "issue-delivery".into(),
                    project_id: "qa-case-2026-001".into(),
                    title: "继续履行与违约责任".into(),
                    description: "供货方未按约交足软件许可。".into(),
                    claim: "要求补充交付 180 套软件许可，并承担逾期交付的违约责任。".into(),
                    status: LegalIssueStatus::Open,
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
                LegalIssue {
                    issue_id: "issue-payment".into(),
                    project_id: "qa-case-2026-001".into(),
                    title: "剩余价款抗辩".into(),
                    description: "供货方请求支付剩余价款，采购方主张同时履行抗辩。".into(),
                    claim: "在供货方完成全部交付前，采购方有权暂缓支付与未交付部分相应的价款。".into(),
                    status: LegalIssueStatus::Open,
                    confirmation_status: ConfirmationStatus::Confirmed,
                },
            ],
            legal_basis: vec![
                LegalBasis {
                    basis_id: "basis-577".into(),
                    project_id: "qa-case-2026-001".into(),
                    issue_id: Some("issue-delivery".into()),
                    source_id: "law:flk-ff808081729d1efe01729d50b5c500bf:flk-version-ff808081729d1efe01729d50b5c500bf:art:577".into(),
                    status: CitationStatus::Valid,
                    invalid_reason: None,
                    case_date: Some("2025-11-03".into()),
                    article_id: "art-9d55a076ae39160252ad9e04".into(),
                    document_id: "flk-ff808081729d1efe01729d50b5c500bf".into(),
                    version_id: "flk-version-ff808081729d1efe01729d50b5c500bf".into(),
                    document_title: "中华人民共和国民法典".into(),
                    version_label: "2020-05-28公布版本".into(),
                    article_number: "第五百七十七条第一款".into(),
                    article_title: None,
                    canonical_label: "《中华人民共和国民法典》第五百七十七条第一款".into(),
                    effective_from: "2021-01-01".into(),
                    effective_to: None,
                    version_status: "in_force".into(),
                    excerpt: "当事人一方不履行合同义务或者履行合同义务不符合约定的，应当承担继续履行、采取补救措施或者赔偿损失等违约责任。".into(),
                    note: "本地引用校验通过".into(),
                    created_at: "2026-07-15T09:00:00+08:00".into(),
                },
                LegalBasis {
                    basis_id: "basis-526".into(),
                    project_id: "qa-case-2026-001".into(),
                    issue_id: Some("issue-payment".into()),
                    source_id: "law:flk-ff808081729d1efe01729d50b5c500bf:flk-version-ff808081729d1efe01729d50b5c500bf:art:526".into(),
                    status: CitationStatus::Valid,
                    invalid_reason: None,
                    case_date: Some("2025-11-03".into()),
                    article_id: "art-9a33e857181b417a53b3add5".into(),
                    document_id: "flk-ff808081729d1efe01729d50b5c500bf".into(),
                    version_id: "flk-version-ff808081729d1efe01729d50b5c500bf".into(),
                    document_title: "中华人民共和国民法典".into(),
                    version_label: "2020-05-28公布版本".into(),
                    article_number: "第五百二十六条第一款".into(),
                    article_title: None,
                    canonical_label: "《中华人民共和国民法典》第五百二十六条第一款".into(),
                    effective_from: "2021-01-01".into(),
                    effective_to: None,
                    version_status: "in_force".into(),
                    excerpt: "当事人互负债务，有先后履行顺序，应当先履行债务一方未履行的，后履行一方有权拒绝其履行请求。先履行一方履行债务不符合约定的，后履行一方有权拒绝其相应的履行请求。".into(),
                    note: "本地引用校验通过".into(),
                    created_at: "2026-07-15T09:00:00+08:00".into(),
                },
            ],
            uncertainties: vec![],
            gaps: vec![],
        }
    }

    #[test]
    fn legacy_document_pdf_export_is_disabled_without_exact_privacy_receipt() {
        let error = require_privacy_safe_document_export().unwrap_err();
        assert_eq!(error.error_type, "privacy_required");
        assert!(error.message.contains("export_approved_review_pdf"));
        assert!(!error.message.contains("case"));
    }
    #[test]
    fn case_pdf_export_requires_confirmation_and_the_exact_preview_seal() {
        let document =
            generate_document(&acceptance_workspace(), DocumentTemplateId::Complaint, None)
                .unwrap();
        let request = ExportDocumentPdfRequest {
            project_id: Some("qa-case-2026-001".into()),
            standalone_input: None,
            template_id: DocumentTemplateId::Complaint,
            model_draft: None,
            expected_revision: Some("a".repeat(64)),
            generation_hash: "b".repeat(64),
            confirmed: true,
            idempotency_key: "pdf-export-seal-test".into(),
        };
        let generated = GeneratedPreview {
            document,
            case_revision: Some("a".repeat(64)),
            generation_hash: "b".repeat(64),
        };
        validate_pdf_export_request(&request).unwrap();
        verify_generation_seal(&request, &generated).unwrap();

        let mut stale = request.clone();
        stale.expected_revision = Some("c".repeat(64));
        assert_eq!(
            verify_generation_seal(&stale, &generated)
                .unwrap_err()
                .error_type,
            "revision_conflict"
        );
        let mut unconfirmed = request;
        unconfirmed.confirmed = false;
        assert_eq!(
            validate_pdf_export_request(&unconfirmed)
                .unwrap_err()
                .error_type,
            "confirmation_required"
        );
    }

    #[test]
    fn succeeded_pdf_export_replays_only_when_the_audited_file_still_matches() {
        let directory = tempfile::tempdir().unwrap();
        let export = directory.path().join("reviewed.pdf");
        fs::write(&export, b"reviewed-pdf").unwrap();
        let details = PdfExportAuditDetails {
            schema_version: legal_services::SERVICE_SCHEMA_VERSION,
            record_id: "record-1".into(),
            export_path: export.clone(),
            file_sha256: file_sha256(&export).unwrap(),
            citation_count: 3,
            case_revision: Some("a".repeat(64)),
            generation_hash: "b".repeat(64),
        };
        let audit = database::OperationAuditRow {
            audit_id: format!("audit:{}", Uuid::new_v4()),
            origin: "desktop".into(),
            operation: "document_export_pdf".into(),
            project_id: Some("qa-case-2026-001".into()),
            request_hash: "c".repeat(64),
            idempotency_key_hash: Some("d".repeat(64)),
            status: "succeeded".into(),
            details_json: serde_json::to_string(&details).unwrap(),
            created_at: "1".into(),
            finished_at: Some("2".into()),
        };

        let response = replay_pdf_export(&audit, &audit.request_hash).unwrap();
        assert!(response.replayed);
        assert_eq!(response.file_name.as_deref(), Some("reviewed.pdf"));

        fs::write(&export, b"changed").unwrap();
        assert_eq!(
            replay_pdf_export(&audit, &audit.request_hash)
                .unwrap_err()
                .error_type,
            "export_changed"
        );
    }

    #[test]
    fn bundled_pdf_font_is_hash_pinned_licensed_and_subsettable() {
        let bytes = material_processing::bundled_pdf_font_bytes();
        assert!(bytes.starts_with(b"\0\x01\0\0"));
        assert_eq!(
            sha256_bytes(bytes),
            material_processing::BUNDLED_PDF_FONT_SHA256
        );
        assert_eq!(
            material_processing::BUNDLED_PDF_FONT_SHA256,
            "c7763f454946833081cc90e73186615f8e1189de9c5e5a5a8752871fd79fddbc"
        );

        let supported = "法律　文书".chars().collect::<BTreeSet<_>>();
        let font = load_bundled_legal_font(&supported).expect("reviewed font subset");
        validate_pdf_font_coverage("内置字体", &font, ["法律　文书"])
            .expect("reviewed glyph coverage");

        for (character, codepoint) in [('😀', "U+1F600"), ('\u{202F}', "U+202F"), ('\t', "U+0009")]
        {
            let unsupported = BTreeSet::from([character]);
            let error = load_bundled_legal_font(&unsupported)
                .expect_err("unsupported rendered character must fail closed");
            assert_eq!(error.error_type, "pdf_font");
            assert!(error.message.contains(codepoint));
        }

        assert!(!pdf_character_requires_glyph('\r'));
        assert!(!pdf_character_requires_glyph('\n'));
        assert!(pdf_character_requires_glyph('\t'));
        assert!(pdf_character_requires_glyph('\u{202F}'));
    }

    #[test]
    fn pdf_export_has_a_valid_header_trailer_and_embedded_content() {
        let temp = tempfile::tempdir().unwrap();
        let doc = generate_document(
            &acceptance_workspace(),
            DocumentTemplateId::EvidenceSchedule,
            Some("律师复核意见：应核对每项证据原件及送达凭证。"),
        )
        .unwrap();
        let citation_table = doc
            .tables
            .iter()
            .find(|table| table.section_heading == "法律依据与案例引用表")
            .expect("PDF input includes the final public citation table");
        assert!(citation_table
            .rows
            .iter()
            .any(|row| row.cells.get(3).is_some_and(|cell| cell == "2021年起施行")));
        assert!(citation_table
            .rows
            .iter()
            .all(|row| row.cells.get(3).is_none_or(|cell| cell != "2021年")));
        let path = temp.path().join("test.pdf");
        write_pdf(&path, &doc).unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"%PDF-"));
        assert!(bytes.windows(5).any(|window| window == b"%%EOF"));
        assert!(
            bytes.len() > 10_000,
            "a nontrivial embedded-font document is expected"
        );
        assert!(
            bytes.len() < 20 * 1024 * 1024,
            "the visual fixture must use subsetted or deduplicated fonts"
        );

        let parsed = lopdf::Document::load(&path).unwrap();
        let embedded_fonts = parsed
            .objects
            .values()
            .filter_map(|object| match object {
                PdfObject::Stream(stream) if stream.dict.has(b"Length1") => Some(stream),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert!(!embedded_fonts.is_empty());
        assert!(embedded_fonts.len() <= 3);
        assert!(embedded_fonts
            .iter()
            .all(|stream| stream.content.len() < 16 * 1024 * 1024));

        let info_id = parsed
            .trailer
            .get(b"Info")
            .and_then(PdfObject::as_reference)
            .unwrap();
        let title = parsed
            .objects
            .get(&info_id)
            .and_then(|object| object.as_dict().ok())
            .and_then(|dictionary| dictionary.get(b"Title").ok())
            .unwrap();
        let PdfObject::String(raw_title, PdfStringFormat::Hexadecimal) = title else {
            panic!("PDF title must be an explicit UTF-16BE hexadecimal string");
        };
        assert_eq!(raw_title, &pdf_utf16be(&doc.title));
        assert!(raw_title.starts_with(&[0xFE, 0xFF]));
        let decoded_units = raw_title[2..]
            .chunks_exact(2)
            .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        assert_eq!(String::from_utf16(&decoded_units).unwrap(), doc.title);
    }

    #[test]
    fn multi_page_pdf_table_keeps_rows_intact_and_repeats_its_header() {
        let temp = tempfile::tempdir().unwrap();
        let mut document = generate_document(
            &acceptance_workspace(),
            DocumentTemplateId::EvidenceSchedule,
            Some("律师复核意见：应核对每项证据原件及送达凭证。"),
        )
        .unwrap();
        let citation_table = document
            .tables
            .iter_mut()
            .find(|table| table.section_heading == "法律依据与案例引用表")
            .unwrap();
        let seed = citation_table.rows.last().unwrap().clone();
        citation_table.rows.clear();
        let labels = ["第一", "第二", "第三", "第四", "第五", "第六"];
        for label in labels {
            let mut row = seed.clone();
            row.cells[2] = format!("第五百二十六条第一款（{label}项）");
            row.cells[4] = format!(
                "{label}项引用开始。\n{}{}\n{label}项引用完毕。",
                seed.cells[4], seed.cells[4]
            );
            row.source_ids.clear();
            citation_table.rows.push(row);
        }
        let citation_headers = citation_table.headers.clone();

        let path = temp.path().join("multi-page-table.pdf");
        begin_pdf_table_page_trace();
        write_pdf(&path, &document).unwrap();
        let parsed = lopdf::Document::load(&path).unwrap();
        assert!(
            parsed.get_pages().len() >= 4,
            "the fixture must exercise more than one citation continuation page"
        );

        let citation_pages = take_pdf_table_page_trace()
            .into_iter()
            .filter(|page| page.headers == citation_headers)
            .collect::<Vec<_>>();
        assert!(citation_pages.len() >= 2);
        assert!(citation_pages
            .iter()
            .all(|page| !page.oversized_continuation && page.row_start < page.row_end));
        assert_eq!(
            citation_pages
                .iter()
                .flat_map(|page| page.row_start..page.row_end)
                .collect::<Vec<_>>(),
            (0..labels.len()).collect::<Vec<_>>(),
            "each ordinary row must be emitted exactly once and only as a complete row"
        );
    }

    #[test]
    fn pdf_line_break_tokens_preserve_legal_text_atoms_and_explicit_lines() {
        let dated = "截至2025-11-03送达";
        let dated_tokens = pdf_break_tokens(dated);
        assert_eq!(dated_tokens.concat(), dated);
        assert!(dated_tokens.iter().any(|token| token == "2025-11-03"));

        assert_eq!(pdf_break_tokens("材料.pdf"), vec!["材", "料.pdf"]);
        assert_eq!(pdf_break_tokens("材料.PDF"), vec!["材", "料.PDF"]);
        assert_eq!(pdf_break_tokens("甲，乙。丙"), vec!["甲，", "乙。", "丙"]);

        let identifier = format!("law:document-version:{}:art:577", "a".repeat(128));
        let identifier_tokens = pdf_break_tokens(&identifier);
        assert_eq!(identifier_tokens.concat(), identifier);
        assert!(identifier_tokens.len() > 8);
        assert!(identifier_tokens
            .iter()
            .all(|token| token.chars().count() <= MAX_PDF_ASCII_TOKEN_CHARS));

        let lines = pdf_table_lines("银行电子回单\r\n2025-11-03");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].concat(), "银行电子回单");
        assert_eq!(lines[1], vec!["2025-11-03"]);
        assert_eq!(pdf_table_lines("a\n\nb").len(), 3);
    }

    #[test]
    fn pdf_export_rejects_missing_glyphs_instead_of_rendering_tofu_boxes() {
        let temp = tempfile::tempdir().unwrap();
        let document = generate_document(
            &acceptance_workspace(),
            DocumentTemplateId::EvidenceSchedule,
            Some("律师复核意见：应核对每项证据原件及送达凭证。"),
        )
        .unwrap();
        for (character, codepoint) in [('😀', "U+1F600"), ('\u{202F}', "U+202F"), ('\t', "U+0009")]
        {
            let mut unsupported_document = document.clone();
            unsupported_document.title.push(character);
            let path = temp.path().join(format!("missing-glyph-{codepoint}.pdf"));

            let error = write_pdf(&path, &unsupported_document).unwrap_err();

            assert_eq!(error.error_type, "pdf_font");
            assert!(error.message.contains(codepoint));
            assert!(!path.exists());
        }
    }

    #[test]
    fn all_six_templates_have_pdf_compatible_table_geometry() {
        let workspace = acceptance_workspace();
        for template in template_catalog() {
            let document = generate_document(
                &workspace,
                template.template_id,
                Some("模型草稿仅用于辅助表达，正式文本由承办律师复核。"),
            )
            .unwrap();
            assert_eq!(document.template.version, "2.1.0");
            assert!(document.tables.iter().all(|table| table
                .column_widths_dxa
                .iter()
                .sum::<u32>()
                == 9_360));
            assert!(!document.markdown.contains("来源标识："));
            validate_pdf_structure(&document).unwrap();
        }
    }

    #[test]
    #[ignore = "requires the formal 1.18-million-article legal resource"]
    fn acceptance_workspace_citations_match_the_formal_legal_database() {
        let database_path = std::env::var_os("LAWYER_ASSISTANCE_FORMAL_LEGAL_CORE")
            .or_else(|| std::env::var_os("LAWYER_ASSISTANCE_FORMAL_LEGAL_DB"))
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/legal_core.sqlite")
            });
        let connection = database::open_legal_core_read_only(&database_path).unwrap();
        for basis in acceptance_workspace().legal_basis {
            let resolved = connection
                .query_row(
                    "
                    SELECT
                      articles.id, articles.document_id, articles.version_id,
                      documents.title, versions.version_label, articles.article_number,
                      citations.canonical_label, versions.effective_from,
                      versions.effective_to, versions.status, articles.content
                    FROM citation_metadata AS citations
                    JOIN law_articles AS articles ON articles.id = citations.article_id
                    JOIN law_documents AS documents ON documents.id = articles.document_id
                    JOIN law_versions AS versions ON versions.id = articles.version_id
                    WHERE citations.citation_id = ?1
                    ",
                    [&basis.source_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, String>(7)?,
                            row.get::<_, Option<String>>(8)?,
                            row.get::<_, String>(9)?,
                            row.get::<_, String>(10)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!(resolved.0, basis.article_id);
            assert_eq!(resolved.1, basis.document_id);
            assert_eq!(resolved.2, basis.version_id);
            assert_eq!(resolved.3, basis.document_title);
            assert_eq!(resolved.4, basis.version_label);
            let public_article_number = basis
                .article_number
                .strip_suffix("第一款")
                .expect("the acceptance fixture records its verified paragraph explicitly");
            let public_canonical_label = basis
                .canonical_label
                .strip_suffix("第一款")
                .expect("the acceptance fixture records its verified paragraph explicitly");
            assert_eq!(resolved.5, public_article_number);
            assert_eq!(resolved.6, public_canonical_label);
            assert_eq!(resolved.7, basis.effective_from);
            assert_eq!(resolved.8, basis.effective_to);
            assert_eq!(resolved.9, basis.version_status);
            assert_eq!(resolved.10, basis.excerpt);
        }
    }

    #[test]
    fn malformed_table_geometry_is_rejected_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let mut document = generate_document(
            &acceptance_workspace(),
            DocumentTemplateId::EvidenceSchedule,
            None,
        )
        .unwrap();
        document.tables[0].column_widths_dxa[0] = 0;
        let path = temp.path().join("invalid.pdf");
        let error = write_pdf(&path, &document).unwrap_err();
        assert_eq!(error.error_type, "pdf_structure");
        assert!(!path.exists());
    }

    fn insert_export_record(connection: &rusqlite::Connection, record_id: &str, export: &Path) {
        database::upsert_case_project(
            connection,
            &database::CaseProjectRow {
                project_id: "recovery-project".into(),
                title: "Recovery".into(),
                case_type: "civil".into(),
                status: "active".into(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .unwrap();
        database::insert_document_generation_record(
            connection,
            &database::DocumentGenerationRecordRow {
                record_id: record_id.into(),
                project_id: "recovery-project".into(),
                template_id: "complaint".into(),
                template_version: "2.0.0".into(),
                source_ids_json: "[]".into(),
                citation_ids_json: "[]".into(),
                export_path: export.to_string_lossy().into_owned(),
                exported_at: "1".into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn prepared_export_is_rolled_back_with_its_audit_record_after_a_crash() {
        let directory = tempfile::tempdir().unwrap();
        let user_database = database::ensure_user_database(directory.path()).unwrap();
        let export = directory.path().join("filing.pdf");
        fs::write(&export, b"previous").unwrap();
        let staged = sibling_path(&export, "export-incoming").unwrap();
        let rollback = sibling_path(&export, "export-previous").unwrap();
        fs::write(&staged, b"replacement").unwrap();
        let destination_sha256 = file_sha256(&export).unwrap();
        let staged_sha256 = file_sha256(&staged).unwrap();
        let record_id = Uuid::new_v4().to_string();
        let audit_id = format!("audit:{}", Uuid::new_v4());
        let connection = database::open_user_database(&user_database).unwrap();
        insert_export_record(&connection, &record_id, &export);
        database::create_operation_audit(
            &connection,
            &database::NewOperationAuditRow {
                audit_id: audit_id.clone(),
                origin: "desktop".into(),
                operation: "document_export_pdf".into(),
                project_id: Some("recovery-project".into()),
                request_hash: "a".repeat(64),
                idempotency_key_hash: Some("b".repeat(64)),
                details_json: "{}".into(),
            },
        )
        .unwrap();
        drop(connection);
        let marker = ExportMarker {
            format_version: 1,
            phase: ExportMarkerPhase::Prepared,
            audit_id: Some(audit_id.clone()),
            record_id: record_id.clone(),
            export_path: export.clone(),
            staged_path: staged.clone(),
            rollback_path: rollback.clone(),
            destination_existed: true,
            destination_sha256: Some(destination_sha256),
            staged_sha256,
        };
        let marker_path = export_marker_path(&user_database, &record_id).unwrap();
        write_export_marker(&marker_path, &marker).unwrap();
        crate::atomic_file::install(&staged, &export, Some(&rollback)).unwrap();

        recover_pending_document_exports(directory.path(), &user_database).unwrap();

        assert_eq!(fs::read(&export).unwrap(), b"previous");
        let connection = database::open_user_database(&user_database).unwrap();
        assert!(
            database::list_document_generation_records(&connection, "recovery-project")
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            database::get_operation_audit(&connection, &audit_id)
                .unwrap()
                .unwrap()
                .status,
            "failed"
        );
        assert!(!marker_path.exists());
    }

    #[test]
    fn committed_export_is_kept_and_only_its_rollback_journal_is_cleaned() {
        let directory = tempfile::tempdir().unwrap();
        let user_database = database::ensure_user_database(directory.path()).unwrap();
        let export = directory.path().join("filing.pdf");
        fs::write(&export, b"previous").unwrap();
        let staged = sibling_path(&export, "export-incoming").unwrap();
        let rollback = sibling_path(&export, "export-previous").unwrap();
        fs::write(&staged, b"replacement").unwrap();
        let destination_sha256 = file_sha256(&export).unwrap();
        let staged_sha256 = file_sha256(&staged).unwrap();
        let record_id = Uuid::new_v4().to_string();
        let connection = database::open_user_database(&user_database).unwrap();
        insert_export_record(&connection, &record_id, &export);
        drop(connection);
        crate::atomic_file::install(&staged, &export, Some(&rollback)).unwrap();
        let marker = ExportMarker {
            format_version: 1,
            phase: ExportMarkerPhase::Committed,
            audit_id: None,
            record_id: record_id.clone(),
            export_path: export.clone(),
            staged_path: staged,
            rollback_path: rollback.clone(),
            destination_existed: true,
            destination_sha256: Some(destination_sha256),
            staged_sha256,
        };
        let marker_path = export_marker_path(&user_database, &record_id).unwrap();
        write_export_marker(&marker_path, &marker).unwrap();

        recover_pending_document_exports(directory.path(), &user_database).unwrap();

        assert_eq!(fs::read(&export).unwrap(), b"replacement");
        assert!(!rollback.exists());
        let connection = database::open_user_database(&user_database).unwrap();
        assert_eq!(
            database::list_document_generation_records(&connection, "recovery-project")
                .unwrap()
                .len(),
            1
        );
        assert!(!marker_path.exists());
    }

    #[test]
    fn rolled_back_marker_is_idempotent_after_marker_deletion_was_interrupted() {
        let directory = tempfile::tempdir().unwrap();
        let user_database = database::ensure_user_database(directory.path()).unwrap();
        let export = directory.path().join("filing.pdf");
        fs::write(&export, b"previous").unwrap();
        let record_id = Uuid::new_v4().to_string();
        let marker = ExportMarker {
            format_version: 1,
            phase: ExportMarkerPhase::RolledBack,
            audit_id: None,
            record_id: record_id.clone(),
            export_path: export.clone(),
            staged_path: sibling_path(&export, "export-incoming").unwrap(),
            rollback_path: sibling_path(&export, "export-previous").unwrap(),
            destination_existed: true,
            destination_sha256: Some(file_sha256(&export).unwrap()),
            staged_sha256: format!("{:064x}", 1),
        };
        let marker_path = export_marker_path(&user_database, &record_id).unwrap();
        write_export_marker(&marker_path, &marker).unwrap();

        recover_pending_document_exports(directory.path(), &user_database).unwrap();

        assert_eq!(fs::read(export).unwrap(), b"previous");
        assert!(!marker_path.exists());
    }

    #[test]
    fn failed_audit_record_deletion_retains_the_complete_rollback_journal() {
        let directory = tempfile::tempdir().unwrap();
        let export = directory.path().join("filing.pdf");
        let staged = sibling_path(&export, "export-incoming").unwrap();
        fs::write(&export, b"previous").unwrap();
        fs::write(&staged, b"replacement").unwrap();
        let marker_path = directory
            .path()
            .join(format!("{EXPORT_MARKER_PREFIX}{}.json", Uuid::new_v4()));
        let record_id = marker_path
            .file_stem()
            .unwrap()
            .to_string_lossy()
            .trim_start_matches(EXPORT_MARKER_PREFIX)
            .to_owned();
        let marker = ExportMarker {
            format_version: 1,
            phase: ExportMarkerPhase::Prepared,
            audit_id: None,
            record_id,
            export_path: export.clone(),
            staged_path: staged.clone(),
            rollback_path: sibling_path(&export, "export-previous").unwrap(),
            destination_existed: true,
            destination_sha256: Some(file_sha256(&export).unwrap()),
            staged_sha256: file_sha256(&staged).unwrap(),
        };
        write_export_marker(&marker_path, &marker).unwrap();
        let connection = rusqlite::Connection::open_in_memory().unwrap();

        let error = cleanup_prepared_export(&marker_path, &marker, Some(&connection)).unwrap_err();

        assert_eq!(error.error_type, "database");
        assert!(marker_path.exists());
        assert!(staged.exists());
        assert_eq!(fs::read(export).unwrap(), b"previous");
    }

    /// Opt-in artifact generator for the mandatory render-and-inspect gate.
    ///
    /// Set `LAWYER_ASSISTANCE_PDF_QA_DIR` to keep the artifact outside `target`.
    #[test]
    #[ignore = "writes one persistent PDF artifact for visual QA"]
    fn generate_pdf_visual_qa_artifact() {
        let output_dir = std::env::var_os("LAWYER_ASSISTANCE_PDF_QA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("target/document-pdf-qa"));
        std::fs::create_dir_all(&output_dir).unwrap();
        let document = generate_document(
            &acceptance_workspace(),
            DocumentTemplateId::EvidenceSchedule,
            Some("律师复核意见：提交或发送前，应结合完整案卷核对事实、主体信息、期限、管辖、签章及所引法律依据的适用性。"),
        )
        .unwrap();
        let path = output_dir.join("法律文书-PDF视觉验收.pdf");
        write_pdf(&path, &document).unwrap();
        println!("{}", path.display());
    }
}
