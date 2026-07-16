use crate::{
    commands::case::{workspace_from_rows, IpcError},
    state::AppState,
};
use domain::document::{
    generate_document, template_catalog, DocumentTable, DocumentTemplateId,
    DocumentTemplateMetadata, GeneratedDocument,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tauri::State;
use uuid::Uuid;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

const MAX_PROJECT_ID_BYTES: usize = 256;
const MAX_MODEL_DRAFT_BYTES: usize = 1024 * 1024;
const MAX_EXPORT_PATH_BYTES: usize = 32 * 1024;
const EXPORT_MARKER_PREFIX: &str = "pending-document-export-";

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
    pub project_id: String,
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
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportDocumentRequest {
    pub project_id: String,
    pub template_id: DocumentTemplateId,
    pub model_draft: Option<String>,
    pub export_path: String,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportDocumentResponse {
    pub record_id: String,
    pub export_path: String,
    pub citation_count: usize,
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
    let document = load_and_generate(
        &state,
        &request.project_id,
        request.template_id,
        request.model_draft.as_deref(),
    )?;
    Ok(PreviewDocumentResponse { document })
}

#[tauri::command]
pub fn export_document(
    state: State<'_, AppState>,
    request: ExportDocumentRequest,
) -> Result<ExportDocumentResponse, IpcError> {
    if request.export_path.trim().is_empty()
        || request.export_path.len() > MAX_EXPORT_PATH_BYTES
        || !request.export_path.to_ascii_lowercase().ends_with(".docx")
    {
        return Err(IpcError::new(
            "validation",
            "exportPath must end with .docx",
        ));
    }
    let _export_guard = state.begin_document_export();
    let document = load_and_generate(
        &state,
        &request.project_id,
        request.template_id,
        request.model_draft.as_deref(),
    )?;
    let export_path = absolute_file_path(Path::new(&request.export_path))?;
    if export_path.exists() && !export_path.is_file() {
        return Err(IpcError::new(
            "validation",
            "exportPath must name a regular file",
        ));
    }
    let staged_path = sibling_path(&export_path, "export-incoming")?;
    let rollback_path = sibling_path(&export_path, "export-previous")?;
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
    let destination_existed = export_path.exists();
    let destination_sha256 = destination_existed
        .then(|| file_sha256(&export_path))
        .transpose()?;
    write_docx(&staged_path, &document)?;
    let staged_sha256 = file_sha256(&staged_path).inspect_err(|_| {
        let _ = fs::remove_file(&staged_path);
    })?;
    let marker_path = export_marker_path(state.user_database_path(), &record_id)?;
    let mut marker = ExportMarker {
        format_version: 1,
        phase: ExportMarkerPhase::Prepared,
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
    let transaction = match connection.transaction() {
        Ok(transaction) => transaction,
        Err(error) => {
            let primary = error.into();
            return Err(combine_cleanup_error(
                primary,
                cleanup_prepared_export(&marker_path, &marker, None),
            ));
        }
    };
    if let Err(error) = database::insert_document_generation_record(
        &transaction,
        &database::DocumentGenerationRecordRow {
            record_id: record_id.clone(),
            project_id: request.project_id,
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
    marker.phase = ExportMarkerPhase::Committed;
    if let Err(error) = write_export_marker(&marker_path, &marker) {
        return Err(combine_cleanup_error(
            error,
            cleanup_prepared_export(&marker_path, &marker, Some(&connection)),
        ));
    }
    if rollback_path.exists() {
        fs::remove_file(&rollback_path).map_err(|error| IpcError::new("io", error.to_string()))?;
    }
    fs::remove_file(&marker_path).map_err(|error| IpcError::new("io", error.to_string()))?;
    Ok(ExportDocumentResponse {
        record_id,
        export_path: export_path.to_string_lossy().into_owned(),
        citation_count: document.citations.len(),
    })
}

fn load_and_generate(
    state: &AppState,
    project_id: &str,
    template_id: DocumentTemplateId,
    model_draft: Option<&str>,
) -> Result<GeneratedDocument, IpcError> {
    if project_id.trim().is_empty() || project_id.len() > MAX_PROJECT_ID_BYTES {
        return Err(IpcError::new("validation", "projectId is required"));
    }
    if model_draft.is_some_and(|draft| draft.len() > MAX_MODEL_DRAFT_BYTES) {
        return Err(IpcError::new(
            "validation",
            "modelDraft exceeds the 1 MiB safety limit",
        ));
    }
    let connection = database::open_user_database(state.user_database_path())?;
    let rows = database::get_case_workspace_rows(&connection, project_id)?
        .ok_or_else(|| IpcError::new("not_found", "case project not found"))?;
    let workspace = workspace_from_rows(rows)?;
    generate_document(&workspace, template_id, model_draft).map_err(|error| {
        IpcError::new(
            "document_validation",
            serde_json::to_string(&error).unwrap_or_else(|_| "document validation failed".into()),
        )
    })
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
        delete_generation_record(connection, &marker.record_id)?;
    }
    rollback_export_files(marker)?;
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

/// Repairs the small two-phase journal used to keep exported DOCX files and
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
        if marker.phase == ExportMarkerPhase::Committed
            && record_exists
            && marker.export_path.is_file()
            && file_sha256(&marker.export_path)? == marker.staged_sha256
        {
            remove_file_if_exists(&marker.staged_path)?;
            remove_file_if_exists(&marker.rollback_path)?;
        } else {
            delete_generation_record(&connection, &marker.record_id)?;
            rollback_export_files(&marker)?;
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

fn write_docx(path: &Path, document: &GeneratedDocument) -> Result<(), IpcError> {
    let path = absolute_file_path(path)?;
    let path = path.as_path();
    validate_docx_structure(document)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| IpcError::new("io", e.to_string()))?;
    }
    let staged_path = sibling_path(path, "docx-incoming")?;
    let rollback_path = sibling_path(path, "docx-previous")?;
    if let Err(error) = write_docx_payload(&staged_path, document) {
        let _ = fs::remove_file(staged_path);
        return Err(error);
    }
    let destination_existed = path.exists();
    if let Err(error) = crate::atomic_file::install(
        &staged_path,
        path,
        destination_existed.then_some(rollback_path.as_path()),
    ) {
        let _ = fs::remove_file(staged_path);
        return Err(IpcError::new("io", error.to_string()));
    }
    if rollback_path.exists() {
        let _ = fs::remove_file(rollback_path);
    }
    Ok(())
}

fn write_docx_payload(path: &Path, document: &GeneratedDocument) -> Result<(), IpcError> {
    let file = File::create(path).map_err(|e| IpcError::new("io", e.to_string()))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let types = content_types_xml();
    let rels = package_relationships_xml();
    let document_rels = document_relationships_xml();
    let mut body = styled_paragraph(&document.title, "Title");
    body.push_str(&styled_paragraph(
        &format!(
            "{} · 模板版本 {} · 内容来源可追溯",
            document.template.scenario, document.template.version
        ),
        "Subtitle",
    ));
    for section in &document.sections {
        let heading_style = match section.level {
            0 | 1 => "Heading1",
            2 => "Heading2",
            _ => "Heading3",
        };
        body.push_str(&styled_paragraph(&section.heading, heading_style));
        for paragraph in &section.paragraphs {
            if is_numbered_section(&section.heading) {
                body.push_str(&numbered_paragraph(paragraph));
            } else if section.heading == "模型草稿（待律师复核）" {
                body.push_str(&styled_paragraph(paragraph, "ModelDraft"));
            } else {
                body.push_str(&styled_paragraph(paragraph, "Normal"));
            }
        }
        for table in document
            .tables
            .iter()
            .filter(|table| table.section_heading == section.heading)
        {
            body.push_str(&table_xml(table));
        }
        if !section.source_ids.is_empty() {
            body.push_str(&styled_paragraph(
                &source_note(&section.heading, &section.source_ids),
                "SourceNote",
            ));
        }
    }
    body.push_str(&styled_paragraph(
        &format!(
            "生成说明：本文件由 Lawyer Assistance 使用 {} v{} 生成；法律依据仅包含状态为 valid 的本地已校验引用。",
            document.template.name, document.template.version
        ),
        "SourceNote",
    ));
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body>{body}<w:sectPr><w:headerReference w:type="default" r:id="rId5"/><w:footerReference w:type="default" r:id="rId6"/><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="708" w:footer="708" w:gutter="0"/><w:cols w:space="720"/><w:docGrid w:linePitch="312"/></w:sectPr></w:body></w:document>"#
    );
    let header = header_xml(&document.template.name);
    let footer = footer_xml();
    let core = core_properties_xml(&document.title);
    let styles = styles_xml();
    for (name, content) in [
        ("[Content_Types].xml", types.as_str()),
        ("_rels/.rels", rels.as_str()),
        ("docProps/core.xml", core.as_str()),
        ("docProps/app.xml", APP_PROPERTIES_XML),
        ("word/document.xml", xml.as_str()),
        ("word/_rels/document.xml.rels", document_rels.as_str()),
        ("word/styles.xml", styles.as_str()),
        ("word/numbering.xml", NUMBERING_XML),
        ("word/settings.xml", SETTINGS_XML),
        ("word/fontTable.xml", FONT_TABLE_XML),
        ("word/header1.xml", header.as_str()),
        ("word/footer1.xml", footer.as_str()),
    ] {
        zip.start_file(name, options)
            .map_err(|e| IpcError::new("docx", e.to_string()))?;
        zip.write_all(content.as_bytes())
            .map_err(|e| IpcError::new("docx", e.to_string()))?;
    }
    let file = zip
        .finish()
        .map_err(|e| IpcError::new("docx", e.to_string()))?;
    file.sync_all()
        .map_err(|error| IpcError::new("io", error.to_string()))?;
    Ok(())
}

fn validate_docx_structure(document: &GeneratedDocument) -> Result<(), IpcError> {
    for table in &document.tables {
        let width = table.column_widths_dxa.iter().copied().sum::<u32>();
        if table.headers.is_empty()
            || table.headers.len() != table.column_widths_dxa.len()
            || width != 9_360
            || table
                .rows
                .iter()
                .any(|row| row.cells.len() != table.headers.len())
        {
            return Err(IpcError::new(
                "docx_structure",
                format!(
                    "table '{}' must have matching headers/cells and exactly 9360 DXA width",
                    table.section_heading
                ),
            ));
        }
    }
    Ok(())
}

fn content_types_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/><Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/><Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>"#.to_owned()
}

fn package_relationships_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>"#.to_owned()
}

fn document_relationships_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/><Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/><Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/><Relationship Id="rId6" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>"#.to_owned()
}

fn core_properties_xml(title: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:title>{}</dc:title><dc:creator>Lawyer Assistance</dc:creator><cp:lastModifiedBy>Lawyer Assistance</cp:lastModifiedBy><dc:subject>可追溯法律文书</dc:subject><dc:description>由本地案件工作区和已校验法律引用生成</dc:description></cp:coreProperties>"#,
        escape_xml(title)
    )
}

fn header_xml(template_name: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:jc w:val="center"/><w:spacing w:after="0"/></w:pPr><w:r><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/><w:color w:val="6B7280"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr><w:t xml:space="preserve">Lawyer Assistance · {}</w:t></w:r></w:p></w:hdr>"#,
        escape_xml(template_name)
    )
}

fn footer_xml() -> String {
    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:pPr><w:pStyle w:val="SourceNote"/><w:jc w:val="right"/><w:spacing w:before="0" w:after="0"/></w:pPr><w:r><w:t>第 </w:t></w:r><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>1</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r><w:r><w:t> 页</w:t></w:r></w:p></w:ftr>"#.to_owned()
}

fn styles_xml() -> String {
    // A 22-point CJK title leaves a single orphan character for ordinary
    // matter names such as the acceptance case. Keep the same centered title
    // hierarchy at 18 points so the complete title fits the printable width.
    STYLES_XML
        .replacen(
            "w:after=\"240\" w:line=\"528\" w:lineRule=\"auto\"",
            "w:after=\"240\" w:line=\"432\" w:lineRule=\"auto\"",
            1,
        )
        .replacen(
            "<w:sz w:val=\"44\"/><w:szCs w:val=\"44\"/>",
            "<w:sz w:val=\"36\"/><w:szCs w:val=\"36\"/>",
            1,
        )
}

fn styled_paragraph(text: &str, style: &str) -> String {
    format!(
        "<w:p><w:pPr><w:pStyle w:val=\"{}\"/></w:pPr>{}</w:p>",
        style,
        runs_xml(text)
    )
}

fn numbered_paragraph(text: &str) -> String {
    format!(
        "<w:p><w:pPr><w:pStyle w:val=\"ListParagraph\"/><w:numPr><w:ilvl w:val=\"0\"/><w:numId w:val=\"1\"/></w:numPr></w:pPr>{}</w:p>",
        runs_xml(text)
    )
}

fn runs_xml(text: &str) -> String {
    let mut output = String::new();
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            output.push_str("<w:r><w:br/></w:r>");
        }
        output.push_str(&format!(
            "<w:r><w:t xml:space=\"preserve\">{}</w:t></w:r>",
            escape_xml(line)
        ));
    }
    output
}

fn table_xml(table: &DocumentTable) -> String {
    let mut output = String::from(
        "<w:tbl><w:tblPr><w:tblStyle w:val=\"TableGrid\"/><w:tblW w:w=\"9360\" w:type=\"dxa\"/><w:tblInd w:w=\"120\" w:type=\"dxa\"/><w:tblLayout w:type=\"fixed\"/><w:tblCellMar><w:top w:w=\"80\" w:type=\"dxa\"/><w:left w:w=\"120\" w:type=\"dxa\"/><w:bottom w:w=\"80\" w:type=\"dxa\"/><w:right w:w=\"120\" w:type=\"dxa\"/></w:tblCellMar><w:tblBorders><w:top w:val=\"single\" w:sz=\"4\" w:color=\"AEB8C4\"/><w:left w:val=\"single\" w:sz=\"4\" w:color=\"AEB8C4\"/><w:bottom w:val=\"single\" w:sz=\"4\" w:color=\"AEB8C4\"/><w:right w:val=\"single\" w:sz=\"4\" w:color=\"AEB8C4\"/><w:insideH w:val=\"single\" w:sz=\"4\" w:color=\"D5DAE1\"/><w:insideV w:val=\"single\" w:sz=\"4\" w:color=\"D5DAE1\"/></w:tblBorders></w:tblPr><w:tblGrid>",
    );
    for width in &table.column_widths_dxa {
        output.push_str(&format!("<w:gridCol w:w=\"{width}\"/>"));
    }
    output.push_str("</w:tblGrid><w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>");
    for (column, (header, width)) in table
        .headers
        .iter()
        .zip(&table.column_widths_dxa)
        .enumerate()
    {
        output.push_str(&table_cell_xml(header, *width, true, column, header));
    }
    output.push_str("</w:tr>");
    for row in &table.rows {
        output.push_str("<w:tr><w:trPr><w:cantSplit/></w:trPr>");
        for (column, ((cell, width), header)) in row
            .cells
            .iter()
            .zip(&table.column_widths_dxa)
            .zip(&table.headers)
            .enumerate()
        {
            output.push_str(&table_cell_xml(cell, *width, false, column, header));
        }
        output.push_str("</w:tr>");
    }
    output.push_str("</w:tbl>");
    output
}

fn table_cell_xml(text: &str, width: u32, header_row: bool, column: usize, header: &str) -> String {
    let fill = if header_row {
        "<w:shd w:val=\"clear\" w:color=\"auto\" w:fill=\"F2F4F7\"/>"
    } else {
        ""
    };
    let alignment = if header_row || should_center_column(column, header) {
        "center"
    } else {
        "left"
    };
    let style = if header_row {
        "TableHeader"
    } else {
        "TableText"
    };
    format!(
        "<w:tc><w:tcPr><w:tcW w:w=\"{width}\" w:type=\"dxa\"/><w:vAlign w:val=\"center\"/>{fill}</w:tcPr><w:p><w:pPr><w:pStyle w:val=\"{style}\"/><w:jc w:val=\"{alignment}\"/></w:pPr>{}</w:p></w:tc>",
        runs_xml(text)
    )
}

fn should_center_column(column: usize, header: &str) -> bool {
    column == 0 && matches!(header, "序号" | "日期" | "诉讼地位")
}

fn is_numbered_section(heading: &str) -> bool {
    matches!(
        heading,
        "诉讼请求" | "答辩意见" | "争点清单" | "正式要求" | "待核对事项"
    )
}

fn source_note(heading: &str, source_ids: &[String]) -> String {
    let kind = if heading == "模型草稿（待律师复核）" {
        "模型草稿（须律师复核）"
    } else if matches!(
        heading,
        "法律依据" | "法律依据与检索结果" | "引用来源映射" | "检索结论使用说明"
    ) {
        "本地已校验法律引用"
    } else {
        "案件工作区已确认数据"
    };
    format!("来源：{kind}｜{}", source_ids.join("、"))
}

fn escape_xml(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            matches!(*character, '\u{0009}' | '\u{000A}' | '\u{000D}')
                || (*character >= '\u{0020}' && *character <= '\u{D7FF}')
                || (*character >= '\u{E000}' && *character <= '\u{FFFD}')
                || (*character >= '\u{10000}' && *character <= '\u{10FFFF}')
        })
        .flat_map(|character| match character {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&apos;".chars().collect(),
            other => vec![other],
        })
        .collect()
}

const APP_PROPERTIES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><Application>Lawyer Assistance</Application><AppVersion>2.0</AppVersion><Company></Company><DocSecurity>0</DocSecurity><ScaleCrop>false</ScaleCrop><LinksUpToDate>false</LinksUpToDate><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged></Properties>"#;

const SETTINGS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:zoom w:percent="100"/><w:defaultTabStop w:val="720"/><w:characterSpacingControl w:val="doNotCompress"/><w:updateFields w:val="true"/><w:compat><w:compatSetting w:name="compatibilityMode" w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat></w:settings>"#;

const FONT_TABLE_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:font w:name="Calibri"><w:family w:val="swiss"/><w:pitch w:val="variable"/></w:font><w:font w:name="宋体"><w:family w:val="roman"/><w:charset w:val="86"/><w:pitch w:val="variable"/></w:font><w:font w:name="微软雅黑"><w:family w:val="swiss"/><w:charset w:val="86"/><w:pitch w:val="variable"/></w:font></w:fonts>"#;

const NUMBERING_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:lvlJc w:val="left"/><w:pPr><w:tabs><w:tab w:val="num" w:pos="720"/></w:tabs><w:ind w:left="720" w:hanging="360"/><w:spacing w:after="160" w:line="280" w:lineRule="auto"/></w:pPr></w:lvl></w:abstractNum><w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:lvlJc w:val="left"/><w:pPr><w:tabs><w:tab w:val="num" w:pos="720"/></w:tabs><w:ind w:left="720" w:hanging="360"/><w:spacing w:after="160" w:line="280" w:lineRule="auto"/></w:pPr></w:lvl></w:abstractNum><w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num><w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num></w:numbering>"#;

const STYLES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体" w:cs="Times New Roman"/><w:sz w:val="22"/><w:szCs w:val="22"/><w:lang w:val="en-US" w:eastAsia="zh-CN"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:before="0" w:after="120" w:line="264" w:lineRule="auto"/><w:widowControl/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:qFormat/><w:pPr><w:spacing w:before="0" w:after="120" w:line="264" w:lineRule="auto"/><w:jc w:val="left"/><w:widowControl/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体"/><w:sz w:val="22"/><w:szCs w:val="22"/><w:color w:val="1F2937"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:next w:val="Subtitle"/><w:qFormat/><w:pPr><w:keepNext/><w:spacing w:before="0" w:after="240" w:line="528" w:lineRule="auto"/><w:jc w:val="center"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/><w:b/><w:color w:val="111827"/><w:sz w:val="44"/><w:szCs w:val="44"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="0" w:after="240" w:line="240" w:lineRule="auto"/><w:jc w:val="center"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/><w:color w:val="6B7280"/><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:uiPriority w:val="9"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="320" w:after="160" w:line="384" w:lineRule="auto"/><w:outlineLvl w:val="0"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/><w:b/><w:color w:val="2E74B5"/><w:sz w:val="32"/><w:szCs w:val="32"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:uiPriority w:val="9"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="240" w:after="120" w:line="312" w:lineRule="auto"/><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/><w:b/><w:color w:val="2E74B5"/><w:sz w:val="26"/><w:szCs w:val="26"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:uiPriority w:val="9"/><w:qFormat/><w:pPr><w:keepNext/><w:keepLines/><w:spacing w:before="160" w:after="80" w:line="288" w:lineRule="auto"/><w:outlineLvl w:val="2"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/><w:b/><w:color w:val="1F4D78"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="ListParagraph"><w:name w:val="List Paragraph"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="160" w:line="280" w:lineRule="auto"/><w:contextualSpacing/></w:pPr></w:style><w:style w:type="paragraph" w:styleId="SourceNote"><w:name w:val="Source Note"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="80" w:after="80" w:line="240" w:lineRule="auto"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体"/><w:i/><w:color w:val="6B7280"/><w:sz w:val="18"/><w:szCs w:val="18"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="ModelDraft"><w:name w:val="Model Draft"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="80" w:after="120" w:line="280" w:lineRule="auto"/><w:ind w:left="120" w:right="120"/><w:shd w:val="clear" w:fill="FFF8E8"/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体"/><w:color w:val="7A5A00"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="TableText"><w:name w:val="Table Text"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/><w:widowControl/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="宋体"/><w:sz w:val="20"/><w:szCs w:val="20"/><w:color w:val="1F2937"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="TableHeader"><w:name w:val="Table Header"/><w:basedOn w:val="TableText"/><w:pPr><w:spacing w:before="0" w:after="0" w:line="240" w:lineRule="auto"/><w:keepNext/></w:pPr><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:eastAsia="微软雅黑"/><w:b/><w:color w:val="1F3A5F"/><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr></w:style><w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:uiPriority w:val="59"/><w:tblPr><w:tblInd w:w="120" w:type="dxa"/><w:tblCellMar><w:top w:w="80" w:type="dxa"/><w:left w:w="120" w:type="dxa"/><w:bottom w:w="80" w:type="dxa"/><w:right w:w="120" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style></w:styles>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use domain::{
        case::{
            CaseFact, CaseParty, CaseProject, CaseProjectStatus, CaseWorkspace, ConfirmationStatus,
            EvidenceItem, EvidenceLink, LegalBasis, LegalIssue, LegalIssueStatus, PartyRole,
        },
        qa::CitationStatus,
    };
    use std::io::Read;

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
                    article_number: "第五百七十七条".into(),
                    article_title: None,
                    canonical_label: "《中华人民共和国民法典》第五百七十七条".into(),
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
                    article_number: "第五百二十六条".into(),
                    article_title: None,
                    canonical_label: "《中华人民共和国民法典》第五百二十六条".into(),
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

    fn read_part(path: &Path, part: &str) -> String {
        let mut archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
        let mut content = String::new();
        archive
            .by_name(part)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        content
    }

    #[test]
    fn docx_is_a_complete_parseable_office_zip_without_external_runtime() {
        let temp = tempfile::tempdir().unwrap();
        let doc = generate_document(
            &acceptance_workspace(),
            DocumentTemplateId::EvidenceSchedule,
            Some("律师复核意见：应核对每项证据原件及送达凭证。"),
        )
        .unwrap();
        let path = temp.path().join("test.docx");
        write_docx(&path, &doc).unwrap();
        let mut archive = zip::ZipArchive::new(File::open(&path).unwrap()).unwrap();
        for part in [
            "word/document.xml",
            "word/styles.xml",
            "word/numbering.xml",
            "word/settings.xml",
            "word/fontTable.xml",
            "word/header1.xml",
            "word/footer1.xml",
            "docProps/core.xml",
        ] {
            assert!(archive.by_name(part).is_ok(), "missing DOCX part {part}");
        }
        drop(archive);

        let document_xml = read_part(&path, "word/document.xml");
        assert!(document_xml.contains("<w:pgSz w:w=\"12240\" w:h=\"15840\"/>"));
        assert!(document_xml.contains("w:top=\"1440\""));
        assert!(document_xml.contains("<w:tblW w:w=\"9360\" w:type=\"dxa\"/>"));
        assert!(document_xml.contains("<w:tblHeader/>"));
        assert!(document_xml.contains("软件采购合同及签章页"));
        assert!(document_xml.contains("律师复核意见：应核对每项证据原件及送达凭证。"));
        let styles = read_part(&path, "word/styles.xml");
        assert!(styles.contains("w:eastAsia=\"宋体\""));
        assert!(styles.contains("w:eastAsia=\"微软雅黑\""));
        assert!(styles.contains("w:styleId=\"Heading2\""));
        assert!(styles.contains("w:styleId=\"TableHeader\""));
        let title_style = styles
            .split("w:styleId=\"Title\"")
            .nth(1)
            .and_then(|suffix| suffix.split("</w:style>").next())
            .expect("Title style exists");
        assert!(title_style.contains("w:line=\"432\""));
        assert!(title_style.contains("w:sz w:val=\"36\""));
        assert!(title_style.contains("w:szCs w:val=\"36\""));
        assert!(read_part(&path, "word/footer1.xml").contains("PAGE"));
    }

    #[test]
    fn all_six_templates_export_with_fixed_table_geometry_and_traceability() {
        let temp = tempfile::tempdir().unwrap();
        let workspace = acceptance_workspace();
        for template in template_catalog() {
            let document = generate_document(
                &workspace,
                template.template_id,
                Some("模型草稿仅用于辅助表达，正式文本由承办律师复核。"),
            )
            .unwrap();
            assert_eq!(document.template.version, "2.0.0");
            assert!(document.tables.iter().all(|table| table
                .column_widths_dxa
                .iter()
                .sum::<u32>()
                == 9_360));
            assert!(document.markdown.contains("来源标识："));
            let path = temp.path().join(format!("{:?}.docx", template.template_id));
            write_docx(&path, &document).unwrap();
            assert!(path.metadata().unwrap().len() > 4_000);
            let document_xml = read_part(&path, "word/document.xml");
            assert!(document_xml.contains(&document.title));
            assert!(document_xml.contains("来源："));
            assert!(document_xml.contains(
                "law:flk-ff808081729d1efe01729d50b5c500bf:flk-version-ff808081729d1efe01729d50b5c500bf:art:577"
            ));
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
            assert_eq!(resolved.5, basis.article_number);
            assert_eq!(resolved.6, basis.canonical_label);
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
        document.tables[0].column_widths_dxa[0] += 1;
        let path = temp.path().join("invalid.docx");
        let error = write_docx(&path, &document).unwrap_err();
        assert_eq!(error.error_type, "docx_structure");
        assert!(!path.exists());
    }

    #[test]
    fn xml_control_characters_are_removed_and_special_characters_are_escaped() {
        let escaped = escape_xml("中文 & <安全> \"引号\"\u{0001}");
        assert_eq!(escaped, "中文 &amp; &lt;安全&gt; &quot;引号&quot;");
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
        let export = directory.path().join("filing.docx");
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
        let marker = ExportMarker {
            format_version: 1,
            phase: ExportMarkerPhase::Prepared,
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
        assert!(!marker_path.exists());
    }

    #[test]
    fn committed_export_is_kept_and_only_its_rollback_journal_is_cleaned() {
        let directory = tempfile::tempdir().unwrap();
        let user_database = database::ensure_user_database(directory.path()).unwrap();
        let export = directory.path().join("filing.docx");
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
        let export = directory.path().join("filing.docx");
        fs::write(&export, b"previous").unwrap();
        let record_id = Uuid::new_v4().to_string();
        let marker = ExportMarker {
            format_version: 1,
            phase: ExportMarkerPhase::RolledBack,
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
        let export = directory.path().join("filing.docx");
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
    /// The six files always use the same complete case workspace. Set
    /// `LAWYER_ASSISTANCE_DOCX_QA_DIR` to keep the artifacts outside `target`.
    #[test]
    #[ignore = "writes six persistent DOCX artifacts for visual QA"]
    fn generate_stage5_visual_qa_bundle() {
        let output_dir = std::env::var_os("LAWYER_ASSISTANCE_DOCX_QA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("target/stage5-docx-qa"));
        std::fs::create_dir_all(&output_dir).unwrap();
        let workspace = acceptance_workspace();
        let names = [
            (DocumentTemplateId::Complaint, "01-民事起诉状.docx"),
            (DocumentTemplateId::Defence, "02-民事答辩状.docx"),
            (DocumentTemplateId::EvidenceSchedule, "03-证据目录.docx"),
            (DocumentTemplateId::FactTimeline, "04-案件事实时间线.docx"),
            (
                DocumentTemplateId::LegalResearchReport,
                "05-法律检索报告.docx",
            ),
            (DocumentTemplateId::LawyerLetter, "06-律师函.docx"),
        ];
        for (template_id, name) in names {
            let document = generate_document(
                &workspace,
                template_id,
                Some("律师复核意见：引用已经过本地效力校验；提交或发送前，须结合完整案卷核对事实、主体信息、期限、管辖及签章。"),
            )
            .unwrap();
            let path = output_dir.join(name);
            write_docx(&path, &document).unwrap();
            println!("{}", path.display());
        }
    }
}
