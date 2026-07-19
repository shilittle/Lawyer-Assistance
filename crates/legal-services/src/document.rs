use crate::{
    audit::{
        hash_serializable, sha256_hex, validate_idempotency_key, validate_sha256,
        CompletedAuditDetails,
    },
    case::authoritative_public_law_locator,
    filesystem::PathIdentityGuard,
    load_full_workspace, open_validated_legal_database, open_validated_user_database_read_only,
    open_validated_user_database_write, require_schema_version, validate_identifier, validate_text,
    LegalServices, ServiceError, SERVICE_SCHEMA_VERSION,
};
use assistant::{
    ArtifactRenderContent, DocumentClause as AssistantDocumentClause,
    DocumentSection as AssistantDocumentSection, DocumentSpec as AssistantDocumentSpec,
    DocumentType as AssistantDocumentType, LegalCitation as AssistantLegalCitation, ProvenanceKind,
    ProvenanceRef, SourceMaterial, SourceMaterialKind, ValidationContext,
};
use domain::{
    document::{DocumentCitation, DocumentTemplateId, GeneratedDocument},
    qa::CitationStatus,
};
use rusqlite::TransactionBehavior;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

const MAX_MODEL_DRAFT_BYTES: usize = 64 * 1024;
const MAX_EXPORT_BYTES: usize = 4 * 1024 * 1024;
const MAX_RELATIVE_PATH_BYTES: usize = 4 * 1024;
const MAX_EXPORT_JOURNAL_BYTES: u64 = 32 * 1024;
const EXPORT_JOURNAL_DIRECTORY: &str = ".lawyer-assistance-export-journal";
const EXPORT_LOCK_FILE: &str = ".export.lock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentExportFormat {
    Markdown,
    Docx,
}

impl DocumentExportFormat {
    fn extension(self) -> &'static str {
        match self {
            Self::Markdown => "md",
            Self::Docx => "docx",
        }
    }

    fn media_type(self) -> &'static str {
        match self {
            Self::Markdown => "text/markdown; charset=utf-8",
            Self::Docx => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentGenerateRequest {
    pub schema_version: u16,
    pub project_id: String,
    pub template_id: DocumentTemplateId,
    pub model_draft: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentGenerateResponse {
    pub schema_version: u16,
    pub project_id: String,
    pub case_revision: String,
    pub generation_hash: String,
    pub document: GeneratedDocument,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentExportRequest {
    pub schema_version: u16,
    pub project_id: String,
    pub template_id: DocumentTemplateId,
    pub model_draft: Option<String>,
    pub expected_revision: String,
    pub generation_hash: String,
    pub relative_path: String,
    pub format: DocumentExportFormat,
    pub overwrite: bool,
    pub confirmed: bool,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentExportResponse {
    pub schema_version: u16,
    pub audit_id: String,
    pub record_id: String,
    pub project_id: String,
    pub case_revision: String,
    pub generation_hash: String,
    pub export_path: String,
    pub format: DocumentExportFormat,
    pub media_type: String,
    pub byte_len: usize,
    pub sha256: String,
    pub replayed: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerationSeal<'a> {
    schema_version: u16,
    project_id: &'a str,
    case_revision: &'a str,
    document: &'a GeneratedDocument,
}

struct GeneratedBundle {
    revision: String,
    generation_hash: String,
    document: GeneratedDocument,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExportRecoveryMarker {
    schema_version: u16,
    audit_id: String,
    output_root_id: String,
    relative_path: String,
    format: DocumentExportFormat,
    stage_relative_path: String,
    backup_relative_path: String,
    content_sha256: String,
    byte_len: usize,
    had_original: bool,
}

struct ResolvedOutputDestination {
    destination: PathBuf,
    relative_path: String,
    output_root_id: String,
    directory_guards: Vec<PathIdentityGuard>,
    existing_guard: Option<PathIdentityGuard>,
}

impl ResolvedOutputDestination {
    #[cfg(unix)]
    fn parent_guard(&self) -> Result<&PathIdentityGuard, ServiceError> {
        self.directory_guards.last().ok_or_else(|| {
            ServiceError::new(
                "internal_contract_error",
                "output parent identity guard is missing",
                false,
            )
        })
    }

    fn verify_directories(&self) -> Result<(), ServiceError> {
        for guard in &self.directory_guards {
            guard.verify()?;
        }
        Ok(())
    }

    fn verify_existing(&self) -> Result<(), ServiceError> {
        if let Some(guard) = &self.existing_guard {
            guard.verify()?;
        }
        Ok(())
    }
}

struct PreparedExport {
    marker: ExportRecoveryMarker,
    marker_path: PathBuf,
    stage_path: PathBuf,
    backup_path: PathBuf,
    resolved: ResolvedOutputDestination,
}

struct ExportProcessLock {
    _file: File,
    _identity_guard: PathIdentityGuard,
}

impl LegalServices {
    pub fn document_generate(
        &self,
        request: DocumentGenerateRequest,
    ) -> Result<DocumentGenerateResponse, ServiceError> {
        validate_generate_request(&request)?;
        let connection = open_validated_user_database_read_only(self.user_database_path())?;
        let bundle = generate_bundle(self, &connection, &request)?;
        Ok(DocumentGenerateResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: request.project_id,
            case_revision: bundle.revision,
            generation_hash: bundle.generation_hash,
            document: bundle.document,
            warnings: bundle.warnings,
        })
    }

    pub fn document_export(
        &self,
        request: DocumentExportRequest,
    ) -> Result<DocumentExportResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("projectId", &request.project_id)?;
        validate_sha256("expectedRevision", &request.expected_revision)?;
        validate_sha256("generationHash", &request.generation_hash)?;
        validate_idempotency_key(&request.idempotency_key)?;
        if !request.confirmed {
            return Err(ServiceError::new(
                "confirmation_required",
                "explicit confirmation is required before exporting a document",
                false,
            ));
        }
        validate_relative_path(&request.relative_path, request.format)?;
        if let Some(draft) = request.model_draft.as_deref() {
            validate_text("modelDraft", draft, MAX_MODEL_DRAFT_BYTES, true)?;
        }
        let request_hash = hash_serializable(&request)?;
        let idempotency_key_hash = sha256_hex(request.idempotency_key.as_bytes());
        let mut connection = open_validated_user_database_write(self.user_database_path())?;
        let _export_lock = acquire_export_process_lock(self.output_root())?;
        recover_document_exports(&mut connection, self.output_root())?;
        let resolved =
            resolve_output_destination(self.output_root(), &request.relative_path, request.format)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = database::get_operation_audit_by_idempotency_key_hash(
            &transaction,
            self.audit_origin(),
            "document_export",
            &idempotency_key_hash,
        )? {
            return replay_document_export(existing, &request, &request_hash, &resolved);
        }

        let generate_request = DocumentGenerateRequest {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: request.project_id.clone(),
            template_id: request.template_id,
            model_draft: request.model_draft.clone(),
        };
        let bundle = generate_bundle(self, &transaction, &generate_request)?;
        if bundle.revision != request.expected_revision {
            return Err(ServiceError::new(
                "revision_conflict",
                "case changed after document generation",
                false,
            )
            .with_details(serde_json::json!({
                "expectedRevision": request.expected_revision,
                "currentRevision": bundle.revision,
            })));
        }
        if bundle.generation_hash != request.generation_hash {
            return Err(ServiceError::new(
                "generation_hash_mismatch",
                "regenerated document does not match the reviewed generation",
                false,
            ));
        }
        let payload = render_document(&bundle.document, request.format)?;
        if payload.len() > MAX_EXPORT_BYTES {
            return Err(ServiceError::new(
                "document_too_large",
                "rendered document exceeds the export byte limit",
                false,
            )
            .with_details(serde_json::json!({
                "limit": MAX_EXPORT_BYTES,
                "actual": payload.len(),
            })));
        }
        let payload_hash = sha256_hex(&payload);
        if resolved.existing_guard.is_some() && !request.overwrite {
            return Err(ServiceError::new(
                "output_exists",
                "output file already exists and overwrite is disabled",
                false,
            ));
        }

        let audit_id = format!("audit:{}", Uuid::new_v4());
        let record_id = format!("document:{}", Uuid::new_v4());
        let exported_at: String =
            transaction.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
                row.get(0)
            })?;
        let source_ids = bundle
            .document
            .fields
            .iter()
            .map(|field| field.source_id.clone())
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let citation_ids = bundle
            .document
            .citations
            .iter()
            .map(|citation| citation.source_id.clone())
            .collect::<Vec<_>>();
        let source_ids_json = serde_json::to_string(&source_ids)?;
        let citation_ids_json = serde_json::to_string(&citation_ids)?;
        let prepared_details = serde_json::to_string(&serde_json::json!({
            "schemaVersion": SERVICE_SCHEMA_VERSION,
            "generationHash": request.generation_hash,
            "caseRevision": bundle.revision,
            "outputRootId": resolved.output_root_id,
            "relativeExportPath": resolved.relative_path,
        }))?;
        let mut prepared = prepare_durable_export(
            self.output_root(),
            resolved,
            &audit_id,
            &payload,
            payload_hash.clone(),
        )?;
        if let Err(error) = database::create_operation_audit(
            &transaction,
            &database::NewOperationAuditRow {
                audit_id: audit_id.clone(),
                origin: self.audit_origin().to_owned(),
                operation: "document_export".to_owned(),
                project_id: Some(request.project_id.clone()),
                request_hash,
                idempotency_key_hash: Some(idempotency_key_hash),
                details_json: prepared_details,
            },
        ) {
            let _ = rollback_prepared_export(&mut prepared);
            return Err(error.into());
        }
        if let Err(error) = transaction.commit() {
            let _ = rollback_prepared_export(&mut prepared);
            return Err(error.into());
        }
        if let Err(error) = publish_prepared_export(&mut prepared, request.overwrite) {
            let _ = rollback_prepared_export(&mut prepared);
            let _ = mark_export_failed(&mut connection, &prepared.marker);
            return Err(error);
        }

        let completed = CompletedAuditDetails::document_export(
            request.generation_hash.clone(),
            bundle.revision.clone(),
            prepared.marker.output_root_id.clone(),
            prepared.marker.relative_path.clone(),
            payload_hash.clone(),
            payload.len(),
            record_id.clone(),
        );
        let completed_json = serde_json::to_string(&completed)?;
        let stored_export_reference = serde_json::to_string(&serde_json::json!({
            "outputRootId": prepared.marker.output_root_id,
            "relativePath": prepared.marker.relative_path,
        }))?;
        let finalize_result = (|| -> Result<(), ServiceError> {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            database::insert_document_generation_record(
                &transaction,
                &database::DocumentGenerationRecordRow {
                    record_id: record_id.clone(),
                    project_id: request.project_id.clone(),
                    template_id: request.template_id.as_str().to_owned(),
                    template_version: bundle.document.template.version.clone(),
                    source_ids_json,
                    citation_ids_json,
                    export_path: stored_export_reference,
                    exported_at,
                },
            )?;
            match database::compare_and_set_operation_audit_status(
                &transaction,
                &audit_id,
                "succeeded",
                &completed_json,
            )? {
                database::OperationAuditStatusUpdateResult::Updated(_) => {}
                database::OperationAuditStatusUpdateResult::Conflict(_)
                | database::OperationAuditStatusUpdateResult::NotFound => {
                    return Err(ServiceError::new(
                        "audit_conflict",
                        "document export audit could not be finalized",
                        false,
                    ));
                }
            }
            transaction.commit()?;
            Ok(())
        })();
        if let Err(error) = finalize_result {
            let _ = rollback_prepared_export(&mut prepared);
            let _ = mark_export_failed(&mut connection, &prepared.marker);
            return Err(error);
        }
        cleanup_committed_export(&prepared)?;
        Ok(DocumentExportResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            audit_id,
            record_id,
            project_id: request.project_id,
            case_revision: bundle.revision,
            generation_hash: request.generation_hash,
            export_path: prepared.resolved.destination.to_string_lossy().into_owned(),
            format: request.format,
            media_type: request.format.media_type().to_owned(),
            byte_len: payload.len(),
            sha256: payload_hash,
            replayed: false,
        })
    }
}

fn validate_generate_request(request: &DocumentGenerateRequest) -> Result<(), ServiceError> {
    require_schema_version(request.schema_version)?;
    validate_identifier("projectId", &request.project_id)?;
    if let Some(draft) = request.model_draft.as_deref() {
        validate_text("modelDraft", draft, MAX_MODEL_DRAFT_BYTES, true)?;
    }
    Ok(())
}

fn generate_bundle(
    services: &LegalServices,
    connection: &rusqlite::Connection,
    request: &DocumentGenerateRequest,
) -> Result<GeneratedBundle, ServiceError> {
    validate_generate_request(request)?;
    let (mut workspace, revision) = load_full_workspace(connection, &request.project_id)?;
    normalize_legacy_legal_basis(services, &mut workspace)?;
    let document = domain::document::generate_document(
        &workspace,
        request.template_id,
        request.model_draft.as_deref(),
    )
    .map_err(|error| {
        ServiceError::new(
            "document_validation_failed",
            "case is incomplete for the requested document template",
            false,
        )
        .with_details(serde_json::json!({
            "code": error.code,
            "missingFields": error.missing_fields,
            "invalidCitationIds": error.invalid_citation_ids,
        }))
    })?;
    let generation_hash = hash_serializable(&GenerationSeal {
        schema_version: SERVICE_SCHEMA_VERSION,
        project_id: &request.project_id,
        case_revision: &revision,
        document: &document,
    })?;
    let warnings = if workspace.gaps.is_empty() {
        Vec::new()
    } else {
        vec![format!("case_has_{}_known_gaps", workspace.gaps.len())]
    };
    Ok(GeneratedBundle {
        revision,
        generation_hash,
        document,
        warnings,
    })
}

fn normalize_legacy_legal_basis(
    services: &LegalServices,
    workspace: &mut domain::case::CaseWorkspace,
) -> Result<(), ServiceError> {
    let needs_normalization = workspace.legal_basis.iter().any(|basis| {
        basis.status == CitationStatus::Valid
            && !basis.article_number.contains('款')
            && !basis.canonical_label.contains('款')
    });
    if !needs_normalization {
        return Ok(());
    }

    let (legal_connection, _identity) = open_validated_legal_database(services.legal_core_path())?;
    for basis in &mut workspace.legal_basis {
        if basis.status != CitationStatus::Valid
            || basis.article_number.contains('款')
            || basis.canonical_label.contains('款')
        {
            continue;
        }
        let Some(source) = citations::source_by_citation_id(&legal_connection, &basis.source_id)?
        else {
            continue;
        };
        if basis.article_id != source.article_id
            || basis.document_id != source.document_id
            || basis.version_id != source.version_id
            || basis.document_title.trim() != source.document_title.trim()
            || basis.effective_from != source.effective_from
            || basis.effective_to != source.effective_to
            || basis.version_status != source.version_status
        {
            continue;
        }
        let validation = citations::validate_answer_citations(
            &legal_connection,
            &format!("[SRC:{}]", basis.source_id),
            std::slice::from_ref(&source),
            basis.case_date.as_deref(),
            false,
        )?;
        if validation.valid_count != 1 || validation.invalid_count != 0 {
            continue;
        }
        let Some(locator) = authoritative_public_law_locator(&source) else {
            continue;
        };
        basis.article_number = locator.clone();
        basis.canonical_label = format!("《{}》{locator}", source.document_title.trim());
    }
    Ok(())
}

fn render_document(
    document: &GeneratedDocument,
    format: DocumentExportFormat,
) -> Result<Vec<u8>, ServiceError> {
    match format {
        DocumentExportFormat::Markdown => Ok(document.markdown.as_bytes().to_vec()),
        DocumentExportFormat::Docx => {
            let (spec, context) = assistant_document_spec(document)?;
            let rendered = assistant::render_document_docx(&spec, &context)?;
            match rendered.content {
                ArtifactRenderContent::Bytes(bytes) => Ok(bytes),
                ArtifactRenderContent::Text(_) => Err(ServiceError::new(
                    "internal_contract_error",
                    "DOCX renderer returned text instead of bytes",
                    false,
                )),
            }
        }
    }
}

fn assistant_document_spec(
    document: &GeneratedDocument,
) -> Result<(AssistantDocumentSpec, ValidationContext), ServiceError> {
    let legal_source_ids = document
        .citations
        .iter()
        .map(|citation| citation.source_id.clone())
        .collect::<BTreeSet<_>>();
    let mut case_source_ids = BTreeSet::new();
    for source_id in document
        .fields
        .iter()
        .map(|field| field.source_id.as_str())
        .chain(
            document
                .sections
                .iter()
                .flat_map(|section| section.source_ids.iter().map(String::as_str)),
        )
        .chain(
            document
                .tables
                .iter()
                .flat_map(|table| table.source_ids.iter().map(String::as_str)),
        )
        .chain(document.tables.iter().flat_map(|table| {
            table
                .rows
                .iter()
                .flat_map(|row| row.source_ids.iter().map(String::as_str))
        }))
    {
        if !source_id.is_empty() && !legal_source_ids.contains(source_id) {
            case_source_ids.insert(source_id.to_owned());
        }
    }
    if case_source_ids.len() > assistant::MAX_DOCUMENT_SOURCE_MATERIALS {
        return Err(ServiceError::new(
            "document_render_failed",
            "document contains too many distinct source references for DOCX export",
            false,
        ));
    }
    let mut context = ValidationContext::default();
    let source_materials = case_source_ids
        .iter()
        .enumerate()
        .map(|(index, source_id)| {
            context.allow_source_ref(source_id);
            SourceMaterial {
                id: source_id.clone(),
                kind: SourceMaterialKind::ConfirmedCase,
                label: format!("案件材料（第{}项）", index + 1),
                locator: None,
            }
        })
        .collect::<Vec<_>>();
    let legal_citations = document
        .citations
        .iter()
        .enumerate()
        .map(|(index, citation)| {
            context.allow_validated_legal_source(&citation.source_id);
            Ok(AssistantLegalCitation {
                id: format!("citation-{index}"),
                source_ref: citation.source_id.clone(),
                marker: format!("[SRC:{}]", citation.source_id),
                citation: public_legal_citation(citation)?,
                proposition: if citation.excerpt.trim().is_empty() {
                    "具体引用内容请结合条文全文核对。".to_owned()
                } else {
                    citation.excerpt.clone()
                },
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    const PUBLIC_REFERENCE_TABLE_HEADING: &str = "法律依据与案例引用表";
    let mut sections = document
        .sections
        .iter()
        .filter(|section| section.heading != PUBLIC_REFERENCE_TABLE_HEADING)
        .enumerate()
        .map(|(index, section)| AssistantDocumentSection {
            id: format!("section-{index}"),
            heading: section.heading.clone(),
            body: if section.paragraphs.is_empty() {
                "本节内容见下表。".to_owned()
            } else {
                section.paragraphs.join("\n\n")
            },
            factual: false,
            provenance: provenance_for_sources(
                &section.source_ids,
                &case_source_ids,
                &legal_source_ids,
            ),
            clauses: Vec::new(),
        })
        .collect::<Vec<_>>();
    for (table_index, table) in document
        .tables
        .iter()
        .filter(|table| table.section_heading != PUBLIC_REFERENCE_TABLE_HEADING)
        .enumerate()
    {
        for (chunk_index, rows) in table
            .rows
            .chunks(assistant::MAX_CLAUSES_PER_SECTION)
            .enumerate()
        {
            let clauses = rows
                .iter()
                .enumerate()
                .map(|(row_index, row)| AssistantDocumentClause {
                    id: format!("table-{table_index}-{chunk_index}-row-{row_index}"),
                    heading: None,
                    body: row.cells.join(" | "),
                    factual: false,
                    provenance: provenance_for_sources(
                        &row.source_ids,
                        &case_source_ids,
                        &legal_source_ids,
                    ),
                })
                .collect();
            sections.push(AssistantDocumentSection {
                id: format!("table-{table_index}-chunk-{chunk_index}"),
                heading: if chunk_index == 0 {
                    table.section_heading.clone()
                } else {
                    format!("{}（续{}）", table.section_heading, chunk_index + 1)
                },
                body: table.headers.join(" | "),
                factual: false,
                provenance: provenance_for_sources(
                    &table.source_ids,
                    &case_source_ids,
                    &legal_source_ids,
                ),
                clauses,
            });
        }
    }
    if sections.is_empty() {
        return Err(ServiceError::new(
            "document_render_failed",
            "generated document has no renderable sections",
            false,
        ));
    }
    Ok((
        AssistantDocumentSpec {
            schema_version: assistant::CONTRACT_SCHEMA_VERSION,
            document_type: assistant_document_type(document.template.template_id),
            title: document.title.clone(),
            parties: Vec::new(),
            sections,
            assumptions: Vec::new(),
            missing_information: Vec::new(),
            source_materials,
            legal_citations,
            risk_warnings: vec!["本稿根据现有案件材料拟具，正式使用前应由承办律师复核。".to_owned()],
        },
        context,
    ))
}

fn public_legal_citation(citation: &DocumentCitation) -> Result<String, ServiceError> {
    let title = citation.title.trim();
    let locator = citation.locator.trim();
    let year = citation
        .effective_or_decided_on
        .trim()
        .get(..4)
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()));
    if title.is_empty()
        || locator.is_empty()
        || !locator.contains('条')
        || !locator.contains('款')
        || year.is_none()
    {
        return Err(ServiceError::new(
            "document_render_failed",
            "generated legal citation is incomplete for public delivery",
            false,
        ));
    }
    Ok(format!(
        "《{title}》{locator}（{}年起施行）",
        year.expect("checked above")
    ))
}

fn provenance_for_sources(
    source_ids: &[String],
    case_source_ids: &BTreeSet<String>,
    legal_source_ids: &BTreeSet<String>,
) -> Vec<ProvenanceRef> {
    let mut seen = BTreeSet::new();
    let mut provenance = Vec::new();
    for source_id in source_ids {
        if !seen.insert(source_id.as_str()) {
            continue;
        }
        if legal_source_ids.contains(source_id) {
            provenance.push(ProvenanceRef {
                kind: ProvenanceKind::LocalLegalSource,
                source_ref: Some(source_id.clone()),
            });
        } else if case_source_ids.contains(source_id) {
            provenance.push(ProvenanceRef {
                kind: ProvenanceKind::ConfirmedCase,
                source_ref: Some(source_id.clone()),
            });
        }
        if provenance.len() == assistant::MAX_PROVENANCE_REFS_PER_ITEM {
            break;
        }
    }
    if provenance.is_empty() {
        provenance.push(ProvenanceRef {
            kind: ProvenanceKind::ModelWording,
            source_ref: None,
        });
    }
    provenance
}

fn assistant_document_type(template: DocumentTemplateId) -> AssistantDocumentType {
    match template {
        DocumentTemplateId::Complaint => AssistantDocumentType::Complaint,
        DocumentTemplateId::Defence => AssistantDocumentType::Defence,
        DocumentTemplateId::EvidenceSchedule => AssistantDocumentType::EvidenceSchedule,
        DocumentTemplateId::FactTimeline => AssistantDocumentType::FactTimeline,
        DocumentTemplateId::LegalResearchReport => AssistantDocumentType::LegalResearchReport,
        DocumentTemplateId::LawyerLetter => AssistantDocumentType::LawyerLetter,
    }
}

fn validate_relative_path(value: &str, format: DocumentExportFormat) -> Result<(), ServiceError> {
    if value.trim().is_empty() || value.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(ServiceError::invalid(
            "relativePath",
            "relative output path is empty or too long",
        ));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ServiceError::new(
            "output_path_rejected",
            "output path must be a normal relative path beneath the configured root",
            false,
        ));
    }
    if path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_none_or(|extension| !extension.eq_ignore_ascii_case(format.extension()))
    {
        return Err(ServiceError::new(
            "output_path_rejected",
            "output extension does not match the requested document format",
            false,
        ));
    }
    Ok(())
}

fn resolve_output_destination(
    root: &Path,
    relative_path: &str,
    format: DocumentExportFormat,
) -> Result<ResolvedOutputDestination, ServiceError> {
    validate_relative_path(relative_path, format)?;
    let relative = Path::new(relative_path);
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let root_guard = PathIdentityGuard::directory(root)?;
    let output_root_id = root_guard.opaque_identity();
    let mut directory_guards = vec![root_guard];
    let mut cursor = root.to_path_buf();
    for component in parent_relative.components() {
        let Component::Normal(component) = component else {
            return Err(ServiceError::new(
                "output_path_rejected",
                "output parent contains a disallowed path component",
                false,
            ));
        };
        cursor.push(component);
        let metadata = fs::symlink_metadata(&cursor).map_err(|_| {
            ServiceError::new(
                "output_parent_missing",
                "output parent directory must already exist",
                false,
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ServiceError::new(
                "output_path_rejected",
                "output parent must not contain symlinks or non-directory components",
                false,
            ));
        }
        #[cfg(unix)]
        let child_guard = directory_guards
            .last()
            .ok_or_else(|| {
                ServiceError::new(
                    "internal_contract_error",
                    "output root guard is missing",
                    false,
                )
            })?
            .directory_child(component, cursor.clone())?;
        #[cfg(not(unix))]
        let child_guard = PathIdentityGuard::directory(&cursor)?;
        directory_guards.push(child_guard);
    }
    let canonical_parent = fs::canonicalize(&cursor).map_err(|_| {
        ServiceError::new(
            "output_parent_missing",
            "output parent directory could not be resolved",
            false,
        )
    })?;
    if !canonical_parent.starts_with(root) {
        return Err(ServiceError::new(
            "output_path_rejected",
            "output path escapes the configured output root",
            false,
        ));
    }
    let file_name = relative.file_name().ok_or_else(|| {
        ServiceError::new(
            "output_path_rejected",
            "output path does not contain a file name",
            false,
        )
    })?;
    let destination = canonical_parent.join(file_name);
    let existing_guard = match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ServiceError::new(
                    "output_path_rejected",
                    "existing output must be a regular non-symlink file",
                    false,
                ));
            }
            #[cfg(unix)]
            let guard = directory_guards
                .last()
                .ok_or_else(|| {
                    ServiceError::new(
                        "internal_contract_error",
                        "output parent guard is missing",
                        false,
                    )
                })?
                .regular_child(file_name, destination.clone(), true)?;
            #[cfg(not(unix))]
            let guard = PathIdentityGuard::regular_file(&destination, true)?;
            Some(guard)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    for guard in &directory_guards {
        guard.verify()?;
    }
    Ok(ResolvedOutputDestination {
        destination,
        relative_path: normalize_relative_path(relative)?,
        output_root_id,
        directory_guards,
        existing_guard,
    })
}

fn normalize_relative_path(path: &Path) -> Result<String, ServiceError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let Component::Normal(value) = component else {
            return Err(ServiceError::new(
                "output_path_rejected",
                "output path contains a disallowed component",
                false,
            ));
        };
        parts.push(value.to_str().ok_or_else(|| {
            ServiceError::new(
                "output_path_rejected",
                "output path must be valid Unicode",
                false,
            )
        })?);
    }
    Ok(parts.join("/"))
}

fn ensure_export_journal_directory(
    root: &Path,
) -> Result<(PathBuf, PathIdentityGuard), ServiceError> {
    let root_guard = PathIdentityGuard::directory(root)?;
    let journal = root.join(EXPORT_JOURNAL_DIRECTORY);
    match fs::symlink_metadata(&journal) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ServiceError::new(
                    "export_recovery_failed",
                    "document export recovery directory is not a regular directory",
                    false,
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            root_guard.verify()?;
            fs::create_dir(&journal)?;
            sync_directory(root)?;
        }
        Err(error) => return Err(error.into()),
    }
    let journal_guard = PathIdentityGuard::directory(&journal)?;
    root_guard.verify()?;
    Ok((journal, journal_guard))
}

fn acquire_export_process_lock(root: &Path) -> Result<ExportProcessLock, ServiceError> {
    let (journal, journal_guard) = ensure_export_journal_directory(root)?;
    let lock_path = journal.join(EXPORT_LOCK_FILE);
    let file = open_export_lock_file(&lock_path)?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => ServiceError::new(
            "operation_in_progress",
            "another document export or recovery is in progress",
            true,
        ),
        std::fs::TryLockError::Error(error) => error.into(),
    })?;
    let identity_guard = PathIdentityGuard::regular_file(&lock_path, true)?;
    journal_guard.verify()?;
    Ok(ExportProcessLock {
        _file: file,
        _identity_guard: identity_guard,
    })
}

#[cfg(windows)]
fn open_export_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    options
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(not(windows))]
fn open_export_lock_file(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)
}

fn prepare_durable_export(
    root: &Path,
    resolved: ResolvedOutputDestination,
    audit_id: &str,
    payload: &[u8],
    content_sha256: String,
) -> Result<PreparedExport, ServiceError> {
    let parent = resolved
        .destination
        .parent()
        .ok_or_else(|| {
            ServiceError::new(
                "output_path_rejected",
                "output path has no parent directory",
                false,
            )
        })?
        .to_path_buf();
    let token = audit_id.strip_prefix("audit:").ok_or_else(|| {
        ServiceError::new(
            "internal_contract_error",
            "document export audit identifier is invalid",
            false,
        )
    })?;
    validate_identifier("auditId", audit_id)?;
    let relative_parent = Path::new(&resolved.relative_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let stage_relative = relative_parent.join(format!(".lawyer-assistance-{token}.stage"));
    let backup_relative = relative_parent.join(format!(".lawyer-assistance-{token}.backup"));
    let stage_relative_path = normalize_relative_path(&stage_relative)?;
    let backup_relative_path = normalize_relative_path(&backup_relative)?;
    let (journal, journal_guard) = ensure_export_journal_directory(root)?;
    let marker_path = journal.join(format!("{token}.json"));
    let stage_path = root.join(&stage_relative);
    let backup_path = root.join(&backup_relative);
    let marker = ExportRecoveryMarker {
        schema_version: SERVICE_SCHEMA_VERSION,
        audit_id: audit_id.to_owned(),
        output_root_id: resolved.output_root_id.clone(),
        relative_path: resolved.relative_path.clone(),
        format: match resolved
            .destination
            .extension()
            .and_then(|value| value.to_str())
        {
            Some(value) if value.eq_ignore_ascii_case("md") => DocumentExportFormat::Markdown,
            Some(value) if value.eq_ignore_ascii_case("docx") => DocumentExportFormat::Docx,
            _ => {
                return Err(ServiceError::new(
                    "internal_contract_error",
                    "resolved export extension is unsupported",
                    false,
                ));
            }
        },
        stage_relative_path,
        backup_relative_path,
        content_sha256,
        byte_len: payload.len(),
        had_original: resolved.existing_guard.is_some(),
    };
    let prepared = PreparedExport {
        marker,
        marker_path,
        stage_path,
        backup_path,
        resolved,
    };
    prepared.resolved.verify_directories()?;
    write_export_marker(&prepared.marker_path, &prepared.marker)?;
    journal_guard.verify()?;
    let stage_result = (|| -> Result<(), ServiceError> {
        #[cfg(unix)]
        let mut stage = prepared.resolved.parent_guard()?.create_new_child(
            prepared.stage_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "staging name is missing", false)
            })?,
        )?;
        #[cfg(not(unix))]
        let mut stage = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&prepared.stage_path)?;
        stage.write_all(payload)?;
        stage.flush()?;
        stage.sync_all()?;
        sync_directory(&parent)?;
        Ok(())
    })();
    if let Err(error) = stage_result {
        let _ = fs::remove_file(&prepared.stage_path);
        let _ = fs::remove_file(&prepared.marker_path);
        return Err(error);
    }
    Ok(prepared)
}

fn write_export_marker(path: &Path, marker: &ExportRecoveryMarker) -> Result<(), ServiceError> {
    let bytes = serde_json::to_vec(marker)?;
    if bytes.len() as u64 > MAX_EXPORT_JOURNAL_BYTES {
        return Err(ServiceError::new(
            "internal_contract_error",
            "document export recovery marker exceeds its byte limit",
            false,
        ));
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&bytes)?;
    file.flush()?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn publish_prepared_export(
    prepared: &mut PreparedExport,
    overwrite: bool,
) -> Result<(), ServiceError> {
    prepared.resolved.verify_directories()?;
    prepared.resolved.verify_existing()?;
    if prepared.marker.had_original {
        if !overwrite {
            return Err(ServiceError::new(
                "output_exists",
                "output file already exists and overwrite is disabled",
                false,
            ));
        }
        prepared.resolved.existing_guard.take();
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.rename_child(
            prepared.resolved.destination.file_name().ok_or_else(|| {
                ServiceError::new(
                    "internal_contract_error",
                    "destination name is missing",
                    false,
                )
            })?,
            prepared.backup_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "backup name is missing", false)
            })?,
        )?;
        #[cfg(not(unix))]
        fs::rename(&prepared.resolved.destination, &prepared.backup_path)?;
        sync_output_parent(&prepared.resolved)?;
    } else if output_child_exists(&prepared.resolved, &prepared.resolved.destination)? {
        return Err(ServiceError::new(
            "output_exists",
            "output file appeared while the export was being prepared",
            true,
        ));
    }
    prepared.resolved.verify_directories()?;
    #[cfg(unix)]
    let stage_guard = prepared.resolved.parent_guard()?.regular_child(
        prepared.stage_path.file_name().ok_or_else(|| {
            ServiceError::new("internal_contract_error", "staging name is missing", false)
        })?,
        prepared.stage_path.clone(),
        true,
    )?;
    #[cfg(not(unix))]
    let stage_guard = PathIdentityGuard::regular_file(&prepared.stage_path, true)?;
    stage_guard.verify()?;
    #[cfg(unix)]
    prepared.resolved.parent_guard()?.hard_link_child(
        prepared.stage_path.file_name().ok_or_else(|| {
            ServiceError::new("internal_contract_error", "staging name is missing", false)
        })?,
        prepared.resolved.destination.file_name().ok_or_else(|| {
            ServiceError::new(
                "internal_contract_error",
                "destination name is missing",
                false,
            )
        })?,
    )?;
    #[cfg(not(unix))]
    fs::hard_link(&prepared.stage_path, &prepared.resolved.destination)?;
    drop(stage_guard);
    #[cfg(unix)]
    prepared
        .resolved
        .parent_guard()?
        .unlink_child(prepared.stage_path.file_name().ok_or_else(|| {
            ServiceError::new("internal_contract_error", "staging name is missing", false)
        })?)?;
    #[cfg(not(unix))]
    fs::remove_file(&prepared.stage_path)?;
    let (actual_len, actual_hash) = bounded_output_file_hash(
        &prepared.resolved,
        &prepared.resolved.destination,
        MAX_EXPORT_BYTES,
        Some(prepared.marker.byte_len),
    )?;
    if actual_len != prepared.marker.byte_len || actual_hash != prepared.marker.content_sha256 {
        return Err(ServiceError::new(
            "export_integrity_failed",
            "published export does not match its staged content",
            false,
        ));
    }
    sync_output_parent(&prepared.resolved)?;
    Ok(())
}

fn rollback_prepared_export(prepared: &mut PreparedExport) -> Result<(), ServiceError> {
    prepared.resolved.verify_directories()?;
    prepared.resolved.verify_existing()?;
    prepared.resolved.existing_guard.take();
    if output_child_exists(&prepared.resolved, &prepared.backup_path)? {
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.regular_child(
            prepared.backup_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "backup name is missing", false)
            })?,
            prepared.backup_path.clone(),
            true,
        )?;
        #[cfg(not(unix))]
        PathIdentityGuard::regular_file(&prepared.backup_path, true)?.verify()?;
        if output_child_exists(&prepared.resolved, &prepared.resolved.destination)? {
            #[cfg(unix)]
            prepared.resolved.parent_guard()?.regular_child(
                prepared.resolved.destination.file_name().ok_or_else(|| {
                    ServiceError::new(
                        "internal_contract_error",
                        "destination name is missing",
                        false,
                    )
                })?,
                prepared.resolved.destination.clone(),
                true,
            )?;
            #[cfg(not(unix))]
            PathIdentityGuard::regular_file(&prepared.resolved.destination, true)?.verify()?;
            #[cfg(unix)]
            prepared.resolved.parent_guard()?.unlink_child(
                prepared.resolved.destination.file_name().ok_or_else(|| {
                    ServiceError::new(
                        "internal_contract_error",
                        "destination name is missing",
                        false,
                    )
                })?,
            )?;
            #[cfg(not(unix))]
            fs::remove_file(&prepared.resolved.destination)?;
        }
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.rename_child(
            prepared.backup_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "backup name is missing", false)
            })?,
            prepared.resolved.destination.file_name().ok_or_else(|| {
                ServiceError::new(
                    "internal_contract_error",
                    "destination name is missing",
                    false,
                )
            })?,
        )?;
        #[cfg(not(unix))]
        fs::rename(&prepared.backup_path, &prepared.resolved.destination)?;
    } else if !prepared.marker.had_original
        && output_child_exists(&prepared.resolved, &prepared.resolved.destination)?
    {
        let (len, hash) = bounded_output_file_hash(
            &prepared.resolved,
            &prepared.resolved.destination,
            MAX_EXPORT_BYTES,
            Some(prepared.marker.byte_len),
        )?;
        if len != prepared.marker.byte_len || hash != prepared.marker.content_sha256 {
            return Err(ServiceError::new(
                "export_recovery_failed",
                "recovery refused to remove an unexpected destination file",
                false,
            ));
        }
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.unlink_child(
            prepared.resolved.destination.file_name().ok_or_else(|| {
                ServiceError::new(
                    "internal_contract_error",
                    "destination name is missing",
                    false,
                )
            })?,
        )?;
        #[cfg(not(unix))]
        fs::remove_file(&prepared.resolved.destination)?;
    }
    if output_child_exists(&prepared.resolved, &prepared.stage_path)? {
        let (len, hash) = bounded_output_file_hash(
            &prepared.resolved,
            &prepared.stage_path,
            MAX_EXPORT_BYTES,
            Some(prepared.marker.byte_len),
        )?;
        if len != prepared.marker.byte_len || hash != prepared.marker.content_sha256 {
            return Err(ServiceError::new(
                "export_recovery_failed",
                "recovery staging file does not match its marker",
                false,
            ));
        }
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.unlink_child(
            prepared.stage_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "staging name is missing", false)
            })?,
        )?;
        #[cfg(not(unix))]
        fs::remove_file(&prepared.stage_path)?;
    }
    sync_output_parent(&prepared.resolved)?;
    fs::remove_file(&prepared.marker_path)?;
    if let Some(parent) = prepared.marker_path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn cleanup_committed_export(prepared: &PreparedExport) -> Result<(), ServiceError> {
    prepared.resolved.verify_directories()?;
    let (len, hash) = bounded_output_file_hash(
        &prepared.resolved,
        &prepared.resolved.destination,
        MAX_EXPORT_BYTES,
        Some(prepared.marker.byte_len),
    )?;
    if len != prepared.marker.byte_len || hash != prepared.marker.content_sha256 {
        return Err(ServiceError::new(
            "export_integrity_failed",
            "committed export does not match its audit marker",
            false,
        ));
    }
    if output_child_exists(&prepared.resolved, &prepared.backup_path)? {
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.regular_child(
            prepared.backup_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "backup name is missing", false)
            })?,
            prepared.backup_path.clone(),
            true,
        )?;
        #[cfg(not(unix))]
        PathIdentityGuard::regular_file(&prepared.backup_path, true)?.verify()?;
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.unlink_child(
            prepared.backup_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "backup name is missing", false)
            })?,
        )?;
        #[cfg(not(unix))]
        fs::remove_file(&prepared.backup_path)?;
    }
    if output_child_exists(&prepared.resolved, &prepared.stage_path)? {
        let (stage_len, stage_hash) = bounded_output_file_hash(
            &prepared.resolved,
            &prepared.stage_path,
            MAX_EXPORT_BYTES,
            Some(prepared.marker.byte_len),
        )?;
        if stage_len != prepared.marker.byte_len || stage_hash != prepared.marker.content_sha256 {
            return Err(ServiceError::new(
                "export_recovery_failed",
                "committed export staging file does not match its marker",
                false,
            ));
        }
        #[cfg(unix)]
        prepared.resolved.parent_guard()?.unlink_child(
            prepared.stage_path.file_name().ok_or_else(|| {
                ServiceError::new("internal_contract_error", "staging name is missing", false)
            })?,
        )?;
        #[cfg(not(unix))]
        fs::remove_file(&prepared.stage_path)?;
    }
    sync_output_parent(&prepared.resolved)?;
    fs::remove_file(&prepared.marker_path)?;
    if let Some(parent) = prepared.marker_path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

fn bounded_file_hash(
    path: &Path,
    maximum_len: usize,
    expected_len: Option<usize>,
) -> Result<(usize, String), ServiceError> {
    let guard = PathIdentityGuard::regular_file(path, true)?;
    let result = bounded_open_file_hash(File::open(path)?, maximum_len, expected_len)?;
    guard.verify()?;
    Ok(result)
}

fn bounded_output_file_hash(
    _resolved: &ResolvedOutputDestination,
    path: &Path,
    maximum_len: usize,
    expected_len: Option<usize>,
) -> Result<(usize, String), ServiceError> {
    #[cfg(unix)]
    {
        let name = path.file_name().ok_or_else(|| {
            ServiceError::new(
                "internal_contract_error",
                "output file name is missing",
                false,
            )
        })?;
        let file = _resolved.parent_guard()?.open_regular_child(name, true)?;
        bounded_open_file_hash(file, maximum_len, expected_len)
    }
    #[cfg(not(unix))]
    {
        bounded_file_hash(path, maximum_len, expected_len)
    }
}

fn bounded_open_file_hash(
    file: File,
    maximum_len: usize,
    expected_len: Option<usize>,
) -> Result<(usize, String), ServiceError> {
    let metadata = file.metadata()?;
    let maximum_len = u64::try_from(maximum_len).unwrap_or(u64::MAX);
    if metadata.len() > maximum_len
        || expected_len.is_some_and(|value| metadata.len() != value as u64)
    {
        return Err(ServiceError::new(
            "export_integrity_failed",
            "export size does not match its bounded audit record",
            false,
        ));
    }
    let mut reader = BufReader::new(file).take(maximum_len.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 32 * 1024];
    let mut total = 0_usize;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read).ok_or_else(|| {
            ServiceError::new("export_integrity_failed", "export size overflowed", false)
        })?;
        if total > maximum_len as usize {
            return Err(ServiceError::new(
                "export_integrity_failed",
                "export exceeds its bounded audit record",
                false,
            ));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, format!("{:x}", hasher.finalize())))
}

fn sync_output_parent(resolved: &ResolvedOutputDestination) -> Result<(), ServiceError> {
    #[cfg(unix)]
    {
        resolved.parent_guard()?.sync_all()
    }
    #[cfg(not(unix))]
    {
        sync_directory(resolved.destination.parent().ok_or_else(|| {
            ServiceError::new("output_path_rejected", "output path has no parent", false)
        })?)
    }
}

fn output_child_exists(
    _resolved: &ResolvedOutputDestination,
    path: &Path,
) -> Result<bool, ServiceError> {
    #[cfg(unix)]
    {
        let name = path.file_name().ok_or_else(|| {
            ServiceError::new(
                "internal_contract_error",
                "output file name is missing",
                false,
            )
        })?;
        _resolved.parent_guard()?.child_exists(name)
    }
    #[cfg(not(unix))]
    {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

fn sync_directory(path: &Path) -> Result<(), ServiceError> {
    let directory = PathIdentityGuard::directory(path)?;
    // Unix exposes directory fsync through a normal read-only descriptor.
    // Windows directory handles do not support `File::sync_all`; the pinned
    // no-delete handle and file-level flushes still protect identity and data.
    #[cfg(not(windows))]
    {
        let file = File::open(path)?;
        file.sync_all()?;
    }
    directory.verify()?;
    Ok(())
}

fn recover_document_exports(
    connection: &mut rusqlite::Connection,
    root: &Path,
) -> Result<(), ServiceError> {
    let (journal, journal_guard) = ensure_export_journal_directory(root)?;
    let mut marker_paths = fs::read_dir(&journal)?
        .map(|entry| entry.map(|value| value.path()))
        .collect::<Result<Vec<_>, _>>()?;
    marker_paths.retain(|path| path.extension().and_then(|value| value.to_str()) == Some("json"));
    marker_paths.sort();
    for marker_path in marker_paths {
        journal_guard.verify()?;
        let marker = read_export_marker(&marker_path)?;
        let mut prepared = prepared_export_from_marker(root, marker_path, marker)?;
        let audit = database::get_operation_audit(connection, &prepared.marker.audit_id)?;
        if audit
            .as_ref()
            .is_some_and(|value| value.status == "succeeded")
        {
            cleanup_committed_export(&prepared)?;
            continue;
        }
        if audit
            .as_ref()
            .is_some_and(|value| value.status == "prepared")
        {
            mark_export_failed(connection, &prepared.marker)?;
        }
        rollback_prepared_export(&mut prepared)?;
    }
    journal_guard.verify()?;
    Ok(())
}

fn read_export_marker(path: &Path) -> Result<ExportRecoveryMarker, ServiceError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_EXPORT_JOURNAL_BYTES
    {
        return Err(ServiceError::new(
            "export_recovery_failed",
            "document export recovery marker is not a bounded regular file",
            false,
        ));
    }
    let guard = PathIdentityGuard::regular_file(path, true)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_EXPORT_JOURNAL_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EXPORT_JOURNAL_BYTES {
        return Err(ServiceError::new(
            "export_recovery_failed",
            "document export recovery marker exceeds its byte limit",
            false,
        ));
    }
    guard.verify()?;
    serde_json::from_slice(&bytes).map_err(|_| {
        ServiceError::new(
            "export_recovery_failed",
            "document export recovery marker is invalid",
            false,
        )
    })
}

fn prepared_export_from_marker(
    root: &Path,
    marker_path: PathBuf,
    marker: ExportRecoveryMarker,
) -> Result<PreparedExport, ServiceError> {
    require_schema_version(marker.schema_version)?;
    validate_identifier("auditId", &marker.audit_id)?;
    validate_sha256("outputRootId", &marker.output_root_id)?;
    validate_sha256("contentSha256", &marker.content_sha256)?;
    if marker.byte_len > MAX_EXPORT_BYTES {
        return Err(ServiceError::new(
            "export_recovery_failed",
            "document export recovery marker has an invalid size",
            false,
        ));
    }
    let resolved = resolve_output_destination(root, &marker.relative_path, marker.format)?;
    if resolved.output_root_id != marker.output_root_id
        || resolved.relative_path != marker.relative_path
    {
        return Err(ServiceError::new(
            "export_recovery_failed",
            "document export root or destination changed during recovery",
            false,
        ));
    }
    let token = marker.audit_id.strip_prefix("audit:").ok_or_else(|| {
        ServiceError::new(
            "export_recovery_failed",
            "document export recovery audit identifier is invalid",
            false,
        )
    })?;
    let parent = Path::new(&marker.relative_path)
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let expected_stage =
        normalize_relative_path(&parent.join(format!(".lawyer-assistance-{token}.stage")))?;
    let expected_backup =
        normalize_relative_path(&parent.join(format!(".lawyer-assistance-{token}.backup")))?;
    if marker.stage_relative_path != expected_stage
        || marker.backup_relative_path != expected_backup
    {
        return Err(ServiceError::new(
            "export_recovery_failed",
            "document export recovery paths are inconsistent",
            false,
        ));
    }
    Ok(PreparedExport {
        stage_path: root.join(Path::new(&marker.stage_relative_path)),
        backup_path: root.join(Path::new(&marker.backup_relative_path)),
        marker_path,
        marker,
        resolved,
    })
}

fn mark_export_failed(
    connection: &mut rusqlite::Connection,
    marker: &ExportRecoveryMarker,
) -> Result<(), ServiceError> {
    let details = serde_json::to_string(&serde_json::json!({
        "schemaVersion": SERVICE_SCHEMA_VERSION,
        "recovered": true,
        "outputRootId": marker.output_root_id,
        "relativeExportPath": marker.relative_path,
    }))?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    match database::compare_and_set_operation_audit_status(
        &transaction,
        &marker.audit_id,
        "failed",
        &details,
    )? {
        database::OperationAuditStatusUpdateResult::Updated(_)
        | database::OperationAuditStatusUpdateResult::NotFound => {}
        database::OperationAuditStatusUpdateResult::Conflict(existing) => {
            if existing.status != "failed" {
                return Err(ServiceError::new(
                    "export_recovery_failed",
                    "document export audit changed during recovery",
                    true,
                ));
            }
        }
    }
    transaction.commit()?;
    Ok(())
}

fn replay_document_export(
    existing: database::OperationAuditRow,
    request: &DocumentExportRequest,
    request_hash: &str,
    expected_destination: &ResolvedOutputDestination,
) -> Result<DocumentExportResponse, ServiceError> {
    if existing.request_hash != request_hash
        || existing.project_id.as_deref() != Some(request.project_id.as_str())
    {
        return Err(ServiceError::new(
            "idempotency_conflict",
            "idempotency key was already used for a different export",
            false,
        ));
    }
    if existing.status != "succeeded" {
        return Err(ServiceError::new(
            if existing.status == "prepared" {
                "operation_in_progress"
            } else {
                "idempotency_conflict"
            },
            "previous export with this idempotency key is not complete",
            existing.status == "prepared",
        ));
    }
    let details: CompletedAuditDetails =
        serde_json::from_str(&existing.details_json).map_err(|_| {
            ServiceError::new(
                "user_database_incompatible",
                "completed export audit details are invalid",
                false,
            )
        })?;
    let path_matches_policy = match (
        details.output_root_id.as_deref(),
        details.relative_export_path.as_deref(),
    ) {
        (Some(root_id), Some(relative_path)) => {
            root_id == expected_destination.output_root_id
                && relative_path == expected_destination.relative_path
        }
        (None, None) => details
            .export_path
            .as_deref()
            .is_some_and(|path| Path::new(path) == expected_destination.destination),
        _ => false,
    };
    if !path_matches_policy {
        return Err(ServiceError::new(
            "export_integrity_failed",
            "completed export path does not match the current output policy",
            false,
        ));
    }
    let payload_hash = details.content_sha256.ok_or_else(|| {
        ServiceError::new(
            "user_database_incompatible",
            "completed export audit hash is missing",
            false,
        )
    })?;
    let expected_len = details.byte_len.ok_or_else(|| {
        ServiceError::new(
            "user_database_incompatible",
            "completed export audit size is missing",
            false,
        )
    })?;
    let (actual_len, actual_hash) = bounded_output_file_hash(
        expected_destination,
        &expected_destination.destination,
        MAX_EXPORT_BYTES,
        Some(expected_len),
    )
    .map_err(|_| {
        ServiceError::new(
            "export_missing",
            "previously completed export is no longer available",
            false,
        )
    })?;
    if actual_hash != payload_hash {
        return Err(ServiceError::new(
            "export_integrity_failed",
            "previously completed export no longer matches its audit hash",
            false,
        ));
    }
    let record_id = details.record_id.ok_or_else(|| {
        ServiceError::new(
            "user_database_incompatible",
            "completed export record id is missing",
            false,
        )
    })?;
    Ok(DocumentExportResponse {
        schema_version: SERVICE_SCHEMA_VERSION,
        audit_id: existing.audit_id,
        record_id,
        project_id: request.project_id.clone(),
        case_revision: details.after_revision.ok_or_else(|| {
            ServiceError::new(
                "user_database_incompatible",
                "completed export revision is missing",
                false,
            )
        })?,
        generation_hash: details.generation_hash.ok_or_else(|| {
            ServiceError::new(
                "user_database_incompatible",
                "completed export generation hash is missing",
                false,
            )
        })?,
        export_path: expected_destination
            .destination
            .to_string_lossy()
            .into_owned(),
        format: request.format,
        media_type: request.format.media_type().to_owned(),
        byte_len: actual_len,
        sha256: payload_hash,
        replayed: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recovery_connection(path: &Path) -> rusqlite::Connection {
        database::validate_and_migrate_user_database(path).expect("initialize recovery database");
        database::open_existing_user_database(path).expect("open recovery database")
    }

    fn insert_prepared_export_audit(connection: &rusqlite::Connection, audit_id: &str) {
        database::create_operation_audit(
            connection,
            &database::NewOperationAuditRow {
                audit_id: audit_id.to_owned(),
                origin: "mcp".to_owned(),
                operation: "document_export".to_owned(),
                project_id: None,
                request_hash: "0".repeat(64),
                idempotency_key_hash: None,
                details_json: "{}".to_owned(),
            },
        )
        .expect("insert prepared audit");
    }

    #[test]
    fn bounded_hash_rejects_files_larger_than_the_export_limit() {
        let directory = tempfile::tempdir().expect("temporary export directory");
        let destination = directory.path().join("document.md");
        fs::write(&destination, b"too-large").expect("write fixture");
        let error = bounded_file_hash(&destination, 3, None).expect_err("size is bounded");
        assert_eq!(error.code, "export_integrity_failed");
    }

    #[test]
    fn recovery_rolls_back_published_file_and_sensitive_backup_for_prepared_audit() {
        let directory = tempfile::tempdir().expect("temporary recovery directory");
        let root = directory.path().join("exports");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create output directories");
        let root = fs::canonicalize(root).expect("canonical output root");
        let reports = root.join("reports");
        let destination = reports.join("recover.md");
        fs::write(&destination, b"private previous content").expect("write previous export");
        let mut connection = recovery_connection(&directory.path().join("user.sqlite"));
        let audit_id = format!("audit:{}", Uuid::new_v4());
        let resolved =
            resolve_output_destination(&root, "reports/recover.md", DocumentExportFormat::Markdown)
                .expect("resolve destination");
        let payload = b"new reviewed content";
        let mut prepared =
            prepare_durable_export(&root, resolved, &audit_id, payload, sha256_hex(payload))
                .expect("prepare durable export");
        insert_prepared_export_audit(&connection, &audit_id);
        publish_prepared_export(&mut prepared, true).expect("publish before simulated crash");
        assert_eq!(fs::read(&destination).expect("published"), payload);
        assert!(prepared.backup_path.exists());
        let marker_path = prepared.marker_path.clone();
        let backup_path = prepared.backup_path.clone();
        drop(prepared);

        recover_document_exports(&mut connection, &root).expect("recover prepared export");
        assert_eq!(
            fs::read(&destination).expect("restored previous export"),
            b"private previous content"
        );
        assert!(!marker_path.exists());
        assert!(!backup_path.exists());
        assert_eq!(
            database::get_operation_audit(&connection, &audit_id)
                .expect("read audit")
                .expect("audit exists")
                .status,
            "failed"
        );
    }

    #[test]
    fn recovery_keeps_committed_export_and_deletes_sensitive_backup() {
        let directory = tempfile::tempdir().expect("temporary recovery directory");
        let root = directory.path().join("exports");
        let reports = root.join("reports");
        fs::create_dir_all(&reports).expect("create output directories");
        let root = fs::canonicalize(root).expect("canonical output root");
        let reports = root.join("reports");
        let destination = reports.join("committed.md");
        fs::write(&destination, b"private previous content").expect("write previous export");
        let mut connection = recovery_connection(&directory.path().join("user.sqlite"));
        let audit_id = format!("audit:{}", Uuid::new_v4());
        let resolved = resolve_output_destination(
            &root,
            "reports/committed.md",
            DocumentExportFormat::Markdown,
        )
        .expect("resolve destination");
        let payload = b"committed reviewed content";
        let mut prepared =
            prepare_durable_export(&root, resolved, &audit_id, payload, sha256_hex(payload))
                .expect("prepare durable export");
        insert_prepared_export_audit(&connection, &audit_id);
        publish_prepared_export(&mut prepared, true).expect("publish export");
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("begin final audit transaction");
        assert!(matches!(
            database::compare_and_set_operation_audit_status(
                &transaction,
                &audit_id,
                "succeeded",
                r#"{"schemaVersion":1}"#,
            )
            .expect("finalize audit"),
            database::OperationAuditStatusUpdateResult::Updated(_)
        ));
        transaction.commit().expect("commit audit");
        let marker_path = prepared.marker_path.clone();
        let backup_path = prepared.backup_path.clone();
        drop(prepared);

        recover_document_exports(&mut connection, &root).expect("recover committed export");
        assert_eq!(fs::read(&destination).expect("committed export"), payload);
        assert!(!marker_path.exists());
        assert!(!backup_path.exists());
    }
}
