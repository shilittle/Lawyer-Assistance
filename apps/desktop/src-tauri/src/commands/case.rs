use domain::case::{
    analyze_case_gaps, CaseFact, CaseFile, CaseGap, CaseParty, CaseProject, CaseWorkspace,
    EvidenceItem, EvidenceLink, LegalBasis, LegalIssue, StructuredCaseExtractionResponse,
};
use domain::qa::LegalSource;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl IpcError {
    fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            message: message.into(),
        }
    }
}

impl From<database::DatabaseInitError> for IpcError {
    fn from(error: database::DatabaseInitError) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<rusqlite::Error> for IpcError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<citations::CitationError> for IpcError {
    fn from(error: citations::CitationError) -> Self {
        Self::new("citation", error.to_string())
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(error: serde_json::Error) -> Self {
        Self::new("serialization", error.to_string())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseProjectsResponse {
    pub projects: Vec<CaseProject>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCaseWorkspaceRequest {
    pub project_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetCaseWorkspaceResponse {
    pub workspace: Option<CaseWorkspace>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertCaseProjectRequest {
    pub project: CaseProject,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseProjectResponse {
    pub project: CaseProject,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCaseProjectRequest {
    pub project_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCaseProjectResponse {
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertCaseFileRequest {
    pub file: CaseFile,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertCasePartyRequest {
    pub party: CaseParty,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertCaseFactRequest {
    pub fact: CaseFact,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertEvidenceItemRequest {
    pub evidence: EvidenceItem,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertEvidenceLinkRequest {
    pub link: EvidenceLink,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertLegalIssueRequest {
    pub issue: LegalIssue,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCaseLegalBasisRequest {
    pub project_id: String,
    pub issue_id: Option<String>,
    pub source_id: String,
    pub case_date: Option<String>,
    pub include_expired: bool,
    pub note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddCaseLegalBasisResponse {
    pub basis: LegalBasis,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitySavedResponse {
    pub saved: bool,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseEntityType {
    File,
    Party,
    Fact,
    Evidence,
    EvidenceLink,
    LegalIssue,
    LegalBasis,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCaseEntityRequest {
    pub entity_type: CaseEntityType,
    pub id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteCaseEntityResponse {
    pub deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeCaseGapsRequest {
    pub project_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeCaseGapsResponse {
    pub gaps: Vec<CaseGap>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseStructuredCaseExtractionRequest {
    pub raw_output: String,
    pub repaired_output: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParseStructuredCaseExtractionResponse {
    pub result: StructuredCaseExtractionResponse,
}

#[tauri::command]
pub fn list_case_projects(state: State<'_, AppState>) -> Result<CaseProjectsResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let projects = database::list_case_projects(&connection)?
        .into_iter()
        .map(project_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(CaseProjectsResponse { projects })
}

#[tauri::command]
pub fn get_case_workspace(
    state: State<'_, AppState>,
    request: GetCaseWorkspaceRequest,
) -> Result<GetCaseWorkspaceResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let workspace = database::get_case_workspace_rows(&connection, &request.project_id)?
        .map(workspace_from_rows)
        .transpose()?;

    Ok(GetCaseWorkspaceResponse { workspace })
}

#[tauri::command]
pub fn upsert_case_project(
    state: State<'_, AppState>,
    request: UpsertCaseProjectRequest,
) -> Result<CaseProjectResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    database::upsert_case_project(&connection, &project_to_row(&request.project)?)?;
    let project = database::get_case_workspace_rows(&connection, &request.project.project_id)?
        .map(|workspace| workspace.project)
        .map(project_from_row)
        .transpose()?
        .unwrap_or(request.project);

    Ok(CaseProjectResponse { project })
}

#[tauri::command]
pub fn delete_case_project(
    state: State<'_, AppState>,
    request: DeleteCaseProjectRequest,
) -> Result<DeleteCaseProjectResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let deleted = database::delete_case_project(&connection, &request.project_id)?;

    Ok(DeleteCaseProjectResponse { deleted })
}

#[tauri::command]
pub fn upsert_case_file(
    state: State<'_, AppState>,
    request: UpsertCaseFileRequest,
) -> Result<EntitySavedResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    database::upsert_case_file(&connection, &file_to_row(&request.file))?;

    Ok(EntitySavedResponse { saved: true })
}

#[tauri::command]
pub fn upsert_case_party(
    state: State<'_, AppState>,
    request: UpsertCasePartyRequest,
) -> Result<EntitySavedResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    database::upsert_case_party(&connection, &party_to_row(&request.party)?)?;

    Ok(EntitySavedResponse { saved: true })
}

#[tauri::command]
pub fn upsert_case_fact(
    state: State<'_, AppState>,
    request: UpsertCaseFactRequest,
) -> Result<EntitySavedResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    database::upsert_case_fact(&connection, &fact_to_row(&request.fact)?)?;

    Ok(EntitySavedResponse { saved: true })
}

#[tauri::command]
pub fn upsert_evidence_item(
    state: State<'_, AppState>,
    request: UpsertEvidenceItemRequest,
) -> Result<EntitySavedResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    database::upsert_evidence_item(&connection, &evidence_to_row(&request.evidence)?)?;

    Ok(EntitySavedResponse { saved: true })
}

#[tauri::command]
pub fn upsert_evidence_link(
    state: State<'_, AppState>,
    request: UpsertEvidenceLinkRequest,
) -> Result<EntitySavedResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    database::upsert_evidence_link(&connection, &link_to_row(&request.link))?;

    Ok(EntitySavedResponse { saved: true })
}

#[tauri::command]
pub fn upsert_legal_issue(
    state: State<'_, AppState>,
    request: UpsertLegalIssueRequest,
) -> Result<EntitySavedResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    database::upsert_legal_issue(&connection, &issue_to_row(&request.issue)?)?;

    Ok(EntitySavedResponse { saved: true })
}

#[tauri::command]
pub fn add_case_legal_basis(
    state: State<'_, AppState>,
    request: AddCaseLegalBasisRequest,
) -> Result<AddCaseLegalBasisResponse, IpcError> {
    let user_connection = database::open_user_database(state.user_database_path())?;
    let workspace = database::get_case_workspace_rows(&user_connection, &request.project_id)?
        .ok_or_else(|| IpcError::new("not_found", "case project not found"))?;
    let issue_id = normalize_optional(request.issue_id.as_deref());

    if let Some(issue_id) = issue_id.as_deref() {
        let issue_belongs_to_project = workspace
            .legal_issues
            .iter()
            .any(|issue| issue.issue_id == issue_id);
        if !issue_belongs_to_project {
            return Err(IpcError::new(
                "not_found",
                "legal issue does not belong to the case project",
            ));
        }
    }

    let source_id = normalize_source_id(&request.source_id);
    if source_id.is_empty() {
        return Err(IpcError::new("invalid_request", "source_id is required"));
    }

    let case_date = normalize_optional(request.case_date.as_deref())
        .or_else(|| workspace.project.opened_on.clone());
    let legal_connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let database_source = citations::source_by_citation_id(&legal_connection, &source_id)?;
    let allowed_sources = database_source
        .clone()
        .into_iter()
        .collect::<Vec<LegalSource>>();
    let answer = format!("[SRC:{source_id}]");
    let report = citations::validate_answer_citations(
        &legal_connection,
        &answer,
        &allowed_sources,
        case_date.as_deref(),
        request.include_expired,
    )?;
    let citation = report
        .citations
        .into_iter()
        .next()
        .ok_or_else(|| IpcError::new("citation", "citation marker could not be parsed"))?;
    let source = citation.source.clone().or(database_source);
    let basis = legal_basis_from_validation(
        &workspace.project.project_id,
        issue_id,
        case_date,
        &request.note,
        citation,
        source,
    );

    database::upsert_legal_basis(&user_connection, &basis_to_row(&basis)?)?;

    Ok(AddCaseLegalBasisResponse { basis })
}

#[tauri::command]
pub fn delete_case_entity(
    state: State<'_, AppState>,
    request: DeleteCaseEntityRequest,
) -> Result<DeleteCaseEntityResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let (table, id_column) = match request.entity_type {
        CaseEntityType::File => ("case_files", "file_id"),
        CaseEntityType::Party => ("case_parties", "party_id"),
        CaseEntityType::Fact => ("case_facts", "fact_id"),
        CaseEntityType::Evidence => ("evidence_items", "evidence_id"),
        CaseEntityType::EvidenceLink => ("evidence_links", "link_id"),
        CaseEntityType::LegalIssue => ("legal_issues", "issue_id"),
        CaseEntityType::LegalBasis => ("legal_basis", "basis_id"),
    };
    let deleted = database::delete_case_entity(&connection, table, id_column, &request.id)?;

    Ok(DeleteCaseEntityResponse { deleted })
}

#[tauri::command]
pub fn analyze_case_gaps_command(
    state: State<'_, AppState>,
    request: AnalyzeCaseGapsRequest,
) -> Result<AnalyzeCaseGapsResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let workspace = database::get_case_workspace_rows(&connection, &request.project_id)?
        .ok_or_else(|| IpcError::new("not_found", "case project not found"))?;
    let workspace = workspace_from_rows(workspace)?;

    Ok(AnalyzeCaseGapsResponse {
        gaps: workspace.gaps,
    })
}

#[tauri::command]
pub fn parse_structured_case_extraction(
    request: ParseStructuredCaseExtractionRequest,
) -> ParseStructuredCaseExtractionResponse {
    ParseStructuredCaseExtractionResponse {
        result: domain::case::parse_structured_case_extraction_with_repair(
            &request.raw_output,
            request.repaired_output.as_deref(),
        ),
    }
}

fn workspace_from_rows(rows: database::CaseWorkspaceRows) -> Result<CaseWorkspace, IpcError> {
    let project = project_from_row(rows.project)?;
    let files = rows.files.into_iter().map(file_from_row).collect();
    let parties = rows
        .parties
        .into_iter()
        .map(party_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let facts = rows
        .facts
        .into_iter()
        .map(fact_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = rows
        .evidence
        .into_iter()
        .map(evidence_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let evidence_links = rows
        .evidence_links
        .into_iter()
        .map(link_from_row)
        .collect::<Vec<_>>();
    let legal_issues = rows
        .legal_issues
        .into_iter()
        .map(issue_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let legal_basis = rows
        .legal_basis
        .into_iter()
        .map(basis_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let gaps = analyze_case_gaps(
        &project.project_id,
        &parties,
        &facts,
        &evidence,
        &evidence_links,
        &legal_issues,
        &legal_basis,
    );

    Ok(CaseWorkspace {
        project,
        files,
        parties,
        facts,
        evidence,
        evidence_links,
        legal_issues,
        legal_basis,
        gaps,
    })
}

fn project_from_row(row: database::CaseProjectRow) -> Result<CaseProject, serde_json::Error> {
    Ok(CaseProject {
        project_id: row.project_id,
        title: row.title,
        case_type: row.case_type,
        status: from_string(row.status)?,
        opened_on: row.opened_on,
        summary: row.summary,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

fn file_from_row(row: database::CaseFileRow) -> CaseFile {
    CaseFile {
        file_id: row.file_id,
        project_id: row.project_id,
        title: row.title,
        file_type: row.file_type,
        storage_reference: row.storage_reference,
        summary: row.summary,
        created_at: row.created_at,
    }
}

fn party_from_row(row: database::CasePartyRow) -> Result<CaseParty, serde_json::Error> {
    Ok(CaseParty {
        party_id: row.party_id,
        project_id: row.project_id,
        name: row.name,
        normalized_name: row.normalized_name,
        role: from_string(row.role)?,
        contact: row.contact,
        notes: row.notes,
    })
}

fn fact_from_row(row: database::CaseFactRow) -> Result<CaseFact, serde_json::Error> {
    Ok(CaseFact {
        fact_id: row.fact_id,
        project_id: row.project_id,
        occurred_on: row.occurred_on,
        title: row.title,
        description: row.description,
        source: row.source,
        confirmation_status: from_string(row.confirmation_status)?,
    })
}

fn evidence_from_row(row: database::EvidenceItemRow) -> Result<EvidenceItem, serde_json::Error> {
    Ok(EvidenceItem {
        evidence_id: row.evidence_id,
        project_id: row.project_id,
        evidence_number: row.evidence_number,
        title: row.title,
        source: row.source,
        formed_on: row.formed_on,
        summary: row.summary,
        storage_reference: row.storage_reference,
        confirmation_status: from_string(row.confirmation_status)?,
    })
}

fn link_from_row(row: database::EvidenceLinkRow) -> EvidenceLink {
    EvidenceLink {
        link_id: row.link_id,
        project_id: row.project_id,
        fact_id: row.fact_id,
        evidence_id: row.evidence_id,
    }
}

fn issue_from_row(row: database::LegalIssueRow) -> Result<LegalIssue, serde_json::Error> {
    Ok(LegalIssue {
        issue_id: row.issue_id,
        project_id: row.project_id,
        title: row.title,
        description: row.description,
        claim: row.claim,
        status: from_string(row.status)?,
        confirmation_status: from_string(row.confirmation_status)?,
    })
}

fn basis_from_row(row: database::LegalBasisRow) -> Result<LegalBasis, serde_json::Error> {
    Ok(LegalBasis {
        basis_id: row.basis_id,
        project_id: row.project_id,
        issue_id: row.issue_id,
        source_id: row.source_id,
        status: from_string(row.status)?,
        invalid_reason: row.invalid_reason.map(from_string).transpose()?,
        case_date: row.case_date,
        article_id: row.article_id,
        document_id: row.document_id,
        version_id: row.version_id,
        document_title: row.document_title,
        version_label: row.version_label,
        article_number: row.article_number,
        article_title: row.article_title,
        canonical_label: row.canonical_label,
        effective_from: row.effective_from,
        effective_to: row.effective_to,
        version_status: row.version_status,
        excerpt: row.excerpt,
        note: row.note,
        created_at: row.created_at,
    })
}

fn project_to_row(project: &CaseProject) -> Result<database::CaseProjectRow, serde_json::Error> {
    Ok(database::CaseProjectRow {
        project_id: project.project_id.clone(),
        title: project.title.clone(),
        case_type: project.case_type.clone(),
        status: to_string(project.status.clone())?,
        opened_on: project.opened_on.clone(),
        summary: project.summary.clone(),
        created_at: project.created_at.clone(),
        updated_at: project.updated_at.clone(),
    })
}

fn file_to_row(file: &CaseFile) -> database::CaseFileRow {
    database::CaseFileRow {
        file_id: file.file_id.clone(),
        project_id: file.project_id.clone(),
        title: file.title.clone(),
        file_type: file.file_type.clone(),
        storage_reference: file.storage_reference.clone(),
        summary: file.summary.clone(),
        created_at: file.created_at.clone(),
    }
}

fn party_to_row(party: &CaseParty) -> Result<database::CasePartyRow, serde_json::Error> {
    Ok(database::CasePartyRow {
        party_id: party.party_id.clone(),
        project_id: party.project_id.clone(),
        name: party.name.clone(),
        normalized_name: party.normalized_name.clone(),
        role: to_string(party.role.clone())?,
        contact: party.contact.clone(),
        notes: party.notes.clone(),
    })
}

fn fact_to_row(fact: &CaseFact) -> Result<database::CaseFactRow, serde_json::Error> {
    Ok(database::CaseFactRow {
        fact_id: fact.fact_id.clone(),
        project_id: fact.project_id.clone(),
        occurred_on: fact.occurred_on.clone(),
        title: fact.title.clone(),
        description: fact.description.clone(),
        source: fact.source.clone(),
        confirmation_status: to_string(fact.confirmation_status.clone())?,
    })
}

fn evidence_to_row(
    evidence: &EvidenceItem,
) -> Result<database::EvidenceItemRow, serde_json::Error> {
    Ok(database::EvidenceItemRow {
        evidence_id: evidence.evidence_id.clone(),
        project_id: evidence.project_id.clone(),
        evidence_number: evidence.evidence_number.clone(),
        title: evidence.title.clone(),
        source: evidence.source.clone(),
        formed_on: evidence.formed_on.clone(),
        summary: evidence.summary.clone(),
        storage_reference: evidence.storage_reference.clone(),
        confirmation_status: to_string(evidence.confirmation_status.clone())?,
    })
}

fn link_to_row(link: &EvidenceLink) -> database::EvidenceLinkRow {
    database::EvidenceLinkRow {
        link_id: link.link_id.clone(),
        project_id: link.project_id.clone(),
        fact_id: link.fact_id.clone(),
        evidence_id: link.evidence_id.clone(),
    }
}

fn issue_to_row(issue: &LegalIssue) -> Result<database::LegalIssueRow, serde_json::Error> {
    Ok(database::LegalIssueRow {
        issue_id: issue.issue_id.clone(),
        project_id: issue.project_id.clone(),
        title: issue.title.clone(),
        description: issue.description.clone(),
        claim: issue.claim.clone(),
        status: to_string(issue.status.clone())?,
        confirmation_status: to_string(issue.confirmation_status.clone())?,
    })
}

fn basis_to_row(basis: &LegalBasis) -> Result<database::LegalBasisRow, serde_json::Error> {
    Ok(database::LegalBasisRow {
        basis_id: basis.basis_id.clone(),
        project_id: basis.project_id.clone(),
        issue_id: basis.issue_id.clone(),
        source_id: basis.source_id.clone(),
        status: to_string(basis.status.clone())?,
        invalid_reason: basis.invalid_reason.clone().map(to_string).transpose()?,
        case_date: basis.case_date.clone(),
        article_id: basis.article_id.clone(),
        document_id: basis.document_id.clone(),
        version_id: basis.version_id.clone(),
        document_title: basis.document_title.clone(),
        version_label: basis.version_label.clone(),
        article_number: basis.article_number.clone(),
        article_title: basis.article_title.clone(),
        canonical_label: basis.canonical_label.clone(),
        effective_from: basis.effective_from.clone(),
        effective_to: basis.effective_to.clone(),
        version_status: basis.version_status.clone(),
        excerpt: basis.excerpt.clone(),
        note: basis.note.clone(),
        created_at: basis.created_at.clone(),
    })
}

fn legal_basis_from_validation(
    project_id: &str,
    issue_id: Option<String>,
    case_date: Option<String>,
    note: &str,
    citation: domain::qa::ValidatedCitation,
    source: Option<LegalSource>,
) -> LegalBasis {
    let source_id = citation.source_id;
    let basis_id = legal_basis_id(
        project_id,
        issue_id.as_deref(),
        &source_id,
        case_date.as_deref(),
    );
    let excerpt = source.as_ref().map(source_excerpt).unwrap_or_default();

    LegalBasis {
        basis_id,
        project_id: project_id.to_owned(),
        issue_id,
        source_id,
        status: citation.status,
        invalid_reason: citation.reason,
        case_date,
        article_id: source
            .as_ref()
            .map(|source| source.article_id.clone())
            .unwrap_or_default(),
        document_id: source
            .as_ref()
            .map(|source| source.document_id.clone())
            .unwrap_or_default(),
        version_id: source
            .as_ref()
            .map(|source| source.version_id.clone())
            .unwrap_or_default(),
        document_title: source
            .as_ref()
            .map(|source| source.document_title.clone())
            .unwrap_or_default(),
        version_label: source
            .as_ref()
            .map(|source| source.version_label.clone())
            .unwrap_or_default(),
        article_number: source
            .as_ref()
            .map(|source| source.article_number.clone())
            .unwrap_or_default(),
        article_title: source
            .as_ref()
            .and_then(|source| source.article_title.clone()),
        canonical_label: source
            .as_ref()
            .map(|source| source.canonical_label.clone())
            .unwrap_or_default(),
        effective_from: source
            .as_ref()
            .map(|source| source.effective_from.clone())
            .unwrap_or_default(),
        effective_to: source
            .as_ref()
            .and_then(|source| source.effective_to.clone()),
        version_status: source
            .as_ref()
            .map(|source| source.version_status.clone())
            .unwrap_or_default(),
        excerpt,
        note: note.trim().to_owned(),
        created_at: String::new(),
    }
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_source_id(value: &str) -> String {
    let trimmed = value.trim();

    trimmed
        .strip_prefix("[SRC:")
        .and_then(|value| value.strip_suffix(']'))
        .map(str::trim)
        .unwrap_or(trimmed)
        .to_owned()
}

fn legal_basis_id(
    project_id: &str,
    issue_id: Option<&str>,
    source_id: &str,
    case_date: Option<&str>,
) -> String {
    let key = format!(
        "{}\n{}\n{}\n{}",
        project_id,
        issue_id.unwrap_or(""),
        source_id,
        case_date.unwrap_or("")
    );

    format!("basis-{:016x}", fnv1a64(key.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }

    hash
}

fn source_excerpt(source: &LegalSource) -> String {
    let text = if source.snippet.trim().is_empty() {
        source.content.as_str()
    } else {
        source.snippet.as_str()
    };

    truncate_chars(text, 600)
}

fn truncate_chars(value: &str, limit: usize) -> String {
    let mut output = value.chars().take(limit).collect::<String>();
    if value.chars().count() > limit {
        output.push_str("...");
    }

    output
}

fn to_string<T>(value: T) -> Result<String, serde_json::Error>
where
    T: Serialize,
{
    let value = serde_json::to_value(value)?;

    Ok(value
        .as_str()
        .expect("enum serializes as a string")
        .to_owned())
}

fn from_string<T>(value: String) -> Result<T, serde_json::Error>
where
    T: DeserializeOwned,
{
    serde_json::from_value(serde_json::Value::String(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::case::{CaseProjectStatus, ConfirmationStatus, LegalIssueStatus, PartyRole};
    use domain::qa::{CitationInvalidReason, CitationStatus};

    #[test]
    fn project_roundtrip_preserves_enum_contracts() {
        let project = CaseProject {
            project_id: "project-1".to_owned(),
            title: "Contract dispute".to_owned(),
            case_type: "civil".to_owned(),
            status: CaseProjectStatus::Active,
            opened_on: Some("2026-01-01".to_owned()),
            summary: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        };

        let row = project_to_row(&project).expect("project maps to row");
        assert_eq!(row.status, "active");

        let restored = project_from_row(row).expect("row maps to project");
        assert_eq!(restored.status, CaseProjectStatus::Active);
    }

    #[test]
    fn entity_rows_preserve_confirmation_statuses() {
        let fact = CaseFact {
            fact_id: "fact-1".to_owned(),
            project_id: "project-1".to_owned(),
            occurred_on: None,
            title: "Payment due".to_owned(),
            description: String::new(),
            source: String::new(),
            confirmation_status: ConfirmationStatus::ModelSuggested,
        };
        let issue = LegalIssue {
            issue_id: "issue-1".to_owned(),
            project_id: "project-1".to_owned(),
            title: "Breach".to_owned(),
            description: String::new(),
            claim: String::new(),
            status: LegalIssueStatus::Open,
            confirmation_status: ConfirmationStatus::Confirmed,
        };
        let party = CaseParty {
            party_id: "party-1".to_owned(),
            project_id: "project-1".to_owned(),
            name: "Acme Ltd.".to_owned(),
            normalized_name: "acmeltd".to_owned(),
            role: PartyRole::Plaintiff,
            contact: String::new(),
            notes: String::new(),
        };

        assert_eq!(
            fact_to_row(&fact).expect("fact maps").confirmation_status,
            "model_suggested"
        );
        assert_eq!(issue_to_row(&issue).expect("issue maps").status, "open");
        assert_eq!(party_to_row(&party).expect("party maps").role, "plaintiff");
    }

    #[test]
    fn legal_basis_rows_preserve_citation_status_and_reason() {
        let basis = LegalBasis {
            basis_id: "basis-1".to_owned(),
            project_id: "project-1".to_owned(),
            issue_id: Some("issue-1".to_owned()),
            source_id: "law:missing:version:art:1".to_owned(),
            status: CitationStatus::Invalid,
            invalid_reason: Some(CitationInvalidReason::DateOutOfRange),
            case_date: Some("2024-01-01".to_owned()),
            article_id: String::new(),
            document_id: String::new(),
            version_id: String::new(),
            document_title: String::new(),
            version_label: String::new(),
            article_number: String::new(),
            article_title: None,
            canonical_label: String::new(),
            effective_from: String::new(),
            effective_to: None,
            version_status: String::new(),
            excerpt: String::new(),
            note: String::new(),
            created_at: String::new(),
        };

        let row = basis_to_row(&basis).expect("basis maps to row");

        assert_eq!(row.status, "invalid");
        assert_eq!(row.invalid_reason.as_deref(), Some("date_out_of_range"));
    }

    #[test]
    fn parse_command_returns_failure_instead_of_throwing() {
        let response = parse_structured_case_extraction(ParseStructuredCaseExtractionRequest {
            raw_output: "{\"parties\":[]}".to_owned(),
            repaired_output: None,
        });

        assert!(response.result.error.is_some());
        assert_eq!(response.result.raw_output, "{\"parties\":[]}");
    }
}
