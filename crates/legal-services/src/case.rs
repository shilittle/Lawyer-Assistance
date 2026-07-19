use crate::{
    audit::{
        hash_serializable, sha256_hex, validate_idempotency_key, validate_sha256,
        CaseMaterialAuditDetail, CompletedAuditDetails,
    },
    filesystem::PathIdentityGuard,
    open_validated_legal_database, open_validated_user_database_read_only,
    open_validated_user_database_write, require_schema_version, validate_identifier, validate_text,
    LegalServices, ServiceError, ServiceOrigin, SERVICE_SCHEMA_VERSION,
};
use assistant::{CaseChangeSpec, ValidationContext};
use domain::{
    case::{
        analyze_case_gaps, CaseFact, CaseFile, CaseGap, CaseParty, CaseProject, CaseProjectStatus,
        CaseUncertainty, CaseWorkspace, EvidenceItem, EvidenceLink, FactIssueLink, LegalBasis,
        LegalIssue, UncertaintyStatus,
    },
    qa::{CitationInvalidReason, CitationStatus, LegalSource},
};
use rusqlite::{params, TransactionBehavior};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

const DEFAULT_CASE_PAGE_SIZE: u32 = 50;
const MAX_CASE_PAGE_SIZE: u32 = 100;
const MAX_CANONICAL_PROPOSAL_BYTES: usize = assistant::MAX_CASE_CHANGE_TEXT_BYTES + 64 * 1024;
const PROPOSAL_SNAPSHOT_REF_PREFIX: &str = "urn:lawyer-assistance:proposal-snapshot:v1:";
const MAX_MATERIAL_IMPORTS: usize = assistant::MAX_ATTACHMENT_TRANSFERS;
const MAX_MATERIAL_PATH_BYTES: usize = 4096;
const MAX_PROJECT_TITLE_BYTES: usize = 256;
const MAX_PROJECT_CASE_TYPE_BYTES: usize = 64;
const MAX_PROJECT_SUMMARY_BYTES: usize = 16 * 1024;

/// Optimistic-concurrency sentinel used only to review creation of a project
/// that is confirmed absent from the initialized user database.
pub const ABSENT_CASE_REVISION: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseGetStateRequest {
    pub schema_version: u16,
    pub project_id: String,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseCollectionCounts {
    pub files: usize,
    pub parties: usize,
    pub facts: usize,
    pub evidence: usize,
    pub evidence_links: usize,
    pub fact_issue_links: usize,
    pub legal_issues: usize,
    pub legal_basis: usize,
    pub uncertainties: usize,
    pub gaps: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseWorkspacePage {
    pub project: CaseProject,
    pub files: Vec<CaseFile>,
    pub parties: Vec<CaseParty>,
    pub facts: Vec<CaseFact>,
    pub evidence: Vec<EvidenceItem>,
    pub evidence_links: Vec<EvidenceLink>,
    pub fact_issue_links: Vec<FactIssueLink>,
    pub legal_issues: Vec<LegalIssue>,
    pub legal_basis: Vec<LegalBasis>,
    pub uncertainties: Vec<CaseUncertainty>,
    pub gaps: Vec<CaseGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseGetStateResponse {
    pub schema_version: u16,
    pub revision: String,
    pub page: u32,
    pub page_size: u32,
    pub has_more: bool,
    pub counts: CaseCollectionCounts,
    pub workspace: CaseWorkspacePage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseAnalyzeGapsRequest {
    pub schema_version: u16,
    pub project_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseAnalyzeGapsResponse {
    pub schema_version: u16,
    pub revision: String,
    pub gaps: Vec<CaseGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalCaseProposal {
    pub schema_version: u16,
    pub project_id: String,
    pub base_revision: String,
    pub changes: CaseChangeSpec,
    pub source_refs: Vec<String>,
    #[serde(default)]
    pub project_bootstrap: Option<CaseProjectBootstrap>,
    #[serde(default)]
    pub material_imports: Vec<SealedCaseMaterialImport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseProjectBootstrap {
    pub title: String,
    pub case_type: String,
    pub opened_on: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseMaterialImportRequest {
    pub material_id: String,
    pub path: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedCaseMaterialImport {
    pub material_id: String,
    pub attachment_id: String,
    pub root_id: String,
    pub relative_path: String,
    pub original_name: String,
    pub title: String,
    pub format: String,
    pub detected_mime: String,
    pub size_bytes: u64,
    pub content_sha256: String,
    pub extracted_text_sha256: String,
    pub segments_sha256: String,
    pub page_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseProposePatchRequest {
    pub schema_version: u16,
    pub project_id: String,
    pub base_revision: String,
    pub changes: CaseChangeSpec,
    #[serde(default)]
    pub project_bootstrap: Option<CaseProjectBootstrap>,
    #[serde(default)]
    pub material_imports: Vec<CaseMaterialImportRequest>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseProposePatchResponse {
    pub schema_version: u16,
    pub proposal_id: String,
    pub canonical_proposal: String,
    pub proposal_hash: String,
    pub base_revision: String,
    pub confidence: f64,
    pub uncertainties: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseApplyPatchRequest {
    pub schema_version: u16,
    pub project_id: String,
    pub canonical_proposal: String,
    pub proposal_hash: String,
    pub expected_revision: String,
    pub confirmed: bool,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseApplyPatchResponse {
    pub schema_version: u16,
    pub audit_id: String,
    pub proposal_hash: String,
    pub previous_revision: String,
    pub revision: String,
    pub applied: bool,
    pub replayed: bool,
}

#[derive(Debug, Clone)]
struct ValidatedLegalBasisSource {
    source: LegalSource,
    status: CitationStatus,
    invalid_reason: Option<CitationInvalidReason>,
    public_locator: String,
}

struct ValidatedCaseChanges {
    legal_sources: BTreeMap<String, ValidatedLegalBasisSource>,
    snapshot_refs: Vec<String>,
}

#[derive(Clone, Copy)]
struct CaseChangeValidationMode<'a> {
    allow_empty: bool,
    reviewed_source_refs: Option<&'a [String]>,
}

struct PreparedCaseMaterialImport {
    seal: SealedCaseMaterialImport,
    bytes: Vec<u8>,
    extracted_text: String,
    segments_json: String,
}

/// Snapshot refs are sealed, service-generated members of
/// `CanonicalCaseProposal::source_refs`. Adapters that separately display or
/// authorize user-facing sources may filter them with this helper, but must
/// preserve the complete vector when reconstructing the canonical proposal.
pub fn is_case_proposal_snapshot_ref(value: &str) -> bool {
    value.starts_with(PROPOSAL_SNAPSHOT_REF_PREFIX)
}

fn validate_case_user_identifier(field: &'static str, value: &str) -> Result<(), ServiceError> {
    validate_identifier(field, value)?;
    if is_case_proposal_snapshot_ref(value) {
        return Err(ServiceError::invalid(
            field,
            "identifier uses a service-reserved namespace",
        ));
    }
    Ok(())
}

impl LegalServices {
    pub fn case_get_state(
        &self,
        request: CaseGetStateRequest,
    ) -> Result<CaseGetStateResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("projectId", &request.project_id)?;
        let page = request.page.unwrap_or(0);
        let page_size = request.page_size.unwrap_or(DEFAULT_CASE_PAGE_SIZE);
        if page_size == 0 || page_size > MAX_CASE_PAGE_SIZE {
            return Err(ServiceError::invalid(
                "pageSize",
                "pageSize must be between 1 and 100",
            ));
        }
        let connection = open_validated_user_database_read_only(self.user_database_path())?;
        let (rows, revision) =
            database::get_case_workspace_rows_with_digest(&connection, &request.project_id)?
                .ok_or_else(|| ServiceError::not_found("case_project"))?;
        let workspace = workspace_from_rows(rows)?;
        let counts = workspace_counts(&workspace);
        let max_count = [
            counts.files,
            counts.parties,
            counts.facts,
            counts.evidence,
            counts.evidence_links,
            counts.fact_issue_links,
            counts.legal_issues,
            counts.legal_basis,
            counts.uncertainties,
            counts.gaps,
        ]
        .into_iter()
        .max()
        .unwrap_or(0);
        let offset = usize::try_from(page)
            .ok()
            .and_then(|page| page.checked_mul(page_size as usize))
            .ok_or_else(|| ServiceError::invalid("page", "page offset is too large"))?;
        let workspace = paginate_workspace(workspace, offset, page_size as usize);
        Ok(CaseGetStateResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            revision,
            page,
            page_size,
            has_more: offset.saturating_add(page_size as usize) < max_count,
            counts,
            workspace,
        })
    }

    pub fn case_analyze_gaps(
        &self,
        request: CaseAnalyzeGapsRequest,
    ) -> Result<CaseAnalyzeGapsResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_identifier("projectId", &request.project_id)?;
        let connection = open_validated_user_database_read_only(self.user_database_path())?;
        let (rows, revision) =
            database::get_case_workspace_rows_with_digest(&connection, &request.project_id)?
                .ok_or_else(|| ServiceError::not_found("case_project"))?;
        Ok(CaseAnalyzeGapsResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            revision,
            gaps: workspace_from_rows(rows)?.gaps,
        })
    }
}

pub(crate) fn load_full_workspace(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> Result<(CaseWorkspace, String), ServiceError> {
    let (rows, digest) = database::get_case_workspace_rows_with_digest(connection, project_id)?
        .ok_or_else(|| ServiceError::not_found("case_project"))?;
    Ok((workspace_from_rows(rows)?, digest))
}

fn workspace_counts(workspace: &CaseWorkspace) -> CaseCollectionCounts {
    CaseCollectionCounts {
        files: workspace.files.len(),
        parties: workspace.parties.len(),
        facts: workspace.facts.len(),
        evidence: workspace.evidence.len(),
        evidence_links: workspace.evidence_links.len(),
        fact_issue_links: workspace.fact_issue_links.len(),
        legal_issues: workspace.legal_issues.len(),
        legal_basis: workspace.legal_basis.len(),
        uncertainties: workspace.uncertainties.len(),
        gaps: workspace.gaps.len(),
    }
}

fn page_slice<T: Clone>(items: &[T], offset: usize, limit: usize) -> Vec<T> {
    items.iter().skip(offset).take(limit).cloned().collect()
}

fn paginate_workspace(workspace: CaseWorkspace, offset: usize, limit: usize) -> CaseWorkspacePage {
    CaseWorkspacePage {
        project: workspace.project,
        files: page_slice(&workspace.files, offset, limit),
        parties: page_slice(&workspace.parties, offset, limit),
        facts: page_slice(&workspace.facts, offset, limit),
        evidence: page_slice(&workspace.evidence, offset, limit),
        evidence_links: page_slice(&workspace.evidence_links, offset, limit),
        fact_issue_links: page_slice(&workspace.fact_issue_links, offset, limit),
        legal_issues: page_slice(&workspace.legal_issues, offset, limit),
        legal_basis: page_slice(&workspace.legal_basis, offset, limit),
        uncertainties: page_slice(&workspace.uncertainties, offset, limit),
        gaps: page_slice(&workspace.gaps, offset, limit),
    }
}

fn workspace_from_rows(rows: database::CaseWorkspaceRows) -> Result<CaseWorkspace, ServiceError> {
    let project = CaseProject {
        project_id: rows.project.project_id,
        title: rows.project.title,
        case_type: rows.project.case_type,
        status: storage_enum(&rows.project.status)?,
        opened_on: rows.project.opened_on,
        summary: rows.project.summary,
        created_at: rows.project.created_at,
        updated_at: rows.project.updated_at,
    };
    let files = rows
        .files
        .into_iter()
        .map(|row| CaseFile {
            file_id: row.file_id,
            project_id: row.project_id,
            title: row.title,
            file_type: row.file_type,
            storage_reference: row.storage_reference,
            summary: row.summary,
            created_at: row.created_at,
        })
        .collect();
    let parties = rows
        .parties
        .into_iter()
        .map(|row| {
            Ok(CaseParty {
                party_id: row.party_id,
                project_id: row.project_id,
                name: row.name,
                normalized_name: row.normalized_name,
                role: storage_enum(&row.role)?,
                contact: row.contact,
                notes: row.notes,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    let facts = rows
        .facts
        .into_iter()
        .map(|row| {
            Ok(CaseFact {
                fact_id: row.fact_id,
                project_id: row.project_id,
                occurred_on: row.occurred_on,
                title: row.title,
                description: row.description,
                source: row.source,
                confirmation_status: storage_enum(&row.confirmation_status)?,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    let evidence = rows
        .evidence
        .into_iter()
        .map(|row| {
            Ok(EvidenceItem {
                evidence_id: row.evidence_id,
                project_id: row.project_id,
                evidence_number: row.evidence_number,
                title: row.title,
                source: row.source,
                formed_on: row.formed_on,
                summary: row.summary,
                storage_reference: row.storage_reference,
                confirmation_status: storage_enum(&row.confirmation_status)?,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    let evidence_links = rows
        .evidence_links
        .into_iter()
        .map(|row| EvidenceLink {
            link_id: row.link_id,
            project_id: row.project_id,
            fact_id: row.fact_id,
            evidence_id: row.evidence_id,
        })
        .collect::<Vec<_>>();
    let fact_issue_links = rows
        .fact_issue_links
        .into_iter()
        .map(|row| FactIssueLink {
            link_id: row.link_id,
            project_id: row.project_id,
            fact_id: row.fact_id,
            issue_id: row.issue_id,
        })
        .collect();
    let legal_issues = rows
        .legal_issues
        .into_iter()
        .map(|row| {
            Ok(LegalIssue {
                issue_id: row.issue_id,
                project_id: row.project_id,
                title: row.title,
                description: row.description,
                claim: row.claim,
                status: storage_enum(&row.status)?,
                confirmation_status: storage_enum(&row.confirmation_status)?,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    let legal_basis = rows
        .legal_basis
        .into_iter()
        .map(|row| {
            Ok(LegalBasis {
                basis_id: row.basis_id,
                project_id: row.project_id,
                issue_id: row.issue_id,
                source_id: row.source_id,
                status: storage_enum(&row.status)?,
                invalid_reason: row
                    .invalid_reason
                    .as_deref()
                    .map(storage_enum)
                    .transpose()?,
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
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    let uncertainties = rows
        .uncertainties
        .into_iter()
        .map(|row| {
            Ok(CaseUncertainty {
                uncertainty_id: row.uncertainty_id,
                project_id: row.project_id,
                description: row.description,
                related_entity_type: storage_enum(&row.related_entity_type)?,
                related_entity_id: row.related_entity_id,
                source_file_ids: serde_json::from_str(&row.source_file_ids_json)?,
                status: storage_enum(&row.status)?,
                resolution: row.resolution,
                confirmation_status: storage_enum(&row.confirmation_status)?,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
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
        fact_issue_links,
        legal_issues,
        legal_basis,
        uncertainties,
        gaps,
    })
}

fn storage_enum<T: DeserializeOwned>(value: &str) -> Result<T, ServiceError> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(|_| {
        ServiceError::new(
            "user_database_incompatible",
            "case row contains an unsupported enum value",
            false,
        )
    })
}

fn validate_project_bootstrap(bootstrap: &CaseProjectBootstrap) -> Result<(), ServiceError> {
    validate_text(
        "projectBootstrap.title",
        &bootstrap.title,
        MAX_PROJECT_TITLE_BYTES,
        false,
    )?;
    validate_text(
        "projectBootstrap.caseType",
        &bootstrap.case_type,
        MAX_PROJECT_CASE_TYPE_BYTES,
        false,
    )?;
    if bootstrap.summary.len() > MAX_PROJECT_SUMMARY_BYTES
        || bootstrap
            .summary
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ServiceError::invalid(
            "projectBootstrap.summary",
            "project summary exceeds its byte limit or contains disallowed controls",
        ));
    }
    if bootstrap
        .opened_on
        .as_deref()
        .is_some_and(|date| !domain::date::is_iso_calendar_date(date))
    {
        return Err(ServiceError::invalid(
            "projectBootstrap.openedOn",
            "openedOn must be a valid YYYY-MM-DD calendar date",
        ));
    }
    Ok(())
}

fn bootstrap_workspace(project_id: &str, bootstrap: &CaseProjectBootstrap) -> CaseWorkspace {
    CaseWorkspace {
        project: CaseProject {
            project_id: project_id.to_owned(),
            title: bootstrap.title.clone(),
            case_type: bootstrap.case_type.clone(),
            status: CaseProjectStatus::Active,
            opened_on: bootstrap.opened_on.clone(),
            summary: bootstrap.summary.clone(),
            created_at: String::new(),
            updated_at: String::new(),
        },
        files: Vec::new(),
        parties: Vec::new(),
        facts: Vec::new(),
        evidence: Vec::new(),
        evidence_links: Vec::new(),
        fact_issue_links: Vec::new(),
        legal_issues: Vec::new(),
        legal_basis: Vec::new(),
        uncertainties: Vec::new(),
        gaps: Vec::new(),
    }
}

fn validate_material_import_requests(
    materials: &[CaseMaterialImportRequest],
) -> Result<(), ServiceError> {
    if materials.len() > MAX_MATERIAL_IMPORTS {
        return Err(ServiceError::invalid(
            "materialImports",
            "at most two source materials may be imported by one proposal",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for material in materials {
        validate_case_user_identifier("materialId", &material.material_id)?;
        validate_text("materialTitle", &material.title, 256, false)?;
        if material.path.is_empty()
            || material.path.len() > MAX_MATERIAL_PATH_BYTES
            || material.path.chars().any(char::is_control)
        {
            return Err(ServiceError::invalid(
                "materialPath",
                "material path must be non-empty and within its byte limit",
            ));
        }
        if !ids.insert(material.material_id.clone()) || !paths.insert(material.path.clone()) {
            return Err(ServiceError::new(
                "material_import_conflict",
                "material identifiers and paths must be unique within a proposal",
                false,
            ));
        }
    }
    Ok(())
}

fn validate_sealed_material_imports(
    materials: &[SealedCaseMaterialImport],
) -> Result<(), ServiceError> {
    if materials.len() > MAX_MATERIAL_IMPORTS {
        return Err(ServiceError::new(
            "invalid_proposal",
            "canonical proposal contains too many source materials",
            false,
        ));
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut hashes = BTreeSet::new();
    for material in materials {
        validate_case_user_identifier("materialId", &material.material_id)?;
        validate_identifier("attachmentId", &material.attachment_id)?;
        validate_sha256("materialRootId", &material.root_id)?;
        validate_sha256("materialContentSha256", &material.content_sha256)?;
        validate_sha256(
            "materialExtractedTextSha256",
            &material.extracted_text_sha256,
        )?;
        validate_sha256("materialSegmentsSha256", &material.segments_sha256)?;
        validate_text("materialTitle", &material.title, 256, false)?;
        validate_material_relative_path(&material.relative_path)?;
        if material.original_name.is_empty()
            || material.original_name.len() > file_ingest::MAX_FILE_NAME_BYTES
            || material.format.is_empty()
            || material.detected_mime.is_empty()
            || material.size_bytes > file_ingest::MAX_FILE_BYTES as u64
            || material.attachment_id != format!("attachment:sha256:{}", material.content_sha256)
        {
            return Err(ServiceError::new(
                "invalid_proposal",
                "canonical material seal is invalid",
                false,
            ));
        }
        if !ids.insert(material.material_id.clone())
            || !paths.insert((material.root_id.clone(), material.relative_path.clone()))
            || !hashes.insert(material.content_sha256.clone())
        {
            return Err(ServiceError::new(
                "invalid_proposal",
                "canonical material seals must be unique",
                false,
            ));
        }
    }
    Ok(())
}

fn prepare_requested_materials(
    services: &LegalServices,
    materials: &[CaseMaterialImportRequest],
) -> Result<Vec<PreparedCaseMaterialImport>, ServiceError> {
    let mut prepared = Vec::with_capacity(materials.len());
    for material in materials {
        let resolved = read_requested_material(services, &material.path)?;
        prepared.push(prepare_material(
            &material.material_id,
            &material.title,
            resolved,
        )?);
    }
    ensure_prepared_materials_unique(&prepared)?;
    Ok(prepared)
}

fn prepare_sealed_materials(
    services: &LegalServices,
    materials: &[SealedCaseMaterialImport],
) -> Result<Vec<PreparedCaseMaterialImport>, ServiceError> {
    let mut prepared = Vec::with_capacity(materials.len());
    for sealed in materials {
        let resolved = read_sealed_material(services, &sealed.root_id, &sealed.relative_path)?;
        let current = prepare_material(&sealed.material_id, &sealed.title, resolved)?;
        if current.seal != *sealed {
            return Err(ServiceError::new(
                "material_snapshot_drift",
                "source material changed after proposal review",
                false,
            ));
        }
        prepared.push(current);
    }
    ensure_prepared_materials_unique(&prepared)?;
    Ok(prepared)
}

struct ResolvedCaseMaterial {
    root_id: String,
    relative_path: String,
    original_name: String,
    bytes: Vec<u8>,
}

fn read_requested_material(
    services: &LegalServices,
    input: &str,
) -> Result<ResolvedCaseMaterial, ServiceError> {
    let input_path = PathBuf::from(input);
    if !input_path.is_absolute() {
        return Err(material_path_rejected());
    }
    let direct_metadata =
        fs::symlink_metadata(&input_path).map_err(|_| material_path_rejected())?;
    if direct_metadata.file_type().is_symlink() || !direct_metadata.is_file() {
        return Err(material_path_rejected());
    }
    let canonical_target = fs::canonicalize(&input_path).map_err(|_| material_path_rejected())?;
    let root = services
        .config()
        .allowed_file_roots
        .iter()
        .filter(|root| canonical_target.starts_with(root))
        .max_by_key(|root| root.components().count())
        .ok_or_else(material_path_rejected)?;
    let relative = canonical_target
        .strip_prefix(root)
        .map_err(|_| material_path_rejected())?;
    let normalized = normalize_material_relative_path(relative)?;
    read_material_beneath_root(root, &normalized, None)
}

fn read_sealed_material(
    services: &LegalServices,
    root_id: &str,
    relative_path: &str,
) -> Result<ResolvedCaseMaterial, ServiceError> {
    validate_material_relative_path(relative_path)?;
    for root in &services.config().allowed_file_roots {
        let Ok(guard) = PathIdentityGuard::directory(root) else {
            continue;
        };
        if guard.opaque_identity() == root_id {
            return read_material_beneath_root(root, relative_path, Some(root_id));
        }
    }
    Err(ServiceError::new(
        "material_snapshot_drift",
        "configured material root changed after proposal review",
        false,
    ))
}

fn read_material_beneath_root(
    root: &Path,
    relative_path: &str,
    expected_root_id: Option<&str>,
) -> Result<ResolvedCaseMaterial, ServiceError> {
    validate_material_relative_path(relative_path)?;
    let relative = Path::new(relative_path);
    let root_guard = PathIdentityGuard::directory(root)?;
    let root_id = root_guard.opaque_identity();
    if expected_root_id.is_some_and(|expected| expected != root_id) {
        return Err(ServiceError::new(
            "material_snapshot_drift",
            "configured material root changed after proposal review",
            false,
        ));
    }
    let mut directory_guards = vec![root_guard];
    let mut cursor = root.to_path_buf();
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(material_path_rejected());
        };
        cursor.push(component);
        let metadata = fs::symlink_metadata(&cursor).map_err(|_| material_path_rejected())?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(material_path_rejected());
        }
        #[cfg(unix)]
        let child = directory_guards
            .last()
            .ok_or_else(material_path_rejected)?
            .directory_child(component, cursor.clone())?;
        #[cfg(not(unix))]
        let child = PathIdentityGuard::directory(&cursor)?;
        directory_guards.push(child);
    }
    let file_name = relative.file_name().ok_or_else(material_path_rejected)?;
    cursor.push(file_name);
    let metadata = fs::symlink_metadata(&cursor).map_err(|_| material_path_rejected())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(material_path_rejected());
    }
    #[cfg(unix)]
    let file_guard = directory_guards
        .last()
        .ok_or_else(material_path_rejected)?
        .regular_child(file_name, cursor, true)?;
    #[cfg(not(unix))]
    let file_guard = PathIdentityGuard::regular_file(&cursor, true)?;
    let bytes = file_guard.read_bounded(file_ingest::MAX_FILE_BYTES)?;
    for guard in &directory_guards {
        guard.verify()?;
    }
    file_guard.verify()?;
    let original_name = file_name
        .to_str()
        .ok_or_else(material_path_rejected)?
        .to_owned();
    Ok(ResolvedCaseMaterial {
        root_id,
        relative_path: normalize_material_relative_path(relative)?,
        original_name,
        bytes,
    })
}

fn validate_material_relative_path(relative_path: &str) -> Result<(), ServiceError> {
    if relative_path.is_empty()
        || relative_path.len() > MAX_MATERIAL_PATH_BYTES
        || relative_path.contains('\\')
        || Path::new(relative_path)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(material_path_rejected());
    }
    Ok(())
}

fn normalize_material_relative_path(path: &Path) -> Result<String, ServiceError> {
    let parts = path
        .components()
        .map(|component| match component {
            Component::Normal(value) => value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(material_path_rejected),
            _ => Err(material_path_rejected()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let normalized = parts.join("/");
    validate_material_relative_path(&normalized)?;
    Ok(normalized)
}

fn material_path_rejected() -> ServiceError {
    ServiceError::new(
        "material_path_rejected",
        "source material must be a regular file beneath a configured allowed root",
        false,
    )
}

fn prepare_material(
    material_id: &str,
    title: &str,
    resolved: ResolvedCaseMaterial,
) -> Result<PreparedCaseMaterialImport, ServiceError> {
    let document = file_ingest::ingest_bytes(&resolved.original_name, &resolved.bytes)?;
    let segments_json = serde_json::to_string(
        &document
            .segments
            .iter()
            .map(|segment| {
                serde_json::json!({
                    "locator": segment.locator,
                    "text": segment.text,
                })
            })
            .collect::<Vec<_>>(),
    )?;
    let seal = SealedCaseMaterialImport {
        material_id: material_id.to_owned(),
        attachment_id: format!("attachment:sha256:{}", document.sha256_hex),
        root_id: resolved.root_id,
        relative_path: resolved.relative_path,
        original_name: document.file_name,
        title: title.to_owned(),
        format: document.format.as_str().to_owned(),
        detected_mime: document.mime_type,
        size_bytes: document.size_bytes,
        content_sha256: document.sha256_hex,
        extracted_text_sha256: sha256_hex(document.text.as_bytes()),
        segments_sha256: sha256_hex(segments_json.as_bytes()),
        page_count: document.page_count,
    };
    Ok(PreparedCaseMaterialImport {
        seal,
        bytes: resolved.bytes,
        extracted_text: document.text,
        segments_json,
    })
}

fn ensure_prepared_materials_unique(
    materials: &[PreparedCaseMaterialImport],
) -> Result<(), ServiceError> {
    let mut hashes = BTreeSet::new();
    if materials
        .iter()
        .any(|material| !hashes.insert(material.seal.content_sha256.clone()))
    {
        return Err(ServiceError::new(
            "material_import_conflict",
            "duplicate material content is not allowed in one proposal",
            false,
        ));
    }
    Ok(())
}

fn ensure_materials_absent(
    connection: &rusqlite::Connection,
    materials: &[PreparedCaseMaterialImport],
) -> Result<(), ServiceError> {
    for material in materials {
        if database::get_attachment_by_sha256(connection, &material.seal.content_sha256)?.is_some()
            || database::get_attachment(connection, &material.seal.attachment_id)?.is_some()
        {
            return Err(ServiceError::new(
                "material_import_conflict",
                "source material content is already present in the user database",
                false,
            ));
        }
    }
    Ok(())
}

fn apply_prepared_materials(
    connection: &rusqlite::Connection,
    project_id: &str,
    materials: &[PreparedCaseMaterialImport],
) -> Result<(), ServiceError> {
    for material in materials {
        let size_bytes = i64::try_from(material.seal.size_bytes).map_err(|_| {
            ServiceError::new(
                "material_file_too_large",
                "source material size cannot be represented safely",
                false,
            )
        })?;
        match database::insert_attachment(
            connection,
            &database::NewAttachmentRow {
                attachment_id: material.seal.attachment_id.clone(),
                project_id: Some(project_id.to_owned()),
                original_name: material.seal.original_name.clone(),
                extension: material.seal.format.clone(),
                detected_mime: material.seal.detected_mime.clone(),
                sha256: material.seal.content_sha256.clone(),
                size_bytes,
                content_blob: material.bytes.clone(),
                extraction_status: "succeeded".to_owned(),
                extracted_text: Some(material.extracted_text.clone()),
                segments_json: material.segments_json.clone(),
                error_code: None,
            },
        )? {
            database::AttachmentInsertResult::Inserted(_) => {}
            database::AttachmentInsertResult::Existing(_) => {
                return Err(ServiceError::new(
                    "material_snapshot_drift",
                    "source material was imported concurrently after proposal review",
                    false,
                ));
            }
        }
        if !database::insert_case_file_if_absent(
            connection,
            &database::CaseFileRow {
                file_id: material.seal.material_id.clone(),
                project_id: project_id.to_owned(),
                title: material.seal.title.clone(),
                file_type: material.seal.format.clone(),
                storage_reference: database::attachment_storage_reference(
                    &material.seal.attachment_id,
                ),
                summary: imported_material_public_summary().to_owned(),
                created_at: String::new(),
            },
        )? {
            return Err(ServiceError::new(
                "entity_id_conflict",
                "material identifier was assigned concurrently",
                false,
            ));
        }
    }
    Ok(())
}

impl LegalServices {
    pub fn case_propose_patch(
        &self,
        request: CaseProposePatchRequest,
    ) -> Result<CaseProposePatchResponse, ServiceError> {
        let connection = open_validated_user_database_read_only(self.user_database_path())?;
        self.case_propose_patch_in_transaction(&connection, request)
    }

    /// Validates and canonicalizes a proposal against a caller-owned snapshot.
    /// This hook performs no database writes and opens no user-db connection.
    pub fn case_propose_patch_in_transaction(
        &self,
        connection: &rusqlite::Connection,
        request: CaseProposePatchRequest,
    ) -> Result<CaseProposePatchResponse, ServiceError> {
        self.case_propose_patch_with_allowed_sources_in_transaction(connection, request, &[])
    }

    /// Desktop adapter hook for source identifiers already authorized by its
    /// conversation-scoped attachment and artifact checks. MCP callers use the
    /// stricter `case_propose_patch_in_transaction` entry point.
    pub fn case_propose_patch_with_allowed_sources_in_transaction(
        &self,
        connection: &rusqlite::Connection,
        request: CaseProposePatchRequest,
        allowed_source_refs: &[String],
    ) -> Result<CaseProposePatchResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_case_user_identifier("projectId", &request.project_id)?;
        validate_sha256("baseRevision", &request.base_revision)?;
        validate_material_import_requests(&request.material_imports)?;
        let (workspace, revision) =
            match database::get_case_workspace_rows_with_digest(connection, &request.project_id)? {
                Some((rows, revision)) => {
                    if request.project_bootstrap.is_some() {
                        return Err(ServiceError::new(
                            "project_bootstrap_conflict",
                            "project bootstrap is only valid for an absent project",
                            false,
                        ));
                    }
                    if revision != request.base_revision {
                        return Err(ServiceError::conflict(
                            "case changed after the requested base revision",
                        )
                        .with_details(serde_json::json!({
                            "expectedRevision": request.base_revision,
                            "currentRevision": revision,
                        })));
                    }
                    (workspace_from_rows(rows)?, revision)
                }
                None => {
                    let bootstrap = request
                        .project_bootstrap
                        .as_ref()
                        .ok_or_else(|| ServiceError::not_found("case_project"))?;
                    validate_project_bootstrap(bootstrap)?;
                    if request.base_revision != ABSENT_CASE_REVISION {
                        return Err(ServiceError::new(
                            "project_bootstrap_revision_required",
                            "an absent project must use the documented bootstrap revision",
                            false,
                        ));
                    }
                    (
                        bootstrap_workspace(&request.project_id, bootstrap),
                        ABSENT_CASE_REVISION.to_owned(),
                    )
                }
            };
        let prepared_materials = prepare_requested_materials(self, &request.material_imports)?;
        ensure_materials_absent(connection, &prepared_materials)?;
        let mut proposal_allowed_sources = allowed_source_refs.to_vec();
        proposal_allowed_sources.extend(
            prepared_materials
                .iter()
                .map(|material| material.seal.material_id.clone()),
        );
        let validated = validate_case_changes(
            self,
            connection,
            &workspace,
            &request.project_id,
            &request.changes,
            &proposal_allowed_sources,
            CaseChangeValidationMode {
                allow_empty: request.project_bootstrap.is_some() || !prepared_materials.is_empty(),
                reviewed_source_refs: None,
            },
        )?;
        let material_seals = prepared_materials
            .into_iter()
            .map(|material| material.seal)
            .collect::<Vec<_>>();
        let bootstrap_project_id = request
            .project_bootstrap
            .is_some()
            .then_some(request.project_id.as_str());
        ensure_case_addition_ids_unused(
            connection,
            &request.changes,
            material_seals
                .iter()
                .map(|material| material.material_id.as_str())
                .chain(bootstrap_project_id),
        )?;
        let source_refs = canonical_proposal_source_refs(
            &request.changes,
            &material_seals,
            validated.snapshot_refs,
        )?;
        let proposal = CanonicalCaseProposal {
            schema_version: SERVICE_SCHEMA_VERSION,
            project_id: request.project_id,
            base_revision: revision.clone(),
            changes: request.changes,
            source_refs,
            project_bootstrap: request.project_bootstrap,
            material_imports: material_seals,
        };
        let canonical_proposal = serde_json::to_string(&proposal)?;
        if canonical_proposal.len() > MAX_CANONICAL_PROPOSAL_BYTES {
            return Err(ServiceError::invalid(
                "changes",
                "canonical proposal exceeds its byte limit",
            ));
        }
        let proposal_hash = sha256_hex(canonical_proposal.as_bytes());
        let mut uncertainties = workspace
            .uncertainties
            .iter()
            .filter(|item| item.status == UncertaintyStatus::Open)
            .map(|item| item.description.clone())
            .take(32)
            .collect::<Vec<_>>();
        uncertainties.push(
            "proposal validation is structural and source-bounded; legal merits require professional review"
                .to_owned(),
        );
        let confidence =
            (0.85_f64 - (uncertainties.len().saturating_sub(1) as f64 * 0.03)).clamp(0.35, 0.85);
        Ok(CaseProposePatchResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            proposal_id: format!("proposal:{}", &proposal_hash[..32]),
            canonical_proposal,
            proposal_hash,
            base_revision: revision,
            confidence,
            uncertainties,
        })
    }

    pub fn case_apply_patch(
        &self,
        request: CaseApplyPatchRequest,
    ) -> Result<CaseApplyPatchResponse, ServiceError> {
        let mut connection = open_validated_user_database_write(self.user_database_path())?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let response =
            self.case_apply_patch_in_transaction(&transaction, request, self.audit_origin)?;
        transaction.commit()?;
        Ok(response)
    }

    /// Applies a fully reviewed patch inside a caller-owned write transaction.
    ///
    /// The caller must open an IMMEDIATE transaction and commit only after any
    /// legacy proposal state has been atomically updated. This hook performs no
    /// BEGIN or COMMIT itself and is therefore safe for the desktop adapter's
    /// existing pending-proposal CAS flow.
    pub fn case_apply_patch_in_transaction(
        &self,
        connection: &rusqlite::Connection,
        request: CaseApplyPatchRequest,
        origin: ServiceOrigin,
    ) -> Result<CaseApplyPatchResponse, ServiceError> {
        self.case_apply_patch_with_allowed_sources_in_transaction(connection, request, origin, &[])
    }

    /// Desktop adapter hook matching the conversation-scoped proposal entry
    /// point above. Authorization of these source ids remains the caller's
    /// responsibility; all structural, revision, hash, audit, and write checks
    /// still run in this shared service.
    pub fn case_apply_patch_with_allowed_sources_in_transaction(
        &self,
        connection: &rusqlite::Connection,
        request: CaseApplyPatchRequest,
        origin: ServiceOrigin,
        allowed_source_refs: &[String],
    ) -> Result<CaseApplyPatchResponse, ServiceError> {
        require_schema_version(request.schema_version)?;
        validate_case_user_identifier("projectId", &request.project_id)?;
        validate_sha256("proposalHash", &request.proposal_hash)?;
        validate_sha256("expectedRevision", &request.expected_revision)?;
        validate_idempotency_key(&request.idempotency_key)?;
        if !request.confirmed {
            return Err(ServiceError::new(
                "confirmation_required",
                "explicit confirmation is required before applying case changes",
                false,
            ));
        }
        if request.canonical_proposal.len() > MAX_CANONICAL_PROPOSAL_BYTES {
            return Err(ServiceError::invalid(
                "canonicalProposal",
                "canonical proposal exceeds its byte limit",
            ));
        }
        let actual_hash = sha256_hex(request.canonical_proposal.as_bytes());
        if actual_hash != request.proposal_hash {
            return Err(ServiceError::new(
                "proposal_hash_mismatch",
                "proposal hash does not match the exact canonical proposal",
                false,
            ));
        }
        let proposal: CanonicalCaseProposal = serde_json::from_str(&request.canonical_proposal)
            .map_err(|_| {
                ServiceError::new(
                    "invalid_proposal",
                    "canonical proposal cannot be decoded",
                    false,
                )
            })?;
        require_schema_version(proposal.schema_version)?;
        if proposal.project_id != request.project_id
            || proposal.base_revision != request.expected_revision
        {
            return Err(ServiceError::new(
                "proposal_scope_mismatch",
                "proposal project or base revision does not match the apply request",
                false,
            ));
        }
        validate_sealed_material_imports(&proposal.material_imports)?;
        let expected_sources =
            proposal_user_source_refs(&proposal.changes, &proposal.material_imports);
        let proposal_sources = proposal
            .source_refs
            .iter()
            .filter(|value| !is_case_proposal_snapshot_ref(value))
            .cloned()
            .collect::<Vec<_>>();
        if expected_sources != proposal_sources {
            return Err(ServiceError::new(
                "invalid_proposal",
                "proposal source audit is inconsistent",
                false,
            ));
        }

        let request_hash = hash_serializable(&request)?;
        let idempotency_key_hash = sha256_hex(request.idempotency_key.as_bytes());
        if let Some(existing) = database::get_operation_audit_by_idempotency_key_hash(
            connection,
            origin.as_str(),
            "case_apply_patch",
            &idempotency_key_hash,
        )? {
            return replay_case_apply(existing, &request, &request_hash);
        }

        let (workspace, current_revision, creating_project) =
            match database::get_case_workspace_rows_with_digest(connection, &request.project_id)? {
                Some((rows, current_revision)) => {
                    if proposal.project_bootstrap.is_some() {
                        return Err(ServiceError::new(
                            "project_bootstrap_conflict",
                            "project was created after the bootstrap proposal was reviewed",
                            false,
                        ));
                    }
                    if current_revision != request.expected_revision {
                        return Err(ServiceError::conflict(
                            "case changed after the proposal was reviewed",
                        )
                        .with_details(serde_json::json!({
                            "expectedRevision": request.expected_revision,
                            "currentRevision": current_revision,
                        })));
                    }
                    (workspace_from_rows(rows)?, current_revision, false)
                }
                None => {
                    let bootstrap = proposal
                        .project_bootstrap
                        .as_ref()
                        .ok_or_else(|| ServiceError::not_found("case_project"))?;
                    validate_project_bootstrap(bootstrap)?;
                    if request.expected_revision != ABSENT_CASE_REVISION {
                        return Err(ServiceError::new(
                            "project_bootstrap_revision_required",
                            "an absent project must use the documented bootstrap revision",
                            false,
                        ));
                    }
                    (
                        bootstrap_workspace(&request.project_id, bootstrap),
                        ABSENT_CASE_REVISION.to_owned(),
                        true,
                    )
                }
            };
        let prepared_materials = prepare_sealed_materials(self, &proposal.material_imports)?;
        ensure_materials_absent(connection, &prepared_materials)?;
        let mut proposal_allowed_sources = allowed_source_refs.to_vec();
        proposal_allowed_sources.extend(
            proposal
                .material_imports
                .iter()
                .map(|material| material.material_id.clone()),
        );
        let validated = validate_case_changes(
            self,
            connection,
            &workspace,
            &request.project_id,
            &proposal.changes,
            &proposal_allowed_sources,
            CaseChangeValidationMode {
                allow_empty: proposal.project_bootstrap.is_some()
                    || !proposal.material_imports.is_empty(),
                reviewed_source_refs: Some(&proposal.source_refs),
            },
        )?;
        let expected_sealed_sources = canonical_proposal_source_refs(
            &proposal.changes,
            &proposal.material_imports,
            validated.snapshot_refs.clone(),
        )?;
        if expected_sealed_sources != proposal.source_refs {
            return Err(ServiceError::new(
                "proposal_snapshot_drift",
                "legal data or a transferred artifact changed after proposal review",
                false,
            ));
        }
        let bootstrap_project_id = creating_project.then_some(request.project_id.as_str());
        ensure_case_addition_ids_unused(
            connection,
            &proposal.changes,
            proposal
                .material_imports
                .iter()
                .map(|material| material.material_id.as_str())
                .chain(bootstrap_project_id),
        )?;

        if creating_project {
            let bootstrap = proposal.project_bootstrap.as_ref().ok_or_else(|| {
                ServiceError::new(
                    "internal_contract_error",
                    "validated project bootstrap is missing",
                    false,
                )
            })?;
            if !database::insert_case_project_if_absent(
                connection,
                &database::CaseProjectRow {
                    project_id: request.project_id.clone(),
                    title: bootstrap.title.clone(),
                    case_type: bootstrap.case_type.clone(),
                    status: "active".to_owned(),
                    opened_on: bootstrap.opened_on.clone(),
                    summary: bootstrap.summary.clone(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )? {
                return Err(ServiceError::new(
                    "project_bootstrap_conflict",
                    "project could not be created atomically",
                    false,
                ));
            }
        }

        let audit_id = format!("audit:{}", Uuid::new_v4());
        database::create_operation_audit(
            connection,
            &database::NewOperationAuditRow {
                audit_id: audit_id.clone(),
                origin: origin.as_str().to_owned(),
                operation: "case_apply_patch".to_owned(),
                project_id: Some(request.project_id.clone()),
                request_hash,
                idempotency_key_hash: Some(idempotency_key_hash),
                details_json: serde_json::to_string(&serde_json::json!({
                    "schemaVersion": SERVICE_SCHEMA_VERSION,
                    "proposalHash": request.proposal_hash,
                    "baseRevision": current_revision,
                    "projectBootstrap": creating_project,
                    "materialCount": proposal.material_imports.len(),
                }))?,
            },
        )?;
        apply_prepared_materials(connection, &request.project_id, &prepared_materials)?;
        apply_confirmed_case_changes(
            connection,
            &request.proposal_hash,
            &request.project_id,
            &proposal.changes,
            &validated.legal_sources,
        )?;
        let new_revision = database::case_workspace_digest(connection, &request.project_id)?
            .ok_or_else(|| ServiceError::not_found("case_project"))?;
        if new_revision == current_revision {
            return Err(ServiceError::new(
                "case_apply_no_effect",
                "confirmed proposal did not change the case revision",
                false,
            ));
        }
        let details = CompletedAuditDetails::case_apply(
            request.proposal_hash.clone(),
            current_revision.clone(),
            new_revision.clone(),
            proposal
                .material_imports
                .iter()
                .map(|material| CaseMaterialAuditDetail {
                    material_id: material.material_id.clone(),
                    attachment_id: material.attachment_id.clone(),
                    root_id: material.root_id.clone(),
                    relative_path: material.relative_path.clone(),
                    content_sha256: material.content_sha256.clone(),
                    extracted_text_sha256: material.extracted_text_sha256.clone(),
                    segments_sha256: material.segments_sha256.clone(),
                })
                .collect(),
        );
        match database::compare_and_set_operation_audit_status(
            connection,
            &audit_id,
            "succeeded",
            &serde_json::to_string(&details)?,
        )? {
            database::OperationAuditStatusUpdateResult::Updated(_) => {}
            database::OperationAuditStatusUpdateResult::Conflict(_)
            | database::OperationAuditStatusUpdateResult::NotFound => {
                return Err(ServiceError::new(
                    "audit_conflict",
                    "operation audit could not be finalized",
                    false,
                ));
            }
        }
        Ok(CaseApplyPatchResponse {
            schema_version: SERVICE_SCHEMA_VERSION,
            audit_id,
            proposal_hash: request.proposal_hash,
            previous_revision: current_revision,
            revision: new_revision,
            applied: true,
            replayed: false,
        })
    }
}

fn replay_case_apply(
    existing: database::OperationAuditRow,
    request: &CaseApplyPatchRequest,
    request_hash: &str,
) -> Result<CaseApplyPatchResponse, ServiceError> {
    if existing.request_hash != request_hash
        || existing.project_id.as_deref() != Some(request.project_id.as_str())
    {
        return Err(ServiceError::new(
            "idempotency_conflict",
            "idempotency key was already used for a different request",
            false,
        ));
    }
    if existing.status == "prepared" {
        return Err(ServiceError::new(
            "operation_in_progress",
            "an operation with this idempotency key is still in progress",
            true,
        ));
    }
    if existing.status != "succeeded" {
        return Err(ServiceError::new(
            "idempotency_conflict",
            "a previous operation with this idempotency key failed",
            false,
        ));
    }
    let details: CompletedAuditDetails =
        serde_json::from_str(&existing.details_json).map_err(|_| {
            ServiceError::new(
                "user_database_incompatible",
                "completed audit details are invalid",
                false,
            )
        })?;
    Ok(CaseApplyPatchResponse {
        schema_version: SERVICE_SCHEMA_VERSION,
        audit_id: existing.audit_id,
        proposal_hash: details.proposal_hash.ok_or_else(|| {
            ServiceError::new(
                "user_database_incompatible",
                "audit proposal hash is missing",
                false,
            )
        })?,
        previous_revision: details.before_revision.ok_or_else(|| {
            ServiceError::new(
                "user_database_incompatible",
                "audit base revision is missing",
                false,
            )
        })?,
        revision: details.after_revision.ok_or_else(|| {
            ServiceError::new(
                "user_database_incompatible",
                "audit result revision is missing",
                false,
            )
        })?,
        applied: true,
        replayed: true,
    })
}

fn validate_case_changes(
    services: &LegalServices,
    connection: &rusqlite::Connection,
    workspace: &CaseWorkspace,
    project_id: &str,
    changes: &CaseChangeSpec,
    allowed_source_refs: &[String],
    mode: CaseChangeValidationMode<'_>,
) -> Result<ValidatedCaseChanges, ServiceError> {
    let mut context = ValidationContext::default();
    for source_ref in std::iter::once(workspace.project.project_id.as_str())
        .chain(workspace.files.iter().map(|item| item.file_id.as_str()))
        .chain(workspace.parties.iter().map(|item| item.party_id.as_str()))
        .chain(workspace.facts.iter().map(|item| item.fact_id.as_str()))
        .chain(
            workspace
                .evidence
                .iter()
                .map(|item| item.evidence_id.as_str()),
        )
        .chain(
            workspace
                .legal_issues
                .iter()
                .map(|item| item.issue_id.as_str()),
        )
        .chain(
            workspace
                .legal_basis
                .iter()
                .map(|item| item.basis_id.as_str()),
        )
        .chain(
            workspace
                .uncertainties
                .iter()
                .map(|item| item.uncertainty_id.as_str()),
        )
    {
        context.allow_source_ref(source_ref);
    }
    if allowed_source_refs.len() > 4096 {
        return Err(ServiceError::invalid(
            "allowedSourceRefs",
            "authorized source set exceeds its item limit",
        ));
    }
    for source_ref in allowed_source_refs {
        validate_case_user_identifier("allowedSourceRef", source_ref)?;
        context.allow_source_ref(source_ref);
    }
    for source_ref in collect_case_change_source_refs(changes) {
        validate_case_user_identifier("sourceRef", &source_ref)?;
    }
    for entity_id in case_addition_ids(changes) {
        validate_case_user_identifier("entityId", &entity_id)?;
    }
    for fact in &workspace.facts {
        context.allow_case_fact(&fact.fact_id);
    }
    for issue in &workspace.legal_issues {
        context.allow_case_issue(&issue.issue_id);
    }
    ensure_case_transfer_preconditions(connection, project_id, changes, &mut context)?;

    let mut legal_sources: BTreeMap<String, ValidatedLegalBasisSource> = BTreeMap::new();
    let (legal_connection, legal_identity) =
        open_validated_legal_database(services.legal_core_path())?;
    if !changes.legal_basis.is_empty() {
        for basis in &changes.legal_basis {
            if let Some(validated) = legal_sources.get(&basis.source_ref) {
                let public_locator =
                    validated_legal_basis_locator(&validated.source, &basis.citation)?;
                if public_locator != validated.public_locator {
                    return Err(ServiceError::new(
                        "unvalidated_legal_source",
                        "legal basis citations for the same source do not match",
                        false,
                    ));
                }
                continue;
            }
            let source = citations::source_by_citation_id(&legal_connection, &basis.source_ref)?
                .ok_or_else(|| {
                    ServiceError::new(
                        "unvalidated_legal_source",
                        "legal basis is not present in the local legal source set",
                        false,
                    )
                })?;
            let validation = citations::validate_answer_citations(
                &legal_connection,
                &basis.marker,
                std::slice::from_ref(&source),
                None,
                false,
            )?;
            let citation = validation.citations.into_iter().next().ok_or_else(|| {
                ServiceError::new(
                    "unvalidated_legal_source",
                    "legal basis did not produce a validation result",
                    false,
                )
            })?;
            if citation.source_id != basis.source_ref || citation.status != CitationStatus::Valid {
                return Err(ServiceError::new(
                    "unvalidated_legal_source",
                    "legal basis is not a currently effective local source",
                    false,
                ));
            }
            let hydrated = citation.source.ok_or_else(|| {
                ServiceError::new(
                    "unvalidated_legal_source",
                    "validated legal source snapshot is missing",
                    false,
                )
            })?;
            if let Some(reviewed) = mode.reviewed_source_refs {
                let current_snapshot = legal_source_snapshot_ref(
                    &basis.source_ref,
                    &hydrated,
                    citation.status.clone(),
                    citation.reason.clone(),
                )?;
                if !reviewed.contains(&current_snapshot) {
                    return Err(ServiceError::new(
                        "proposal_snapshot_drift",
                        "legal data changed after proposal review",
                        false,
                    ));
                }
            }
            let public_locator = validated_legal_basis_locator(&hydrated, &basis.citation)?;
            context.allow_validated_legal_source(&basis.source_ref);
            legal_sources.insert(
                basis.source_ref.clone(),
                ValidatedLegalBasisSource {
                    source: hydrated,
                    status: citation.status,
                    invalid_reason: citation.reason,
                    public_locator,
                },
            );
        }
    }
    for fact in &changes.facts {
        if fact
            .occurred_on
            .as_deref()
            .is_some_and(|date| !domain::date::is_iso_calendar_date(date))
        {
            return Err(ServiceError::invalid(
                "occurredOn",
                "occurredOn must be a valid YYYY-MM-DD calendar date",
            ));
        }
    }
    if case_changes_are_empty(changes) && mode.allow_empty {
        if changes.schema_version != assistant::CONTRACT_SCHEMA_VERSION {
            return Err(ServiceError::new(
                "invalid_proposal",
                "case proposal uses an unsupported bounded-contract version",
                false,
            ));
        }
    } else {
        changes.validate(&context)?;
    }
    let mut snapshot_refs = vec![proposal_snapshot_ref(
        "legal-dataset",
        &hash_serializable(&legal_identity)?,
    )];
    for (source_ref, validated) in &legal_sources {
        snapshot_refs.push(legal_source_snapshot_ref(
            source_ref,
            &validated.source,
            validated.status.clone(),
            validated.invalid_reason.clone(),
        )?);
    }
    for transfer in &changes.artifact_transfers {
        let artifact = database::get_artifact(connection, &transfer.artifact_id)?
            .ok_or_else(|| ServiceError::not_found("artifact"))?;
        let version = database::get_artifact_version(
            connection,
            &artifact.artifact_id,
            artifact.current_version,
        )?
        .ok_or_else(|| {
            ServiceError::new(
                "user_database_incompatible",
                "artifact current version is missing",
                false,
            )
        })?;
        let digest = hash_serializable(&serde_json::json!({
            "artifactId": artifact.artifact_id,
            "kind": artifact.kind,
            "title": artifact.title,
            "status": artifact.status,
            "currentVersion": artifact.current_version,
            "versionId": version.version_id,
            "contentJson": version.content_json,
            "renderedText": version.rendered_text,
            "sourceRefsJson": version.source_refs_json,
            "citationReportJson": version.citation_report_json,
            "providerSnapshotJson": version.provider_snapshot_json,
        }))?;
        snapshot_refs.push(format!(
            "{PROPOSAL_SNAPSHOT_REF_PREFIX}artifact:{}:{}:{digest}",
            sha256_hex(transfer.artifact_id.as_bytes()),
            artifact.current_version,
        ));
    }
    for transfer in &changes.attachment_transfers {
        let attachment = database::get_attachment(connection, &transfer.attachment_id)?
            .ok_or_else(|| ServiceError::not_found("attachment"))?;
        let digest = attachment_snapshot_digest(&attachment);
        snapshot_refs.push(format!(
            "{PROPOSAL_SNAPSHOT_REF_PREFIX}attachment:{}:{digest}",
            sha256_hex(transfer.attachment_id.as_bytes()),
        ));
    }
    snapshot_refs.sort();
    snapshot_refs.dedup();
    Ok(ValidatedCaseChanges {
        legal_sources,
        snapshot_refs,
    })
}

fn legal_source_snapshot_ref(
    source_ref: &str,
    source: &LegalSource,
    status: CitationStatus,
    invalid_reason: Option<CitationInvalidReason>,
) -> Result<String, ServiceError> {
    let digest = hash_serializable(&serde_json::json!({
        "source": source,
        "status": status,
        "invalidReason": invalid_reason,
    }))?;
    Ok(format!(
        "{PROPOSAL_SNAPSHOT_REF_PREFIX}legal-source:{}:{digest}",
        sha256_hex(source_ref.as_bytes())
    ))
}

fn attachment_snapshot_digest(attachment: &database::AttachmentRow) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"lawyer-assistance-attachment-proposal-snapshot-v1\0");
    update_snapshot_field(&mut hasher, attachment.attachment_id.as_bytes());
    update_snapshot_optional_field(&mut hasher, attachment.project_id.as_deref());
    update_snapshot_field(&mut hasher, attachment.original_name.as_bytes());
    update_snapshot_field(&mut hasher, attachment.extension.as_bytes());
    update_snapshot_field(&mut hasher, attachment.detected_mime.as_bytes());
    update_snapshot_field(&mut hasher, attachment.sha256.as_bytes());
    update_snapshot_field(&mut hasher, &attachment.size_bytes.to_be_bytes());
    update_snapshot_field(&mut hasher, &attachment.content_blob);
    update_snapshot_field(&mut hasher, attachment.extraction_status.as_bytes());
    update_snapshot_optional_field(&mut hasher, attachment.extracted_text.as_deref());
    update_snapshot_field(&mut hasher, attachment.segments_json.as_bytes());
    update_snapshot_optional_field(&mut hasher, attachment.error_code.as_deref());
    update_snapshot_field(&mut hasher, attachment.created_at.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn update_snapshot_optional_field(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => {
            hasher.update([1]);
            update_snapshot_field(hasher, value.as_bytes());
        }
        None => hasher.update([0]),
    }
}

fn update_snapshot_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn proposal_snapshot_ref(kind: &str, digest: &str) -> String {
    format!("{PROPOSAL_SNAPSHOT_REF_PREFIX}{kind}:{digest}")
}

fn canonical_proposal_source_refs(
    changes: &CaseChangeSpec,
    material_imports: &[SealedCaseMaterialImport],
    snapshot_refs: Vec<String>,
) -> Result<Vec<String>, ServiceError> {
    let material_snapshot_refs = material_imports
        .iter()
        .map(|material| {
            Ok(format!(
                "{PROPOSAL_SNAPSHOT_REF_PREFIX}material:{}:{}",
                sha256_hex(material.material_id.as_bytes()),
                hash_serializable(material)?
            ))
        })
        .collect::<Result<Vec<_>, ServiceError>>()?;
    Ok(proposal_user_source_refs(changes, material_imports)
        .into_iter()
        .chain(snapshot_refs)
        .chain(material_snapshot_refs)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn proposal_user_source_refs(
    changes: &CaseChangeSpec,
    material_imports: &[SealedCaseMaterialImport],
) -> Vec<String> {
    collect_case_change_source_refs(changes)
        .into_iter()
        .chain(
            material_imports
                .iter()
                .map(|material| material.material_id.clone()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn collect_case_change_source_refs(changes: &CaseChangeSpec) -> Vec<String> {
    changes
        .facts
        .iter()
        .flat_map(|item| item.source_refs.iter().cloned())
        .chain(
            changes
                .evidence
                .iter()
                .flat_map(|item| item.source_refs.iter().cloned()),
        )
        .chain(
            changes
                .issues
                .iter()
                .flat_map(|item| item.source_refs.iter().cloned()),
        )
        .chain(
            changes
                .legal_basis
                .iter()
                .map(|item| item.source_ref.clone()),
        )
        .chain(
            changes
                .attachment_transfers
                .iter()
                .map(|item| item.attachment_id.clone()),
        )
        .chain(
            changes
                .artifact_transfers
                .iter()
                .map(|item| item.artifact_id.clone()),
        )
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn ensure_case_addition_ids_unused<'a>(
    connection: &rusqlite::Connection,
    changes: &CaseChangeSpec,
    extra_ids: impl IntoIterator<Item = &'a str>,
) -> Result<(), ServiceError> {
    let mut ids = case_addition_ids(changes);
    ids.extend(extra_ids.into_iter().map(str::to_owned));
    let mut proposal_ids = BTreeSet::new();
    for id in ids {
        if !proposal_ids.insert(id.clone()) {
            return Err(ServiceError::new(
                "entity_id_conflict",
                "proposed entity identifiers collide after deterministic expansion",
                false,
            ));
        }
        let exists: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM projects WHERE project_id = ?1
                 UNION ALL SELECT 1 FROM case_files WHERE file_id = ?1
                 UNION ALL SELECT 1 FROM case_parties WHERE party_id = ?1
                 UNION ALL SELECT 1 FROM case_facts WHERE fact_id = ?1
                 UNION ALL SELECT 1 FROM evidence_items WHERE evidence_id = ?1
                 UNION ALL SELECT 1 FROM evidence_links WHERE link_id = ?1
                 UNION ALL SELECT 1 FROM legal_issues WHERE issue_id = ?1
                 UNION ALL SELECT 1 FROM fact_issue_links WHERE link_id = ?1
                 UNION ALL SELECT 1 FROM case_uncertainties WHERE uncertainty_id = ?1
                 UNION ALL SELECT 1 FROM legal_basis WHERE basis_id = ?1
             )",
            [&id],
            |row| row.get(0),
        )?;
        if exists {
            return Err(ServiceError::new(
                "entity_id_conflict",
                "a proposed case entity identifier already exists",
                false,
            ));
        }
    }
    Ok(())
}

fn case_addition_ids(changes: &CaseChangeSpec) -> Vec<String> {
    let mut ids = changes
        .facts
        .iter()
        .map(|item| item.id.clone())
        .chain(changes.evidence.iter().map(|item| item.id.clone()))
        .chain(changes.issues.iter().map(|item| item.id.clone()))
        .collect::<Vec<_>>();
    for basis in &changes.legal_basis {
        ids.extend(
            (0..basis.issue_ids.len().max(1)).map(|index| legal_basis_row_id(&basis.id, index)),
        );
    }
    ids
}

fn case_changes_are_empty(changes: &CaseChangeSpec) -> bool {
    changes.facts.is_empty()
        && changes.evidence.is_empty()
        && changes.issues.is_empty()
        && changes.legal_basis.is_empty()
        && changes.attachment_transfers.is_empty()
        && changes.artifact_transfers.is_empty()
}

fn ensure_case_transfer_preconditions(
    connection: &rusqlite::Connection,
    project_id: &str,
    changes: &CaseChangeSpec,
    context: &mut ValidationContext,
) -> Result<(), ServiceError> {
    for transfer in &changes.attachment_transfers {
        let attachment = database::get_attachment(connection, &transfer.attachment_id)?
            .ok_or_else(|| ServiceError::not_found("attachment"))?;
        match attachment.project_id.as_deref() {
            None => {
                if !database::attachment_can_be_claimed_for_case(
                    connection,
                    &transfer.attachment_id,
                    project_id,
                )? {
                    return Err(ServiceError::new(
                        "transfer_conflict",
                        "attachment cannot be claimed by this case",
                        false,
                    ));
                }
            }
            Some(owner) if owner == project_id => {}
            Some(_) => {
                return Err(ServiceError::new(
                    "transfer_conflict",
                    "attachment belongs to another case",
                    false,
                ));
            }
        }
        let storage_reference = database::attachment_storage_reference(&transfer.attachment_id);
        let legacy_reference = format!("attachment:{storage_reference}");
        let exists: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM case_files
                 WHERE project_id = ?1 AND storage_reference IN (?2, ?3, ?4)
             )",
            params![
                project_id,
                transfer.attachment_id,
                storage_reference,
                legacy_reference
            ],
            |row| row.get(0),
        )?;
        if exists {
            return Err(ServiceError::new(
                "transfer_conflict",
                "attachment was already transferred into the case",
                false,
            ));
        }
        context.allow_attachment(&transfer.attachment_id);
        context.allow_source_ref(&transfer.attachment_id);
    }
    for transfer in &changes.artifact_transfers {
        let artifact = database::get_artifact(connection, &transfer.artifact_id)?
            .ok_or_else(|| ServiceError::not_found("artifact"))?;
        if artifact.status == "archived" || artifact.project_id.is_some() {
            return Err(ServiceError::new(
                "transfer_conflict",
                "artifact is archived or already assigned to a case",
                false,
            ));
        }
        if artifact.title != transfer.title {
            return Err(ServiceError::new(
                "transfer_conflict",
                "artifact title changed after proposal creation",
                false,
            ));
        }
        context.allow_artifact(&transfer.artifact_id);
        context.allow_source_ref(&transfer.artifact_id);
    }
    Ok(())
}

fn apply_confirmed_case_changes(
    connection: &rusqlite::Connection,
    proposal_hash: &str,
    project_id: &str,
    changes: &CaseChangeSpec,
    legal_sources: &BTreeMap<String, ValidatedLegalBasisSource>,
) -> Result<(), ServiceError> {
    let short_hash = &proposal_hash[..16];
    let evidence_numbers =
        allocate_public_evidence_numbers(connection, project_id, changes.evidence.len())?;
    for fact in &changes.facts {
        database::upsert_case_fact(
            connection,
            &database::CaseFactRow {
                fact_id: fact.id.clone(),
                project_id: project_id.to_owned(),
                occurred_on: fact.occurred_on.clone(),
                title: case_fact_title(&fact.statement),
                description: fact.statement.clone(),
                source: public_case_source(&fact.source_refs).to_owned(),
                confirmation_status: "confirmed".to_owned(),
            },
        )?;
    }
    for issue in &changes.issues {
        database::upsert_legal_issue(
            connection,
            &database::LegalIssueRow {
                issue_id: issue.id.clone(),
                project_id: project_id.to_owned(),
                title: issue.title.clone(),
                description: issue.analysis.clone(),
                claim: String::new(),
                status: "open".to_owned(),
                confirmation_status: "confirmed".to_owned(),
            },
        )?;
    }
    for (index, evidence) in changes.evidence.iter().enumerate() {
        database::upsert_evidence_item(
            connection,
            &database::EvidenceItemRow {
                evidence_id: evidence.id.clone(),
                project_id: project_id.to_owned(),
                evidence_number: evidence_numbers[index].clone(),
                title: evidence.title.clone(),
                source: public_case_source(&evidence.source_refs).to_owned(),
                formed_on: None,
                summary: evidence.summary.clone(),
                storage_reference: String::new(),
                confirmation_status: "confirmed".to_owned(),
            },
        )?;
        for (fact_index, fact_id) in evidence.proves_fact_ids.iter().enumerate() {
            database::upsert_evidence_link(
                connection,
                &database::EvidenceLinkRow {
                    link_id: format!("evidence-link:{short_hash}:{index}:{fact_index}"),
                    project_id: project_id.to_owned(),
                    fact_id: fact_id.clone(),
                    evidence_id: evidence.id.clone(),
                },
            )?;
        }
    }
    for (index, issue) in changes.issues.iter().enumerate() {
        for (fact_index, fact_id) in issue.related_fact_ids.iter().enumerate() {
            database::upsert_fact_issue_link(
                connection,
                &database::FactIssueLinkRow {
                    link_id: format!("fact-issue-link:{short_hash}:{index}:{fact_index}"),
                    project_id: project_id.to_owned(),
                    fact_id: fact_id.clone(),
                    issue_id: issue.id.clone(),
                },
            )?;
        }
    }
    for basis in &changes.legal_basis {
        let validated = legal_sources.get(&basis.source_ref).ok_or_else(|| {
            ServiceError::new(
                "unvalidated_legal_source",
                "legal basis source snapshot is missing",
                false,
            )
        })?;
        if basis.issue_ids.is_empty() {
            insert_hydrated_legal_basis(
                connection,
                &legal_basis_row_id(&basis.id, 0),
                project_id,
                None,
                validated,
                &basis.proposition,
            )?;
        } else {
            for (index, issue_id) in basis.issue_ids.iter().enumerate() {
                insert_hydrated_legal_basis(
                    connection,
                    &legal_basis_row_id(&basis.id, index),
                    project_id,
                    Some(issue_id),
                    validated,
                    &basis.proposition,
                )?;
            }
        }
    }
    for (index, transfer) in changes.attachment_transfers.iter().enumerate() {
        let attachment = database::get_attachment(connection, &transfer.attachment_id)?
            .ok_or_else(|| ServiceError::not_found("attachment"))?;
        if attachment.project_id.is_none()
            && !database::claim_attachment_for_case(
                connection,
                &transfer.attachment_id,
                project_id,
            )?
        {
            return Err(ServiceError::new(
                "transfer_conflict",
                "attachment could not be claimed atomically",
                false,
            ));
        }
        let storage_reference = database::attachment_storage_reference(&transfer.attachment_id);
        database::upsert_case_file(
            connection,
            &database::CaseFileRow {
                file_id: format!("case-file:{short_hash}:{index}"),
                project_id: project_id.to_owned(),
                title: transfer.title.clone(),
                file_type: attachment.extension.clone(),
                storage_reference,
                summary: transferred_material_public_summary().to_owned(),
                created_at: String::new(),
            },
        )?;
    }
    for transfer in &changes.artifact_transfers {
        if !database::bind_artifact_to_case(connection, &transfer.artifact_id, project_id)? {
            return Err(ServiceError::new(
                "transfer_conflict",
                "artifact could not be transferred atomically",
                false,
            ));
        }
    }
    Ok(())
}

fn legal_basis_row_id(base_id: &str, issue_index: usize) -> String {
    if issue_index == 0 {
        base_id.to_owned()
    } else {
        format!("{base_id}:issue:{issue_index}")
    }
}

fn insert_hydrated_legal_basis(
    connection: &rusqlite::Connection,
    basis_id: &str,
    project_id: &str,
    issue_id: Option<&str>,
    validated: &ValidatedLegalBasisSource,
    proposition: &str,
) -> Result<(), ServiceError> {
    let source = &validated.source;
    let canonical_label = format!(
        "《{}》{}",
        source.document_title.trim(),
        validated.public_locator
    );
    database::upsert_legal_basis(
        connection,
        &database::LegalBasisRow {
            basis_id: basis_id.to_owned(),
            project_id: project_id.to_owned(),
            issue_id: issue_id.map(str::to_owned),
            source_id: source.source_id.clone(),
            status: storage_enum_string(&validated.status)?,
            invalid_reason: validated
                .invalid_reason
                .as_ref()
                .map(storage_enum_string)
                .transpose()?,
            case_date: None,
            article_id: source.article_id.clone(),
            document_id: source.document_id.clone(),
            version_id: source.version_id.clone(),
            document_title: source.document_title.clone(),
            version_label: source.version_label.clone(),
            article_number: validated.public_locator.clone(),
            article_title: source.article_title.clone(),
            canonical_label,
            effective_from: source.effective_from.clone(),
            effective_to: source.effective_to.clone(),
            version_status: source.version_status.clone(),
            excerpt: source.snippet.clone(),
            note: proposition.to_owned(),
            created_at: String::new(),
        },
    )?;
    Ok(())
}

fn validated_legal_basis_locator(
    source: &LegalSource,
    citation: &str,
) -> Result<String, ServiceError> {
    let parts = assistant::parse_public_citation(citation).ok_or_else(|| {
        ServiceError::new(
            "unvalidated_legal_source",
            "legal basis citation is not a complete public citation",
            false,
        )
    })?;
    if parts.kind != assistant::PublicCitationKind::Law
        || parts.title.trim() != source.document_title.trim()
        || source.effective_from.get(..4) != Some(parts.year)
    {
        return Err(ServiceError::new(
            "unvalidated_legal_source",
            "legal basis citation does not match the validated local source",
            false,
        ));
    }

    let expected = authoritative_public_law_locator(source).ok_or_else(|| {
        ServiceError::new(
            "unvalidated_legal_source",
            "legal basis source does not support an exact paragraph citation",
            false,
        )
    })?;
    if parts.locator != expected {
        return Err(ServiceError::new(
            "unvalidated_legal_source",
            "legal basis paragraph citation does not match the validated local source",
            false,
        ));
    }
    Ok(expected)
}

pub(crate) fn authoritative_public_law_locator(source: &LegalSource) -> Option<String> {
    let article_number = source.article_number.trim();
    let article_end = article_number.find('条')? + '条'.len_utf8();
    let article = article_number.get(..article_end)?;
    if !article.starts_with('第') || article.chars().count() < 3 {
        return None;
    }
    let paragraph = explicit_paragraph_label(article_number.get(article_end..).unwrap_or_default())
        .or_else(|| explicit_paragraph_label(&source.canonical_label))
        .or_else(|| verified_single_full_paragraph(&source.content).then_some("第一款"))?;
    Some(format!("{article}{paragraph}"))
}

fn explicit_paragraph_label(value: &str) -> Option<&str> {
    let paragraph_end = value.find('款')? + '款'.len_utf8();
    let before = value.get(..paragraph_end)?;
    let paragraph_start = before.rfind('第')?;
    let label = before.get(paragraph_start..paragraph_end)?;
    (label.chars().count() >= 3).then_some(label)
}

fn verified_single_full_paragraph(content: &str) -> bool {
    let content = content.trim();
    if content.is_empty()
        || !content.ends_with('。')
        || content.contains('\u{fffd}')
        || ["…", "...", "省略", "节选", "截断", "未完", "（略）", "[略]"]
            .iter()
            .any(|marker| content.contains(marker))
    {
        return false;
    }
    content
        .split(['\n', '\u{2028}', '\u{2029}'])
        .filter(|paragraph| !paragraph.trim().is_empty())
        .take(2)
        .count()
        == 1
}

fn storage_enum_string<T: Serialize>(value: &T) -> Result<String, ServiceError> {
    serde_json::to_value(value)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| {
            ServiceError::new(
                "internal_contract_error",
                "domain enum did not serialize to a string",
                false,
            )
        })
}

fn public_case_source(source_refs: &[String]) -> &'static str {
    if source_refs.is_empty() {
        "人工确认"
    } else {
        "经确认的案件信息"
    }
}

fn imported_material_public_summary() -> &'static str {
    "已导入案件材料，材料内容已完成提取。"
}

fn transferred_material_public_summary() -> &'static str {
    "经确认纳入本案的材料。"
}

fn allocate_public_evidence_numbers(
    connection: &rusqlite::Connection,
    project_id: &str,
    count: usize,
) -> Result<Vec<String>, ServiceError> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut statement = connection.prepare(
        "SELECT evidence_number FROM evidence_items WHERE project_id = ?1 ORDER BY evidence_id",
    )?;
    let existing = statement.query_map([project_id], |row| row.get::<_, String>(0))?;
    let mut used = BTreeSet::new();
    for value in existing {
        let value = value?;
        if let Ok(number) = value.parse::<usize>() {
            if number > 0 {
                used.insert(number);
            }
        }
    }

    let mut result = Vec::with_capacity(count);
    let mut candidate = 1_usize;
    while result.len() < count {
        if used.insert(candidate) {
            result.push(candidate.to_string());
        }
        candidate = candidate.checked_add(1).ok_or_else(|| {
            ServiceError::new(
                "evidence_number_exhausted",
                "no public evidence number is available",
                false,
            )
        })?;
    }
    Ok(result)
}

fn case_fact_title(statement: &str) -> String {
    statement
        .trim()
        .lines()
        .next()
        .unwrap_or(statement.trim())
        .chars()
        .take(120)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legal_source(content: &str) -> LegalSource {
        LegalSource {
            source_id: "law:civil-code:577".to_owned(),
            article_id: "article-577".to_owned(),
            document_id: "civil-code".to_owned(),
            version_id: "civil-code-2021".to_owned(),
            document_title: "中华人民共和国民法典".to_owned(),
            version_label: "2021年施行版本".to_owned(),
            article_number: "第五百七十七条".to_owned(),
            article_title: None,
            canonical_label: "《中华人民共和国民法典》第五百七十七条".to_owned(),
            content: content.to_owned(),
            snippet: content.to_owned(),
            effective_from: "2021-01-01".to_owned(),
            effective_to: None,
            version_status: "in_force".to_owned(),
        }
    }

    #[test]
    fn complete_single_paragraph_source_is_persisted_at_first_paragraph() {
        let source = legal_source("当事人一方不履行合同义务的，应当承担违约责任。");
        assert_eq!(
            validated_legal_basis_locator(
                &source,
                "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）",
            )
            .unwrap(),
            "第五百七十七条第一款"
        );
    }

    #[test]
    fn multi_paragraph_source_cannot_be_assigned_an_invented_paragraph() {
        let source = legal_source("第一款内容。\n第二款内容。");
        let error = validated_legal_basis_locator(
            &source,
            "《中华人民共和国民法典》第五百七十七条第一款（2021年起施行）",
        )
        .unwrap_err();
        assert_eq!(error.code, "unvalidated_legal_source");
    }

    #[test]
    fn proposal_citation_must_match_the_validated_title_locator_and_year() {
        let source = legal_source("当事人一方不履行合同义务的，应当承担违约责任。");
        for citation in [
            "《中华人民共和国民法典》第五百七十七条第二款（2021年起施行）",
            "《中华人民共和国民法典》第五百七十七条第一款（2022年起施行）",
            "《中华人民共和国合同法》第五百七十七条第一款（2021年起施行）",
        ] {
            assert!(validated_legal_basis_locator(&source, citation).is_err());
        }
    }
}
