use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt::{self, Display},
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};

pub const LEGAL_CORE_DB_FILE_NAME: &str = "legal_core.sqlite";
pub const USER_DB_FILE_NAME: &str = "user.sqlite";
pub const USER_SCHEMA_VERSION: i64 = 8;
const USER_CANONICAL_SCHEMA_MARKER_KEY: &str = "canonical_schema_version";
// This marker describes the exact canonical shape within schema version 8.
// Keep it independent from USER_SCHEMA_VERSION so constraint-only repairs can
// be applied once without pretending that an unverified v6 database is sound.
const USER_CANONICAL_SCHEMA_MARKER_VALUE: &str = "v8-fact-issue-links-20260716";
const PENDING_EXTRACTION_REVIEW_RETENTION_SQL: &str = "+7 days";
const CASE_MATERIAL_DIGEST_DOMAIN: &[u8] = b"lawyer-assistance-case-materials-v1\0";
const LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX: &str = "migration-unassigned-legal-answers";
const LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE: &str = "迁移隔离：旧版未归属问答记录";
const LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY: &str =
    "这些问答记录来自旧版数据库，旧版未保存案件归属，不能推断其真实案件。可在此查看恢复；删除本隔离项目会级联彻底清除全部记录。";
pub const LEGAL_CORE_SCHEMA_SQL: &str = include_str!("../../../data/schema/legal_core.sql");

#[derive(Debug)]
pub enum DatabaseInitError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    InvalidUserSchemaVersion(String),
    UnsupportedUserSchemaVersion { found: i64, supported: i64 },
}

impl Display for DatabaseInitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "database filesystem error: {error}"),
            Self::Sqlite(error) => write!(formatter, "sqlite initialization error: {error}"),
            Self::InvalidUserSchemaVersion(value) => {
                write!(formatter, "invalid user database schema version: {value}")
            }
            Self::UnsupportedUserSchemaVersion { found, supported } => write!(
                formatter,
                "user database schema version {found} is newer than supported version {supported}"
            ),
        }
    }
}

impl Error for DatabaseInitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Sqlite(error) => Some(error),
            Self::InvalidUserSchemaVersion(_) | Self::UnsupportedUserSchemaVersion { .. } => None,
        }
    }
}

impl From<std::io::Error> for DatabaseInitError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for DatabaseInitError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

pub fn user_database_path(app_local_data_dir: impl AsRef<Path>) -> PathBuf {
    app_local_data_dir.as_ref().join(USER_DB_FILE_NAME)
}

pub fn ensure_user_database(
    app_local_data_dir: impl AsRef<Path>,
) -> Result<PathBuf, DatabaseInitError> {
    let database_path = user_database_path(app_local_data_dir);

    if let Some(parent) = database_path.parent() {
        fs::create_dir_all(parent)?;
    }

    validate_and_migrate_user_database(&database_path)?;

    Ok(database_path)
}

/// Migrates a user database copy and proves that its final schema and
/// referential integrity match the canonical contract. Restore staging uses
/// this before it can mark a file as pending for the next process start.
pub fn validate_and_migrate_user_database(
    user_database_path: impl AsRef<Path>,
) -> Result<(), DatabaseInitError> {
    let mut connection = open_user_database(user_database_path)?;
    let claims_current_canonical_schema = existing_user_schema_version(&connection)?
        == Some(USER_SCHEMA_VERSION)
        && user_database_metadata_value(&connection, USER_CANONICAL_SCHEMA_MARKER_KEY)?.as_deref()
            == Some(USER_CANONICAL_SCHEMA_MARKER_VALUE);
    if claims_current_canonical_schema {
        // A file that claims the exact current schema must already contain that
        // schema. Do not silently bless a damaged or fabricated current backup
        // by creating whichever tables it omitted.
        validate_canonical_user_table_shapes(&connection)?;
    }
    run_user_migrations(&mut connection)?;
    cleanup_expired_pending_extraction_reviews(&connection)?;
    validate_canonical_user_database(&connection)?;
    Ok(())
}

/// Validates an already migrated database without changing a byte. Restore
/// recovery uses this after hashing a staged copy so the marker remains valid
/// even if the process stops between the atomic swap and marker cleanup.
pub fn validate_user_database_read_only(
    user_database_path: impl AsRef<Path>,
) -> Result<(), DatabaseInitError> {
    let connection = rusqlite::Connection::open_with_flags(
        user_database_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    validate_canonical_user_database(&connection)
}

pub fn open_user_database(
    user_database_path: impl AsRef<Path>,
) -> Result<rusqlite::Connection, DatabaseInitError> {
    let connection = rusqlite::Connection::open(user_database_path)?;

    // User commands open short-lived connections and Tauri may execute more
    // than one write command at a time. SQLite otherwise fails immediately on
    // a transient writer lock. A bounded wait is sufficient for this small,
    // local workload and avoids changing the persistent journal mode (and its
    // backup/sidecar-file lifecycle) merely to serialize short writes.
    connection.busy_timeout(Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;

    Ok(connection)
}

pub fn open_legal_core_read_only(
    legal_core_path: impl AsRef<Path>,
) -> Result<rusqlite::Connection, DatabaseInitError> {
    let connection = rusqlite::Connection::open_with_flags(
        legal_core_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;

    configure_legal_core_connection(&connection)?;

    Ok(connection)
}

pub fn initialize_legal_core_database(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    connection.execute_batch(LEGAL_CORE_SCHEMA_SQL)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderProfileRow {
    pub id: String,
    pub kind: String,
    pub display_name: String,
    pub model_id: String,
    pub base_url: String,
    pub credential_account_id: String,
    pub capabilities_json: String,
    pub options_json: String,
}

pub fn list_provider_profiles(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<Vec<ProviderProfileRow>> {
    let mut statement = connection.prepare(
        "
        SELECT
            id,
            kind,
            display_name,
            model_id,
            base_url,
            credential_account_id,
            capabilities_json,
            options_json
        FROM provider_profiles
        ORDER BY updated_at DESC, display_name ASC
        ",
    )?;

    let profiles = statement
        .query_map([], provider_profile_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(profiles)
}

pub fn get_provider_profile(
    connection: &rusqlite::Connection,
    id: &str,
) -> rusqlite::Result<Option<ProviderProfileRow>> {
    let mut statement = connection.prepare(
        "
        SELECT
            id,
            kind,
            display_name,
            model_id,
            base_url,
            credential_account_id,
            capabilities_json,
            options_json
        FROM provider_profiles
        WHERE id = ?1
        ",
    )?;

    let mut rows = statement.query([id])?;

    if let Some(row) = rows.next()? {
        Ok(Some(provider_profile_from_row(row)?))
    } else {
        Ok(None)
    }
}

pub fn upsert_provider_profile(
    connection: &rusqlite::Connection,
    profile: &ProviderProfileRow,
) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO provider_profiles (
            id,
            kind,
            display_name,
            model_id,
            base_url,
            credential_account_id,
            capabilities_json,
            options_json
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        ON CONFLICT(id) DO UPDATE SET
            kind = excluded.kind,
            display_name = excluded.display_name,
            model_id = excluded.model_id,
            base_url = excluded.base_url,
            credential_account_id = excluded.credential_account_id,
            capabilities_json = excluded.capabilities_json,
            options_json = excluded.options_json,
            updated_at = CURRENT_TIMESTAMP
        ",
        (
            &profile.id,
            &profile.kind,
            &profile.display_name,
            &profile.model_id,
            &profile.base_url,
            &profile.credential_account_id,
            &profile.capabilities_json,
            &profile.options_json,
        ),
    )?;

    Ok(())
}

pub fn delete_provider_profile(
    connection: &rusqlite::Connection,
    id: &str,
) -> rusqlite::Result<bool> {
    let affected_rows = connection.execute("DELETE FROM provider_profiles WHERE id = ?1", [id])?;

    Ok(affected_rows > 0)
}

fn provider_profile_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProviderProfileRow> {
    Ok(ProviderProfileRow {
        id: row.get(0)?,
        kind: row.get(1)?,
        display_name: row.get(2)?,
        model_id: row.get(3)?,
        base_url: row.get(4)?,
        credential_account_id: row.get(5)?,
        capabilities_json: row.get(6)?,
        options_json: row.get(7)?,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseProjectRow {
    pub project_id: String,
    pub title: String,
    pub case_type: String,
    pub status: String,
    pub opened_on: Option<String>,
    pub summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseFileRow {
    pub file_id: String,
    pub project_id: String,
    pub title: String,
    pub file_type: String,
    pub storage_reference: String,
    pub summary: String,
    pub created_at: String,
}

/// Hashes exactly the ordered material fields included in the extraction
/// prompt. Length-prefixing every field makes the encoding unambiguous even
/// when user text contains separators or NUL-like boundary patterns.
pub fn case_materials_digest_from_rows(
    files: &[CaseFileRow],
    source_file_ids: &[String],
) -> Option<String> {
    let files_by_id = files
        .iter()
        .map(|file| (file.file_id.as_str(), file))
        .collect::<std::collections::HashMap<_, _>>();
    let selected = source_file_ids
        .iter()
        .map(|file_id| files_by_id.get(file_id.as_str()).copied())
        .collect::<Option<Vec<_>>>()?;
    Some(case_materials_digest(&selected))
}

fn case_materials_digest(files: &[&CaseFileRow]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CASE_MATERIAL_DIGEST_DOMAIN);
    hasher.update((files.len() as u64).to_be_bytes());
    for file in files {
        for value in [
            file.file_id.as_str(),
            file.title.as_str(),
            file.file_type.as_str(),
            file.summary.as_str(),
        ] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value.as_bytes());
        }
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn current_case_materials_digest(
    connection: &rusqlite::Connection,
    project_id: &str,
    source_file_ids: &[String],
) -> rusqlite::Result<Option<String>> {
    let mut selected = Vec::with_capacity(source_file_ids.len());
    for file_id in source_file_ids {
        let file = connection
            .query_row(
                "SELECT file_id, project_id, title, file_type, storage_reference, summary, created_at
                 FROM case_files WHERE project_id = ?1 AND file_id = ?2",
                params![project_id, file_id],
                case_file_from_row,
            )
            .optional()?;
        let Some(file) = file else {
            return Ok(None);
        };
        selected.push(file);
    }
    let references = selected.iter().collect::<Vec<_>>();
    Ok(Some(case_materials_digest(&references)))
}

fn validate_provider_audit_snapshot_json(snapshot_json: &str) -> rusqlite::Result<()> {
    let value = serde_json::from_str::<serde_json::Value>(snapshot_json)
        .map_err(|_| invalid_provider_audit_snapshot())?;
    let Some(snapshot) = value.as_object() else {
        return Err(invalid_provider_audit_snapshot());
    };
    if !has_exact_json_keys(
        snapshot,
        &["kind", "modelId", "baseUrl", "capabilities", "options"],
    ) || !bounded_single_line_json_string(snapshot.get("kind"), 64)
        || !snapshot
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| {
                matches!(
                    kind,
                    "silicon_flow" | "volcengine_ark" | "deep_seek" | "qwen" | "custom"
                )
            })
        || !bounded_single_line_json_string(snapshot.get("modelId"), 512)
        || !bounded_single_line_json_string(snapshot.get("baseUrl"), 2_048)
    {
        return Err(invalid_provider_audit_snapshot());
    }

    let Some(capabilities) = snapshot
        .get("capabilities")
        .and_then(serde_json::Value::as_object)
    else {
        return Err(invalid_provider_audit_snapshot());
    };
    let capability_keys = [
        "chat",
        "streaming",
        "customModelId",
        "customBaseUrl",
        "reasoning",
    ];
    if !has_exact_json_keys(capabilities, &capability_keys)
        || capability_keys.iter().any(|key| {
            !capabilities
                .get(*key)
                .is_some_and(serde_json::Value::is_boolean)
        })
    {
        return Err(invalid_provider_audit_snapshot());
    }

    let Some(options) = snapshot
        .get("options")
        .and_then(serde_json::Value::as_object)
    else {
        return Err(invalid_provider_audit_snapshot());
    };
    if !has_exact_json_keys(
        options,
        &[
            "thinking",
            "enableThinking",
            "thinkingBudget",
            "reasoningEffort",
            "endpointId",
            "workspaceId",
            "allowPrivateNetwork",
        ],
    ) || !optional_json_bool(options.get("thinking"))
        || !optional_json_bool(options.get("enableThinking"))
        || !optional_json_u32(options.get("thinkingBudget"))
        || !optional_reasoning_effort(options.get("reasoningEffort"))
        || !optional_bounded_json_string(options.get("endpointId"), 512)
        || !optional_bounded_json_string(options.get("workspaceId"), 512)
        || !optional_json_bool(options.get("allowPrivateNetwork"))
    {
        return Err(invalid_provider_audit_snapshot());
    }

    Ok(())
}

fn has_exact_json_keys(object: &serde_json::Map<String, serde_json::Value>, keys: &[&str]) -> bool {
    object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
}

fn bounded_single_line_json_string(value: Option<&serde_json::Value>, max_bytes: usize) -> bool {
    value
        .and_then(serde_json::Value::as_str)
        .is_some_and(|text| {
            !text.is_empty() && text.len() <= max_bytes && !text.chars().any(char::is_control)
        })
}

fn optional_bounded_json_string(value: Option<&serde_json::Value>, max_bytes: usize) -> bool {
    value.is_some_and(|value| {
        value.is_null() || bounded_single_line_json_string(Some(value), max_bytes)
    })
}

fn optional_json_bool(value: Option<&serde_json::Value>) -> bool {
    value.is_some_and(|value| value.is_null() || value.is_boolean())
}

fn optional_json_u32(value: Option<&serde_json::Value>) -> bool {
    value.is_some_and(|value| {
        value.is_null()
            || value
                .as_u64()
                .is_some_and(|number| u32::try_from(number).is_ok())
    })
}

fn optional_reasoning_effort(value: Option<&serde_json::Value>) -> bool {
    value.is_some_and(|value| {
        value.is_null()
            || value
                .as_str()
                .is_some_and(|effort| matches!(effort, "low" | "medium" | "high" | "max"))
    })
}

fn invalid_provider_audit_snapshot() -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "provider audit snapshot does not match the fixed no-credential schema",
    )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasePartyRow {
    pub party_id: String,
    pub project_id: String,
    pub name: String,
    pub normalized_name: String,
    pub role: String,
    pub contact: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseFactRow {
    pub fact_id: String,
    pub project_id: String,
    pub occurred_on: Option<String>,
    pub title: String,
    pub description: String,
    pub source: String,
    pub confirmation_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceItemRow {
    pub evidence_id: String,
    pub project_id: String,
    pub evidence_number: String,
    pub title: String,
    pub source: String,
    pub formed_on: Option<String>,
    pub summary: String,
    pub storage_reference: String,
    pub confirmation_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceLinkRow {
    pub link_id: String,
    pub project_id: String,
    pub fact_id: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactIssueLinkRow {
    pub link_id: String,
    pub project_id: String,
    pub fact_id: String,
    pub issue_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegalIssueRow {
    pub issue_id: String,
    pub project_id: String,
    pub title: String,
    pub description: String,
    pub claim: String,
    pub status: String,
    pub confirmation_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseUncertaintyRow {
    pub uncertainty_id: String,
    pub project_id: String,
    pub description: String,
    pub related_entity_type: String,
    pub related_entity_id: Option<String>,
    pub source_file_ids_json: String,
    pub status: String,
    pub resolution: String,
    pub confirmation_status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegalBasisRow {
    pub basis_id: String,
    pub project_id: String,
    pub issue_id: Option<String>,
    pub source_id: String,
    pub status: String,
    pub invalid_reason: Option<String>,
    pub case_date: Option<String>,
    pub article_id: String,
    pub document_id: String,
    pub version_id: String,
    pub document_title: String,
    pub version_label: String,
    pub article_number: String,
    pub article_title: Option<String>,
    pub canonical_label: String,
    pub effective_from: String,
    pub effective_to: Option<String>,
    pub version_status: String,
    pub excerpt: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseWorkspaceRows {
    pub project: CaseProjectRow,
    pub files: Vec<CaseFileRow>,
    pub parties: Vec<CasePartyRow>,
    pub facts: Vec<CaseFactRow>,
    pub evidence: Vec<EvidenceItemRow>,
    pub evidence_links: Vec<EvidenceLinkRow>,
    pub fact_issue_links: Vec<FactIssueLinkRow>,
    pub legal_issues: Vec<LegalIssueRow>,
    pub legal_basis: Vec<LegalBasisRow>,
    pub uncertainties: Vec<CaseUncertaintyRow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfirmedCaseExtractionRows {
    pub review_id: String,
    pub project_id: String,
    pub provider_id: String,
    pub source_file_ids: Vec<String>,
    /// Optimistic-concurrency revision of the exact pending payload being
    /// confirmed. Confirmation consumes only this revision.
    pub expected_revision: i64,
    /// Canonical JSON serialized from the exact typed extraction the user is
    /// confirming. The confirmation transaction compares it with the latest
    /// autosaved pending payload so a stale window cannot replay an older edit.
    pub reviewed_extraction_json: String,
    pub parties: Vec<CasePartyRow>,
    pub facts: Vec<CaseFactRow>,
    pub evidence: Vec<EvidenceItemRow>,
    pub evidence_links: Vec<EvidenceLinkRow>,
    pub legal_issues: Vec<LegalIssueRow>,
    pub uncertainties: Vec<CaseUncertaintyRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingExtractionReviewRow {
    pub review_id: String,
    pub project_id: String,
    pub provider_id: String,
    pub provider_snapshot_json: String,
    pub source_file_ids_json: String,
    /// SHA-256 over the exact ordered material fields sent to the provider.
    /// An empty value is reserved for migrated legacy drafts, which cannot be
    /// confirmed because their original prompt snapshot is unknowable.
    pub source_materials_digest: String,
    pub extraction_json: String,
    pub revision: i64,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingExtractionReviewUpdate {
    pub revision: i64,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingExtractionReviewUpdateResult {
    Updated(PendingExtractionReviewUpdate),
    Conflict,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegalAnswerRecordRow {
    pub record_id: String,
    pub project_id: Option<String>,
    pub provider_id: String,
    pub provider_snapshot_json: String,
    pub question: String,
    pub answer_text: String,
    pub case_date: Option<String>,
    pub query_json: String,
    pub source_ids_json: String,
    pub verified_citations_json: String,
    pub invalid_citations_json: String,
    pub unsupported_legal_conclusion: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentGenerationRecordRow {
    pub record_id: String,
    pub project_id: String,
    pub template_id: String,
    pub template_version: String,
    pub source_ids_json: String,
    pub citation_ids_json: String,
    pub export_path: String,
    pub exported_at: String,
}

pub fn insert_document_generation_record(
    connection: &rusqlite::Connection,
    row: &DocumentGenerationRecordRow,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO document_generation_records
         (record_id, project_id, template_id, template_version, source_ids_json,
          citation_ids_json, export_path, exported_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            row.record_id,
            row.project_id,
            row.template_id,
            row.template_version,
            row.source_ids_json,
            row.citation_ids_json,
            row.export_path,
            row.exported_at
        ],
    )?;
    Ok(())
}

pub fn list_document_generation_records(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<DocumentGenerationRecordRow>> {
    let mut statement = connection.prepare(
        "SELECT record_id, project_id, template_id, template_version, source_ids_json,
                citation_ids_json, export_path, exported_at
         FROM document_generation_records WHERE project_id = ?1
         ORDER BY exported_at DESC, record_id DESC",
    )?;
    let rows = statement
        .query_map([project_id], |row| {
            Ok(DocumentGenerationRecordRow {
                record_id: row.get(0)?,
                project_id: row.get(1)?,
                template_id: row.get(2)?,
                template_version: row.get(3)?,
                source_ids_json: row.get(4)?,
                citation_ids_json: row.get(5)?,
                export_path: row.get(6)?,
                exported_at: row.get(7)?,
            })
        })?
        .collect();
    rows
}

pub fn list_case_projects(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<Vec<CaseProjectRow>> {
    let mut statement = connection.prepare(
        "
        SELECT project_id, title, case_type, status, opened_on, summary, created_at, updated_at
        FROM projects
        ORDER BY updated_at DESC, title ASC
        ",
    )?;
    let rows = statement
        .query_map([], case_project_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

pub fn case_project_exists(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM projects WHERE project_id = ?1)",
        [project_id],
        |row| row.get(0),
    )
}

pub fn get_case_workspace_rows(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Option<CaseWorkspaceRows>> {
    // Every component must come from one SQLite read snapshot. Without an
    // explicit transaction a concurrent confirmation/delete can commit
    // between the project SELECT and any child SELECT, producing a workspace
    // assembled from different points in time.
    let transaction = connection.unchecked_transaction()?;
    let project = transaction
        .query_row(
            "
            SELECT project_id, title, case_type, status, opened_on, summary, created_at, updated_at
            FROM projects
            WHERE project_id = ?1
            ",
            [project_id],
            case_project_from_row,
        )
        .optional()?;

    let workspace = project
        .map(|project| {
            Ok::<_, rusqlite::Error>(CaseWorkspaceRows {
                project,
                files: list_case_files(&transaction, project_id)?,
                parties: list_case_parties(&transaction, project_id)?,
                facts: list_case_facts(&transaction, project_id)?,
                evidence: list_evidence_items(&transaction, project_id)?,
                evidence_links: list_evidence_links(&transaction, project_id)?,
                fact_issue_links: list_fact_issue_links(&transaction, project_id)?,
                legal_issues: list_legal_issues(&transaction, project_id)?,
                legal_basis: list_legal_basis(&transaction, project_id)?,
                uncertainties: list_case_uncertainties(&transaction, project_id)?,
            })
        })
        .transpose()?;
    transaction.commit()?;
    Ok(workspace)
}

pub fn upsert_case_project(
    connection: &rusqlite::Connection,
    project: &CaseProjectRow,
) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO projects (project_id, title, case_type, status, opened_on, summary)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(project_id) DO UPDATE SET
            title = excluded.title,
            case_type = excluded.case_type,
            status = excluded.status,
            opened_on = excluded.opened_on,
            summary = excluded.summary,
            updated_at = CURRENT_TIMESTAMP
        ",
        params![
            project.project_id,
            project.title,
            project.case_type,
            project.status,
            project.opened_on,
            project.summary
        ],
    )?;

    Ok(())
}

pub fn delete_case_project(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<bool> {
    let affected_rows =
        connection.execute("DELETE FROM projects WHERE project_id = ?1", [project_id])?;

    Ok(affected_rows > 0)
}

pub fn upsert_case_file(
    connection: &rusqlite::Connection,
    file: &CaseFileRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO case_files (file_id, project_id, title, file_type, storage_reference, summary)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        ON CONFLICT(file_id) DO UPDATE SET
            title = excluded.title,
            file_type = excluded.file_type,
            storage_reference = excluded.storage_reference,
            summary = excluded.summary
        WHERE case_files.project_id = excluded.project_id
        ",
        params![
            file.file_id,
            file.project_id,
            file.title,
            file.file_type,
            file.storage_reference,
            file.summary
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "case file id is already assigned to another project",
    )
}

pub fn upsert_case_party(
    connection: &rusqlite::Connection,
    party: &CasePartyRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO case_parties (party_id, project_id, name, normalized_name, role, contact, notes)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(party_id) DO UPDATE SET
            name = excluded.name,
            normalized_name = excluded.normalized_name,
            role = excluded.role,
            contact = excluded.contact,
            notes = excluded.notes
        WHERE case_parties.project_id = excluded.project_id
        ",
        params![
            party.party_id,
            party.project_id,
            party.name,
            party.normalized_name,
            party.role,
            party.contact,
            party.notes
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "case party id is already assigned to another project",
    )
}

pub fn upsert_case_fact(
    connection: &rusqlite::Connection,
    fact: &CaseFactRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO case_facts (
            fact_id, project_id, occurred_on, title, description, source, confirmation_status
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(fact_id) DO UPDATE SET
            occurred_on = excluded.occurred_on,
            title = excluded.title,
            description = excluded.description,
            source = excluded.source,
            confirmation_status = excluded.confirmation_status
        WHERE case_facts.project_id = excluded.project_id
        ",
        params![
            fact.fact_id,
            fact.project_id,
            fact.occurred_on,
            fact.title,
            fact.description,
            fact.source,
            fact.confirmation_status
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "case fact id is already assigned to another project",
    )
}

pub fn upsert_evidence_item(
    connection: &rusqlite::Connection,
    evidence: &EvidenceItemRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO evidence_items (
            evidence_id, project_id, evidence_number, title, source, formed_on, summary,
            storage_reference, confirmation_status
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(evidence_id) DO UPDATE SET
            evidence_number = excluded.evidence_number,
            title = excluded.title,
            source = excluded.source,
            formed_on = excluded.formed_on,
            summary = excluded.summary,
            storage_reference = excluded.storage_reference,
            confirmation_status = excluded.confirmation_status
        WHERE evidence_items.project_id = excluded.project_id
        ",
        params![
            evidence.evidence_id,
            evidence.project_id,
            evidence.evidence_number,
            evidence.title,
            evidence.source,
            evidence.formed_on,
            evidence.summary,
            evidence.storage_reference,
            evidence.confirmation_status
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "evidence item id is already assigned to another project",
    )
}

pub fn upsert_legal_issue(
    connection: &rusqlite::Connection,
    issue: &LegalIssueRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO legal_issues (
            issue_id, project_id, title, description, claim, status, confirmation_status
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(issue_id) DO UPDATE SET
            title = excluded.title,
            description = excluded.description,
            claim = excluded.claim,
            status = excluded.status,
            confirmation_status = excluded.confirmation_status
        WHERE legal_issues.project_id = excluded.project_id
        ",
        params![
            issue.issue_id,
            issue.project_id,
            issue.title,
            issue.description,
            issue.claim,
            issue.status,
            issue.confirmation_status
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "legal issue id is already assigned to another project",
    )
}

pub fn upsert_case_uncertainty(
    connection: &rusqlite::Connection,
    uncertainty: &CaseUncertaintyRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO case_uncertainties (
            uncertainty_id, project_id, description, related_entity_type, related_entity_id,
            source_file_ids_json, status, resolution, confirmation_status
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(uncertainty_id) DO UPDATE SET
            description = excluded.description,
            related_entity_type = excluded.related_entity_type,
            related_entity_id = excluded.related_entity_id,
            source_file_ids_json = excluded.source_file_ids_json,
            status = excluded.status,
            resolution = excluded.resolution,
            confirmation_status = excluded.confirmation_status,
            updated_at = CURRENT_TIMESTAMP
        WHERE case_uncertainties.project_id = excluded.project_id
        ",
        params![
            uncertainty.uncertainty_id,
            uncertainty.project_id,
            uncertainty.description,
            uncertainty.related_entity_type,
            uncertainty.related_entity_id,
            uncertainty.source_file_ids_json,
            uncertainty.status,
            uncertainty.resolution,
            uncertainty.confirmation_status
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "case uncertainty id is already assigned to another project",
    )
}

pub fn insert_confirmed_case_extraction(
    connection: &mut rusqlite::Connection,
    rows: &ConfirmedCaseExtractionRows,
) -> rusqlite::Result<()> {
    // Expired review payloads are retention-bounded data, not merely hidden
    // rows. Do this before opening the confirmation transaction so the cleanup
    // is committed even when confirmation is rejected as expired.
    cleanup_expired_pending_extraction_reviews(connection)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

    let persisted_provenance = transaction
        .query_row(
            "
            SELECT provider_id, provider_snapshot_json, source_file_ids_json,
                   source_materials_digest, extraction_json, revision
            FROM pending_extraction_reviews
            WHERE review_id = ?1
              AND project_id = ?2
              AND expires_at > CURRENT_TIMESTAMP
            ",
            params![rows.review_id, rows.project_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()?;
    let Some((
        persisted_provider_id,
        persisted_provider_snapshot_json,
        persisted_source_file_ids_json,
        persisted_source_materials_digest,
        persisted_extraction_json,
        persisted_revision,
    )) = persisted_provenance
    else {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    };
    let persisted_source_file_ids =
        serde_json::from_str::<Vec<String>>(&persisted_source_file_ids_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let persisted_extraction =
        serde_json::from_str::<serde_json::Value>(&persisted_extraction_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    let reviewed_extraction =
        serde_json::from_str::<serde_json::Value>(&rows.reviewed_extraction_json)
            .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?;
    validate_provider_audit_snapshot_json(&persisted_provider_snapshot_json)?;
    let current_source_materials_digest =
        current_case_materials_digest(&transaction, &rows.project_id, &rows.source_file_ids)?;
    if persisted_provider_id != rows.provider_id
        || persisted_source_file_ids != rows.source_file_ids
        || persisted_source_materials_digest.len() != 64
        || current_source_materials_digest.as_deref()
            != Some(persisted_source_materials_digest.as_str())
        || persisted_extraction != reviewed_extraction
        || persisted_revision != rows.expected_revision
    {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }

    transaction.execute(
        "
        INSERT INTO case_extraction_confirmations (
            review_id, project_id, provider_id, provider_snapshot_json,
            source_file_ids_json
        ) VALUES (?1, ?2, ?3, ?4, ?5)
        ",
        params![
            rows.review_id,
            rows.project_id,
            rows.provider_id,
            persisted_provider_snapshot_json,
            serde_json::to_string(&rows.source_file_ids)
                .map_err(|error| rusqlite::Error::ToSqlConversionFailure(Box::new(error)))?
        ],
    )?;

    for party in &rows.parties {
        insert_case_party(&transaction, party)?;
    }
    for fact in &rows.facts {
        insert_case_fact(&transaction, fact)?;
    }
    for evidence in &rows.evidence {
        insert_evidence_item(&transaction, evidence)?;
    }
    for issue in &rows.legal_issues {
        insert_legal_issue(&transaction, issue)?;
    }
    for link in &rows.evidence_links {
        insert_evidence_link(&transaction, link)?;
    }
    for uncertainty in &rows.uncertainties {
        insert_case_uncertainty(&transaction, uncertainty)?;
    }

    // Confirmation and pending-review consumption are one atomic operation.
    // A crash cannot leave an already-applied review available for replay.
    let consumed = transaction.execute(
        "DELETE FROM pending_extraction_reviews
         WHERE review_id = ?1 AND project_id = ?2 AND revision = ?3",
        params![rows.review_id, rows.project_id, rows.expected_revision],
    )?;
    if consumed != 1 {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }

    transaction.commit()
}

pub fn insert_pending_extraction_review(
    connection: &mut rusqlite::Connection,
    review: &PendingExtractionReviewRow,
) -> rusqlite::Result<bool> {
    validate_provider_audit_snapshot_json(&review.provider_snapshot_json)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute(
        "DELETE FROM pending_extraction_reviews WHERE expires_at <= CURRENT_TIMESTAMP",
        [],
    )?;
    let inserted = transaction.execute(
        "
        INSERT INTO pending_extraction_reviews (
            review_id, project_id, provider_id, provider_snapshot_json,
            source_file_ids_json, source_materials_digest, extraction_json,
            revision, created_at, expires_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, CURRENT_TIMESTAMP,
            datetime(CURRENT_TIMESTAMP, ?8)
        )
        ON CONFLICT DO NOTHING
        ",
        params![
            review.review_id,
            review.project_id,
            review.provider_id,
            review.provider_snapshot_json,
            review.source_file_ids_json,
            review.source_materials_digest,
            review.extraction_json,
            PENDING_EXTRACTION_REVIEW_RETENTION_SQL,
        ],
    )?;
    transaction.commit()?;
    Ok(inserted == 1)
}

pub fn cleanup_expired_pending_extraction_reviews(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<usize> {
    connection.execute(
        "DELETE FROM pending_extraction_reviews WHERE expires_at <= CURRENT_TIMESTAMP",
        [],
    )
}

pub fn get_pending_extraction_review(
    connection: &rusqlite::Connection,
    review_id: &str,
) -> rusqlite::Result<Option<PendingExtractionReviewRow>> {
    cleanup_expired_pending_extraction_reviews(connection)?;
    connection
        .query_row(
            "
        SELECT review_id, project_id, provider_id, provider_snapshot_json,
               source_file_ids_json, source_materials_digest, extraction_json,
               revision, created_at, expires_at
        FROM pending_extraction_reviews
        WHERE review_id = ?1 AND expires_at > CURRENT_TIMESTAMP
        ",
            [review_id],
            pending_extraction_review_from_row,
        )
        .optional()
}

pub fn get_pending_extraction_review_for_project(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Option<PendingExtractionReviewRow>> {
    cleanup_expired_pending_extraction_reviews(connection)?;
    connection
        .query_row(
            "
        SELECT review_id, project_id, provider_id, provider_snapshot_json,
               source_file_ids_json, source_materials_digest, extraction_json,
               revision, created_at, expires_at
        FROM pending_extraction_reviews
        WHERE project_id = ?1 AND expires_at > CURRENT_TIMESTAMP
        ",
            [project_id],
            pending_extraction_review_from_row,
        )
        .optional()
}

pub fn delete_pending_extraction_review(
    connection: &rusqlite::Connection,
    review_id: &str,
    project_id: &str,
    expected_revision: i64,
) -> rusqlite::Result<bool> {
    Ok(connection.execute(
        "DELETE FROM pending_extraction_reviews
         WHERE review_id = ?1
           AND project_id = ?2
           AND revision = ?3
           AND expires_at > CURRENT_TIMESTAMP",
        params![review_id, project_id, expected_revision],
    )? > 0)
}

pub fn update_pending_extraction_review_payload(
    connection: &mut rusqlite::Connection,
    review_id: &str,
    project_id: &str,
    provider_id: &str,
    source_file_ids: &[String],
    extraction_json: &str,
    expected_revision: i64,
) -> rusqlite::Result<PendingExtractionReviewUpdateResult> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute(
        "DELETE FROM pending_extraction_reviews WHERE expires_at <= CURRENT_TIMESTAMP",
        [],
    )?;
    let persisted = transaction
        .query_row(
            "
            SELECT source_file_ids_json, revision
            FROM pending_extraction_reviews
            WHERE review_id = ?1
              AND project_id = ?2
              AND provider_id = ?3
              AND expires_at > CURRENT_TIMESTAMP
            ",
            params![review_id, project_id, provider_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((persisted_source_file_ids_json, persisted_revision)) = persisted else {
        transaction.commit()?;
        return Ok(PendingExtractionReviewUpdateResult::NotFound);
    };
    let persisted_source_file_ids =
        serde_json::from_str::<Vec<String>>(&persisted_source_file_ids_json).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    if persisted_source_file_ids != source_file_ids {
        transaction.commit()?;
        return Ok(PendingExtractionReviewUpdateResult::NotFound);
    }
    if persisted_revision != expected_revision {
        transaction.commit()?;
        return Ok(PendingExtractionReviewUpdateResult::Conflict);
    }

    let affected = transaction.execute(
        "
        UPDATE pending_extraction_reviews
        SET extraction_json = ?1,
            revision = revision + 1,
            expires_at = datetime(CURRENT_TIMESTAMP, ?6)
        WHERE review_id = ?2
          AND project_id = ?3
          AND provider_id = ?4
          AND revision = ?5
          AND expires_at > CURRENT_TIMESTAMP
        ",
        params![
            extraction_json,
            review_id,
            project_id,
            provider_id,
            expected_revision,
            PENDING_EXTRACTION_REVIEW_RETENTION_SQL,
        ],
    )?;
    if affected != 1 {
        transaction.commit()?;
        return Ok(PendingExtractionReviewUpdateResult::Conflict);
    }
    let (revision, expires_at) = transaction.query_row(
        "SELECT revision, expires_at FROM pending_extraction_reviews WHERE review_id = ?1",
        [review_id],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
    )?;
    transaction.commit()?;
    Ok(PendingExtractionReviewUpdateResult::Updated(
        PendingExtractionReviewUpdate {
            revision,
            expires_at,
        },
    ))
}

fn pending_extraction_review_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PendingExtractionReviewRow> {
    Ok(PendingExtractionReviewRow {
        review_id: row.get(0)?,
        project_id: row.get(1)?,
        provider_id: row.get(2)?,
        provider_snapshot_json: row.get(3)?,
        source_file_ids_json: row.get(4)?,
        source_materials_digest: row.get(5)?,
        extraction_json: row.get(6)?,
        revision: row.get(7)?,
        created_at: row.get(8)?,
        expires_at: row.get(9)?,
    })
}

fn insert_case_party(
    connection: &rusqlite::Connection,
    party: &CasePartyRow,
) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO case_parties (
            party_id, project_id, name, normalized_name, role, contact, notes
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ",
        params![
            party.party_id,
            party.project_id,
            party.name,
            party.normalized_name,
            party.role,
            party.contact,
            party.notes
        ],
    )?;
    Ok(())
}

fn insert_case_fact(connection: &rusqlite::Connection, fact: &CaseFactRow) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO case_facts (
            fact_id, project_id, occurred_on, title, description, source, confirmation_status
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ",
        params![
            fact.fact_id,
            fact.project_id,
            fact.occurred_on,
            fact.title,
            fact.description,
            fact.source,
            fact.confirmation_status
        ],
    )?;
    Ok(())
}

fn insert_evidence_item(
    connection: &rusqlite::Connection,
    evidence: &EvidenceItemRow,
) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO evidence_items (
            evidence_id, project_id, evidence_number, title, source, formed_on, summary,
            storage_reference, confirmation_status
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ",
        params![
            evidence.evidence_id,
            evidence.project_id,
            evidence.evidence_number,
            evidence.title,
            evidence.source,
            evidence.formed_on,
            evidence.summary,
            evidence.storage_reference,
            evidence.confirmation_status
        ],
    )?;
    Ok(())
}

fn insert_legal_issue(
    connection: &rusqlite::Connection,
    issue: &LegalIssueRow,
) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO legal_issues (
            issue_id, project_id, title, description, claim, status, confirmation_status
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ",
        params![
            issue.issue_id,
            issue.project_id,
            issue.title,
            issue.description,
            issue.claim,
            issue.status,
            issue.confirmation_status
        ],
    )?;
    Ok(())
}

fn insert_evidence_link(
    connection: &rusqlite::Connection,
    link: &EvidenceLinkRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO evidence_links (link_id, project_id, fact_id, evidence_id)
        SELECT ?1, ?2, ?3, ?4
        WHERE EXISTS (
            SELECT 1 FROM case_facts
            WHERE fact_id = ?3 AND project_id = ?2
        ) AND EXISTS (
            SELECT 1 FROM evidence_items
            WHERE evidence_id = ?4 AND project_id = ?2
        )
        ",
        params![
            link.link_id,
            link.project_id,
            link.fact_id,
            link.evidence_id
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "evidence link fact and evidence must belong to its project",
    )
}

fn insert_case_uncertainty(
    connection: &rusqlite::Connection,
    uncertainty: &CaseUncertaintyRow,
) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO case_uncertainties (
            uncertainty_id, project_id, description, related_entity_type, related_entity_id,
            source_file_ids_json, status, resolution, confirmation_status
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ",
        params![
            uncertainty.uncertainty_id,
            uncertainty.project_id,
            uncertainty.description,
            uncertainty.related_entity_type,
            uncertainty.related_entity_id,
            uncertainty.source_file_ids_json,
            uncertainty.status,
            uncertainty.resolution,
            uncertainty.confirmation_status
        ],
    )?;
    Ok(())
}

pub fn upsert_legal_basis(
    connection: &rusqlite::Connection,
    basis: &LegalBasisRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO legal_basis (
            basis_id,
            project_id,
            issue_id,
            source_id,
            status,
            invalid_reason,
            case_date,
            article_id,
            document_id,
            version_id,
            document_title,
            version_label,
            article_number,
            article_title,
            canonical_label,
            effective_from,
            effective_to,
            version_status,
            excerpt,
            note
        )
        SELECT
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
            ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20
        WHERE ?3 IS NULL OR EXISTS (
            SELECT 1 FROM legal_issues
            WHERE issue_id = ?3 AND project_id = ?2
        )
        ON CONFLICT(basis_id) DO UPDATE SET
            issue_id = excluded.issue_id,
            source_id = excluded.source_id,
            status = excluded.status,
            invalid_reason = excluded.invalid_reason,
            case_date = excluded.case_date,
            article_id = excluded.article_id,
            document_id = excluded.document_id,
            version_id = excluded.version_id,
            document_title = excluded.document_title,
            version_label = excluded.version_label,
            article_number = excluded.article_number,
            article_title = excluded.article_title,
            canonical_label = excluded.canonical_label,
            effective_from = excluded.effective_from,
            effective_to = excluded.effective_to,
            version_status = excluded.version_status,
            excerpt = excluded.excerpt,
            note = excluded.note
        WHERE legal_basis.project_id = excluded.project_id
        ",
        params![
            basis.basis_id,
            basis.project_id,
            basis.issue_id,
            basis.source_id,
            basis.status,
            basis.invalid_reason,
            basis.case_date,
            basis.article_id,
            basis.document_id,
            basis.version_id,
            basis.document_title,
            basis.version_label,
            basis.article_number,
            basis.article_title,
            basis.canonical_label,
            basis.effective_from,
            basis.effective_to,
            basis.version_status,
            basis.excerpt,
            basis.note
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "legal basis id must stay in its project, and its issue must belong to that project",
    )
}

pub fn upsert_evidence_link(
    connection: &rusqlite::Connection,
    link: &EvidenceLinkRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO evidence_links (link_id, project_id, fact_id, evidence_id)
        SELECT ?1, ?2, ?3, ?4
        WHERE EXISTS (
            SELECT 1 FROM case_facts
            WHERE fact_id = ?3 AND project_id = ?2
        ) AND EXISTS (
            SELECT 1 FROM evidence_items
            WHERE evidence_id = ?4 AND project_id = ?2
        )
        ON CONFLICT(link_id) DO UPDATE SET
            fact_id = excluded.fact_id,
            evidence_id = excluded.evidence_id
        WHERE evidence_links.project_id = excluded.project_id
        ",
        params![
            link.link_id,
            link.project_id,
            link.fact_id,
            link.evidence_id
        ],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "evidence link id must stay in its project, and its fact and evidence must belong to that project",
    )
}

pub fn upsert_fact_issue_link(
    connection: &rusqlite::Connection,
    link: &FactIssueLinkRow,
) -> rusqlite::Result<()> {
    let affected_rows = connection.execute(
        "
        INSERT INTO fact_issue_links (link_id, project_id, fact_id, issue_id)
        SELECT ?1, ?2, ?3, ?4
        WHERE EXISTS (
            SELECT 1 FROM case_facts
            WHERE fact_id = ?3 AND project_id = ?2
        ) AND EXISTS (
            SELECT 1 FROM legal_issues
            WHERE issue_id = ?4 AND project_id = ?2
        )
        ON CONFLICT(link_id) DO UPDATE SET
            fact_id = excluded.fact_id,
            issue_id = excluded.issue_id
        WHERE fact_issue_links.project_id = excluded.project_id
        ",
        params![link.link_id, link.project_id, link.fact_id, link.issue_id],
    )?;

    ensure_project_scoped_write(
        affected_rows,
        "fact-issue link id must stay in its project, and its fact and issue must belong to that project",
    )
}

fn ensure_project_scoped_write(affected_rows: usize, message: &str) -> rusqlite::Result<()> {
    if affected_rows == 0 {
        return Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
            Some(message.to_owned()),
        ));
    }

    Ok(())
}

pub fn delete_case_entity(
    connection: &mut rusqlite::Connection,
    table: &str,
    id_column: &str,
    id: &str,
    project_id: &str,
) -> rusqlite::Result<bool> {
    let sql = match (table, id_column) {
        ("case_files", "file_id") => {
            "DELETE FROM case_files WHERE file_id = ?1 AND project_id = ?2"
        }
        ("case_parties", "party_id") => {
            "DELETE FROM case_parties WHERE party_id = ?1 AND project_id = ?2"
        }
        ("case_facts", "fact_id") => {
            "DELETE FROM case_facts WHERE fact_id = ?1 AND project_id = ?2"
        }
        ("evidence_items", "evidence_id") => {
            "DELETE FROM evidence_items WHERE evidence_id = ?1 AND project_id = ?2"
        }
        ("evidence_links", "link_id") => {
            "DELETE FROM evidence_links WHERE link_id = ?1 AND project_id = ?2"
        }
        ("fact_issue_links", "link_id") => {
            "DELETE FROM fact_issue_links WHERE link_id = ?1 AND project_id = ?2"
        }
        ("legal_issues", "issue_id") => {
            "DELETE FROM legal_issues WHERE issue_id = ?1 AND project_id = ?2"
        }
        ("legal_basis", "basis_id") => {
            "DELETE FROM legal_basis WHERE basis_id = ?1 AND project_id = ?2"
        }
        ("case_uncertainties", "uncertainty_id") => {
            "DELETE FROM case_uncertainties WHERE uncertainty_id = ?1 AND project_id = ?2"
        }
        _ => return Err(rusqlite::Error::InvalidParameterName(table.to_owned())),
    };
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if table == "case_files" {
        let referenced: bool = transaction.query_row(
            "
            SELECT EXISTS(
                SELECT 1
                FROM case_extraction_confirmations AS confirmation,
                     json_each(confirmation.source_file_ids_json) AS source_file
                WHERE source_file.value = ?1
                  AND confirmation.project_id = ?2
            )
            ",
            params![id, project_id],
            |row| row.get(0),
        )?;
        if referenced {
            return Err(rusqlite::Error::InvalidParameterName(
                "case material is referenced by a confirmed extraction".to_owned(),
            ));
        }
    }
    let related_entity_type = match table {
        "case_parties" => Some("party"),
        "case_facts" => Some("fact"),
        "evidence_items" => Some("evidence"),
        "legal_issues" => Some("legal_issue"),
        _ => None,
    };
    if let Some(related_entity_type) = related_entity_type {
        transaction.execute(
            "
            UPDATE case_uncertainties
            SET related_entity_type = 'general', related_entity_id = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE related_entity_type = ?1 AND related_entity_id = ?2 AND project_id = ?3
            ",
            params![related_entity_type, id, project_id],
        )?;
    }
    let affected_rows = transaction.execute(sql, params![id, project_id])?;
    transaction.commit()?;

    Ok(affected_rows > 0)
}

fn list_case_files(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<CaseFileRow>> {
    let mut statement = connection.prepare(
        "
        SELECT file_id, project_id, title, file_type, storage_reference, summary, created_at
        FROM case_files
        WHERE project_id = ?1
        ORDER BY created_at ASC, title ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], case_file_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_case_parties(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<CasePartyRow>> {
    let mut statement = connection.prepare(
        "
        SELECT party_id, project_id, name, normalized_name, role, contact, notes
        FROM case_parties
        WHERE project_id = ?1
        ORDER BY name ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], case_party_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_case_facts(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<CaseFactRow>> {
    let mut statement = connection.prepare(
        "
        SELECT fact_id, project_id, occurred_on, title, description, source, confirmation_status
        FROM case_facts
        WHERE project_id = ?1
        ORDER BY occurred_on IS NULL, occurred_on ASC, title ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], case_fact_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_evidence_items(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<EvidenceItemRow>> {
    let mut statement = connection.prepare(
        "
        SELECT
            evidence_id, project_id, evidence_number, title, source, formed_on, summary,
            storage_reference, confirmation_status
        FROM evidence_items
        WHERE project_id = ?1
        ORDER BY evidence_number ASC, title ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], evidence_item_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_evidence_links(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<EvidenceLinkRow>> {
    let mut statement = connection.prepare(
        "
        SELECT link_id, project_id, fact_id, evidence_id
        FROM evidence_links
        WHERE project_id = ?1
        ORDER BY link_id ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], evidence_link_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_fact_issue_links(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<FactIssueLinkRow>> {
    let mut statement = connection.prepare(
        "
        SELECT link_id, project_id, fact_id, issue_id
        FROM fact_issue_links
        WHERE project_id = ?1
        ORDER BY link_id ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], fact_issue_link_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_legal_issues(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<LegalIssueRow>> {
    let mut statement = connection.prepare(
        "
        SELECT issue_id, project_id, title, description, claim, status, confirmation_status
        FROM legal_issues
        WHERE project_id = ?1
        ORDER BY title ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], legal_issue_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_legal_basis(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<LegalBasisRow>> {
    let mut statement = connection.prepare(
        "
        SELECT
            basis_id,
            project_id,
            issue_id,
            source_id,
            status,
            invalid_reason,
            case_date,
            article_id,
            document_id,
            version_id,
            document_title,
            version_label,
            article_number,
            article_title,
            canonical_label,
            effective_from,
            effective_to,
            version_status,
            excerpt,
            note,
            created_at
        FROM legal_basis
        WHERE project_id = ?1
        ORDER BY created_at DESC, source_id ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], legal_basis_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

fn list_case_uncertainties(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<CaseUncertaintyRow>> {
    let mut statement = connection.prepare(
        "
        SELECT
            uncertainty_id, project_id, description, related_entity_type, related_entity_id,
            source_file_ids_json, status, resolution, confirmation_status, created_at, updated_at
        FROM case_uncertainties
        WHERE project_id = ?1
        ORDER BY status ASC, created_at ASC
        ",
    )?;
    let rows = statement
        .query_map([project_id], case_uncertainty_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

pub fn insert_legal_answer_record(
    connection: &rusqlite::Connection,
    record: &LegalAnswerRecordRow,
) -> rusqlite::Result<()> {
    validate_provider_audit_snapshot_json(&record.provider_snapshot_json)?;
    connection.execute(
        "
        INSERT INTO legal_answer_records (
            record_id,
            project_id,
            provider_id,
            provider_snapshot_json,
            question,
            answer_text,
            case_date,
            query_json,
            source_ids_json,
            verified_citations_json,
            invalid_citations_json,
            unsupported_legal_conclusion
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ",
        params![
            record.record_id,
            record.project_id,
            record.provider_id,
            record.provider_snapshot_json,
            record.question,
            record.answer_text,
            record.case_date,
            record.query_json,
            record.source_ids_json,
            record.verified_citations_json,
            record.invalid_citations_json,
            if record.unsupported_legal_conclusion {
                1_i64
            } else {
                0_i64
            }
        ],
    )?;

    Ok(())
}

pub fn list_legal_answer_records(
    connection: &rusqlite::Connection,
    limit: u32,
) -> rusqlite::Result<Vec<LegalAnswerRecordRow>> {
    let limit = i64::from(limit.clamp(1, 100));
    let mut statement = connection.prepare(
        "
        SELECT
            record_id,
            project_id,
            provider_id,
            provider_snapshot_json,
            question,
            answer_text,
            case_date,
            query_json,
            source_ids_json,
            verified_citations_json,
            invalid_citations_json,
            unsupported_legal_conclusion,
            created_at
        FROM legal_answer_records
        ORDER BY created_at DESC
        LIMIT ?1
        ",
    )?;

    let rows = statement
        .query_map([limit], legal_answer_record_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(rows)
}

pub fn list_legal_answer_records_for_project(
    connection: &rusqlite::Connection,
    project_id: &str,
    limit: u32,
) -> rusqlite::Result<Vec<LegalAnswerRecordRow>> {
    list_legal_answer_records_for_project_before(connection, project_id, None, None, limit)
}

pub fn list_legal_answer_records_for_project_before(
    connection: &rusqlite::Connection,
    project_id: &str,
    before_created_at: Option<&str>,
    before_record_id: Option<&str>,
    limit: u32,
) -> rusqlite::Result<Vec<LegalAnswerRecordRow>> {
    let limit = i64::from(limit.clamp(1, 100));
    let mut statement = connection.prepare(
        "
        SELECT
            record_id,
            project_id,
            provider_id,
            provider_snapshot_json,
            question,
            answer_text,
            case_date,
            query_json,
            source_ids_json,
            verified_citations_json,
            invalid_citations_json,
            unsupported_legal_conclusion,
            created_at
        FROM legal_answer_records
        WHERE project_id = ?1
          AND (
              ?2 IS NULL
              OR created_at < ?2
              OR (created_at = ?2 AND record_id < ?3)
          )
        ORDER BY created_at DESC, record_id DESC
        LIMIT ?4
        ",
    )?;
    let rows = statement
        .query_map(
            params![project_id, before_created_at, before_record_id, limit],
            legal_answer_record_from_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn case_project_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaseProjectRow> {
    Ok(CaseProjectRow {
        project_id: row.get(0)?,
        title: row.get(1)?,
        case_type: row.get(2)?,
        status: row.get(3)?,
        opened_on: row.get(4)?,
        summary: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

fn case_file_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaseFileRow> {
    Ok(CaseFileRow {
        file_id: row.get(0)?,
        project_id: row.get(1)?,
        title: row.get(2)?,
        file_type: row.get(3)?,
        storage_reference: row.get(4)?,
        summary: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn case_party_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CasePartyRow> {
    Ok(CasePartyRow {
        party_id: row.get(0)?,
        project_id: row.get(1)?,
        name: row.get(2)?,
        normalized_name: row.get(3)?,
        role: row.get(4)?,
        contact: row.get(5)?,
        notes: row.get(6)?,
    })
}

fn case_fact_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaseFactRow> {
    Ok(CaseFactRow {
        fact_id: row.get(0)?,
        project_id: row.get(1)?,
        occurred_on: row.get(2)?,
        title: row.get(3)?,
        description: row.get(4)?,
        source: row.get(5)?,
        confirmation_status: row.get(6)?,
    })
}

fn evidence_item_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvidenceItemRow> {
    Ok(EvidenceItemRow {
        evidence_id: row.get(0)?,
        project_id: row.get(1)?,
        evidence_number: row.get(2)?,
        title: row.get(3)?,
        source: row.get(4)?,
        formed_on: row.get(5)?,
        summary: row.get(6)?,
        storage_reference: row.get(7)?,
        confirmation_status: row.get(8)?,
    })
}

fn evidence_link_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EvidenceLinkRow> {
    Ok(EvidenceLinkRow {
        link_id: row.get(0)?,
        project_id: row.get(1)?,
        fact_id: row.get(2)?,
        evidence_id: row.get(3)?,
    })
}

fn fact_issue_link_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FactIssueLinkRow> {
    Ok(FactIssueLinkRow {
        link_id: row.get(0)?,
        project_id: row.get(1)?,
        fact_id: row.get(2)?,
        issue_id: row.get(3)?,
    })
}

fn legal_issue_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LegalIssueRow> {
    Ok(LegalIssueRow {
        issue_id: row.get(0)?,
        project_id: row.get(1)?,
        title: row.get(2)?,
        description: row.get(3)?,
        claim: row.get(4)?,
        status: row.get(5)?,
        confirmation_status: row.get(6)?,
    })
}

fn legal_basis_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LegalBasisRow> {
    Ok(LegalBasisRow {
        basis_id: row.get(0)?,
        project_id: row.get(1)?,
        issue_id: row.get(2)?,
        source_id: row.get(3)?,
        status: row.get(4)?,
        invalid_reason: row.get(5)?,
        case_date: row.get(6)?,
        article_id: row.get(7)?,
        document_id: row.get(8)?,
        version_id: row.get(9)?,
        document_title: row.get(10)?,
        version_label: row.get(11)?,
        article_number: row.get(12)?,
        article_title: row.get(13)?,
        canonical_label: row.get(14)?,
        effective_from: row.get(15)?,
        effective_to: row.get(16)?,
        version_status: row.get(17)?,
        excerpt: row.get(18)?,
        note: row.get(19)?,
        created_at: row.get(20)?,
    })
}

fn case_uncertainty_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CaseUncertaintyRow> {
    Ok(CaseUncertaintyRow {
        uncertainty_id: row.get(0)?,
        project_id: row.get(1)?,
        description: row.get(2)?,
        related_entity_type: row.get(3)?,
        related_entity_id: row.get(4)?,
        source_file_ids_json: row.get(5)?,
        status: row.get(6)?,
        resolution: row.get(7)?,
        confirmation_status: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

fn legal_answer_record_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LegalAnswerRecordRow> {
    let unsupported: i64 = row.get(11)?;

    Ok(LegalAnswerRecordRow {
        record_id: row.get(0)?,
        project_id: row.get(1)?,
        provider_id: row.get(2)?,
        provider_snapshot_json: row.get(3)?,
        question: row.get(4)?,
        answer_text: row.get(5)?,
        case_date: row.get(6)?,
        query_json: row.get(7)?,
        source_ids_json: row.get(8)?,
        verified_citations_json: row.get(9)?,
        invalid_citations_json: row.get(10)?,
        unsupported_legal_conclusion: unsupported != 0,
        created_at: row.get(12)?,
    })
}

fn configure_legal_core_connection(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    // The legal corpus is immutable for application connections and is much
    // larger than SQLite's page cache.  Mapping a bounded 1 GiB window lets
    // the operating system share hot FTS/index pages across short-lived
    // read-only connections without reserving an equally large heap cache.
    connection.pragma_update(None, "mmap_size", 1_073_741_824_i64)?;
    connection.pragma_update(None, "query_only", "ON")?;

    Ok(())
}

#[derive(Debug)]
struct UserTableMigrationSpec {
    name: &'static str,
    canonical_columns: &'static [&'static str],
    required_legacy_columns: &'static [&'static str],
}

// Keep this list in parent-before-child copy order. Columns absent from older
// schemas are filled by the canonical table defaults. Required columns are the
// minimum data-bearing contract of every historical version that introduced
// the table; a missing or unknown column is treated as schema damage instead
// of silently inventing or dropping user data.
const USER_TABLE_MIGRATION_SPECS: &[UserTableMigrationSpec] = &[
    UserTableMigrationSpec {
        name: "provider_profiles",
        canonical_columns: &[
            "id",
            "kind",
            "display_name",
            "model_id",
            "base_url",
            "credential_account_id",
            "capabilities_json",
            "options_json",
            "created_at",
            "updated_at",
        ],
        required_legacy_columns: &[
            "id",
            "kind",
            "display_name",
            "model_id",
            "base_url",
            "credential_account_id",
            "capabilities_json",
            "options_json",
        ],
    },
    UserTableMigrationSpec {
        name: "projects",
        canonical_columns: &[
            "project_id",
            "title",
            "case_type",
            "status",
            "opened_on",
            "summary",
            "created_at",
            "updated_at",
        ],
        required_legacy_columns: &["project_id", "title", "status"],
    },
    UserTableMigrationSpec {
        name: "case_files",
        canonical_columns: &[
            "file_id",
            "project_id",
            "title",
            "file_type",
            "storage_reference",
            "summary",
            "created_at",
        ],
        required_legacy_columns: &["file_id", "project_id", "title"],
    },
    UserTableMigrationSpec {
        name: "pending_extraction_reviews",
        canonical_columns: &[
            "review_id",
            "project_id",
            "provider_id",
            "provider_snapshot_json",
            "source_file_ids_json",
            "source_materials_digest",
            "extraction_json",
            "revision",
            "created_at",
            "expires_at",
        ],
        required_legacy_columns: &[
            "review_id",
            "project_id",
            "provider_id",
            "source_file_ids_json",
            "extraction_json",
        ],
    },
    UserTableMigrationSpec {
        name: "case_parties",
        canonical_columns: &[
            "party_id",
            "project_id",
            "name",
            "normalized_name",
            "role",
            "contact",
            "notes",
        ],
        required_legacy_columns: &["party_id", "project_id", "name", "role"],
    },
    UserTableMigrationSpec {
        name: "case_facts",
        canonical_columns: &[
            "fact_id",
            "project_id",
            "occurred_on",
            "title",
            "description",
            "source",
            "confirmation_status",
        ],
        required_legacy_columns: &["fact_id", "project_id", "title", "confirmation_status"],
    },
    UserTableMigrationSpec {
        name: "evidence_items",
        canonical_columns: &[
            "evidence_id",
            "project_id",
            "evidence_number",
            "title",
            "source",
            "formed_on",
            "summary",
            "storage_reference",
            "confirmation_status",
        ],
        required_legacy_columns: &[
            "evidence_id",
            "project_id",
            "evidence_number",
            "title",
            "confirmation_status",
        ],
    },
    UserTableMigrationSpec {
        name: "legal_issues",
        canonical_columns: &[
            "issue_id",
            "project_id",
            "title",
            "description",
            "claim",
            "status",
            "confirmation_status",
        ],
        required_legacy_columns: &[
            "issue_id",
            "project_id",
            "title",
            "status",
            "confirmation_status",
        ],
    },
    UserTableMigrationSpec {
        name: "evidence_links",
        canonical_columns: &["link_id", "project_id", "fact_id", "evidence_id"],
        required_legacy_columns: &["link_id", "project_id", "fact_id", "evidence_id"],
    },
    UserTableMigrationSpec {
        name: "fact_issue_links",
        canonical_columns: &["link_id", "project_id", "fact_id", "issue_id"],
        required_legacy_columns: &["link_id", "project_id", "fact_id", "issue_id"],
    },
    UserTableMigrationSpec {
        name: "case_extraction_confirmations",
        canonical_columns: &[
            "review_id",
            "project_id",
            "provider_id",
            "provider_snapshot_json",
            "source_file_ids_json",
            "confirmed_at",
        ],
        required_legacy_columns: &[
            "review_id",
            "project_id",
            "provider_id",
            "source_file_ids_json",
        ],
    },
    UserTableMigrationSpec {
        name: "case_uncertainties",
        canonical_columns: &[
            "uncertainty_id",
            "project_id",
            "description",
            "related_entity_type",
            "related_entity_id",
            "source_file_ids_json",
            "status",
            "resolution",
            "confirmation_status",
            "created_at",
            "updated_at",
        ],
        required_legacy_columns: &[
            "uncertainty_id",
            "project_id",
            "description",
            "status",
            "confirmation_status",
        ],
    },
    UserTableMigrationSpec {
        name: "legal_basis",
        canonical_columns: &[
            "basis_id",
            "project_id",
            "issue_id",
            "source_id",
            "status",
            "invalid_reason",
            "case_date",
            "article_id",
            "document_id",
            "version_id",
            "document_title",
            "version_label",
            "article_number",
            "article_title",
            "canonical_label",
            "effective_from",
            "effective_to",
            "version_status",
            "excerpt",
            "note",
            "created_at",
        ],
        required_legacy_columns: &["basis_id", "project_id", "source_id", "status"],
    },
    UserTableMigrationSpec {
        name: "legal_answer_records",
        canonical_columns: &[
            "record_id",
            "project_id",
            "provider_id",
            "provider_snapshot_json",
            "question",
            "answer_text",
            "case_date",
            "query_json",
            "source_ids_json",
            "verified_citations_json",
            "invalid_citations_json",
            "unsupported_legal_conclusion",
            "created_at",
        ],
        required_legacy_columns: &[
            "record_id",
            "provider_id",
            "question",
            "query_json",
            "source_ids_json",
            "verified_citations_json",
            "invalid_citations_json",
            "unsupported_legal_conclusion",
        ],
    },
    UserTableMigrationSpec {
        name: "document_generation_records",
        canonical_columns: &[
            "record_id",
            "project_id",
            "template_id",
            "template_version",
            "source_ids_json",
            "citation_ids_json",
            "export_path",
            "exported_at",
        ],
        required_legacy_columns: &[
            "record_id",
            "project_id",
            "template_id",
            "template_version",
            "source_ids_json",
            "citation_ids_json",
            "export_path",
            "exported_at",
        ],
    },
];

const USER_SCHEMA_INDEX_NAMES: &[&str] = &[
    "idx_provider_profiles_kind",
    "idx_projects_updated",
    "idx_case_files_project",
    "idx_pending_extraction_reviews_expires",
    "idx_case_extraction_confirmations_project",
    "idx_case_parties_project",
    "idx_case_facts_project",
    "idx_evidence_items_project",
    "idx_evidence_links_project",
    "idx_fact_issue_links_project",
    "idx_legal_issues_project",
    "idx_case_uncertainties_project",
    "idx_legal_basis_project",
    "idx_legal_answer_records_created",
    "idx_legal_answer_records_project_created",
    "idx_document_generation_project_exported",
];

const USER_SCHEMA_TRIGGER_NAMES: &[&str] = &[
    "trg_legal_basis_issue_project_insert",
    "trg_legal_basis_issue_project_update",
];

const LEGACY_USER_TABLE_DROP_ORDER: &[&str] = &[
    "case_extraction_confirmations",
    "pending_extraction_reviews",
    "legal_answer_records",
    "evidence_links",
    "fact_issue_links",
    "legal_basis",
    "document_generation_records",
    "case_uncertainties",
    "case_files",
    "case_parties",
    "case_facts",
    "evidence_items",
    "legal_issues",
    "projects",
    "provider_profiles",
];

fn legacy_user_table_name(table: &str) -> String {
    format!("__lawyer_assistance_v6_legacy_{table}")
}

fn sqlite_table_exists(connection: &rusqlite::Connection, table: &str) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
}

fn stage_legacy_user_tables(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<HashSet<&'static str>> {
    let mut staged = HashSet::new();
    for spec in USER_TABLE_MIGRATION_SPECS {
        if !sqlite_table_exists(transaction, spec.name)? {
            continue;
        }
        let legacy_name = legacy_user_table_name(spec.name);
        if sqlite_table_exists(transaction, &legacy_name)? {
            return Err(user_schema_migration_error(format!(
                "reserved migration table already exists: {legacy_name}"
            )));
        }
        transaction.execute(
            &format!(
                "ALTER TABLE \"{}\" RENAME TO \"{}\"",
                spec.name, legacy_name
            ),
            [],
        )?;
        staged.insert(spec.name);
    }

    // Named indexes retain their names when a table is renamed. Remove the
    // historical copies so the canonical DDL can recreate them on the new
    // tables. The surrounding transaction restores them on any later failure.
    for index_name in USER_SCHEMA_INDEX_NAMES {
        transaction.execute(&format!("DROP INDEX IF EXISTS \"{index_name}\""), [])?;
    }
    // Triggers, like indexes, keep their global names after ALTER TABLE RENAME.
    // Drop the legacy copies transactionally so canonical triggers can be
    // created on the replacement tables. Rollback restores them on failure.
    for trigger_name in USER_SCHEMA_TRIGGER_NAMES {
        transaction.execute(&format!("DROP TRIGGER IF EXISTS \"{trigger_name}\""), [])?;
    }

    Ok(staged)
}

fn table_columns(
    connection: &rusqlite::Connection,
    table: &str,
) -> rusqlite::Result<HashSet<String>> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<HashSet<_>>>()?;
    Ok(columns)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForeignKeyContract {
    target_table: String,
    on_delete: String,
    columns: Vec<(i64, String, String)>,
}

fn table_foreign_key_contracts(
    connection: &rusqlite::Connection,
    table: &str,
) -> rusqlite::Result<Vec<ForeignKeyContract>> {
    let mut statement = connection.prepare(&format!("PRAGMA foreign_key_list(\"{table}\")"))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut grouped = BTreeMap::<i64, ForeignKeyContract>::new();
    for (id, sequence, target_table, from, to, on_delete) in rows {
        let contract = grouped.entry(id).or_insert_with(|| ForeignKeyContract {
            target_table,
            on_delete,
            columns: Vec::new(),
        });
        contract.columns.push((sequence, from, to));
    }
    let mut contracts = grouped.into_values().collect::<Vec<_>>();
    for contract in &mut contracts {
        contract.columns.sort_by_key(|column| column.0);
    }
    Ok(contracts)
}

fn table_has_unique_columns(
    connection: &rusqlite::Connection,
    table: &str,
    expected_columns: &[&str],
) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA index_list(\"{table}\")"))?;
    let indexes = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(4)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (index_name, unique, partial) in indexes {
        if !unique || partial {
            continue;
        }
        let mut columns = connection.prepare(&format!("PRAGMA index_info(\"{index_name}\")"))?;
        let found = columns
            .query_map([], |row| row.get::<_, String>(2))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if found
            .iter()
            .map(String::as_str)
            .eq(expected_columns.iter().copied())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_fact_issue_schema_contract(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    for (table, columns) in [
        ("case_facts", &["project_id", "fact_id"][..]),
        ("legal_issues", &["project_id", "issue_id"][..]),
        (
            "fact_issue_links",
            &["project_id", "fact_id", "issue_id"][..],
        ),
    ] {
        if !table_has_unique_columns(connection, table, columns)? {
            return Err(user_schema_migration_error(format!(
                "canonical {table} unique project-scope contract is missing"
            ))
            .into());
        }
    }

    let mut found = table_foreign_key_contracts(connection, "fact_issue_links")?;
    found.sort_by(|left, right| left.target_table.cmp(&right.target_table));
    let mut expected = vec![
        ForeignKeyContract {
            target_table: "case_facts".to_owned(),
            on_delete: "CASCADE".to_owned(),
            columns: vec![
                (0, "project_id".to_owned(), "project_id".to_owned()),
                (1, "fact_id".to_owned(), "fact_id".to_owned()),
            ],
        },
        ForeignKeyContract {
            target_table: "legal_issues".to_owned(),
            on_delete: "CASCADE".to_owned(),
            columns: vec![
                (0, "project_id".to_owned(), "project_id".to_owned()),
                (1, "issue_id".to_owned(), "issue_id".to_owned()),
            ],
        },
        ForeignKeyContract {
            target_table: "projects".to_owned(),
            on_delete: "CASCADE".to_owned(),
            columns: vec![(0, "project_id".to_owned(), "project_id".to_owned())],
        },
    ];
    expected.sort_by(|left, right| left.target_table.cmp(&right.target_table));
    if found != expected {
        return Err(user_schema_migration_error(
            "canonical fact_issue_links foreign-key contract is invalid".to_owned(),
        )
        .into());
    }

    Ok(())
}

fn copy_legacy_user_table(
    transaction: &rusqlite::Transaction<'_>,
    spec: &UserTableMigrationSpec,
) -> rusqlite::Result<()> {
    let legacy_name = legacy_user_table_name(spec.name);
    let source_columns = table_columns(transaction, &legacy_name)?;
    let canonical_columns = spec
        .canonical_columns
        .iter()
        .copied()
        .collect::<HashSet<_>>();

    if let Some(unknown) = source_columns
        .iter()
        .find(|column| !canonical_columns.contains(column.as_str()))
    {
        return Err(user_schema_migration_error(format!(
            "legacy table {} contains unsupported column {unknown}; refusing to drop user data",
            spec.name
        )));
    }
    if let Some(missing) = spec
        .required_legacy_columns
        .iter()
        .find(|column| !source_columns.contains(**column))
    {
        return Err(user_schema_migration_error(format!(
            "legacy table {} is missing required column {missing}",
            spec.name
        )));
    }

    let copied_columns = spec
        .canonical_columns
        .iter()
        .filter(|column| source_columns.contains(**column))
        .map(|column| format!("\"{column}\""))
        .collect::<Vec<_>>();
    let column_list = copied_columns.join(", ");
    let source_count: i64 = transaction.query_row(
        &format!("SELECT COUNT(*) FROM \"{legacy_name}\""),
        [],
        |row| row.get(0),
    )?;
    let copied = transaction.execute(
        &format!(
            "INSERT INTO \"{}\" ({column_list}) SELECT {column_list} FROM \"{legacy_name}\"",
            spec.name
        ),
        [],
    )?;
    if i64::try_from(copied).ok() != Some(source_count) {
        return Err(user_schema_migration_error(format!(
            "legacy table {} row count changed during migration",
            spec.name
        )));
    }

    Ok(())
}

fn legacy_legal_answer_unowned_count(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<i64> {
    let legacy_name = legacy_user_table_name("legal_answer_records");
    let source_columns = table_columns(transaction, &legacy_name)?;
    if source_columns.contains("project_id") {
        transaction.query_row(
            &format!(
                "SELECT COUNT(*) FROM \"{legacy_name}\"
                 WHERE project_id IS NULL OR length(project_id) = 0"
            ),
            [],
            |row| row.get(0),
        )
    } else {
        transaction.query_row(
            &format!("SELECT COUNT(*) FROM \"{legacy_name}\""),
            [],
            |row| row.get(0),
        )
    }
}

fn create_legacy_answer_quarantine_project(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<String> {
    // Never reuse an existing project with the reserved-looking ID: it may be
    // genuine user data. Select the first unused deterministic suffix instead.
    for suffix in 0..10_000_u32 {
        let project_id = if suffix == 0 {
            LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX.to_owned()
        } else {
            format!("{LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX}-{suffix}")
        };
        if case_project_exists(transaction, &project_id)? {
            continue;
        }
        transaction.execute(
            "
            INSERT INTO projects (project_id, title, case_type, status, summary)
            VALUES (?1, ?2, 'migration_quarantine', 'archived', ?3)
            ",
            params![
                project_id,
                LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE,
                LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY
            ],
        )?;
        return Ok(project_id);
    }

    Err(user_schema_migration_error(
        "could not allocate a collision-safe legacy answer quarantine project".to_owned(),
    ))
}

fn copy_legacy_legal_answers_into_quarantine(
    transaction: &rusqlite::Transaction<'_>,
    spec: &UserTableMigrationSpec,
    quarantine_project_id: &str,
) -> rusqlite::Result<()> {
    let legacy_name = legacy_user_table_name(spec.name);
    let source_columns = table_columns(transaction, &legacy_name)?;
    let canonical_columns = spec
        .canonical_columns
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    if let Some(unknown) = source_columns
        .iter()
        .find(|column| !canonical_columns.contains(column.as_str()))
    {
        return Err(user_schema_migration_error(format!(
            "legacy table {} contains unsupported column {unknown}; refusing to drop user data",
            spec.name
        )));
    }
    if let Some(missing) = spec
        .required_legacy_columns
        .iter()
        .find(|column| !source_columns.contains(**column))
    {
        return Err(user_schema_migration_error(format!(
            "legacy table {} is missing required column {missing}",
            spec.name
        )));
    }

    let mut destination_columns = Vec::new();
    let mut select_expressions = Vec::new();
    for column in spec.canonical_columns {
        if *column == "project_id" {
            destination_columns.push("\"project_id\"".to_owned());
            select_expressions.push(if source_columns.contains("project_id") {
                "CASE WHEN project_id IS NULL OR length(project_id) = 0 THEN ?1 ELSE project_id END"
                    .to_owned()
            } else {
                "?1".to_owned()
            });
        } else if source_columns.contains(*column) {
            destination_columns.push(format!("\"{column}\""));
            select_expressions.push(format!("\"{column}\""));
        }
    }
    let source_count: i64 = transaction.query_row(
        &format!("SELECT COUNT(*) FROM \"{legacy_name}\""),
        [],
        |row| row.get(0),
    )?;
    let copied = transaction.execute(
        &format!(
            "INSERT INTO \"{}\" ({}) SELECT {} FROM \"{legacy_name}\"",
            spec.name,
            destination_columns.join(", "),
            select_expressions.join(", ")
        ),
        [quarantine_project_id],
    )?;
    if i64::try_from(copied).ok() != Some(source_count) {
        return Err(user_schema_migration_error(format!(
            "legacy table {} row count changed during migration",
            spec.name
        )));
    }

    Ok(())
}

fn migrate_staged_user_tables(
    transaction: &rusqlite::Transaction<'_>,
    staged: &HashSet<&str>,
) -> rusqlite::Result<()> {
    for spec in USER_TABLE_MIGRATION_SPECS {
        if staged.contains(spec.name) {
            if spec.name == "legal_answer_records"
                && legacy_legal_answer_unowned_count(transaction)? > 0
            {
                let quarantine_project_id = create_legacy_answer_quarantine_project(transaction)?;
                copy_legacy_legal_answers_into_quarantine(
                    transaction,
                    spec,
                    &quarantine_project_id,
                )?;
            } else {
                copy_legacy_user_table(transaction, spec)?;
            }
        }
    }

    validate_project_scoped_relations(transaction)?;

    for table in LEGACY_USER_TABLE_DROP_ORDER {
        if staged.contains(table) {
            transaction.execute(
                &format!("DROP TABLE \"{}\"", legacy_user_table_name(table)),
                [],
            )?;
        }
    }

    let mut statement = transaction.prepare("PRAGMA foreign_key_check")?;
    if statement.query([])?.next()?.is_some() {
        return Err(user_schema_migration_error(
            "foreign key violations remain after canonical migration".to_owned(),
        ));
    }

    Ok(())
}

fn validate_project_scoped_relations(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
    let invalid_evidence_link: bool = connection.query_row(
        "
        SELECT EXISTS(
            SELECT 1
            FROM evidence_links AS link
            LEFT JOIN case_facts AS fact
              ON fact.fact_id = link.fact_id
             AND fact.project_id = link.project_id
            LEFT JOIN evidence_items AS evidence
              ON evidence.evidence_id = link.evidence_id
             AND evidence.project_id = link.project_id
            WHERE fact.fact_id IS NULL OR evidence.evidence_id IS NULL
        )
        ",
        [],
        |row| row.get(0),
    )?;
    if invalid_evidence_link {
        return Err(user_schema_migration_error(
            "evidence links must reference a fact and evidence item from their own project"
                .to_owned(),
        ));
    }

    let invalid_fact_issue_link: bool = connection.query_row(
        "
        SELECT EXISTS(
            SELECT 1
            FROM fact_issue_links AS link
            LEFT JOIN case_facts AS fact
              ON fact.fact_id = link.fact_id
             AND fact.project_id = link.project_id
            LEFT JOIN legal_issues AS issue
              ON issue.issue_id = link.issue_id
             AND issue.project_id = link.project_id
            WHERE fact.fact_id IS NULL OR issue.issue_id IS NULL
        )
        ",
        [],
        |row| row.get(0),
    )?;
    if invalid_fact_issue_link {
        return Err(user_schema_migration_error(
            "fact-issue links must reference a fact and legal issue from their own project"
                .to_owned(),
        ));
    }

    let invalid_legal_basis: bool = connection.query_row(
        "
        SELECT EXISTS(
            SELECT 1
            FROM legal_basis AS basis
            LEFT JOIN legal_issues AS issue
              ON issue.issue_id = basis.issue_id
             AND issue.project_id = basis.project_id
            WHERE basis.issue_id IS NOT NULL AND issue.issue_id IS NULL
        )
        ",
        [],
        |row| row.get(0),
    )?;
    if invalid_legal_basis {
        return Err(user_schema_migration_error(
            "legal basis issue must belong to the same project".to_owned(),
        ));
    }

    Ok(())
}

fn validate_canonical_user_database(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    validate_canonical_user_table_shapes(connection)?;

    let marker = user_database_metadata_value(connection, USER_CANONICAL_SCHEMA_MARKER_KEY)?;
    if marker.as_deref() != Some(USER_CANONICAL_SCHEMA_MARKER_VALUE) {
        return Err(user_schema_migration_error(
            "canonical user schema marker is missing or invalid".to_owned(),
        )
        .into());
    }
    validate_exact_canonical_user_schema(connection)?;
    validate_project_scoped_relations(connection)?;
    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(user_schema_migration_error(
            "foreign key violations remain in user database".to_owned(),
        )
        .into());
    }
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(
            user_schema_migration_error("user database quick_check failed".to_owned()).into(),
        );
    }
    Ok(())
}

type UserSchemaObject = (String, String, String, String);

fn user_schema_objects(
    connection: &rusqlite::Connection,
) -> Result<Vec<UserSchemaObject>, DatabaseInitError> {
    let mut statement = connection.prepare(
        "
        SELECT type, name, tbl_name, COALESCE(sql, '')
        FROM sqlite_master
        WHERE type IN ('table', 'index', 'trigger', 'view')
          AND name NOT LIKE 'sqlite_%'
        ORDER BY type, name
        ",
    )?;
    let objects = statement
        .query_map([], |row| {
            let sql = row.get::<_, String>(3)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                sql.split_whitespace().collect::<Vec<_>>().join(" "),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(objects)
}

fn validate_exact_canonical_user_schema(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    // Generate the expected schema through the same canonical migration code
    // in a separate empty database. Comparing every non-internal sqlite_master
    // object proves PK/UNIQUE/CHECK/FK clauses, index definitions and complete
    // trigger bodies; matching column names or object names alone is not
    // sufficient for a restore trust boundary.
    let mut canonical = rusqlite::Connection::open_in_memory()?;
    canonical.pragma_update(None, "foreign_keys", "ON")?;
    canonical.pragma_update(None, "trusted_schema", "OFF")?;
    run_user_migrations(&mut canonical)?;

    if user_schema_objects(connection)? != user_schema_objects(&canonical)? {
        return Err(user_schema_migration_error(
            "user database sqlite_master does not match the exact canonical schema".to_owned(),
        )
        .into());
    }
    Ok(())
}

fn validate_canonical_user_table_shapes(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    let metadata_columns = table_columns(connection, "user_database_metadata")?;
    let expected_metadata_columns = ["key", "value", "updated_at"]
        .into_iter()
        .map(str::to_owned)
        .collect::<HashSet<_>>();
    if metadata_columns != expected_metadata_columns {
        return Err(user_schema_migration_error(
            "user_database_metadata does not match the canonical schema".to_owned(),
        )
        .into());
    }

    for spec in USER_TABLE_MIGRATION_SPECS {
        if !sqlite_table_exists(connection, spec.name)? {
            return Err(user_schema_migration_error(format!(
                "canonical user table is missing: {}",
                spec.name
            ))
            .into());
        }
        let found = table_columns(connection, spec.name)?;
        let expected = spec
            .canonical_columns
            .iter()
            .map(|column| (*column).to_owned())
            .collect::<HashSet<_>>();
        if found != expected {
            return Err(user_schema_migration_error(format!(
                "canonical user table has an unexpected shape: {}",
                spec.name
            ))
            .into());
        }
    }

    validate_fact_issue_schema_contract(connection)?;

    Ok(())
}

fn user_schema_migration_error(message: String) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CONSTRAINT),
        Some(message),
    )
}

fn user_database_metadata_value(
    connection: &rusqlite::Connection,
    key: &str,
) -> Result<Option<String>, DatabaseInitError> {
    connection
        .query_row(
            "SELECT value FROM user_database_metadata WHERE key = ?1",
            [key],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn run_user_migrations(connection: &mut rusqlite::Connection) -> Result<(), DatabaseInitError> {
    let existing_version = existing_user_schema_version(connection)?;
    let schema_version_value = USER_SCHEMA_VERSION.to_string();
    let expected_canonical_marker = USER_CANONICAL_SCHEMA_MARKER_VALUE;
    if let Some(found) = existing_version {
        if found > USER_SCHEMA_VERSION {
            return Err(DatabaseInitError::UnsupportedUserSchemaVersion {
                found,
                supported: USER_SCHEMA_VERSION,
            });
        }
    }
    let canonical_schema_marker = if existing_version.is_some() {
        user_database_metadata_value(connection, USER_CANONICAL_SCHEMA_MARKER_KEY)?
    } else {
        None
    };
    let mut known_user_table_exists = false;
    for spec in USER_TABLE_MIGRATION_SPECS {
        if sqlite_table_exists(connection, spec.name)? {
            known_user_table_exists = true;
            break;
        }
    }
    let needs_canonical_rebuild = match existing_version {
        Some(found) => {
            found < USER_SCHEMA_VERSION
                || (found == USER_SCHEMA_VERSION
                    && canonical_schema_marker.as_deref() != Some(expected_canonical_marker))
        }
        // A truly empty database can be initialized in place. Known tables
        // without a version are legacy or interrupted state and must not be
        // blessed with the canonical marker without rebuilding their shape.
        None => known_user_table_exists,
    };
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let staged_tables = if needs_canonical_rebuild {
        stage_legacy_user_tables(&transaction)?
    } else {
        HashSet::new()
    };

    transaction.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS user_database_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS provider_profiles (
            id TEXT PRIMARY KEY CHECK (length(id) > 0),
            kind TEXT NOT NULL CHECK (length(kind) > 0),
            display_name TEXT NOT NULL CHECK (length(display_name) > 0),
            model_id TEXT NOT NULL CHECK (length(model_id) > 0),
            base_url TEXT NOT NULL CHECK (length(base_url) > 0),
            credential_account_id TEXT NOT NULL CHECK (length(credential_account_id) > 0),
            capabilities_json TEXT NOT NULL,
            options_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_provider_profiles_kind
            ON provider_profiles(kind);

        CREATE TABLE IF NOT EXISTS projects (
            project_id TEXT PRIMARY KEY CHECK (length(project_id) > 0),
            title TEXT NOT NULL CHECK (length(title) > 0),
            case_type TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
            opened_on TEXT,
            summary TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS case_files (
            file_id TEXT PRIMARY KEY CHECK (length(file_id) > 0),
            project_id TEXT NOT NULL,
            title TEXT NOT NULL CHECK (length(title) > 0),
            file_type TEXT NOT NULL DEFAULT '',
            storage_reference TEXT NOT NULL DEFAULT '',
            summary TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS pending_extraction_reviews (
            review_id TEXT PRIMARY KEY CHECK (length(review_id) > 0),
            project_id TEXT NOT NULL UNIQUE,
            provider_id TEXT NOT NULL CHECK (length(provider_id) > 0),
            provider_snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK (
                json_valid(provider_snapshot_json)
                AND length(provider_snapshot_json) <= 65536
            ),
            source_file_ids_json TEXT NOT NULL,
            source_materials_digest TEXT NOT NULL DEFAULT '' CHECK (
                length(source_materials_digest) IN (0, 64)
            ),
            extraction_json TEXT NOT NULL,
            revision INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL DEFAULT (datetime(CURRENT_TIMESTAMP, '+7 days')),
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS case_extraction_confirmations (
            review_id TEXT PRIMARY KEY CHECK (length(review_id) > 0),
            project_id TEXT NOT NULL,
            provider_id TEXT NOT NULL CHECK (length(provider_id) > 0),
            provider_snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK (
                json_valid(provider_snapshot_json)
                AND length(provider_snapshot_json) <= 65536
            ),
            source_file_ids_json TEXT NOT NULL,
            confirmed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS case_parties (
            party_id TEXT PRIMARY KEY CHECK (length(party_id) > 0),
            project_id TEXT NOT NULL,
            name TEXT NOT NULL CHECK (length(name) > 0),
            normalized_name TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL CHECK (
                role IN ('plaintiff', 'defendant', 'claimant', 'respondent', 'third_party', 'other')
            ),
            contact TEXT NOT NULL DEFAULT '',
            notes TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS case_facts (
            fact_id TEXT PRIMARY KEY CHECK (length(fact_id) > 0),
            project_id TEXT NOT NULL,
            occurred_on TEXT,
            title TEXT NOT NULL CHECK (length(title) > 0),
            description TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            confirmation_status TEXT NOT NULL CHECK (
                confirmation_status IN ('model_suggested', 'confirmed')
            ),
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
            UNIQUE(project_id, fact_id)
        );

        CREATE TABLE IF NOT EXISTS evidence_items (
            evidence_id TEXT PRIMARY KEY CHECK (length(evidence_id) > 0),
            project_id TEXT NOT NULL,
            evidence_number TEXT NOT NULL CHECK (length(evidence_number) > 0),
            title TEXT NOT NULL CHECK (length(title) > 0),
            source TEXT NOT NULL DEFAULT '',
            formed_on TEXT,
            summary TEXT NOT NULL DEFAULT '',
            storage_reference TEXT NOT NULL DEFAULT '',
            confirmation_status TEXT NOT NULL CHECK (
                confirmation_status IN ('model_suggested', 'confirmed')
            ),
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
            UNIQUE(project_id, evidence_number),
            UNIQUE(project_id, evidence_id)
        );

        CREATE TABLE IF NOT EXISTS evidence_links (
            link_id TEXT PRIMARY KEY CHECK (length(link_id) > 0),
            project_id TEXT NOT NULL,
            fact_id TEXT NOT NULL,
            evidence_id TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
            FOREIGN KEY(project_id, fact_id)
                REFERENCES case_facts(project_id, fact_id) ON DELETE CASCADE,
            FOREIGN KEY(project_id, evidence_id)
                REFERENCES evidence_items(project_id, evidence_id) ON DELETE CASCADE,
            UNIQUE(fact_id, evidence_id)
        );

        CREATE TABLE IF NOT EXISTS legal_issues (
            issue_id TEXT PRIMARY KEY CHECK (length(issue_id) > 0),
            project_id TEXT NOT NULL,
            title TEXT NOT NULL CHECK (length(title) > 0),
            description TEXT NOT NULL DEFAULT '',
            claim TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
            confirmation_status TEXT NOT NULL CHECK (
                confirmation_status IN ('model_suggested', 'confirmed')
            ),
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
            UNIQUE(project_id, issue_id)
        );

        CREATE TABLE IF NOT EXISTS fact_issue_links (
            link_id TEXT PRIMARY KEY CHECK (length(link_id) > 0),
            project_id TEXT NOT NULL,
            fact_id TEXT NOT NULL,
            issue_id TEXT NOT NULL,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
            FOREIGN KEY(project_id, fact_id)
                REFERENCES case_facts(project_id, fact_id) ON DELETE CASCADE,
            FOREIGN KEY(project_id, issue_id)
                REFERENCES legal_issues(project_id, issue_id) ON DELETE CASCADE,
            UNIQUE(project_id, fact_id, issue_id)
        );

        CREATE TABLE IF NOT EXISTS case_uncertainties (
            uncertainty_id TEXT PRIMARY KEY CHECK (length(uncertainty_id) > 0),
            project_id TEXT NOT NULL,
            description TEXT NOT NULL CHECK (length(description) > 0),
            related_entity_type TEXT NOT NULL DEFAULT 'general' CHECK (
                related_entity_type IN ('general', 'party', 'fact', 'evidence', 'legal_issue')
            ),
            related_entity_id TEXT,
            source_file_ids_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
            resolution TEXT NOT NULL DEFAULT '',
            confirmation_status TEXT NOT NULL CHECK (
                confirmation_status IN ('model_suggested', 'confirmed')
            ),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS legal_basis (
            basis_id TEXT PRIMARY KEY CHECK (length(basis_id) > 0),
            project_id TEXT NOT NULL,
            issue_id TEXT,
            source_id TEXT NOT NULL CHECK (length(source_id) > 0),
            status TEXT NOT NULL CHECK (status IN ('valid', 'invalid')),
            invalid_reason TEXT,
            case_date TEXT,
            article_id TEXT NOT NULL DEFAULT '',
            document_id TEXT NOT NULL DEFAULT '',
            version_id TEXT NOT NULL DEFAULT '',
            document_title TEXT NOT NULL DEFAULT '',
            version_label TEXT NOT NULL DEFAULT '',
            article_number TEXT NOT NULL DEFAULT '',
            article_title TEXT,
            canonical_label TEXT NOT NULL DEFAULT '',
            effective_from TEXT NOT NULL DEFAULT '',
            effective_to TEXT,
            version_status TEXT NOT NULL DEFAULT '',
            excerpt TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
            FOREIGN KEY(issue_id) REFERENCES legal_issues(issue_id) ON DELETE SET NULL
        );

        CREATE TRIGGER IF NOT EXISTS trg_legal_basis_issue_project_insert
        BEFORE INSERT ON legal_basis
        WHEN NEW.issue_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM legal_issues
            WHERE issue_id = NEW.issue_id AND project_id = NEW.project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'legal basis issue must belong to the same project');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_legal_basis_issue_project_update
        BEFORE UPDATE OF project_id, issue_id ON legal_basis
        WHEN NEW.issue_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM legal_issues
            WHERE issue_id = NEW.issue_id AND project_id = NEW.project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'legal basis issue must belong to the same project');
        END;

        CREATE INDEX IF NOT EXISTS idx_projects_updated
            ON projects(updated_at);
        CREATE INDEX IF NOT EXISTS idx_case_files_project
            ON case_files(project_id);
        CREATE INDEX IF NOT EXISTS idx_pending_extraction_reviews_expires
            ON pending_extraction_reviews(expires_at);
        CREATE INDEX IF NOT EXISTS idx_case_extraction_confirmations_project
            ON case_extraction_confirmations(project_id, confirmed_at);
        CREATE INDEX IF NOT EXISTS idx_case_parties_project
            ON case_parties(project_id, name);
        CREATE INDEX IF NOT EXISTS idx_case_facts_project
            ON case_facts(project_id, occurred_on);
        CREATE INDEX IF NOT EXISTS idx_evidence_items_project
            ON evidence_items(project_id, evidence_number);
        CREATE INDEX IF NOT EXISTS idx_evidence_links_project
            ON evidence_links(project_id);
        CREATE INDEX IF NOT EXISTS idx_fact_issue_links_project
            ON fact_issue_links(project_id, issue_id, fact_id);
        CREATE INDEX IF NOT EXISTS idx_legal_issues_project
            ON legal_issues(project_id);
        CREATE INDEX IF NOT EXISTS idx_case_uncertainties_project
            ON case_uncertainties(project_id, status);
        CREATE INDEX IF NOT EXISTS idx_legal_basis_project
            ON legal_basis(project_id, issue_id);

        CREATE TABLE IF NOT EXISTS legal_answer_records (
            record_id TEXT PRIMARY KEY CHECK (length(record_id) > 0),
            project_id TEXT NOT NULL CHECK (length(project_id) > 0),
            provider_id TEXT NOT NULL CHECK (length(provider_id) > 0),
            provider_snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK (
                json_valid(provider_snapshot_json)
                AND length(provider_snapshot_json) <= 65536
            ),
            question TEXT NOT NULL CHECK (length(question) > 0),
            answer_text TEXT NOT NULL DEFAULT '',
            case_date TEXT,
            query_json TEXT NOT NULL,
            source_ids_json TEXT NOT NULL,
            verified_citations_json TEXT NOT NULL,
            invalid_citations_json TEXT NOT NULL,
            unsupported_legal_conclusion INTEGER NOT NULL CHECK (
                unsupported_legal_conclusion IN (0, 1)
            ),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_legal_answer_records_created
            ON legal_answer_records(created_at);
        CREATE INDEX IF NOT EXISTS idx_legal_answer_records_project_created
            ON legal_answer_records(project_id, created_at);

        CREATE TABLE IF NOT EXISTS document_generation_records (
            record_id TEXT PRIMARY KEY CHECK (length(record_id) > 0),
            project_id TEXT NOT NULL,
            template_id TEXT NOT NULL CHECK (length(template_id) > 0),
            template_version TEXT NOT NULL CHECK (length(template_version) > 0),
            source_ids_json TEXT NOT NULL CHECK (json_valid(source_ids_json)),
            citation_ids_json TEXT NOT NULL CHECK (json_valid(citation_ids_json)),
            export_path TEXT NOT NULL DEFAULT '',
            exported_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_document_generation_project_exported
            ON document_generation_records(project_id, exported_at);
        ",
    )?;

    if !staged_tables.is_empty() {
        migrate_staged_user_tables(&transaction, &staged_tables)?;
    }

    transaction.execute(
        "
        INSERT INTO user_database_metadata (key, value)
        VALUES ('schema_version', ?1)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        ",
        [schema_version_value.as_str()],
    )?;
    transaction.execute(
        "
        INSERT INTO user_database_metadata (key, value)
        VALUES (?1, ?2)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        ",
        (USER_CANONICAL_SCHEMA_MARKER_KEY, expected_canonical_marker),
    )?;

    transaction.commit()?;

    Ok(())
}

fn existing_user_schema_version(
    connection: &rusqlite::Connection,
) -> Result<Option<i64>, DatabaseInitError> {
    let metadata_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'user_database_metadata')",
        [],
        |row| row.get(0),
    )?;
    if !metadata_exists {
        return Ok(None);
    }
    let value = connection
        .query_row(
            "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    value
        .map(|value| {
            value
                .parse::<i64>()
                .map_err(|_| DatabaseInitError::InvalidUserSchemaVersion(value))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_database_is_created_under_app_local_data_dir() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");

        assert_eq!(database_path, directory.path().join(USER_DB_FILE_NAME));
        assert!(database_path.is_file());
    }

    #[test]
    fn user_database_waits_for_a_short_competing_writer_and_then_succeeds() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut first = open_user_database(&database_path).expect("first connection opens");
        let second = open_user_database(&database_path).expect("second connection opens");
        let configured_timeout_ms: i64 = second
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .expect("busy timeout reads");
        assert_eq!(configured_timeout_ms, 5_000);

        let first_write = first
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("first writer acquires lock");
        first_write
            .execute(
                "INSERT INTO projects (project_id, title, status)
                 VALUES ('writer-one', 'Writer one', 'active')",
                [],
            )
            .expect("first writer inserts while holding transaction");

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            started_tx.send(()).expect("contender start signal sends");
            let result = second
                .execute(
                    "INSERT INTO projects (project_id, title, status)
                     VALUES ('writer-two', 'Writer two', 'active')",
                    [],
                )
                .map_err(|error| error.to_string());
            finished_tx
                .send(result)
                .expect("contender completion signal sends");
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("contender starts");
        assert!(finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err());
        first_write.commit().expect("first writer releases lock");
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("contender finishes after lock release")
            .expect("contending write succeeds within busy timeout");
        contender.join().expect("contender exits");

        let connection = open_user_database(&database_path).expect("database reopens");
        let project_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id LIKE 'writer-%'",
                [],
                |row| row.get(0),
            )
            .expect("both writes are visible");
        assert_eq!(project_count, 2);
    }

    #[test]
    fn read_then_write_command_waits_for_writer_before_starting_transaction() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut first = open_user_database(&database_path).expect("first connection opens");
        seed_project(&first, "project-lock");
        upsert_case_file(
            &first,
            &CaseFileRow {
                file_id: "file-lock".to_owned(),
                project_id: "project-lock".to_owned(),
                title: "Lock test file".to_owned(),
                file_type: String::new(),
                storage_reference: String::new(),
                summary: String::new(),
                created_at: String::new(),
            },
        )
        .expect("file inserts");
        let mut second = open_user_database(&database_path).expect("second connection opens");

        let first_write = first
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("first writer acquires lock");
        first_write
            .execute(
                "UPDATE projects SET summary = 'writer-held' WHERE project_id = 'project-lock'",
                [],
            )
            .expect("first writer updates while holding transaction");

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            started_tx.send(()).expect("contender start signal sends");
            let result = delete_case_entity(
                &mut second,
                "case_files",
                "file_id",
                "file-lock",
                "project-lock",
            )
            .map_err(|error| error.to_string());
            finished_tx
                .send(result)
                .expect("contender completion signal sends");
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("contender starts");
        assert!(finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err());
        first_write.commit().expect("first writer releases lock");
        assert!(finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("read-then-write command finishes after lock release")
            .expect("read-then-write command succeeds within busy timeout"));
        contender.join().expect("contender exits");

        let connection = open_user_database(&database_path).expect("database reopens");
        assert_eq!(table_row_count(&connection, "case_files"), 0);
    }

    #[test]
    fn canonical_migration_waits_for_competing_writer_before_rebuild() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        seed_unversioned_weak_projects_database(&database_path, true);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("unmarked legacy database opens");
            connection
                .execute(
                    "INSERT INTO user_database_metadata (key, value)
                     VALUES ('schema_version', '6')",
                    [],
                )
                .expect("legacy schema version inserts");
        }

        let mut first = open_user_database(&database_path).expect("first connection opens");
        let first_write = first
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("first writer acquires lock");
        first_write
            .execute(
                "UPDATE projects SET summary = 'committed-before-rebuild'
                 WHERE project_id = 'unversioned-project'",
                [],
            )
            .expect("legacy writer updates while holding transaction");

        let directory_path = directory.path().to_path_buf();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            started_tx.send(()).expect("migration start signal sends");
            let result = ensure_user_database(&directory_path).map_err(|error| error.to_string());
            finished_tx
                .send(result)
                .expect("migration completion signal sends");
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("migration starts");
        assert!(finished_rx
            .recv_timeout(Duration::from_millis(150))
            .is_err());
        first_write.commit().expect("first writer releases lock");
        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("migration finishes after lock release")
            .expect("migration succeeds within busy timeout");
        contender.join().expect("migration contender exits");

        assert_rebuilt_unversioned_project_database(&database_path);
        let connection = open_user_database(&database_path).expect("rebuilt database opens");
        let summary: String = connection
            .query_row(
                "SELECT summary FROM projects WHERE project_id = 'unversioned-project'",
                [],
                |row| row.get(0),
            )
            .expect("committed legacy update survives rebuild");
        assert_eq!(summary, "committed-before-rebuild");
    }

    #[test]
    fn user_database_uses_transaction_migration() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let connection = open_user_database(&database_path).expect("user database opens");

        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version exists");

        assert_eq!(schema_version, USER_SCHEMA_VERSION.to_string());
    }

    #[test]
    fn claimed_current_backup_rejects_weakened_fact_issue_schema_contract() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("canonical database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            connection
                .execute_batch(
                    "DROP TABLE fact_issue_links;
                     CREATE TABLE fact_issue_links (
                         link_id TEXT PRIMARY KEY,
                         project_id TEXT NOT NULL,
                         fact_id TEXT NOT NULL,
                         issue_id TEXT NOT NULL,
                         UNIQUE(project_id, fact_id, issue_id)
                     );
                     CREATE INDEX idx_fact_issue_links_project
                         ON fact_issue_links(project_id, issue_id, fact_id);",
                )
                .expect("fact-issue table is replaced by a shape-compatible weak table");
        }

        let error = validate_and_migrate_user_database(&database_path)
            .expect_err("a current marker cannot bless missing project-scope foreign keys");
        assert!(error
            .to_string()
            .contains("fact_issue_links foreign-key contract"));
    }

    #[test]
    fn claimed_current_backup_rejects_same_columns_with_weakened_legacy_constraints() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("canonical database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            connection
                .execute_batch(
                    "DROP TABLE evidence_links;
                     CREATE TABLE evidence_links (
                         link_id TEXT,
                         project_id TEXT,
                         fact_id TEXT,
                         evidence_id TEXT
                     );
                     CREATE INDEX idx_evidence_links_project
                         ON evidence_links(link_id);
                     DROP TRIGGER trg_legal_basis_issue_project_insert;
                     CREATE TRIGGER trg_legal_basis_issue_project_insert
                     BEFORE INSERT ON legal_basis
                     BEGIN
                         SELECT 1;
                     END;",
                )
                .expect("legacy relationship constraints are weakened without changing names");
        }

        let error = validate_and_migrate_user_database(&database_path)
            .expect_err("a current marker cannot bless weak tables, indexes or trigger bodies");
        assert!(error
            .to_string()
            .contains("sqlite_master does not match the exact canonical schema"));
    }

    #[test]
    fn canonical_migration_adds_zero_revision_to_existing_pending_reviews() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        let connection = rusqlite::Connection::open(&database_path).expect("legacy database opens");
        connection
            .execute_batch(
                "
                CREATE TABLE user_database_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO user_database_metadata (key, value)
                VALUES ('schema_version', '7');
                INSERT INTO user_database_metadata (key, value)
                VALUES (
                    'canonical_schema_version',
                    'v7-answer-ownership-pending-review-quarantine-20260714'
                );
                CREATE TABLE projects (
                    project_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                INSERT INTO projects (project_id, title, status)
                VALUES ('project-pending-migration', 'Pending migration', 'active');
                CREATE TABLE pending_extraction_reviews (
                    review_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL UNIQUE,
                    provider_id TEXT NOT NULL,
                    source_file_ids_json TEXT NOT NULL,
                    extraction_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    expires_at TEXT NOT NULL
                );
                INSERT INTO pending_extraction_reviews (
                    review_id, project_id, provider_id, source_file_ids_json,
                    extraction_json, expires_at
                ) VALUES (
                    'review-pending-migration', 'project-pending-migration', 'provider',
                    '[\"file\"]',
                    '{\"parties\":[],\"facts\":[],\"evidence\":[],\"legalIssues\":[],\"uncertainties\":[]}',
                    datetime(CURRENT_TIMESTAMP, '+30 minutes')
                );
                ",
            )
            .expect("legacy pending review schema seeds");
        drop(connection);

        ensure_user_database(directory.path()).expect("pending review schema migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let row = get_pending_extraction_review(&connection, "review-pending-migration")
            .expect("migrated review reads")
            .expect("migrated review remains");
        assert_eq!(row.revision, 0);
        assert_eq!(
            row.provider_snapshot_json, "{}",
            "legacy review must not invent a provider audit snapshot"
        );
        assert_eq!(
            row.source_materials_digest, "",
            "legacy review has no trustworthy prompt snapshot and must fail closed on confirm"
        );
        connection
            .execute(
                "UPDATE pending_extraction_reviews SET revision = -1
                 WHERE review_id = 'review-pending-migration'",
                [],
            )
            .expect_err("canonical revision constraint rejects negative revisions");
    }

    #[test]
    fn user_database_migrates_v1_to_provider_profile_schema() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '1');
                    ",
                )
                .expect("legacy schema writes");
        }

        ensure_user_database(directory.path()).expect("legacy database migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version exists");
        let provider_profile_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'provider_profiles'",
                [],
                |row| row.get(0),
            )
            .expect("sqlite_master can be queried");

        assert_eq!(schema_version, USER_SCHEMA_VERSION.to_string());
        assert_eq!(provider_profile_count, 1);
    }

    #[test]
    fn user_database_migrates_v2_to_case_schema() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE provider_profiles (
                        id TEXT PRIMARY KEY,
                        kind TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        base_url TEXT NOT NULL,
                        credential_account_id TEXT NOT NULL,
                        capabilities_json TEXT NOT NULL,
                        options_json TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '2');
                    ",
                )
                .expect("legacy schema writes");
        }

        ensure_user_database(directory.path()).expect("legacy database migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");

        for table in [
            "projects",
            "case_files",
            "pending_extraction_reviews",
            "case_extraction_confirmations",
            "case_parties",
            "case_facts",
            "evidence_items",
            "evidence_links",
            "fact_issue_links",
            "legal_issues",
            "case_uncertainties",
            "legal_basis",
            "legal_answer_records",
        ] {
            assert_eq!(sqlite_master_count(&connection, table), 1, "{table} exists");
        }
    }

    #[test]
    fn user_database_migrates_v3_to_legal_answer_records() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE provider_profiles (
                        id TEXT PRIMARY KEY,
                        kind TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        base_url TEXT NOT NULL,
                        credential_account_id TEXT NOT NULL,
                        capabilities_json TEXT NOT NULL,
                        options_json TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        case_type TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        opened_on TEXT,
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE case_files (
                        file_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        file_type TEXT NOT NULL DEFAULT '',
                        storage_reference TEXT NOT NULL DEFAULT '',
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE case_parties (
                        party_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        normalized_name TEXT NOT NULL DEFAULT '',
                        role TEXT NOT NULL,
                        contact TEXT NOT NULL DEFAULT '',
                        notes TEXT NOT NULL DEFAULT ''
                    );
                    CREATE TABLE case_facts (
                        fact_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        occurred_on TEXT,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        source TEXT NOT NULL DEFAULT '',
                        confirmation_status TEXT NOT NULL
                    );
                    CREATE TABLE evidence_items (
                        evidence_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        evidence_number TEXT NOT NULL,
                        title TEXT NOT NULL,
                        source TEXT NOT NULL DEFAULT '',
                        formed_on TEXT,
                        summary TEXT NOT NULL DEFAULT '',
                        storage_reference TEXT NOT NULL DEFAULT '',
                        confirmation_status TEXT NOT NULL
                    );
                    CREATE TABLE evidence_links (
                        link_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        fact_id TEXT NOT NULL,
                        evidence_id TEXT NOT NULL
                    );
                    CREATE TABLE legal_issues (
                        issue_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        claim TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        confirmation_status TEXT NOT NULL
                    );
                    INSERT INTO provider_profiles (
                        id, kind, display_name, model_id, base_url,
                        credential_account_id, capabilities_json, options_json
                    ) VALUES (
                        'legacy-provider', 'deep_seek', 'Legacy Provider', 'legacy-model',
                        'https://api.deepseek.com', 'legacy-account', '{}', '{}'
                    );
                    INSERT INTO projects (
                        project_id, title, case_type, status, opened_on, summary
                    ) VALUES (
                        'legacy-project', 'Legacy project', 'contract', 'active',
                        '2024-01-01', 'Preserved project'
                    );
                    INSERT INTO case_files (
                        file_id, project_id, title, file_type, storage_reference, summary
                    ) VALUES (
                        'legacy-file', 'legacy-project', 'Legacy material', 'text',
                        'legacy.txt', 'Preserved material'
                    );
                    INSERT INTO case_parties (
                        party_id, project_id, name, normalized_name, role, contact, notes
                    ) VALUES (
                        'legacy-party', 'legacy-project', 'Legacy party', 'legacyparty',
                        'plaintiff', '', 'Preserved party'
                    );
                    INSERT INTO case_facts (
                        fact_id, project_id, occurred_on, title, description, source,
                        confirmation_status
                    ) VALUES (
                        'legacy-fact', 'legacy-project', '2024-01-02', 'Legacy fact',
                        'Preserved fact', 'manual', 'confirmed'
                    );
                    INSERT INTO evidence_items (
                        evidence_id, project_id, evidence_number, title, source, formed_on,
                        summary, storage_reference, confirmation_status
                    ) VALUES (
                        'legacy-evidence', 'legacy-project', 'E-1', 'Legacy evidence',
                        'manual', '2024-01-03', 'Preserved evidence', 'evidence.txt', 'confirmed'
                    );
                    INSERT INTO evidence_links (link_id, project_id, fact_id, evidence_id)
                    VALUES (
                        'legacy-link', 'legacy-project', 'legacy-fact', 'legacy-evidence'
                    );
                    INSERT INTO legal_issues (
                        issue_id, project_id, title, description, claim, status,
                        confirmation_status
                    ) VALUES (
                        'legacy-issue', 'legacy-project', 'Legacy issue', 'Preserved issue',
                        'Legacy claim', 'open', 'confirmed'
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '3');
                    ",
                )
                .expect("legacy schema writes");
        }

        ensure_user_database(directory.path()).expect("legacy database migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version exists");

        assert_eq!(schema_version, USER_SCHEMA_VERSION.to_string());
        assert_eq!(sqlite_master_count(&connection, "legal_answer_records"), 1);
        assert_eq!(sqlite_master_count(&connection, "legal_basis"), 1);

        let migrated_fact: String = connection
            .query_row(
                "SELECT description FROM case_facts WHERE fact_id = 'legacy-fact'",
                [],
                |row| row.get(0),
            )
            .expect("non-empty legacy fact survives migration");
        assert_eq!(migrated_fact, "Preserved fact");
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM evidence_links", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("migrated link count reads"),
            1
        );

        let foreign_keys = {
            let mut statement = connection
                .prepare("PRAGMA foreign_key_list(evidence_links)")
                .expect("foreign key list prepares");
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(6)?,
                    ))
                })
                .expect("foreign key list queries")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("foreign key list collects")
        };
        assert!(foreign_keys.contains(&(
            "projects".to_owned(),
            "project_id".to_owned(),
            "CASCADE".to_owned()
        )));
        assert!(foreign_keys.contains(&(
            "case_facts".to_owned(),
            "fact_id".to_owned(),
            "CASCADE".to_owned()
        )));
        assert!(foreign_keys.contains(&(
            "evidence_items".to_owned(),
            "evidence_id".to_owned(),
            "CASCADE".to_owned()
        )));

        let evidence_indexes = {
            let mut statement = connection
                .prepare("PRAGMA index_list(evidence_items)")
                .expect("index list prepares");
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)? != 0))
                })
                .expect("index list queries")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("index list collects")
        };
        assert!(evidence_indexes
            .iter()
            .any(|(name, _)| name == "idx_evidence_items_project"));
        assert!(evidence_indexes.iter().any(|(_, unique)| *unique));

        let check_error = connection
            .execute(
                "INSERT INTO projects (project_id, title, status) VALUES ('bad', 'Bad', 'invalid')",
                [],
            )
            .expect_err("canonical project CHECK rejects invalid status");
        assert!(matches!(check_error, rusqlite::Error::SqliteFailure(_, _)));
        let unique_error = connection
            .execute(
                "INSERT INTO evidence_items (
                    evidence_id, project_id, evidence_number, title, confirmation_status
                 ) VALUES ('duplicate-evidence', 'legacy-project', 'E-1', 'Duplicate', 'confirmed')",
                [],
            )
            .expect_err("canonical evidence UNIQUE rejects duplicate project number");
        assert!(matches!(unique_error, rusqlite::Error::SqliteFailure(_, _)));

        connection
            .execute(
                "DELETE FROM projects WHERE project_id = 'legacy-project'",
                [],
            )
            .expect("canonical project cascade deletes migrated children");
        for table in [
            "case_files",
            "case_parties",
            "case_facts",
            "evidence_items",
            "evidence_links",
            "fact_issue_links",
            "legal_issues",
        ] {
            let remaining: i64 = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .expect("child count reads after cascade");
            assert_eq!(remaining, 0, "{table} cascades after migration");
        }
    }

    #[test]
    fn user_database_migrates_v4_to_legal_basis_schema() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE provider_profiles (
                        id TEXT PRIMARY KEY,
                        kind TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        model_id TEXT NOT NULL,
                        base_url TEXT NOT NULL,
                        credential_account_id TEXT NOT NULL,
                        capabilities_json TEXT NOT NULL,
                        options_json TEXT NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        case_type TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        opened_on TEXT,
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE legal_issues (
                        issue_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        claim TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        confirmation_status TEXT NOT NULL
                    );
                    CREATE TABLE legal_answer_records (
                        record_id TEXT PRIMARY KEY,
                        provider_id TEXT NOT NULL,
                        question TEXT NOT NULL,
                        answer_text TEXT NOT NULL DEFAULT '',
                        case_date TEXT,
                        query_json TEXT NOT NULL,
                        source_ids_json TEXT NOT NULL,
                        verified_citations_json TEXT NOT NULL,
                        invalid_citations_json TEXT NOT NULL,
                        unsupported_legal_conclusion INTEGER NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '4');
                    ",
                )
                .expect("legacy schema writes");
        }

        ensure_user_database(directory.path()).expect("legacy database migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version exists");

        assert_eq!(schema_version, USER_SCHEMA_VERSION.to_string());
        assert_eq!(sqlite_master_count(&connection, "legal_basis"), 1);
        assert_eq!(
            table_row_count(&connection, "projects"),
            0,
            "an empty legacy answer table must not create a quarantine project"
        );
    }

    #[test]
    fn user_database_migrates_v6_answers_into_collision_safe_deletable_quarantine() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        case_type TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        opened_on TEXT,
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE legal_answer_records (
                        record_id TEXT PRIMARY KEY,
                        provider_id TEXT NOT NULL,
                        question TEXT NOT NULL,
                        answer_text TEXT NOT NULL DEFAULT '',
                        case_date TEXT,
                        query_json TEXT NOT NULL,
                        source_ids_json TEXT NOT NULL,
                        verified_citations_json TEXT NOT NULL,
                        invalid_citations_json TEXT NOT NULL,
                        unsupported_legal_conclusion INTEGER NOT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO projects (project_id, title, status)
                    VALUES ('legacy-project', 'Legacy project', 'active');
                    INSERT INTO projects (project_id, title, status)
                    VALUES (
                        'migration-unassigned-legal-answers',
                        'User project occupying the reserved-looking ID',
                        'active'
                    );
                    INSERT INTO legal_answer_records (
                        record_id, provider_id, question, answer_text, case_date,
                        query_json, source_ids_json, verified_citations_json,
                        invalid_citations_json, unsupported_legal_conclusion, created_at
                    ) VALUES (
                        'legacy-answer', 'legacy-provider', 'Preserve question',
                        'Preserve answer', '2024-01-02', '{\"keywords\":[\"breach\"]}',
                        '[\"source-1\"]',
                        '[{\"rawMarker\":\"[SRC:source-1]\",\"sourceId\":\"source-1\",\"status\":\"valid\",\"reason\":null,\"source\":null}]',
                        '[]', 0,
                        '2026-07-13 10:00:00'
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '6');
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('canonical_schema_version', 'v6-project-scope-integrity-20260713');
                    ",
                )
                .expect("v6 fixture writes");
        }

        ensure_user_database(directory.path()).expect("v6 database migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let migrated = connection
            .query_row(
                "SELECT project_id, provider_id, question, answer_text, case_date,
                        query_json, source_ids_json, verified_citations_json,
                        invalid_citations_json, unsupported_legal_conclusion, created_at
                 FROM legal_answer_records WHERE record_id = 'legacy-answer'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, i64>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                },
            )
            .expect("legacy answer survives");
        let quarantine_project_id = format!("{LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX}-1");
        assert_eq!(
            migrated.0, quarantine_project_id,
            "the pre-existing base ID must never receive unowned records"
        );
        assert_eq!(migrated.1, "legacy-provider");
        assert_eq!(migrated.2, "Preserve question");
        assert_eq!(migrated.3, "Preserve answer");
        assert_eq!(migrated.4.as_deref(), Some("2024-01-02"));
        assert_eq!(migrated.5, r#"{"keywords":["breach"]}"#);
        assert_eq!(migrated.6, r#"["source-1"]"#);
        assert_eq!(
            migrated.7,
            r#"[{"rawMarker":"[SRC:source-1]","sourceId":"source-1","status":"valid","reason":null,"source":null}]"#
        );
        assert_eq!(migrated.8, "[]");
        assert_eq!(migrated.9, 0);
        assert_eq!(migrated.10, "2026-07-13 10:00:00");

        let quarantine = connection
            .query_row(
                "SELECT title, status, summary FROM projects WHERE project_id = ?1",
                [&quarantine_project_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("quarantine project is visible and recoverable");
        assert_eq!(quarantine.0, LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE);
        assert_eq!(quarantine.1, "archived");
        assert_eq!(quarantine.2, LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY);
        let project_id_not_null: i64 = connection
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('legal_answer_records')
                 WHERE name = 'project_id'",
                [],
                |row| row.get(0),
            )
            .expect("canonical project ownership constraint reads");
        assert_eq!(project_id_not_null, 1);
        assert_eq!(
            list_legal_answer_records_for_project(&connection, &quarantine_project_id, 10)
                .expect("quarantined history is readable")
                .len(),
            1
        );
        assert!(
            case_project_exists(&connection, LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX)
                .expect("colliding user project remains")
        );
        assert!(delete_case_project(&connection, &quarantine_project_id)
            .expect("quarantine project deletes"));
        assert_eq!(
            table_row_count(&connection, "legal_answer_records"),
            0,
            "deleting the quarantine project removes every legacy sensitive answer"
        );
        assert!(
            case_project_exists(&connection, LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX)
                .expect("colliding user project still remains after quarantine deletion")
        );
    }

    #[test]
    fn user_database_migrates_v5_to_uncertainty_schema_without_losing_projects() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        case_type TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        opened_on TEXT,
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO projects (project_id, title, status)
                    VALUES ('legacy-project', 'Legacy project', 'active');
                    CREATE TABLE case_facts (
                        fact_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        occurred_on TEXT,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL DEFAULT '',
                        source TEXT NOT NULL DEFAULT '',
                        confirmation_status TEXT NOT NULL,
                        FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE
                    );
                    INSERT INTO case_facts (
                        fact_id, project_id, title, description, source, confirmation_status
                    ) VALUES (
                        'legacy-fact', 'legacy-project', 'Legacy fact', 'Kept during migration',
                        'manual', 'confirmed'
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '5');
                    ",
                )
                .expect("v5 schema writes");
        }

        ensure_user_database(directory.path()).expect("v5 database migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version exists");
        let project_title: String = connection
            .query_row(
                "SELECT title FROM projects WHERE project_id = 'legacy-project'",
                [],
                |row| row.get(0),
            )
            .expect("legacy project remains");

        assert_eq!(schema_version, USER_SCHEMA_VERSION.to_string());
        assert_eq!(project_title, "Legacy project");
        assert_eq!(sqlite_master_count(&connection, "case_uncertainties"), 1);
        let workspace = get_case_workspace_rows(&connection, "legacy-project")
            .expect("legacy workspace reads")
            .expect("legacy workspace exists");
        assert_eq!(workspace.facts[0].title, "Legacy fact");
    }

    #[test]
    fn user_database_migration_failure_rolls_back() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '2');
                    CREATE TABLE case_parties (
                        party_id TEXT PRIMARY KEY
                    );
                    ",
                )
                .expect("broken legacy schema writes");
        }

        let error = ensure_user_database(directory.path())
            .expect_err("broken schema causes migration failure");
        assert!(matches!(error, DatabaseInitError::Sqlite(_)));

        let connection = rusqlite::Connection::open(&database_path).expect("database reopens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version still exists");

        assert_eq!(schema_version, "2");
        assert_eq!(sqlite_master_count(&connection, "projects"), 0);
        assert_eq!(sqlite_master_count(&connection, "case_uncertainties"), 0);
    }

    #[test]
    fn invalid_legacy_rows_abort_canonical_rebuild_without_data_loss() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        case_type TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        opened_on TEXT,
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO projects (project_id, title, status)
                    VALUES ('invalid-project', 'Must survive rollback', 'legacy-invalid-status');
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '3');
                    ",
                )
                .expect("invalid legacy row is representable before canonical migration");
        }

        let error = ensure_user_database(directory.path())
            .expect_err("invalid legacy CHECK value aborts migration");
        assert!(matches!(error, DatabaseInitError::Sqlite(_)));

        let connection = rusqlite::Connection::open(&database_path).expect("database reopens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("old schema version survives rollback");
        let status: String = connection
            .query_row(
                "SELECT status FROM projects WHERE project_id = 'invalid-project'",
                [],
                |row| row.get(0),
            )
            .expect("invalid legacy row is not silently deleted");

        assert_eq!(schema_version, "3");
        assert_eq!(status, "legacy-invalid-status");
        assert_eq!(sqlite_master_count(&connection, "provider_profiles"), 0);
        assert_eq!(
            sqlite_master_count(&connection, "__lawyer_assistance_v6_legacy_projects"),
            0
        );
    }

    #[test]
    fn cross_project_legacy_evidence_link_aborts_rebuild_without_data_loss() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        status TEXT NOT NULL
                    );
                    CREATE TABLE case_facts (
                        fact_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        confirmation_status TEXT NOT NULL
                    );
                    CREATE TABLE evidence_items (
                        evidence_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        evidence_number TEXT NOT NULL,
                        title TEXT NOT NULL,
                        confirmation_status TEXT NOT NULL
                    );
                    CREATE TABLE evidence_links (
                        link_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        fact_id TEXT NOT NULL,
                        evidence_id TEXT NOT NULL
                    );
                    INSERT INTO projects (project_id, title, status) VALUES
                        ('project-a', 'Project A', 'active'),
                        ('project-b', 'Project B', 'active');
                    INSERT INTO case_facts (
                        fact_id, project_id, title, confirmation_status
                    ) VALUES ('fact-a', 'project-a', 'Fact A', 'confirmed');
                    INSERT INTO evidence_items (
                        evidence_id, project_id, evidence_number, title, confirmation_status
                    ) VALUES ('evidence-b', 'project-b', 'B-1', 'Evidence B', 'confirmed');
                    INSERT INTO evidence_links (link_id, project_id, fact_id, evidence_id)
                    VALUES ('cross-link', 'project-a', 'fact-a', 'evidence-b');
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '3');
                    ",
                )
                .expect("cross-project legacy link is representable");
        }

        let error = ensure_user_database(directory.path())
            .expect_err("cross-project legacy evidence link aborts canonical rebuild");
        assert!(matches!(error, DatabaseInitError::Sqlite(_)));

        let connection =
            rusqlite::Connection::open(&database_path).expect("legacy database reopens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("legacy schema version survives rollback");
        assert_eq!(schema_version, "3");
        assert_eq!(table_row_count(&connection, "evidence_links"), 1);
        assert_eq!(
            sqlite_master_count(&connection, "__lawyer_assistance_v6_legacy_evidence_links"),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM user_database_metadata WHERE key = ?1",
                    [USER_CANONICAL_SCHEMA_MARKER_KEY],
                    |row| row.get::<_, i64>(0),
                )
                .expect("marker absence is queryable"),
            0
        );
    }

    #[test]
    fn cross_project_legacy_legal_basis_aborts_rebuild_without_data_loss() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        status TEXT NOT NULL
                    );
                    CREATE TABLE legal_issues (
                        issue_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        status TEXT NOT NULL,
                        confirmation_status TEXT NOT NULL
                    );
                    CREATE TABLE legal_basis (
                        basis_id TEXT PRIMARY KEY,
                        project_id TEXT NOT NULL,
                        issue_id TEXT,
                        source_id TEXT NOT NULL,
                        status TEXT NOT NULL
                    );
                    INSERT INTO projects (project_id, title, status) VALUES
                        ('project-a', 'Project A', 'active'),
                        ('project-b', 'Project B', 'active');
                    INSERT INTO legal_issues (
                        issue_id, project_id, title, status, confirmation_status
                    ) VALUES ('issue-b', 'project-b', 'Issue B', 'open', 'confirmed');
                    INSERT INTO legal_basis (basis_id, project_id, issue_id, source_id, status)
                    VALUES ('cross-basis', 'project-a', 'issue-b', 'law:test', 'valid');
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '4');
                    ",
                )
                .expect("cross-project legacy legal basis is representable");
        }

        let error = ensure_user_database(directory.path())
            .expect_err("cross-project legacy legal basis aborts canonical rebuild");
        assert!(matches!(error, DatabaseInitError::Sqlite(_)));

        let connection =
            rusqlite::Connection::open(&database_path).expect("legacy database reopens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("legacy schema version survives rollback");
        assert_eq!(schema_version, "4");
        assert_eq!(table_row_count(&connection, "legal_basis"), 1);
        assert_eq!(
            sqlite_master_count(&connection, "__lawyer_assistance_v6_legacy_legal_basis"),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM user_database_metadata WHERE key = ?1",
                    [USER_CANONICAL_SCHEMA_MARKER_KEY],
                    |row| row.get::<_, i64>(0),
                )
                .expect("marker absence is queryable"),
            0
        );
    }

    #[test]
    fn unmarked_v6_database_from_legacy_if_not_exists_path_is_repaired_once() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("legacy database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE projects (
                        project_id TEXT PRIMARY KEY,
                        title TEXT NOT NULL,
                        case_type TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL,
                        opened_on TEXT,
                        summary TEXT NOT NULL DEFAULT '',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO projects (project_id, title, status)
                    VALUES ('mis-migrated-v6', 'Preserve me', 'active');
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '6');
                    ",
                )
                .expect("previous IF NOT EXISTS migration shape is created");
        }

        ensure_user_database(directory.path()).expect("unmarked v6 schema is rebuilt");
        {
            let connection = open_user_database(&database_path).expect("repaired database opens");
            let marker: String = connection
                .query_row(
                    "SELECT value FROM user_database_metadata WHERE key = ?1",
                    [USER_CANONICAL_SCHEMA_MARKER_KEY],
                    |row| row.get(0),
                )
                .expect("canonical marker is recorded");
            let title: String = connection
                .query_row(
                    "SELECT title FROM projects WHERE project_id = 'mis-migrated-v6'",
                    [],
                    |row| row.get(0),
                )
                .expect("pre-existing v6 data survives repair");
            assert_eq!(marker, USER_CANONICAL_SCHEMA_MARKER_VALUE);
            assert_eq!(title, "Preserve me");
            connection
                .execute(
                    "INSERT INTO projects (project_id, title, status)
                     VALUES ('bad-after-repair', 'Bad', 'not-a-status')",
                    [],
                )
                .expect_err("repaired v6 table has canonical CHECK constraints");
        }

        ensure_user_database(directory.path()).expect("marked canonical v6 reopen is idempotent");
        let connection = open_user_database(&database_path).expect("database opens after recheck");
        let preserved: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id = 'mis-migrated-v6'",
                [],
                |row| row.get(0),
            )
            .expect("preserved project remains after idempotent reopen");
        assert_eq!(preserved, 1);
    }

    #[test]
    fn unversioned_business_tables_without_metadata_are_rebuilt_before_marking() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        seed_unversioned_weak_projects_database(&database_path, false);

        ensure_user_database(directory.path()).expect("unversioned business schema is rebuilt");
        assert_rebuilt_unversioned_project_database(&database_path);
    }

    #[test]
    fn metadata_without_schema_version_rebuilds_existing_business_tables() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        seed_unversioned_weak_projects_database(&database_path, true);

        ensure_user_database(directory.path())
            .expect("business schema without a version row is rebuilt");
        assert_rebuilt_unversioned_project_database(&database_path);

        let connection = open_user_database(&database_path).expect("rebuilt database opens");
        let legacy_note: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'legacy_note'",
                [],
                |row| row.get(0),
            )
            .expect("unrelated metadata survives rebuild");
        assert_eq!(legacy_note, "preserve");
    }

    #[test]
    fn future_user_schema_is_rejected_without_downgrade_or_writes() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        {
            let connection =
                rusqlite::Connection::open(&database_path).expect("future database opens");
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('schema_version', '999');
                    CREATE TABLE future_only_data (value TEXT NOT NULL);
                    INSERT INTO future_only_data (value) VALUES ('must remain');
                    ",
                )
                .expect("future schema writes");
        }

        let error = ensure_user_database(directory.path())
            .expect_err("future schema must not be silently downgraded");
        assert!(matches!(
            error,
            DatabaseInitError::UnsupportedUserSchemaVersion {
                found: 999,
                supported: USER_SCHEMA_VERSION
            }
        ));

        let connection = rusqlite::Connection::open(&database_path).expect("database reopens");
        let schema_version: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("future schema version remains");
        let future_value: String = connection
            .query_row("SELECT value FROM future_only_data", [], |row| row.get(0))
            .expect("future-only data remains");
        assert_eq!(schema_version, "999");
        assert_eq!(future_value, "must remain");
        assert_eq!(sqlite_master_count(&connection, "projects"), 0);
    }

    #[test]
    fn provider_profile_crud_persists_without_api_key_columns() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        {
            let connection = open_user_database(&database_path).expect("user database opens");
            upsert_provider_profile(
                &connection,
                &ProviderProfileRow {
                    id: "deepseek-main".to_owned(),
                    kind: "deep_seek".to_owned(),
                    display_name: "DeepSeek Main".to_owned(),
                    model_id: "deepseek-chat".to_owned(),
                    base_url: "https://api.deepseek.com".to_owned(),
                    credential_account_id: "default".to_owned(),
                    capabilities_json: r#"{"chat":true}"#.to_owned(),
                    options_json: r#"{"reasoningEffort":"high"}"#.to_owned(),
                },
            )
            .expect("provider profile inserts");
        }

        let connection = open_user_database(&database_path).expect("user database reopens");
        let profiles = list_provider_profiles(&connection).expect("provider profiles list");
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].id, "deepseek-main");
        assert_eq!(profiles[0].model_id, "deepseek-chat");

        let mut updated = profiles[0].clone();
        updated.display_name = "DeepSeek Updated".to_owned();
        upsert_provider_profile(&connection, &updated).expect("provider profile updates");
        let updated = get_provider_profile(&connection, "deepseek-main")
            .expect("provider profile reads")
            .expect("provider profile exists");
        assert_eq!(updated.display_name, "DeepSeek Updated");

        let mut statement = connection
            .prepare("PRAGMA table_info(provider_profiles)")
            .expect("table info prepares");
        let column_names = statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("table info queries")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("table info collects");
        assert!(!column_names.iter().any(|name| {
            let lower = name.to_ascii_lowercase();
            lower.contains("api") || lower.contains("key") || lower.contains("secret")
        }));

        assert!(delete_provider_profile(&connection, "deepseek-main")
            .expect("provider profile deletes"));
        assert!(list_provider_profiles(&connection)
            .expect("provider profiles list after delete")
            .is_empty());
    }

    #[test]
    fn provider_profile_kinds_remain_compatible_and_custom_is_schema_free() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let kinds = [
            "deep_seek",
            "qwen",
            "silicon_flow",
            "volcengine_ark",
            "custom",
        ];
        {
            let connection = open_user_database(&database_path).expect("user database opens");
            for kind in kinds {
                upsert_provider_profile(
                    &connection,
                    &ProviderProfileRow {
                        id: format!("{kind}-main"),
                        kind: kind.to_owned(),
                        display_name: format!("{kind} profile"),
                        model_id: "model-id".to_owned(),
                        base_url: "https://models.example.com/v1".to_owned(),
                        credential_account_id: "default".to_owned(),
                        capabilities_json: r#"{"chat":true,"streaming":true}"#.to_owned(),
                        options_json: "{}".to_owned(),
                    },
                )
                .expect("provider kind inserts without a schema migration");
            }
        }

        let connection = open_user_database(&database_path).expect("user database reopens");
        let profiles = list_provider_profiles(&connection).expect("provider profiles list");
        assert_eq!(profiles.len(), kinds.len());
        for kind in kinds {
            let profile = profiles
                .iter()
                .find(|profile| profile.id == format!("{kind}-main"))
                .expect("provider kind survives restart");
            assert_eq!(profile.kind, kind);
            assert_eq!(profile.credential_account_id, "default");
        }
    }

    #[test]
    fn case_workspace_crud_persists_and_cascades() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        {
            let connection = open_user_database(&database_path).expect("user database opens");
            upsert_case_project(
                &connection,
                &CaseProjectRow {
                    project_id: "project-1".to_owned(),
                    title: "Contract dispute".to_owned(),
                    case_type: "civil".to_owned(),
                    status: "active".to_owned(),
                    opened_on: Some("2026-01-02".to_owned()),
                    summary: "Payment dispute".to_owned(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .expect("project inserts");
            upsert_case_file(
                &connection,
                &CaseFileRow {
                    file_id: "file-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    title: "Client notes".to_owned(),
                    file_type: "note".to_owned(),
                    storage_reference: "inline".to_owned(),
                    summary: "Initial intake".to_owned(),
                    created_at: String::new(),
                },
            )
            .expect("file inserts");
            upsert_case_party(
                &connection,
                &CasePartyRow {
                    party_id: "party-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    name: "Acme Ltd.".to_owned(),
                    normalized_name: "acmeltd".to_owned(),
                    role: "plaintiff".to_owned(),
                    contact: String::new(),
                    notes: String::new(),
                },
            )
            .expect("party inserts");
            upsert_case_fact(
                &connection,
                &CaseFactRow {
                    fact_id: "fact-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    occurred_on: Some("2026-01-03".to_owned()),
                    title: "Contract signed".to_owned(),
                    description: "The parties signed the contract.".to_owned(),
                    source: "Client".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("fact inserts");
            upsert_evidence_item(
                &connection,
                &EvidenceItemRow {
                    evidence_id: "evidence-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    evidence_number: "E-1".to_owned(),
                    title: "Signed contract".to_owned(),
                    source: "Client upload".to_owned(),
                    formed_on: Some("2026-01-03".to_owned()),
                    summary: "Signed PDF".to_owned(),
                    storage_reference: "contract.pdf".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("evidence inserts");
            upsert_evidence_link(
                &connection,
                &EvidenceLinkRow {
                    link_id: "link-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    fact_id: "fact-1".to_owned(),
                    evidence_id: "evidence-1".to_owned(),
                },
            )
            .expect("link inserts");
            upsert_legal_issue(
                &connection,
                &LegalIssueRow {
                    issue_id: "issue-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    title: "Breach".to_owned(),
                    description: "Late payment".to_owned(),
                    claim: "Request payment".to_owned(),
                    status: "open".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("issue inserts");
            upsert_fact_issue_link(
                &connection,
                &FactIssueLinkRow {
                    link_id: "fact-issue-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    fact_id: "fact-1".to_owned(),
                    issue_id: "issue-1".to_owned(),
                },
            )
            .expect("fact-issue link inserts");
            upsert_case_uncertainty(
                &connection,
                &CaseUncertaintyRow {
                    uncertainty_id: "uncertainty-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    description: "Payment date requires confirmation".to_owned(),
                    related_entity_type: "fact".to_owned(),
                    related_entity_id: Some("fact-1".to_owned()),
                    source_file_ids_json: r#"["file-1"]"#.to_owned(),
                    status: "open".to_owned(),
                    resolution: String::new(),
                    confirmation_status: "confirmed".to_owned(),
                    created_at: String::new(),
                    updated_at: String::new(),
                },
            )
            .expect("uncertainty inserts");
            upsert_legal_basis(
                &connection,
                &LegalBasisRow {
                    basis_id: "basis-1".to_owned(),
                    project_id: "project-1".to_owned(),
                    issue_id: Some("issue-1".to_owned()),
                    source_id: "law:cn-civil-code:cn-civil-code-20210101:art:577".to_owned(),
                    status: "valid".to_owned(),
                    invalid_reason: None,
                    case_date: Some("2026-01-02".to_owned()),
                    article_id: "article-577".to_owned(),
                    document_id: "cn-civil-code".to_owned(),
                    version_id: "cn-civil-code-20210101".to_owned(),
                    document_title: "Civil Code".to_owned(),
                    version_label: "2021 version".to_owned(),
                    article_number: "Article 577".to_owned(),
                    article_title: Some("Breach liability".to_owned()),
                    canonical_label: "Civil Code Article 577".to_owned(),
                    effective_from: "2021-01-01".to_owned(),
                    effective_to: None,
                    version_status: "in_force".to_owned(),
                    excerpt: "Breach liability excerpt".to_owned(),
                    note: "Primary claim basis".to_owned(),
                    created_at: String::new(),
                },
            )
            .expect("basis inserts");
        }

        let connection = open_user_database(&database_path).expect("user database reopens");
        let workspace = get_case_workspace_rows(&connection, "project-1")
            .expect("workspace reads")
            .expect("workspace exists");
        assert_eq!(workspace.parties.len(), 1);
        assert_eq!(workspace.facts.len(), 1);
        assert_eq!(workspace.evidence.len(), 1);
        assert_eq!(workspace.evidence_links.len(), 1);
        assert_eq!(workspace.fact_issue_links.len(), 1);
        assert_eq!(workspace.legal_issues.len(), 1);
        assert_eq!(workspace.legal_basis.len(), 1);
        assert_eq!(workspace.uncertainties.len(), 1);
        assert_eq!(
            workspace.legal_basis[0].issue_id.as_deref(),
            Some("issue-1")
        );

        let mut fact = workspace.facts[0].clone();
        fact.title = "Contract executed".to_owned();
        upsert_case_fact(&connection, &fact).expect("fact updates");
        let updated = get_case_workspace_rows(&connection, "project-1")
            .expect("workspace reads after update")
            .expect("workspace still exists");
        assert_eq!(updated.facts[0].title, "Contract executed");

        assert!(delete_case_project(&connection, "project-1").expect("project deletes"));
        for table in [
            "case_files",
            "case_extraction_confirmations",
            "case_parties",
            "case_facts",
            "evidence_items",
            "evidence_links",
            "fact_issue_links",
            "legal_issues",
            "case_uncertainties",
            "legal_basis",
        ] {
            assert_eq!(table_row_count(&connection, table), 0, "{table} cascades");
        }
    }

    #[test]
    fn child_upserts_reject_cross_project_id_reuse_without_mutating_owner() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut connection = open_user_database(&database_path).expect("user database opens");
        seed_project(&connection, "project-a");
        seed_project(&connection, "project-b");

        let mut file = CaseFileRow {
            file_id: "shared-file".to_owned(),
            project_id: "project-a".to_owned(),
            title: "Owned file".to_owned(),
            file_type: "note".to_owned(),
            storage_reference: String::new(),
            summary: String::new(),
            created_at: String::new(),
        };
        upsert_case_file(&connection, &file).expect("owned file inserts");
        file.project_id = "project-b".to_owned();
        file.title = "Hijacked file".to_owned();
        assert_project_scope_error(
            upsert_case_file(&connection, &file).expect_err("cross-project file update fails"),
            "case file",
        );
        assert_eq!(
            project_and_value(&connection, "case_files", "file_id", "shared-file", "title"),
            ("project-a".to_owned(), "Owned file".to_owned())
        );

        let mut party = CasePartyRow {
            party_id: "shared-party".to_owned(),
            project_id: "project-a".to_owned(),
            name: "Owned party".to_owned(),
            normalized_name: "ownedparty".to_owned(),
            role: "plaintiff".to_owned(),
            contact: String::new(),
            notes: String::new(),
        };
        upsert_case_party(&connection, &party).expect("owned party inserts");
        party.project_id = "project-b".to_owned();
        party.name = "Hijacked party".to_owned();
        assert_project_scope_error(
            upsert_case_party(&connection, &party).expect_err("cross-project party update fails"),
            "case party",
        );
        assert_eq!(
            project_and_value(
                &connection,
                "case_parties",
                "party_id",
                "shared-party",
                "name"
            ),
            ("project-a".to_owned(), "Owned party".to_owned())
        );

        let mut fact = CaseFactRow {
            fact_id: "shared-fact".to_owned(),
            project_id: "project-a".to_owned(),
            occurred_on: None,
            title: "Owned fact".to_owned(),
            description: String::new(),
            source: String::new(),
            confirmation_status: "confirmed".to_owned(),
        };
        upsert_case_fact(&connection, &fact).expect("owned fact inserts");
        fact.project_id = "project-b".to_owned();
        fact.title = "Hijacked fact".to_owned();
        assert_project_scope_error(
            upsert_case_fact(&connection, &fact).expect_err("cross-project fact update fails"),
            "case fact",
        );
        assert_eq!(
            project_and_value(&connection, "case_facts", "fact_id", "shared-fact", "title"),
            ("project-a".to_owned(), "Owned fact".to_owned())
        );

        let mut evidence = EvidenceItemRow {
            evidence_id: "shared-evidence".to_owned(),
            project_id: "project-a".to_owned(),
            evidence_number: "A-1".to_owned(),
            title: "Owned evidence".to_owned(),
            source: String::new(),
            formed_on: None,
            summary: String::new(),
            storage_reference: String::new(),
            confirmation_status: "confirmed".to_owned(),
        };
        upsert_evidence_item(&connection, &evidence).expect("owned evidence inserts");
        evidence.project_id = "project-b".to_owned();
        evidence.evidence_number = "B-1".to_owned();
        evidence.title = "Hijacked evidence".to_owned();
        assert_project_scope_error(
            upsert_evidence_item(&connection, &evidence)
                .expect_err("cross-project evidence update fails"),
            "evidence item",
        );
        assert_eq!(
            project_and_value(
                &connection,
                "evidence_items",
                "evidence_id",
                "shared-evidence",
                "title"
            ),
            ("project-a".to_owned(), "Owned evidence".to_owned())
        );

        let mut issue = LegalIssueRow {
            issue_id: "shared-issue".to_owned(),
            project_id: "project-a".to_owned(),
            title: "Owned issue".to_owned(),
            description: String::new(),
            claim: String::new(),
            status: "open".to_owned(),
            confirmation_status: "confirmed".to_owned(),
        };
        upsert_legal_issue(&connection, &issue).expect("owned issue inserts");
        issue.project_id = "project-b".to_owned();
        issue.title = "Hijacked issue".to_owned();
        assert_project_scope_error(
            upsert_legal_issue(&connection, &issue).expect_err("cross-project issue update fails"),
            "legal issue",
        );
        assert_eq!(
            project_and_value(
                &connection,
                "legal_issues",
                "issue_id",
                "shared-issue",
                "title"
            ),
            ("project-a".to_owned(), "Owned issue".to_owned())
        );

        let mut uncertainty = CaseUncertaintyRow {
            uncertainty_id: "shared-uncertainty".to_owned(),
            project_id: "project-a".to_owned(),
            description: "Owned uncertainty".to_owned(),
            related_entity_type: "general".to_owned(),
            related_entity_id: None,
            source_file_ids_json: "[]".to_owned(),
            status: "open".to_owned(),
            resolution: String::new(),
            confirmation_status: "confirmed".to_owned(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        upsert_case_uncertainty(&connection, &uncertainty).expect("owned uncertainty inserts");
        uncertainty.project_id = "project-b".to_owned();
        uncertainty.description = "Hijacked uncertainty".to_owned();
        assert_project_scope_error(
            upsert_case_uncertainty(&connection, &uncertainty)
                .expect_err("cross-project uncertainty update fails"),
            "case uncertainty",
        );
        assert_eq!(
            project_and_value(
                &connection,
                "case_uncertainties",
                "uncertainty_id",
                "shared-uncertainty",
                "description"
            ),
            ("project-a".to_owned(), "Owned uncertainty".to_owned())
        );

        let mut basis = LegalBasisRow {
            basis_id: "shared-basis".to_owned(),
            project_id: "project-a".to_owned(),
            issue_id: None,
            source_id: "law:test:version:art:1".to_owned(),
            status: "valid".to_owned(),
            invalid_reason: None,
            case_date: None,
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
            note: "Owned basis".to_owned(),
            created_at: String::new(),
        };
        upsert_legal_basis(&connection, &basis).expect("owned basis inserts");
        basis.project_id = "project-b".to_owned();
        basis.note = "Hijacked basis".to_owned();
        assert_project_scope_error(
            upsert_legal_basis(&connection, &basis).expect_err("cross-project basis update fails"),
            "legal basis",
        );
        assert_eq!(
            project_and_value(
                &connection,
                "legal_basis",
                "basis_id",
                "shared-basis",
                "note"
            ),
            ("project-a".to_owned(), "Owned basis".to_owned())
        );

        assert!(!delete_case_entity(
            &mut connection,
            "case_facts",
            "fact_id",
            "shared-fact",
            "project-b",
        )
        .expect("cross-project delete is rejected as not owned"));
        assert_eq!(
            project_and_value(&connection, "case_facts", "fact_id", "shared-fact", "title"),
            ("project-a".to_owned(), "Owned fact".to_owned())
        );
    }

    #[test]
    fn legal_basis_requires_same_project_issue_and_preserves_set_null_delete() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let connection = open_user_database(&database_path).expect("user database opens");
        seed_project(&connection, "project-a");
        seed_project(&connection, "project-b");

        for (issue_id, project_id) in [("issue-a", "project-a"), ("issue-b", "project-b")] {
            upsert_legal_issue(
                &connection,
                &LegalIssueRow {
                    issue_id: issue_id.to_owned(),
                    project_id: project_id.to_owned(),
                    title: issue_id.to_owned(),
                    description: String::new(),
                    claim: String::new(),
                    status: "open".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("issue inserts");
        }

        let mut basis = LegalBasisRow {
            basis_id: "basis-a".to_owned(),
            project_id: "project-a".to_owned(),
            issue_id: Some("issue-b".to_owned()),
            source_id: "law:test:version:art:1".to_owned(),
            status: "valid".to_owned(),
            invalid_reason: None,
            case_date: None,
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
        assert_project_scope_error(
            upsert_legal_basis(&connection, &basis)
                .expect_err("cross-project legal basis insert fails"),
            "legal basis",
        );
        connection
            .execute(
                "INSERT INTO legal_basis (basis_id, project_id, issue_id, source_id, status)
                 VALUES ('direct-cross-basis', 'project-a', 'issue-b', 'law:test', 'valid')",
                [],
            )
            .expect_err("canonical trigger rejects direct mixed-project legal basis SQL");
        assert_eq!(table_row_count(&connection, "legal_basis"), 0);

        basis.issue_id = Some("issue-a".to_owned());
        upsert_legal_basis(&connection, &basis).expect("same-project legal basis inserts");
        connection
            .execute("DELETE FROM legal_issues WHERE issue_id = 'issue-a'", [])
            .expect("deleting the issue preserves its basis");
        let remaining_issue_id: Option<String> = connection
            .query_row(
                "SELECT issue_id FROM legal_basis WHERE basis_id = 'basis-a'",
                [],
                |row| row.get(0),
            )
            .expect("basis survives issue deletion");
        assert_eq!(remaining_issue_id, None);
    }

    #[test]
    fn evidence_links_require_project_fact_and_evidence_to_share_one_owner() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let connection = open_user_database(&database_path).expect("user database opens");
        seed_project(&connection, "project-a");
        seed_project(&connection, "project-b");

        for (fact_id, project_id) in [("fact-a", "project-a"), ("fact-b", "project-b")] {
            upsert_case_fact(
                &connection,
                &CaseFactRow {
                    fact_id: fact_id.to_owned(),
                    project_id: project_id.to_owned(),
                    occurred_on: None,
                    title: fact_id.to_owned(),
                    description: String::new(),
                    source: String::new(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("fact inserts");
        }
        for (evidence_id, project_id, evidence_number) in [
            ("evidence-a-1", "project-a", "A-1"),
            ("evidence-a-2", "project-a", "A-2"),
            ("evidence-b", "project-b", "B-1"),
        ] {
            upsert_evidence_item(
                &connection,
                &EvidenceItemRow {
                    evidence_id: evidence_id.to_owned(),
                    project_id: project_id.to_owned(),
                    evidence_number: evidence_number.to_owned(),
                    title: evidence_id.to_owned(),
                    source: String::new(),
                    formed_on: None,
                    summary: String::new(),
                    storage_reference: String::new(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("evidence inserts");
        }

        let mixed_project_link = EvidenceLinkRow {
            link_id: "mixed-project-link".to_owned(),
            project_id: "project-a".to_owned(),
            fact_id: "fact-a".to_owned(),
            evidence_id: "evidence-b".to_owned(),
        };
        assert_project_scope_error(
            upsert_evidence_link(&connection, &mixed_project_link)
                .expect_err("mixed-project link insert fails"),
            "evidence link",
        );
        assert_eq!(table_row_count(&connection, "evidence_links"), 0);
        connection
            .execute(
                "INSERT INTO evidence_links (link_id, project_id, fact_id, evidence_id)
                 VALUES ('direct-mixed-link', 'project-a', 'fact-a', 'evidence-b')",
                [],
            )
            .expect_err("canonical composite foreign key rejects direct mixed-project SQL");
        assert_eq!(table_row_count(&connection, "evidence_links"), 0);

        let mut link = EvidenceLinkRow {
            link_id: "owned-link".to_owned(),
            project_id: "project-a".to_owned(),
            fact_id: "fact-a".to_owned(),
            evidence_id: "evidence-a-1".to_owned(),
        };
        upsert_evidence_link(&connection, &link).expect("valid link inserts");
        link.evidence_id = "evidence-a-2".to_owned();
        upsert_evidence_link(&connection, &link).expect("same-project link updates");

        link.evidence_id = "evidence-b".to_owned();
        assert_project_scope_error(
            upsert_evidence_link(&connection, &link)
                .expect_err("cross-project evidence replacement fails"),
            "evidence link",
        );
        assert_eq!(
            evidence_link_owner_and_targets(&connection, "owned-link"),
            (
                "project-a".to_owned(),
                "fact-a".to_owned(),
                "evidence-a-2".to_owned()
            )
        );

        link.project_id = "project-b".to_owned();
        link.fact_id = "fact-b".to_owned();
        link.evidence_id = "evidence-b".to_owned();
        assert_project_scope_error(
            upsert_evidence_link(&connection, &link)
                .expect_err("cross-project link id reuse fails"),
            "evidence link",
        );
        assert_eq!(
            evidence_link_owner_and_targets(&connection, "owned-link"),
            (
                "project-a".to_owned(),
                "fact-a".to_owned(),
                "evidence-a-2".to_owned()
            )
        );

        let batch_mixed_project_link = EvidenceLinkRow {
            link_id: "batch-mixed-project-link".to_owned(),
            ..mixed_project_link
        };
        assert_project_scope_error(
            insert_evidence_link(&connection, &batch_mixed_project_link)
                .expect_err("batch link insert enforces the same ownership rule"),
            "evidence link",
        );
        assert_eq!(table_row_count(&connection, "evidence_links"), 1);
    }

    #[test]
    fn fact_issue_links_are_strictly_project_scoped_unique_and_cascade() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let connection = open_user_database(&database_path).expect("user database opens");
        seed_project(&connection, "project-a");
        seed_project(&connection, "project-b");

        for (fact_id, project_id) in [("fact-a", "project-a"), ("fact-b", "project-b")] {
            upsert_case_fact(
                &connection,
                &CaseFactRow {
                    fact_id: fact_id.to_owned(),
                    project_id: project_id.to_owned(),
                    occurred_on: None,
                    title: fact_id.to_owned(),
                    description: String::new(),
                    source: String::new(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("fact inserts");
        }
        for (issue_id, project_id) in [("issue-a", "project-a"), ("issue-b", "project-b")] {
            upsert_legal_issue(
                &connection,
                &LegalIssueRow {
                    issue_id: issue_id.to_owned(),
                    project_id: project_id.to_owned(),
                    title: issue_id.to_owned(),
                    description: String::new(),
                    claim: String::new(),
                    status: "open".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("issue inserts");
        }

        let mixed = FactIssueLinkRow {
            link_id: "mixed-link".to_owned(),
            project_id: "project-a".to_owned(),
            fact_id: "fact-a".to_owned(),
            issue_id: "issue-b".to_owned(),
        };
        assert_project_scope_error(
            upsert_fact_issue_link(&connection, &mixed)
                .expect_err("mixed-project relationship is rejected"),
            "fact-issue link",
        );
        connection
            .execute(
                "INSERT INTO fact_issue_links (link_id, project_id, fact_id, issue_id)
                 VALUES ('direct-mixed', 'project-a', 'fact-a', 'issue-b')",
                [],
            )
            .expect_err("composite foreign key rejects direct mixed-project SQL");

        let valid = FactIssueLinkRow {
            link_id: "owned-link".to_owned(),
            project_id: "project-a".to_owned(),
            fact_id: "fact-a".to_owned(),
            issue_id: "issue-a".to_owned(),
        };
        upsert_fact_issue_link(&connection, &valid).expect("same-project relationship inserts");
        assert_project_scope_error(
            upsert_fact_issue_link(
                &connection,
                &FactIssueLinkRow {
                    link_id: "duplicate-link".to_owned(),
                    ..valid.clone()
                },
            )
            .expect_err("one fact/issue pair cannot be duplicated"),
            "UNIQUE",
        );
        assert_project_scope_error(
            upsert_fact_issue_link(
                &connection,
                &FactIssueLinkRow {
                    link_id: valid.link_id.clone(),
                    project_id: "project-b".to_owned(),
                    fact_id: "fact-b".to_owned(),
                    issue_id: "issue-b".to_owned(),
                },
            )
            .expect_err("relationship id cannot move between projects"),
            "fact-issue link",
        );
        let workspace = get_case_workspace_rows(&connection, "project-a")
            .expect("workspace reads")
            .expect("project exists");
        assert_eq!(workspace.fact_issue_links, vec![valid.clone()]);

        connection
            .execute("DELETE FROM case_facts WHERE fact_id = 'fact-a'", [])
            .expect("fact deletes");
        assert_eq!(table_row_count(&connection, "fact_issue_links"), 0);
        upsert_case_fact(
            &connection,
            &CaseFactRow {
                fact_id: "fact-a".to_owned(),
                project_id: "project-a".to_owned(),
                occurred_on: None,
                title: "fact-a".to_owned(),
                description: String::new(),
                source: String::new(),
                confirmation_status: "confirmed".to_owned(),
            },
        )
        .expect("fact reinserts");
        upsert_fact_issue_link(&connection, &valid).expect("relationship reinserts");
        connection
            .execute("DELETE FROM legal_issues WHERE issue_id = 'issue-a'", [])
            .expect("issue deletes");
        assert_eq!(table_row_count(&connection, "fact_issue_links"), 0);
    }

    #[test]
    fn version_seven_migration_preserves_entities_and_adds_empty_fact_issue_links() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("current database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            seed_project(&connection, "legacy-project");
            upsert_case_fact(
                &connection,
                &CaseFactRow {
                    fact_id: "legacy-fact".to_owned(),
                    project_id: "legacy-project".to_owned(),
                    occurred_on: None,
                    title: "Preserved fact".to_owned(),
                    description: String::new(),
                    source: String::new(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("legacy fact inserts");
            upsert_legal_issue(
                &connection,
                &LegalIssueRow {
                    issue_id: "legacy-issue".to_owned(),
                    project_id: "legacy-project".to_owned(),
                    title: "Preserved issue".to_owned(),
                    description: String::new(),
                    claim: String::new(),
                    status: "open".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("legacy issue inserts");
            connection
                .execute_batch(
                    "DROP TABLE fact_issue_links;
                     UPDATE user_database_metadata SET value = '7'
                     WHERE key = 'schema_version';
                     UPDATE user_database_metadata
                     SET value = 'v7-document-generation-records-20260715'
                     WHERE key = 'canonical_schema_version';",
                )
                .expect("database is reduced to the v7 contract");
        }

        ensure_user_database(directory.path()).expect("v7 database migrates to v8");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let workspace = get_case_workspace_rows(&connection, "legacy-project")
            .expect("workspace reads")
            .expect("project survives");
        assert_eq!(workspace.facts[0].title, "Preserved fact");
        assert_eq!(workspace.legal_issues[0].title, "Preserved issue");
        assert!(workspace.fact_issue_links.is_empty());
    }

    #[test]
    fn canonical_rebuild_preserves_existing_fact_issue_links() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("current database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            seed_project(&connection, "project-rebuild");
            upsert_case_fact(
                &connection,
                &CaseFactRow {
                    fact_id: "fact-rebuild".to_owned(),
                    project_id: "project-rebuild".to_owned(),
                    occurred_on: None,
                    title: "Fact".to_owned(),
                    description: String::new(),
                    source: String::new(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("fact inserts");
            upsert_legal_issue(
                &connection,
                &LegalIssueRow {
                    issue_id: "issue-rebuild".to_owned(),
                    project_id: "project-rebuild".to_owned(),
                    title: "Issue".to_owned(),
                    description: String::new(),
                    claim: String::new(),
                    status: "open".to_owned(),
                    confirmation_status: "confirmed".to_owned(),
                },
            )
            .expect("issue inserts");
            upsert_fact_issue_link(
                &connection,
                &FactIssueLinkRow {
                    link_id: "link-rebuild".to_owned(),
                    project_id: "project-rebuild".to_owned(),
                    fact_id: "fact-rebuild".to_owned(),
                    issue_id: "issue-rebuild".to_owned(),
                },
            )
            .expect("relationship inserts");
            connection
                .execute(
                    "UPDATE user_database_metadata SET value = 'precanonical-v8'
                     WHERE key = 'canonical_schema_version'",
                    [],
                )
                .expect("marker is made stale");
        }

        ensure_user_database(directory.path()).expect("canonical rebuild succeeds");
        let connection = open_user_database(&database_path).expect("rebuilt database opens");
        let workspace = get_case_workspace_rows(&connection, "project-rebuild")
            .expect("workspace reads")
            .expect("project survives");
        assert_eq!(workspace.fact_issue_links.len(), 1);
        assert_eq!(workspace.fact_issue_links[0].link_id, "link-rebuild");
        assert_eq!(
            sqlite_master_count(
                &connection,
                "__lawyer_assistance_v6_legacy_fact_issue_links"
            ),
            0
        );
    }

    #[test]
    fn pending_extraction_review_survives_restart_is_project_scoped_and_expires() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        {
            let mut connection = open_user_database(&database_path).expect("database opens");
            seed_project(&connection, "project-pending");
            insert_pending_extraction_review(
                &mut connection,
                &PendingExtractionReviewRow {
                    review_id: "review-pending".to_owned(),
                    project_id: "project-pending".to_owned(),
                    provider_id: "provider-pending".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                    source_file_ids_json: r#"["file-1"]"#.to_owned(),
                    source_materials_digest: "0".repeat(64),
                    extraction_json: r#"{"parties":[],"facts":[],"evidence":[],"legalIssues":[],"uncertainties":[]}"#.to_owned(),
                    revision: 0,
                    created_at: String::new(),
                    expires_at: String::new(),
                },
            )
            .expect("pending review inserts");
        }

        let connection = open_user_database(&database_path).expect("database reopens");
        let restored = get_pending_extraction_review_for_project(&connection, "project-pending")
            .expect("pending project lookup succeeds")
            .expect("pending review survives restart");
        assert_eq!(restored.review_id, "review-pending");
        assert!(!delete_pending_extraction_review(
            &connection,
            "review-pending",
            "different-project",
            0,
        )
        .expect("wrong-owner deletion is rejected"));
        connection
            .execute(
                "UPDATE pending_extraction_reviews SET expires_at = '2000-01-01 00:00:00'",
                [],
            )
            .expect("fixture expiry updates");
        assert!(get_pending_extraction_review(&connection, "review-pending")
            .expect("expired lookup succeeds")
            .is_none());
        let retained: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pending_extraction_reviews",
                [],
                |row| row.get(0),
            )
            .expect("physical retention count reads");
        assert_eq!(
            retained, 0,
            "expired sensitive payload is physically removed"
        );
    }

    #[test]
    fn confirmation_requires_matching_unexpired_persisted_provenance() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_extraction_project_and_file(&connection);
        let rows = confirmed_extraction_rows();

        assert!(matches!(
            insert_confirmed_case_extraction(&mut connection, &rows),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        persist_pending_for_confirmed_rows(&mut connection, &rows);

        let mut wrong_provider = rows.clone();
        wrong_provider.provider_id = "other-provider".to_owned();
        assert!(matches!(
            insert_confirmed_case_extraction(&mut connection, &wrong_provider),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        let mut wrong_sources = rows.clone();
        wrong_sources.source_file_ids = vec!["different-file".to_owned()];
        assert!(matches!(
            insert_confirmed_case_extraction(&mut connection, &wrong_sources),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        let mut stale_payload = rows.clone();
        stale_payload.reviewed_extraction_json =
            r#"{"parties":[{"name":"stale-window","role":"plaintiff"}],"facts":[],"evidence":[],"legalIssues":[],"uncertainties":[]}"#
                .to_owned();
        assert!(matches!(
            insert_confirmed_case_extraction(&mut connection, &stale_payload),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        assert_eq!(
            table_row_count(&connection, "case_extraction_confirmations"),
            0
        );
        assert!(get_pending_extraction_review(&connection, &rows.review_id)
            .expect("pending lookup succeeds")
            .is_some());

        insert_confirmed_case_extraction(&mut connection, &rows)
            .expect("matching persisted provenance confirms");
        assert_eq!(
            table_row_count(&connection, "case_extraction_confirmations"),
            1
        );
        let confirmed_snapshot: String = connection
            .query_row(
                "SELECT provider_snapshot_json FROM case_extraction_confirmations
                 WHERE review_id = ?1",
                [&rows.review_id],
                |row| row.get(0),
            )
            .expect("confirmed provider snapshot reads");
        assert_eq!(
            confirmed_snapshot,
            provider_snapshot_json(),
            "confirmation must copy the immutable generation-time provider snapshot"
        );
        assert!(get_pending_extraction_review(&connection, &rows.review_id)
            .expect("consumed lookup succeeds")
            .is_none());
    }

    #[test]
    fn expired_review_is_physically_removed_and_cannot_confirm() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_extraction_project_and_file(&connection);
        let rows = confirmed_extraction_rows();
        persist_pending_for_confirmed_rows(&mut connection, &rows);
        connection
            .execute(
                "UPDATE pending_extraction_reviews SET expires_at = '2000-01-01 00:00:00'",
                [],
            )
            .expect("fixture expires");

        assert!(matches!(
            insert_confirmed_case_extraction(&mut connection, &rows),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        let retained: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pending_extraction_reviews",
                [],
                |row| row.get(0),
            )
            .expect("retention count reads");
        assert_eq!(retained, 0);
        assert_eq!(
            table_row_count(&connection, "case_extraction_confirmations"),
            0
        );
    }

    #[test]
    fn pending_review_payload_update_is_provenance_scoped_and_extends_expiry() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_extraction_project_and_file(&connection);
        let rows = confirmed_extraction_rows();
        persist_pending_for_confirmed_rows(&mut connection, &rows);
        connection
            .execute(
                "UPDATE pending_extraction_reviews
                 SET expires_at = datetime(CURRENT_TIMESTAMP, '+1 minute')",
                [],
            )
            .expect("fixture shortens expiry");
        let revised = r#"{"parties":[],"facts":[{"occurredOn":null,"title":"Reviewed","description":"Edited","evidenceNumbers":[]}],"evidence":[],"legalIssues":[],"uncertainties":[]}"#;

        assert!(
            update_pending_extraction_review_payload(
                &mut connection,
                &rows.review_id,
                &rows.project_id,
                "wrong-provider",
                &rows.source_file_ids,
                revised,
                0,
            )
            .expect("wrong-provider update is typed")
                == PendingExtractionReviewUpdateResult::NotFound
        );
        assert!(
            update_pending_extraction_review_payload(
                &mut connection,
                &rows.review_id,
                &rows.project_id,
                &rows.provider_id,
                &["wrong-file".to_owned()],
                revised,
                0,
            )
            .expect("wrong-source update is typed")
                == PendingExtractionReviewUpdateResult::NotFound
        );

        let updated = update_pending_extraction_review_payload(
            &mut connection,
            &rows.review_id,
            &rows.project_id,
            &rows.provider_id,
            &rows.source_file_ids,
            revised,
            0,
        )
        .expect("matching update succeeds");
        let PendingExtractionReviewUpdateResult::Updated(updated) = updated else {
            panic!("matching update must return the advanced revision");
        };
        assert_eq!(updated.revision, 1);
        let stored: (String, i64, String) = connection
            .query_row(
                "SELECT extraction_json, revision, expires_at FROM pending_extraction_reviews
                 WHERE review_id = ?1",
                [&rows.review_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("updated review reads");
        assert_eq!(stored.0, revised);
        assert_eq!(stored.1, 1);
        assert_eq!(stored.2, updated.expires_at);
        let remaining_days: f64 = connection
            .query_row(
                "SELECT julianday(expires_at) - julianday(CURRENT_TIMESTAMP)
                 FROM pending_extraction_reviews WHERE review_id = ?1",
                [&rows.review_id],
                |row| row.get(0),
            )
            .expect("expiry duration reads");
        assert!(remaining_days > 6.9, "expiry is renewed for seven days");
    }

    #[test]
    fn pending_review_revision_cas_rejects_stale_cross_connection_mutations() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut first = open_user_database(&database_path).expect("first database opens");
        seed_extraction_project_and_file(&first);
        let rows = confirmed_extraction_rows();
        persist_pending_for_confirmed_rows(&mut first, &rows);
        let mut second = open_user_database(&database_path).expect("second database opens");
        let material_digest =
            current_case_materials_digest(&second, &rows.project_id, &rows.source_file_ids)
                .expect("material digest reads")
                .expect("material exists");

        assert!(!insert_pending_extraction_review(
            &mut second,
            &PendingExtractionReviewRow {
                review_id: "review-from-another-window".to_owned(),
                project_id: rows.project_id.clone(),
                provider_id: "other-provider".to_owned(),
                provider_snapshot_json: provider_snapshot_json(),
                source_file_ids_json: r#"["file-source"]"#.to_owned(),
                source_materials_digest: material_digest,
                extraction_json:
                    r#"{"parties":[],"facts":[],"evidence":[],"legalIssues":[],"uncertainties":[]}"#
                        .to_owned(),
                revision: 0,
                created_at: String::new(),
                expires_at: String::new(),
            },
        )
        .expect("conflicting create is typed"));
        let original = get_pending_extraction_review_for_project(&second, &rows.project_id)
            .expect("authoritative pending review reads")
            .expect("authoritative pending review remains");
        assert_eq!(original.review_id, rows.review_id);
        assert_eq!(original.provider_id, rows.provider_id);
        assert_eq!(original.revision, 0);

        let first_edit = r#"{"parties":[],"facts":[{"occurredOn":null,"title":"First window","description":"Newest","evidenceNumbers":[]}],"evidence":[],"legalIssues":[],"uncertainties":[]}"#;
        let stale_edit = r#"{"parties":[],"facts":[{"occurredOn":null,"title":"Stale window","description":"Must not win","evidenceNumbers":[]}],"evidence":[],"legalIssues":[],"uncertainties":[]}"#;
        let first_result = update_pending_extraction_review_payload(
            &mut first,
            &rows.review_id,
            &rows.project_id,
            &rows.provider_id,
            &rows.source_file_ids,
            first_edit,
            0,
        )
        .expect("first autosave succeeds");
        assert!(matches!(
            first_result,
            PendingExtractionReviewUpdateResult::Updated(PendingExtractionReviewUpdate {
                revision: 1,
                ..
            })
        ));

        let stale_autosave = update_pending_extraction_review_payload(
            &mut second,
            &rows.review_id,
            &rows.project_id,
            &rows.provider_id,
            &rows.source_file_ids,
            stale_edit,
            0,
        )
        .expect("stale autosave is typed");
        assert_eq!(
            stale_autosave,
            PendingExtractionReviewUpdateResult::Conflict
        );
        let stored = get_pending_extraction_review(&second, &rows.review_id)
            .expect("pending review reads")
            .expect("pending review remains");
        assert_eq!(stored.extraction_json, first_edit);
        assert_eq!(stored.revision, 1);

        let mut stale_confirmation = rows.clone();
        stale_confirmation.reviewed_extraction_json = first_edit.to_owned();
        stale_confirmation.expected_revision = 0;
        assert!(matches!(
            insert_confirmed_case_extraction(&mut second, &stale_confirmation),
            Err(rusqlite::Error::QueryReturnedNoRows)
        ));
        assert_eq!(table_row_count(&second, "case_extraction_confirmations"), 0);
        assert!(
            !delete_pending_extraction_review(&second, &rows.review_id, &rows.project_id, 0,)
                .expect("stale discard is rejected")
        );

        let second_edit = r#"{"parties":[],"facts":[{"occurredOn":null,"title":"First window again","description":"Queued second save","evidenceNumbers":[]}],"evidence":[],"legalIssues":[],"uncertainties":[]}"#;
        let second_result = update_pending_extraction_review_payload(
            &mut first,
            &rows.review_id,
            &rows.project_id,
            &rows.provider_id,
            &rows.source_file_ids,
            second_edit,
            1,
        )
        .expect("consecutive autosave succeeds");
        assert!(matches!(
            second_result,
            PendingExtractionReviewUpdateResult::Updated(PendingExtractionReviewUpdate {
                revision: 2,
                ..
            })
        ));
        assert!(
            !delete_pending_extraction_review(&second, &rows.review_id, &rows.project_id, 1,)
                .expect("discard cannot delete a newer queued save")
        );
        assert!(
            delete_pending_extraction_review(&second, &rows.review_id, &rows.project_id, 2,)
                .expect("current revision can be discarded")
        );
    }

    #[test]
    fn confirmed_extraction_is_atomic_preserves_materials_and_survives_restart() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        {
            let mut connection = open_user_database(&database_path).expect("database opens");
            seed_extraction_project_and_file(&connection);
            let rows = confirmed_extraction_rows();
            let material_digest =
                current_case_materials_digest(&connection, &rows.project_id, &rows.source_file_ids)
                    .expect("material digest reads")
                    .expect("material exists");
            insert_pending_extraction_review(
                &mut connection,
                &PendingExtractionReviewRow {
                    review_id: rows.review_id.clone(),
                    project_id: rows.project_id.clone(),
                    provider_id: rows.provider_id.clone(),
                    provider_snapshot_json: provider_snapshot_json(),
                    source_file_ids_json: r#"["file-source"]"#.to_owned(),
                    source_materials_digest: material_digest,
                    extraction_json: r#"{"parties":[],"facts":[],"evidence":[],"legalIssues":[],"uncertainties":[]}"#.to_owned(),
                    revision: 0,
                    created_at: String::new(),
                    expires_at: String::new(),
                },
            )
            .expect("pending review persists");

            insert_confirmed_case_extraction(&mut connection, &rows)
                .expect("confirmed extraction commits");
            assert!(
                get_pending_extraction_review(&connection, &rows.review_id)
                    .expect("pending review lookup succeeds")
                    .is_none(),
                "confirmation consumes the persistent review atomically"
            );
            insert_confirmed_case_extraction(&mut connection, &rows)
                .expect_err("review confirmation is idempotency-protected");
            assert_eq!(
                table_row_count(&connection, "case_extraction_confirmations"),
                1
            );

            let material = connection
                .query_row(
                    "SELECT title, summary, storage_reference FROM case_files WHERE file_id = 'file-source'",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .expect("original material reads");
            assert_eq!(
                material,
                (
                    "Original material".to_owned(),
                    "Original text".to_owned(),
                    "client-note.txt".to_owned()
                )
            );
        }

        let connection = open_user_database(&database_path).expect("database reopens");
        let workspace = get_case_workspace_rows(&connection, "project-extraction")
            .expect("workspace reads after restart")
            .expect("workspace exists");
        assert_eq!(workspace.parties.len(), 1);
        assert_eq!(workspace.facts.len(), 1);
        assert_eq!(workspace.evidence.len(), 1);
        assert_eq!(workspace.evidence_links.len(), 1);
        assert_eq!(workspace.legal_issues.len(), 1);
        assert_eq!(workspace.uncertainties.len(), 1);
        assert_eq!(workspace.facts[0].title, "Reviewed fact title");
        assert_eq!(workspace.facts[0].confirmation_status, "confirmed");
        assert_eq!(
            workspace.uncertainties[0].description,
            "Reviewed uncertainty"
        );
    }

    #[test]
    fn confirmed_extraction_rolls_back_every_entity_on_late_failure() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_extraction_project_and_file(&connection);
        let rows = confirmed_extraction_rows();
        persist_pending_for_confirmed_rows(&mut connection, &rows);
        connection
            .execute_batch(
                "
                CREATE TRIGGER fail_uncertainty_insert
                BEFORE INSERT ON case_uncertainties
                BEGIN
                    SELECT RAISE(ABORT, 'late uncertainty failure');
                END;
                ",
            )
            .expect("failure trigger installs");

        let error = insert_confirmed_case_extraction(&mut connection, &rows)
            .expect_err("late failure aborts transaction");
        assert!(error.to_string().contains("late uncertainty failure"));

        for table in [
            "case_parties",
            "case_facts",
            "evidence_items",
            "evidence_links",
            "fact_issue_links",
            "legal_issues",
            "case_uncertainties",
        ] {
            assert_eq!(table_row_count(&connection, table), 0, "{table} rolls back");
        }
        assert_eq!(table_row_count(&connection, "case_files"), 1);
        assert!(
            get_pending_extraction_review(&connection, &rows.review_id)
                .expect("pending review lookup succeeds")
                .is_some(),
            "failed confirmation keeps the authoritative pending review for retry"
        );
    }

    #[test]
    fn confirmed_provenance_blocks_material_deletion_and_entity_delete_clears_link() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_extraction_project_and_file(&connection);
        let rows = confirmed_extraction_rows();
        persist_pending_for_confirmed_rows(&mut connection, &rows);
        insert_confirmed_case_extraction(&mut connection, &rows)
            .expect("confirmed extraction commits");

        delete_case_entity(
            &mut connection,
            "case_files",
            "file_id",
            "file-source",
            "project-extraction",
        )
        .expect_err("confirmed source material cannot be deleted silently");
        assert!(delete_case_entity(
            &mut connection,
            "case_facts",
            "fact_id",
            "batch-fact",
            "project-extraction",
        )
        .expect("fact deletes"));

        let workspace = get_case_workspace_rows(&connection, "project-extraction")
            .expect("workspace reads")
            .expect("workspace exists");
        assert_eq!(workspace.files.len(), 1);
        assert!(workspace.facts.is_empty());
        assert_eq!(workspace.uncertainties[0].related_entity_type, "general");
        assert!(workspace.uncertainties[0].related_entity_id.is_none());
    }

    #[test]
    fn legal_answer_records_persist_verified_citations_without_raw_provider_response() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        {
            let connection = open_user_database(&database_path).expect("user database opens");
            seed_project(&connection, "project-answer");
            insert_legal_answer_record(
                &connection,
                &LegalAnswerRecordRow {
                    record_id: "answer-1".to_owned(),
                    project_id: Some("project-answer".to_owned()),
                    provider_id: "deepseek-main".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                    question: "What is breach liability?".to_owned(),
                    answer_text: "Answer with [SRC:law:a:b:art:1]".to_owned(),
                    case_date: Some("2024-01-01".to_owned()),
                    query_json: r#"{"keywords":["breach"]}"#.to_owned(),
                    source_ids_json: r#"["law:a:b:art:1"]"#.to_owned(),
                    verified_citations_json: r#"[{"sourceId":"law:a:b:art:1"}]"#.to_owned(),
                    invalid_citations_json: "[]".to_owned(),
                    unsupported_legal_conclusion: false,
                    created_at: String::new(),
                },
            )
            .expect("answer record inserts");
            seed_project(&connection, "project-answer-other");
            insert_legal_answer_record(
                &connection,
                &LegalAnswerRecordRow {
                    record_id: "answer-2".to_owned(),
                    project_id: Some("project-answer-other".to_owned()),
                    provider_id: "deepseek-main".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                    question: "Other case question".to_owned(),
                    answer_text: "Other case answer".to_owned(),
                    case_date: None,
                    query_json: "{}".to_owned(),
                    source_ids_json: "[]".to_owned(),
                    verified_citations_json: "[]".to_owned(),
                    invalid_citations_json: "[]".to_owned(),
                    unsupported_legal_conclusion: true,
                    created_at: String::new(),
                },
            )
            .expect("other case answer inserts");
        }

        let connection = open_user_database(&database_path).expect("user database reopens");
        let records = list_legal_answer_records(&connection, 10).expect("answer records list");

        assert_eq!(records.len(), 2);
        let project_records =
            list_legal_answer_records_for_project(&connection, "project-answer", 10)
                .expect("project answer records list");
        assert_eq!(project_records.len(), 1);
        assert_eq!(project_records[0].record_id, "answer-1");
        assert_eq!(
            project_records[0].provider_snapshot_json,
            provider_snapshot_json()
        );
        assert_eq!(
            project_records[0].verified_citations_json,
            r#"[{"sourceId":"law:a:b:art:1"}]"#
        );
        assert!(!project_records[0]
            .answer_text
            .contains("full provider response"));
        assert!(delete_case_project(&connection, "project-answer").expect("project deletes"));
        assert!(
            list_legal_answer_records_for_project(&connection, "project-answer", 10)
                .expect("deleted project records list")
                .is_empty()
        );
        assert_eq!(
            list_legal_answer_records(&connection, 10)
                .expect("other project's answer remains")
                .len(),
            1
        );
    }

    #[test]
    fn legal_answer_project_history_uses_stable_created_at_record_id_cursor() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "project-history");
        for record_id in ["answer-1", "answer-2", "answer-3"] {
            insert_legal_answer_record(
                &connection,
                &LegalAnswerRecordRow {
                    record_id: record_id.to_owned(),
                    project_id: Some("project-history".to_owned()),
                    provider_id: "provider".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                    question: format!("question {record_id}"),
                    answer_text: format!("answer {record_id}"),
                    case_date: None,
                    query_json: "{}".to_owned(),
                    source_ids_json: "[]".to_owned(),
                    verified_citations_json: "[]".to_owned(),
                    invalid_citations_json: "[]".to_owned(),
                    unsupported_legal_conclusion: false,
                    created_at: String::new(),
                },
            )
            .expect("history row inserts");
        }
        connection
            .execute_batch(
                "UPDATE legal_answer_records SET created_at = '2026-07-14 10:00:03'
                   WHERE record_id = 'answer-3';
                 UPDATE legal_answer_records SET created_at = '2026-07-14 10:00:02'
                   WHERE record_id IN ('answer-1', 'answer-2');",
            )
            .expect("history timestamps set");

        let first = list_legal_answer_records_for_project_before(
            &connection,
            "project-history",
            None,
            None,
            2,
        )
        .expect("first page reads");
        assert_eq!(
            first
                .iter()
                .map(|row| row.record_id.as_str())
                .collect::<Vec<_>>(),
            vec!["answer-3", "answer-2"]
        );
        let second = list_legal_answer_records_for_project_before(
            &connection,
            "project-history",
            Some(&first[1].created_at),
            Some(&first[1].record_id),
            2,
        )
        .expect("second page reads");
        assert_eq!(
            second
                .iter()
                .map(|row| row.record_id.as_str())
                .collect::<Vec<_>>(),
            vec!["answer-1"]
        );
    }

    #[test]
    fn user_database_tables_do_not_have_api_key_columns() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let connection = open_user_database(&database_path).expect("user database opens");

        for table in [
            "provider_profiles",
            "projects",
            "case_files",
            "case_extraction_confirmations",
            "case_parties",
            "case_facts",
            "evidence_items",
            "evidence_links",
            "fact_issue_links",
            "legal_issues",
            "case_uncertainties",
            "legal_basis",
            "legal_answer_records",
        ] {
            let mut statement = connection
                .prepare(&format!("PRAGMA table_info({table})"))
                .expect("table info prepares");
            let column_names = statement
                .query_map([], |row| row.get::<_, String>(1))
                .expect("table info queries")
                .collect::<rusqlite::Result<Vec<_>>>()
                .expect("table info collects");

            assert!(!column_names.iter().any(|name| {
                let lower = name.to_ascii_lowercase();
                lower.contains("api") || lower.contains("key") || lower.contains("secret")
            }));
        }
    }

    #[test]
    fn legal_core_database_opens_read_only_with_safe_pragmas() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(LEGAL_CORE_DB_FILE_NAME);

        let writable_connection =
            rusqlite::Connection::open(&database_path).expect("legal core database exists");
        initialize_legal_core_database(&writable_connection).expect("schema initializes");

        let read_only_connection =
            open_legal_core_read_only(&database_path).expect("legal core opens read-only");
        let query_only: i64 = read_only_connection
            .query_row("PRAGMA query_only", [], |row| row.get(0))
            .expect("query_only pragma is readable");
        let trusted_schema: i64 = read_only_connection
            .query_row("PRAGMA trusted_schema", [], |row| row.get(0))
            .expect("trusted_schema pragma is readable");
        let mmap_size: i64 = read_only_connection
            .query_row("PRAGMA mmap_size", [], |row| row.get(0))
            .expect("mmap_size pragma is readable");
        let error = read_only_connection
            .execute("CREATE TABLE write_probe (id INTEGER PRIMARY KEY)", [])
            .expect_err("read-only legal core rejects writes");

        assert_eq!(query_only, 1);
        assert_eq!(trusted_schema, 0);
        assert_eq!(mmap_size, 1_073_741_824);
        assert!(matches!(error, rusqlite::Error::SqliteFailure(_, _)));
    }

    #[test]
    fn legal_core_schema_contains_required_stage_one_tables() {
        let connection = rusqlite::Connection::open_in_memory().expect("memory database opens");
        initialize_legal_core_database(&connection).expect("schema initializes");

        for table in [
            "law_documents",
            "law_versions",
            "law_articles",
            "law_relations",
            "law_aliases",
            "issuing_authorities",
            "legal_topics",
            "article_topics",
            "guiding_cases",
            "document_templates",
            "citation_metadata",
            "database_metadata",
            "source_systems",
            "source_records",
            "source_categories",
            "coverage_audit",
            "ingestion_audit",
            "legal_attachments",
            "law_articles_fts",
        ] {
            let count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .expect("sqlite_master can be queried");

            assert_eq!(count, 1, "{table} should exist");
        }
    }

    fn seed_unversioned_weak_projects_database(
        database_path: &std::path::Path,
        include_metadata: bool,
    ) {
        let connection =
            rusqlite::Connection::open(database_path).expect("unversioned database opens");
        if include_metadata {
            connection
                .execute_batch(
                    "
                    CREATE TABLE user_database_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO user_database_metadata (key, value)
                    VALUES ('legacy_note', 'preserve');
                    ",
                )
                .expect("unversioned metadata is created");
        }
        connection
            .execute_batch(
                "
                CREATE TABLE projects (
                    project_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    case_type TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    opened_on TEXT,
                    summary TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO projects (project_id, title, status)
                VALUES ('unversioned-project', 'Preserve me', 'active');
                ",
            )
            .expect("weak unversioned business table is created");
    }

    fn assert_rebuilt_unversioned_project_database(database_path: &std::path::Path) {
        let connection = open_user_database(database_path).expect("rebuilt database opens");
        let marker: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = ?1",
                [USER_CANONICAL_SCHEMA_MARKER_KEY],
                |row| row.get(0),
            )
            .expect("canonical marker exists");
        let title: String = connection
            .query_row(
                "SELECT title FROM projects WHERE project_id = 'unversioned-project'",
                [],
                |row| row.get(0),
            )
            .expect("legacy project survives rebuild");

        assert_eq!(marker, USER_CANONICAL_SCHEMA_MARKER_VALUE);
        assert_eq!(title, "Preserve me");
        connection
            .execute(
                "INSERT INTO projects (project_id, title, status)
                 VALUES ('invalid-after-rebuild', 'Invalid', 'legacy-status')",
                [],
            )
            .expect_err("canonical project CHECK is present after rebuild");
    }

    #[test]
    fn provider_audit_snapshot_schema_rejects_unknown_secret_fields_and_partial_shapes() {
        validate_provider_audit_snapshot_json(&provider_snapshot_json())
            .expect("fixed provider audit snapshot is accepted");
        for kind in [
            "deep_seek",
            "qwen",
            "silicon_flow",
            "volcengine_ark",
            "custom",
        ] {
            let snapshot = provider_snapshot_json().replace("deep_seek", kind);
            validate_provider_audit_snapshot_json(&snapshot)
                .unwrap_or_else(|_| panic!("provider kind {kind} must remain supported"));
        }

        for invalid in [
            "{}",
            r#"{"apiKey":"must-never-persist"}"#,
            r#"{"kind":"deep_seek","modelId":"model","baseUrl":"https://api.example.invalid","capabilities":{},"options":{}}"#,
            r#"{"kind":"deep_seek","modelId":"model","baseUrl":"https://api.example.invalid","capabilities":{"chat":true,"streaming":true,"customModelId":true,"customBaseUrl":true,"reasoning":true},"options":{"thinking":false,"enableThinking":null,"thinkingBudget":null,"reasoningEffort":null,"endpointId":null,"workspaceId":null,"allowPrivateNetwork":false},"apiKey":"must-never-persist"}"#,
        ] {
            let error = validate_provider_audit_snapshot_json(invalid)
                .expect_err("non-contract provider snapshot is rejected");
            assert!(!error.to_string().contains("must-never-persist"));
        }
    }

    fn provider_snapshot_json() -> String {
        r#"{"kind":"deep_seek","modelId":"test-model","baseUrl":"https://api.example.invalid/v1","capabilities":{"chat":true,"streaming":true,"customModelId":true,"customBaseUrl":true,"reasoning":true},"options":{"thinking":false,"enableThinking":null,"thinkingBudget":null,"reasoningEffort":null,"endpointId":null,"workspaceId":null,"allowPrivateNetwork":false}}"#.to_owned()
    }

    fn seed_project(connection: &rusqlite::Connection, project_id: &str) {
        upsert_case_project(
            connection,
            &CaseProjectRow {
                project_id: project_id.to_owned(),
                title: project_id.to_owned(),
                case_type: "civil".to_owned(),
                status: "active".to_owned(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .expect("project inserts");
    }

    fn assert_project_scope_error(error: rusqlite::Error, expected_message: &str) {
        assert!(
            matches!(
                &error,
                rusqlite::Error::SqliteFailure(_, Some(message))
                    if message.contains(expected_message)
            ),
            "unexpected project-scope error: {error}"
        );
    }

    fn project_and_value(
        connection: &rusqlite::Connection,
        table: &str,
        id_column: &str,
        id: &str,
        value_column: &str,
    ) -> (String, String) {
        connection
            .query_row(
                &format!("SELECT project_id, {value_column} FROM {table} WHERE {id_column} = ?1"),
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("project-scoped row reads")
    }

    fn evidence_link_owner_and_targets(
        connection: &rusqlite::Connection,
        link_id: &str,
    ) -> (String, String, String) {
        connection
            .query_row(
                "SELECT project_id, fact_id, evidence_id FROM evidence_links WHERE link_id = ?1",
                [link_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("evidence link reads")
    }

    fn sqlite_master_count(connection: &rusqlite::Connection, name: &str) -> i64 {
        connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .expect("sqlite_master can be queried")
    }

    fn seed_extraction_project_and_file(connection: &rusqlite::Connection) {
        upsert_case_project(
            connection,
            &CaseProjectRow {
                project_id: "project-extraction".to_owned(),
                title: "Extraction project".to_owned(),
                case_type: "civil".to_owned(),
                status: "active".to_owned(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .expect("project inserts");
        upsert_case_file(
            connection,
            &CaseFileRow {
                file_id: "file-source".to_owned(),
                project_id: "project-extraction".to_owned(),
                title: "Original material".to_owned(),
                file_type: "note".to_owned(),
                storage_reference: "client-note.txt".to_owned(),
                summary: "Original text".to_owned(),
                created_at: String::new(),
            },
        )
        .expect("source file inserts");
    }

    fn confirmed_extraction_rows() -> ConfirmedCaseExtractionRows {
        ConfirmedCaseExtractionRows {
            review_id: "review-batch-1".to_owned(),
            project_id: "project-extraction".to_owned(),
            provider_id: "mock-provider".to_owned(),
            source_file_ids: vec!["file-source".to_owned()],
            expected_revision: 0,
            reviewed_extraction_json:
                r#"{"parties":[],"facts":[],"evidence":[],"legalIssues":[],"uncertainties":[]}"#
                    .to_owned(),
            parties: vec![CasePartyRow {
                party_id: "batch-party".to_owned(),
                project_id: "project-extraction".to_owned(),
                name: "Reviewed party".to_owned(),
                normalized_name: "reviewedparty".to_owned(),
                role: "plaintiff".to_owned(),
                contact: String::new(),
                notes: String::new(),
            }],
            facts: vec![CaseFactRow {
                fact_id: "batch-fact".to_owned(),
                project_id: "project-extraction".to_owned(),
                occurred_on: Some("2026-01-02".to_owned()),
                title: "Reviewed fact title".to_owned(),
                description: "Reviewed fact description".to_owned(),
                source: "confirmed extraction".to_owned(),
                confirmation_status: "confirmed".to_owned(),
            }],
            evidence: vec![EvidenceItemRow {
                evidence_id: "batch-evidence".to_owned(),
                project_id: "project-extraction".to_owned(),
                evidence_number: "EX-1".to_owned(),
                title: "Reviewed evidence".to_owned(),
                source: "client".to_owned(),
                formed_on: None,
                summary: String::new(),
                storage_reference: String::new(),
                confirmation_status: "confirmed".to_owned(),
            }],
            evidence_links: vec![EvidenceLinkRow {
                link_id: "batch-link".to_owned(),
                project_id: "project-extraction".to_owned(),
                fact_id: "batch-fact".to_owned(),
                evidence_id: "batch-evidence".to_owned(),
            }],
            legal_issues: vec![LegalIssueRow {
                issue_id: "batch-issue".to_owned(),
                project_id: "project-extraction".to_owned(),
                title: "Reviewed issue".to_owned(),
                description: String::new(),
                claim: String::new(),
                status: "open".to_owned(),
                confirmation_status: "confirmed".to_owned(),
            }],
            uncertainties: vec![CaseUncertaintyRow {
                uncertainty_id: "batch-uncertainty".to_owned(),
                project_id: "project-extraction".to_owned(),
                description: "Reviewed uncertainty".to_owned(),
                related_entity_type: "fact".to_owned(),
                related_entity_id: Some("batch-fact".to_owned()),
                source_file_ids_json: r#"["file-source"]"#.to_owned(),
                status: "open".to_owned(),
                resolution: String::new(),
                confirmation_status: "confirmed".to_owned(),
                created_at: String::new(),
                updated_at: String::new(),
            }],
        }
    }

    fn persist_pending_for_confirmed_rows(
        connection: &mut rusqlite::Connection,
        rows: &ConfirmedCaseExtractionRows,
    ) {
        let material_digest =
            current_case_materials_digest(connection, &rows.project_id, &rows.source_file_ids)
                .expect("material digest reads")
                .expect("material exists");
        insert_pending_extraction_review(
            connection,
            &PendingExtractionReviewRow {
                review_id: rows.review_id.clone(),
                project_id: rows.project_id.clone(),
                provider_id: rows.provider_id.clone(),
                provider_snapshot_json: provider_snapshot_json(),
                source_file_ids_json: serde_json::to_string(&rows.source_file_ids)
                    .expect("source IDs serialize"),
                source_materials_digest: material_digest,
                extraction_json: rows.reviewed_extraction_json.clone(),
                revision: rows.expected_revision,
                created_at: String::new(),
                expires_at: String::new(),
            },
        )
        .expect("pending review persists");
    }

    fn table_row_count(connection: &rusqlite::Connection, table: &str) -> i64 {
        let sql = match table {
            "projects" => "SELECT COUNT(*) FROM projects",
            "case_files" => "SELECT COUNT(*) FROM case_files",
            "case_extraction_confirmations" => "SELECT COUNT(*) FROM case_extraction_confirmations",
            "case_parties" => "SELECT COUNT(*) FROM case_parties",
            "case_facts" => "SELECT COUNT(*) FROM case_facts",
            "evidence_items" => "SELECT COUNT(*) FROM evidence_items",
            "evidence_links" => "SELECT COUNT(*) FROM evidence_links",
            "fact_issue_links" => "SELECT COUNT(*) FROM fact_issue_links",
            "legal_issues" => "SELECT COUNT(*) FROM legal_issues",
            "case_uncertainties" => "SELECT COUNT(*) FROM case_uncertainties",
            "legal_basis" => "SELECT COUNT(*) FROM legal_basis",
            "legal_answer_records" => "SELECT COUNT(*) FROM legal_answer_records",
            _ => panic!("unexpected table: {table}"),
        };

        connection
            .query_row(sql, [], |row| row.get(0))
            .expect("table row count can be queried")
    }
}
