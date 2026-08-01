use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt::{self, Display},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicI64, Ordering},
    time::Duration,
};

use rusqlite::{functions::FunctionFlags, params, OptionalExtension};
use sha2::{Digest, Sha256};

mod migration_source;

pub use migration_source::{
    validate_open_user_database_migration_source_read_only,
    validate_user_database_migration_source_read_only,
    with_validated_user_database_migration_source_read_only, UserMigrationSourceFileProof,
    UserMigrationSourceProof, UserMigrationTableProof, V031UserSchemaProvenance,
    ValidatedUserMigrationSourceSession, ValidatedUserSourceSchema,
    V031_USER_CANONICAL_EMPTY_FIXTURE_SHA256, V031_USER_CANONICAL_SCHEMA_MARKER,
    V031_USER_GENERATION_CARGO_LOCK_SHA256, V031_USER_GENERATION_DATABASE_SOURCE_SHA256,
    V031_USER_GENERATOR_SHA256, V031_USER_INTERNAL_SCHEMA_MANIFEST_SHA256,
    V031_USER_INTERNAL_SCHEMA_OBJECT_COUNT, V031_USER_SCHEMA_MANIFEST_SHA256,
    V031_USER_SCHEMA_OBJECT_COUNT, V031_USER_SCHEMA_PROVENANCE, V031_USER_SCHEMA_VERSION,
};

pub const LEGAL_CORE_DB_FILE_NAME: &str = "legal_core.sqlite";
pub const USER_DB_FILE_NAME: &str = "user.sqlite";
pub const USER_SCHEMA_VERSION: i64 = 11;
const USER_CANONICAL_SCHEMA_MARKER_KEY: &str = "canonical_schema_version";
// This marker describes the exact canonical shape within schema version 11.
// Keep it independent from USER_SCHEMA_VERSION so constraint-only repairs can
// be applied once without pretending that an unverified current database is sound.
const USER_CANONICAL_SCHEMA_MARKER_VALUE: &str =
    "v11-case-assistant-exact-proposal-provenance-trusted-retirement-20260731";
const PENDING_EXTRACTION_REVIEW_RETENTION_SQL: &str = "+7 days";
const CASE_MATERIAL_DIGEST_DOMAIN: &[u8] = b"lawyer-assistance-case-materials-v1\0";
const CASE_WORKSPACE_DIGEST_DOMAIN: &[u8] = b"lawyer-assistance-case-workspace-v2-artifacts\0";
const MAX_CASE_ASSISTANT_SOURCE_SNAPSHOTS_BYTES: usize = 256 * 1024;
const MAX_CASE_ASSISTANT_OUTPUT_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_CASE_ASSISTANT_OUTPUT_PREVIEW_BYTES: usize = 16 * 1024;
const MAX_CASE_ASSISTANT_TOOL_AUDIT_BYTES: usize = 64 * 1024;
const MAX_CASE_ASSISTANT_AUDIT_BODY_BYTES: u64 = 16 * 1024 * 1024;
const CASE_PROJECT_DELETED_RETIREMENT_REASON: &str = "case_project_deleted";
const PRIVACY_JOURNAL_RECOVERY_RETIREMENT_REASON: &str = "privacy_journal_recovery";
const LEGACY_MIGRATION_CLEANUP_RETIREMENT_REASON: &str = "legacy_migration_cleanup";
const LEGACY_QA_CONVERSATION_ID_PREFIX: &str = "legacy-qa:";
const LEGACY_QA_TITLE_MAX_CHARS: usize = 80;
const COMPAT_QA_CONVERSATION_ID_PREFIX: &str = "qa:";
const LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX: &str = "migration-unassigned-legal-answers";
const LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE: &str = "迁移隔离：旧版未归属问答记录";
const LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY: &str =
    "这些问答记录来自旧版数据库，旧版未保存案件归属，不能推断其真实案件。可在此查看恢复；删除本隔离项目会级联彻底清除全部记录。";
pub const LEGAL_CORE_SCHEMA_SQL: &str = include_str!("../../../data/schema/legal_core.sql");

static NEXT_CASE_RETIREMENT_CONNECTION_NONCE: AtomicI64 = AtomicI64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
struct CaseRetirementAuthority {
    connection_nonce: i64,
    project_id: String,
    retirement_reason: String,
    privacy_deletion_id: Option<String>,
}

thread_local! {
    static CASE_RETIREMENT_AUTHORITY_STACK: RefCell<Vec<CaseRetirementAuthority>> =
        const { RefCell::new(Vec::new()) };
}

struct CaseRetirementAuthorityGuard {
    authority: CaseRetirementAuthority,
}

impl CaseRetirementAuthorityGuard {
    fn enter(authority: CaseRetirementAuthority) -> Self {
        CASE_RETIREMENT_AUTHORITY_STACK.with(|stack| {
            stack.borrow_mut().push(authority.clone());
        });
        Self { authority }
    }
}

impl Drop for CaseRetirementAuthorityGuard {
    fn drop(&mut self) {
        CASE_RETIREMENT_AUTHORITY_STACK.with(|stack| {
            let removed = stack.borrow_mut().pop();
            debug_assert_eq!(removed.as_ref(), Some(&self.authority));
        });
    }
}

fn next_case_retirement_connection_nonce() -> Result<i64, DatabaseInitError> {
    NEXT_CASE_RETIREMENT_CONNECTION_NONCE
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .map_err(|_| {
            user_schema_migration_error(
                "case retirement connection nonce space is exhausted".to_owned(),
            )
            .into()
        })
}

fn case_retirement_connection_nonce(connection: &rusqlite::Connection) -> rusqlite::Result<i64> {
    connection.query_row("SELECT case_retirement_connection_nonce()", [], |row| {
        row.get(0)
    })
}

fn with_case_retirement_authority<T>(
    connection: &rusqlite::Connection,
    project_id: &str,
    retirement_reason: &str,
    privacy_deletion_id: Option<&str>,
    operation: impl FnOnce() -> rusqlite::Result<T>,
) -> rusqlite::Result<T> {
    let authority = CaseRetirementAuthority {
        connection_nonce: case_retirement_connection_nonce(connection)?,
        project_id: project_id.to_owned(),
        retirement_reason: retirement_reason.to_owned(),
        privacy_deletion_id: privacy_deletion_id.map(str::to_owned),
    };
    let _guard = CaseRetirementAuthorityGuard::enter(authority);
    operation()
}

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
        validate_canonical_user_database(&connection)?;
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
    let connection = open_user_database_read_only(user_database_path)?;
    validate_open_user_database(&connection)
}

/// Opens an existing user database without granting SQLite write or create
/// access. Service-layer read tools use this entry point so validation and
/// queries run on the same read-only connection.
pub fn open_user_database_read_only(
    user_database_path: impl AsRef<Path>,
) -> Result<rusqlite::Connection, DatabaseInitError> {
    let connection = rusqlite::Connection::open_with_flags(
        user_database_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    configure_user_database_connection(&connection)?;
    connection.pragma_update(None, "query_only", "ON")?;
    Ok(connection)
}

/// Opens an existing user database for writes, but never creates a missing
/// file. Initialization and migration intentionally continue to use
/// [`open_user_database`].
pub fn open_existing_user_database(
    user_database_path: impl AsRef<Path>,
) -> Result<rusqlite::Connection, DatabaseInitError> {
    let connection = rusqlite::Connection::open_with_flags(
        user_database_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
    )?;
    configure_user_database_connection(&connection)?;
    Ok(connection)
}

/// Validates the canonical user schema on an already-open connection. Keeping
/// this separate from path opening lets security-sensitive callers pin and
/// identity-check the file once, then validate that exact SQLite handle.
pub fn validate_open_user_database(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    validate_canonical_user_database(connection)
}

pub fn open_user_database(
    user_database_path: impl AsRef<Path>,
) -> Result<rusqlite::Connection, DatabaseInitError> {
    let connection = rusqlite::Connection::open(user_database_path)?;

    configure_user_database_connection(&connection)?;

    Ok(connection)
}

fn configure_user_database_connection(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    // User commands open short-lived connections and Tauri may execute more
    // than one write command at a time. SQLite otherwise fails immediately on
    // a transient writer lock. A bounded wait is sufficient for this small,
    // local workload and avoids changing the persistent journal mode (and its
    // backup/sidecar-file lifecycle) merely to serialize short writes.
    connection.busy_timeout(Duration::from_secs(5))?;
    let retirement_connection_nonce = next_case_retirement_connection_nonce()?;
    connection.create_scalar_function(
        "case_retirement_connection_nonce",
        0,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        move |_| Ok(retirement_connection_nonce),
    )?;
    connection.create_scalar_function(
        "case_retirement_authorized",
        3,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_INNOCUOUS,
        move |context| {
            let project_id = context.get::<String>(0)?;
            let retirement_reason = context.get::<String>(1)?;
            let privacy_deletion_id = context.get::<Option<String>>(2)?;
            let authorized = CASE_RETIREMENT_AUTHORITY_STACK.with(|stack| {
                stack.borrow().last().is_some_and(|authority| {
                    authority.connection_nonce == retirement_connection_nonce
                        && authority.project_id == project_id
                        && authority.retirement_reason == retirement_reason
                        && authority.privacy_deletion_id == privacy_deletion_id
                })
            });
            Ok(i64::from(authorized))
        },
    )?;
    connection.create_scalar_function(
        "case_assistant_sha256",
        1,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let value = context.get::<String>(0)?;
            Ok(sha256_hex(value.as_bytes()))
        },
    )?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    // Append-preserving lineage tables rely on DELETE triggers also firing
    // for SQLite's REPLACE conflict algorithm.
    connection.pragma_update(None, "recursive_triggers", "ON")?;
    Ok(())
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

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn canonical_json_value(json: &str, max_bytes: usize) -> rusqlite::Result<serde_json::Value> {
    if json.is_empty() || json.len() > max_bytes {
        return Err(user_schema_migration_error(
            "case assistant canonical JSON exceeds its bounded contract".to_owned(),
        ));
    }
    let value = serde_json::from_str::<serde_json::Value>(json).map_err(|_| {
        user_schema_migration_error("case assistant canonical JSON is invalid".to_owned())
    })?;
    let encoded = serde_json::to_string(&value).map_err(|_| {
        user_schema_migration_error("case assistant canonical JSON could not be encoded".to_owned())
    })?;
    if encoded != json {
        return Err(user_schema_migration_error(
            "case assistant JSON must use the canonical compact encoding".to_owned(),
        ));
    }
    Ok(value)
}

fn validate_case_assistant_source_snapshots_json(
    snapshots_json: &str,
    expected_sha256: &str,
) -> rusqlite::Result<()> {
    let value = canonical_json_value(snapshots_json, MAX_CASE_ASSISTANT_SOURCE_SNAPSHOTS_BYTES)?;
    if !is_lower_hex_sha256(expected_sha256)
        || sha256_hex(snapshots_json.as_bytes()) != expected_sha256
    {
        return Err(user_schema_migration_error(
            "case assistant source snapshot hash is invalid".to_owned(),
        ));
    }
    let snapshots = value.as_array().ok_or_else(|| {
        user_schema_migration_error(
            "case assistant source snapshots must be a JSON array".to_owned(),
        )
    })?;
    if snapshots.is_empty() || snapshots.len() > 64 {
        return Err(user_schema_migration_error(
            "case assistant source snapshot count is out of bounds".to_owned(),
        ));
    }

    const SNAPSHOT_KEYS: &[&str] = &[
        "approvedPayloadSha256",
        "extractionSha256",
        "generationId",
        "generationNumber",
        "generationRowVersion",
        "materialId",
        "ordinal",
        "redactedContentSha256",
        "riskRevision",
        "riskRevisionHash",
        "selectionId",
        "selectionRowVersion",
    ];
    let mut material_ids = HashSet::new();
    let mut generation_ids = HashSet::new();
    let mut selection_ids = HashSet::new();
    for (ordinal, snapshot) in snapshots.iter().enumerate() {
        let object = snapshot.as_object().ok_or_else(|| {
            user_schema_migration_error(
                "case assistant source snapshot must be an object".to_owned(),
            )
        })?;
        if !has_exact_json_keys(object, SNAPSHOT_KEYS)
            || object.get("ordinal").and_then(serde_json::Value::as_u64)
                != u64::try_from(ordinal).ok()
            || ![
                "generationNumber",
                "generationRowVersion",
                "riskRevision",
                "selectionRowVersion",
            ]
            .iter()
            .all(|key| {
                object
                    .get(*key)
                    .and_then(serde_json::Value::as_u64)
                    .is_some_and(|value| value > 0 && i64::try_from(value).is_ok())
            })
            || ![
                "approvedPayloadSha256",
                "extractionSha256",
                "redactedContentSha256",
                "riskRevisionHash",
            ]
            .iter()
            .all(|key| {
                object
                    .get(*key)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(is_lower_hex_sha256)
            })
        {
            return Err(user_schema_migration_error(
                "case assistant source snapshot does not match the closed schema".to_owned(),
            ));
        }
        let opaque_id = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .filter(|value| {
                    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
                })
        };
        let Some(material_id) = opaque_id("materialId") else {
            return Err(user_schema_migration_error(
                "case assistant material snapshot identifier is invalid".to_owned(),
            ));
        };
        let Some(generation_id) = opaque_id("generationId") else {
            return Err(user_schema_migration_error(
                "case assistant generation snapshot identifier is invalid".to_owned(),
            ));
        };
        let Some(selection_id) = opaque_id("selectionId") else {
            return Err(user_schema_migration_error(
                "case assistant selection snapshot identifier is invalid".to_owned(),
            ));
        };
        if !material_ids.insert(material_id.to_owned())
            || !generation_ids.insert(generation_id.to_owned())
            || !selection_ids.insert(selection_id.to_owned())
        {
            return Err(user_schema_migration_error(
                "case assistant source snapshots contain duplicate lineage".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_case_assistant_output_payload_json(
    output_kind: &str,
    output_payload_json: &str,
    output_sha256: &str,
) -> rusqlite::Result<()> {
    if !matches!(
        output_kind,
        "case_analysis" | "case_document" | "case_diagram"
    ) || !is_lower_hex_sha256(output_sha256)
    {
        return Err(user_schema_migration_error(
            "case assistant output metadata is invalid".to_owned(),
        ));
    }
    let value = canonical_json_value(output_payload_json, MAX_CASE_ASSISTANT_OUTPUT_PAYLOAD_BYTES)?;
    let object = value.as_object().ok_or_else(|| {
        user_schema_migration_error("case assistant output payload must be an object".to_owned())
    })?;
    if !has_exact_json_keys(object, &["content", "outputKind", "schemaVersion"])
        || object
            .get("schemaVersion")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        || object.get("outputKind").and_then(serde_json::Value::as_str) != Some(output_kind)
        || object.get("content").is_none_or(serde_json::Value::is_null)
        || sha256_hex(output_payload_json.as_bytes()) != output_sha256
    {
        return Err(user_schema_migration_error(
            "case assistant output payload does not match its typed hash contract".to_owned(),
        ));
    }
    Ok(())
}

fn validate_case_assistant_expected_proposal_source_refs(
    output_kind: &str,
    source_refs_json: &str,
    source_refs_sha256: &str,
) -> rusqlite::Result<()> {
    if !is_lower_hex_sha256(source_refs_sha256)
        || sha256_hex(source_refs_json.as_bytes()) != source_refs_sha256
    {
        return Err(user_schema_migration_error(
            "case assistant expected proposal source refs do not match their hash".to_owned(),
        ));
    }
    let value = canonical_json_value(source_refs_json, MAX_CASE_ASSISTANT_SOURCE_SNAPSHOTS_BYTES)?;
    let refs = value.as_array().ok_or_else(|| {
        user_schema_migration_error(
            "case assistant expected proposal source refs must be an array".to_owned(),
        )
    })?;
    let mut previous: Option<&str> = None;
    for source_ref in refs {
        let source_ref = source_ref.as_str().filter(|source_ref| {
            !source_ref.is_empty()
                && source_ref.len() <= 256
                && !source_ref.chars().any(char::is_control)
        });
        let Some(source_ref) = source_ref else {
            return Err(user_schema_migration_error(
                "case assistant expected proposal source ref is invalid".to_owned(),
            ));
        };
        if previous.is_some_and(|previous| previous >= source_ref) {
            return Err(user_schema_migration_error(
                "case assistant expected proposal source refs must be strictly sorted".to_owned(),
            ));
        }
        previous = Some(source_ref);
    }
    if output_kind != "case_analysis" && !refs.is_empty() {
        return Err(user_schema_migration_error(
            "non-analysis case assistant output cannot expect proposal source refs".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedCaseAssistantToolAudit {
    project_id: String,
    conversation_id: String,
    generation_ids: Vec<String>,
    workspace_digest: String,
    output_kind: Option<String>,
    typed_output_sha256: Option<String>,
    proposal_source_refs_sha256: Option<String>,
    source_generation_ids: Vec<String>,
    project_binding_sha256: Option<String>,
    source_snapshots_sha256: Option<String>,
}

fn invalid_case_assistant_tool_audit() -> rusqlite::Error {
    user_schema_migration_error(
        "case assistant tool audit does not match the fixed no-body schema".to_owned(),
    )
}

fn case_assistant_audit_text<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    max_bytes: usize,
) -> Option<&'a str> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|value| {
            !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
        })
}

fn case_assistant_audit_identifier<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<&'a str> {
    case_assistant_audit_text(object, key, 128)
        .filter(|value| !value.contains('/') && !value.contains('\\'))
}

fn case_assistant_audit_id_array(value: Option<&serde_json::Value>) -> Option<Vec<String>> {
    let values = value?.as_array()?;
    if values.is_empty() || values.len() > 16 {
        return None;
    }
    let mut identifiers = Vec::with_capacity(values.len());
    let mut unique = HashSet::with_capacity(values.len());
    for value in values {
        let identifier = value.as_str().filter(|identifier| {
            !identifier.is_empty()
                && identifier.len() <= 128
                && !identifier.chars().any(char::is_control)
                && !identifier.contains('/')
                && !identifier.contains('\\')
        })?;
        if !unique.insert(identifier.to_owned()) {
            return None;
        }
        identifiers.push(identifier.to_owned());
    }
    Some(identifiers)
}

fn case_assistant_confirmation_audit_is_unreceived(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(serde_json::Value::as_object)
        .is_some_and(|confirmation| {
            has_exact_json_keys(confirmation, &["received", "writebackRequired"])
                && confirmation
                    .get("received")
                    .and_then(serde_json::Value::as_bool)
                    == Some(false)
                && confirmation
                    .get("writebackRequired")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
        })
}

fn validate_case_assistant_tool_audit_contract(
    run_id: &str,
    run_provider_snapshot_json: &str,
    status: &str,
    input_audit_json: &str,
    output_audit_json: &str,
    source_audit_json: &str,
    error_type: Option<&str>,
) -> rusqlite::Result<ValidatedCaseAssistantToolAudit> {
    validate_provider_audit_snapshot_json(run_provider_snapshot_json)?;
    let run_provider_snapshot =
        serde_json::from_str::<serde_json::Value>(run_provider_snapshot_json)
            .map_err(|_| invalid_case_assistant_tool_audit())?;

    let input = canonical_json_value(input_audit_json, MAX_CASE_ASSISTANT_TOOL_AUDIT_BYTES)?;
    let input = input
        .as_object()
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    if run_id.is_empty()
        || run_id.len() > 128
        || run_id.chars().any(char::is_control)
        || run_id.contains('/')
        || run_id.contains('\\')
        || !has_exact_json_keys(
            input,
            &[
                "capability",
                "classification",
                "confirmation",
                "inputCounts",
                "inputHashes",
                "inputIds",
                "providerSnapshot",
                "requestId",
                "runId",
                "status",
            ],
        )
        || case_assistant_audit_identifier(input, "requestId") != Some(run_id)
        || case_assistant_audit_identifier(input, "runId") != Some(run_id)
        || case_assistant_audit_text(input, "capability", 64) != Some("assistant.case_work")
        || case_assistant_audit_text(input, "classification", 64) != Some("case_redacted_approved")
        || case_assistant_audit_text(input, "status", 32) != Some("running")
        || input.get("providerSnapshot") != Some(&run_provider_snapshot)
        || !case_assistant_confirmation_audit_is_unreceived(input.get("confirmation"))
    {
        return Err(invalid_case_assistant_tool_audit());
    }

    let input_ids = input
        .get("inputIds")
        .and_then(serde_json::Value::as_object)
        .filter(|value| {
            has_exact_json_keys(
                value,
                &["conversationId", "projectId", "redactionGenerationIds"],
            )
        })
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    let project_id = case_assistant_audit_identifier(input_ids, "projectId")
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    let conversation_id = case_assistant_audit_identifier(input_ids, "conversationId")
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    let generation_ids = case_assistant_audit_id_array(input_ids.get("redactionGenerationIds"))
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    if generation_ids
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(invalid_case_assistant_tool_audit());
    }

    let input_hashes = input
        .get("inputHashes")
        .and_then(serde_json::Value::as_object)
        .filter(|value| {
            has_exact_json_keys(
                value,
                &[
                    "generationSetSha256",
                    "historySha256",
                    "minimalContextSha256",
                    "promptSha256",
                    "workspaceDigest",
                ],
            )
        })
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    if input_hashes.values().any(|value| {
        value
            .as_str()
            .is_none_or(|value| !is_lower_hex_sha256(value))
    }) {
        return Err(invalid_case_assistant_tool_audit());
    }
    let workspace_digest = input_hashes
        .get("workspaceDigest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_case_assistant_tool_audit)?;

    let input_counts = input
        .get("inputCounts")
        .and_then(serde_json::Value::as_object)
        .filter(|value| {
            has_exact_json_keys(
                value,
                &[
                    "generationCount",
                    "historyBytes",
                    "historyMessages",
                    "knownBodyBytes",
                    "promptBytes",
                ],
            )
        })
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    if input_counts.values().any(|value| {
        value
            .as_u64()
            .is_none_or(|value| value > MAX_CASE_ASSISTANT_AUDIT_BODY_BYTES)
    }) || input_counts
        .get("generationCount")
        .and_then(serde_json::Value::as_u64)
        != u64::try_from(generation_ids.len()).ok()
    {
        return Err(invalid_case_assistant_tool_audit());
    }

    let mut validated = ValidatedCaseAssistantToolAudit {
        project_id: project_id.to_owned(),
        conversation_id: conversation_id.to_owned(),
        generation_ids,
        workspace_digest: workspace_digest.to_owned(),
        output_kind: None,
        typed_output_sha256: None,
        proposal_source_refs_sha256: None,
        source_generation_ids: Vec::new(),
        project_binding_sha256: None,
        source_snapshots_sha256: None,
    };

    if status == "running" {
        if output_audit_json != "{}" || source_audit_json != "{}" || error_type.is_some() {
            return Err(invalid_case_assistant_tool_audit());
        }
        return Ok(validated);
    }

    let output = canonical_json_value(output_audit_json, MAX_CASE_ASSISTANT_TOOL_AUDIT_BYTES)?;
    let output = output
        .as_object()
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    let source = canonical_json_value(source_audit_json, MAX_CASE_ASSISTANT_TOOL_AUDIT_BYTES)?;
    let source = source
        .as_object()
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    if status == "succeeded" {
        if error_type.is_some()
            || !has_exact_json_keys(
                output,
                &[
                    "confirmation",
                    "outputCounts",
                    "outputHashes",
                    "outputIds",
                    "status",
                ],
            )
            || case_assistant_audit_text(output, "status", 32) != Some("succeeded")
            || !case_assistant_confirmation_audit_is_unreceived(output.get("confirmation"))
            || !has_exact_json_keys(
                source,
                &[
                    "classification",
                    "confirmation",
                    "inputHashes",
                    "providerSnapshot",
                    "sourceRefs",
                ],
            )
            || case_assistant_audit_text(source, "classification", 64)
                != Some("case_redacted_approved")
            || source.get("providerSnapshot") != Some(&run_provider_snapshot)
            || !case_assistant_confirmation_audit_is_unreceived(source.get("confirmation"))
        {
            return Err(invalid_case_assistant_tool_audit());
        }
        let output_ids = output
            .get("outputIds")
            .and_then(serde_json::Value::as_object)
            .filter(|value| has_exact_json_keys(value, &["pendingOutputKind"]))
            .ok_or_else(invalid_case_assistant_tool_audit)?;
        let output_kind = case_assistant_audit_text(output_ids, "pendingOutputKind", 32)
            .filter(|value| matches!(*value, "case_analysis" | "case_document" | "case_diagram"))
            .ok_or_else(invalid_case_assistant_tool_audit)?;
        let output_hashes = output
            .get("outputHashes")
            .and_then(serde_json::Value::as_object)
            .filter(|value| {
                has_exact_json_keys(
                    value,
                    &[
                        "approvedEnvelopeSha256",
                        "proposalSourceRefsSha256",
                        "providerOutputSha256",
                        "typedOutputSha256",
                    ],
                )
            })
            .ok_or_else(invalid_case_assistant_tool_audit)?;
        if output_hashes.values().any(|value| {
            value
                .as_str()
                .is_none_or(|value| !is_lower_hex_sha256(value))
        }) {
            return Err(invalid_case_assistant_tool_audit());
        }
        let output_counts = output
            .get("outputCounts")
            .and_then(serde_json::Value::as_object)
            .filter(|value| {
                has_exact_json_keys(value, &["approvedEnvelopeBytes", "bytes", "items"])
            })
            .ok_or_else(invalid_case_assistant_tool_audit)?;
        if output_counts.values().any(|value| {
            value
                .as_u64()
                .is_none_or(|value| value > MAX_CASE_ASSISTANT_AUDIT_BODY_BYTES)
        }) || output_counts
            .get("items")
            .and_then(serde_json::Value::as_u64)
            != Some(1)
        {
            return Err(invalid_case_assistant_tool_audit());
        }
        let source_refs = case_assistant_audit_id_array(source.get("sourceRefs"))
            .ok_or_else(invalid_case_assistant_tool_audit)?;
        let source_hashes = source
            .get("inputHashes")
            .and_then(serde_json::Value::as_object)
            .filter(|value| {
                has_exact_json_keys(
                    value,
                    &[
                        "aggregateExtractionSha256",
                        "aggregateRedactedContentSha256",
                        "aggregateSourceSha256",
                        "projectBindingSha256",
                        "sourceSnapshotsSha256",
                    ],
                )
            })
            .ok_or_else(invalid_case_assistant_tool_audit)?;
        if source_hashes.values().any(|value| {
            value
                .as_str()
                .is_none_or(|value| !is_lower_hex_sha256(value))
        }) {
            return Err(invalid_case_assistant_tool_audit());
        }
        validated.output_kind = Some(output_kind.to_owned());
        validated.typed_output_sha256 = output_hashes
            .get("typedOutputSha256")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        validated.proposal_source_refs_sha256 = output_hashes
            .get("proposalSourceRefsSha256")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        validated.source_generation_ids = source_refs;
        validated.project_binding_sha256 = source_hashes
            .get("projectBindingSha256")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        validated.source_snapshots_sha256 = source_hashes
            .get("sourceSnapshotsSha256")
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        return Ok(validated);
    }

    if !matches!(status, "failed" | "cancelled")
        || error_type.is_none_or(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        })
        || !has_exact_json_keys(output, &["errorType", "outputCounts", "status"])
        || case_assistant_audit_text(output, "status", 32) != Some(status)
        || case_assistant_audit_text(output, "errorType", 128) != error_type
        || !output
            .get("outputCounts")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|counts| {
                has_exact_json_keys(counts, &["items"])
                    && counts.get("items").and_then(serde_json::Value::as_u64) == Some(0)
            })
        || !has_exact_json_keys(source, &["confirmation", "providerSnapshot", "sourceRefs"])
        || source.get("providerSnapshot") != Some(&run_provider_snapshot)
        || !source
            .get("confirmation")
            .and_then(serde_json::Value::as_object)
            .is_some_and(|confirmation| {
                has_exact_json_keys(confirmation, &["received"])
                    && confirmation
                        .get("received")
                        .and_then(serde_json::Value::as_bool)
                        == Some(false)
            })
        || case_assistant_audit_id_array(source.get("sourceRefs")).is_none()
    {
        return Err(invalid_case_assistant_tool_audit());
    }
    Ok(validated)
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
pub enum ConversationScope {
    Assistant,
    CaseWork,
}

impl ConversationScope {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Assistant => "assistant",
            Self::CaseWork => "case_work",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationRow {
    pub conversation_id: String,
    pub project_id: Option<String>,
    pub scope: ConversationScope,
    pub title: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCaseAssistantPendingOutputRow {
    pub pending_output_id: String,
    pub project_id: String,
    pub conversation_id: String,
    pub run_id: String,
    pub assistant_message_id: String,
    pub project_binding_sha256: String,
    /// Canonical compact JSON array. Each item is a closed, metadata-only
    /// generation and selection snapshot; approved source bodies never belong
    /// in this user-database lineage.
    pub source_snapshots_json: String,
    pub source_snapshots_sha256: String,
    /// Canonical compact JSON array that the confirmation path must reproduce
    /// exactly before creating an analysis proposal. Non-analysis outputs use
    /// the canonical empty array.
    pub expected_proposal_source_refs_json: String,
    pub expected_proposal_source_refs_sha256: String,
    pub output_kind: String,
    /// Canonical typed output, not the raw Provider response envelope.
    pub output_payload_json: String,
    pub output_preview: String,
    pub output_sha256: String,
    pub output_version: i64,
    pub workspace_base_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseAssistantPendingOutputRow {
    pub pending_output_id: String,
    pub project_id: String,
    pub conversation_id: String,
    pub run_id: String,
    pub assistant_message_id: String,
    pub project_binding_sha256: String,
    pub source_snapshots_json: String,
    pub source_snapshots_sha256: String,
    pub expected_proposal_source_refs_json: String,
    pub expected_proposal_source_refs_sha256: String,
    pub output_kind: String,
    pub output_payload_json: String,
    pub output_preview: String,
    pub output_sha256: String,
    pub output_version: i64,
    pub workspace_base_digest: String,
    pub status: String,
    pub confirmed_artifact_id: Option<String>,
    pub confirmed_proposal_id: Option<String>,
    pub confirmation_request_sha256: Option<String>,
    pub row_version: i64,
    pub created_at: String,
    pub confirmed_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseAssistantConfirmationTarget {
    Artifact(String),
    Proposal(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmCaseAssistantPendingOutput<'a> {
    pub pending_output_id: &'a str,
    pub project_id: &'a str,
    pub expected_output_version: i64,
    pub expected_output_sha256: &'a str,
    pub expected_workspace_base_digest: &'a str,
    pub expected_proposal_source_refs_json: &'a str,
    pub expected_proposal_source_refs_sha256: &'a str,
    pub confirmation_request_sha256: &'a str,
    pub target: &'a CaseAssistantConfirmationTarget,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseAssistantPendingOutputConfirmResult {
    Confirmed(CaseAssistantPendingOutputRow),
    Conflict(CaseAssistantPendingOutputRow),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessageRow {
    pub message_id: String,
    pub conversation_id: String,
    pub role: String,
    pub kind: String,
    pub text_summary: String,
    pub artifact_id: Option<String>,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub message_id: String,
    pub conversation_id: String,
    pub role: String,
    pub kind: String,
    pub text_summary: String,
    pub artifact_id: Option<String>,
    pub run_id: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAttachmentRow {
    pub attachment_id: String,
    pub project_id: Option<String>,
    pub original_name: String,
    pub extension: String,
    pub detected_mime: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub content_blob: Vec<u8>,
    pub extraction_status: String,
    pub extracted_text: Option<String>,
    pub segments_json: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRow {
    pub attachment_id: String,
    pub project_id: Option<String>,
    pub original_name: String,
    pub extension: String,
    pub detected_mime: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub content_blob: Vec<u8>,
    pub extraction_status: String,
    pub extracted_text: Option<String>,
    pub segments_json: String,
    pub error_code: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentInsertResult {
    Inserted(AttachmentRow),
    Existing(AttachmentRow),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttachmentDeleteResult {
    Deleted,
    InUse,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageAttachmentRow {
    pub message_id: String,
    pub attachment_id: String,
    pub ordinal: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationSourceRow {
    pub conversation_id: String,
    pub source_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifactRow {
    pub artifact_id: String,
    pub conversation_id: Option<String>,
    pub project_id: Option<String>,
    pub kind: String,
    pub title: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRow {
    pub artifact_id: String,
    pub conversation_id: Option<String>,
    pub project_id: Option<String>,
    pub kind: String,
    pub title: String,
    pub status: String,
    pub current_version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifactVersionRow {
    pub version_id: String,
    pub artifact_id: String,
    pub content_json: String,
    pub rendered_text: String,
    pub source_refs_json: String,
    pub citation_report_json: String,
    pub provider_snapshot_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactVersionRow {
    pub version_id: String,
    pub artifact_id: String,
    pub version_number: i64,
    pub content_json: String,
    pub rendered_text: String,
    pub source_refs_json: String,
    pub citation_report_json: String,
    pub provider_snapshot_json: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactVersionCreateResult {
    Created(ArtifactVersionRow),
    Conflict,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAgentRunRow {
    pub run_id: String,
    pub conversation_id: String,
    pub user_message_id: String,
    pub provider_id: Option<String>,
    pub provider_snapshot_json: String,
    pub intent: String,
    pub status: String,
    pub budget_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRunRow {
    pub run_id: String,
    pub conversation_id: String,
    pub user_message_id: String,
    pub assistant_message_id: Option<String>,
    pub provider_id: Option<String>,
    pub provider_snapshot_json: String,
    pub intent: String,
    pub status: String,
    pub budget_json: String,
    pub error_type: Option<String>,
    pub created_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentRunStatusUpdateResult {
    Updated(AgentRunRow),
    Conflict(AgentRunRow),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToolCallRow {
    pub tool_call_id: String,
    pub run_id: String,
    pub ordinal: i64,
    pub capability_name: String,
    pub status: String,
    pub access_mode: String,
    pub requires_confirmation: bool,
    pub input_audit_json: String,
    pub output_audit_json: String,
    pub source_audit_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallRow {
    pub tool_call_id: String,
    pub run_id: String,
    pub ordinal: i64,
    pub capability_name: String,
    pub status: String,
    pub access_mode: String,
    pub requires_confirmation: bool,
    pub input_audit_json: String,
    pub output_audit_json: String,
    pub source_audit_json: String,
    pub error_type: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolCallStatusUpdateResult {
    Updated(ToolCallRow),
    Conflict(ToolCallRow),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCaseChangeProposalRow {
    pub proposal_id: String,
    pub conversation_id: String,
    pub project_id: String,
    pub run_id: Option<String>,
    pub base_case_digest: String,
    pub changes_json: String,
    pub source_refs_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseChangeProposalRow {
    pub proposal_id: String,
    pub conversation_id: String,
    pub project_id: String,
    pub run_id: Option<String>,
    pub base_case_digest: String,
    pub status: String,
    pub changes_json: String,
    pub source_refs_json: String,
    pub created_at: String,
    pub decided_at: Option<String>,
    pub applied_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseChangeProposalStatusUpdateResult {
    Updated(CaseChangeProposalRow),
    Conflict(CaseChangeProposalRow),
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewOperationAuditRow {
    pub audit_id: String,
    pub origin: String,
    pub operation: String,
    pub project_id: Option<String>,
    pub request_hash: String,
    pub idempotency_key_hash: Option<String>,
    pub details_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationAuditRow {
    pub audit_id: String,
    pub origin: String,
    pub operation: String,
    pub project_id: Option<String>,
    pub request_hash: String,
    pub idempotency_key_hash: Option<String>,
    pub status: String,
    pub details_json: String,
    pub created_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationAuditStatusUpdateResult {
    Updated(OperationAuditRow),
    Conflict(OperationAuditRow),
    NotFound,
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

pub fn create_conversation(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    project_id: Option<&str>,
    title: &str,
) -> rusqlite::Result<ConversationRow> {
    connection.execute(
        "INSERT INTO conversations (conversation_id, project_id, scope, title, status)
         VALUES (?1, ?2, 'assistant', ?3, 'open')",
        params![conversation_id, project_id, title],
    )?;
    get_conversation(connection, conversation_id)?.ok_or_else(|| {
        user_schema_migration_error("created conversation could not be reloaded".to_owned())
    })
}

pub fn create_case_work_conversation(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    project_id: &str,
    title: &str,
) -> rusqlite::Result<ConversationRow> {
    let changed = connection.execute(
        "INSERT INTO conversations (conversation_id, project_id, scope, title, status)
         SELECT ?1, project_id, 'case_work', ?3, 'open'
         FROM projects
         WHERE project_id = ?2 AND status = 'active'",
        params![conversation_id, project_id, title],
    )?;
    if changed != 1 {
        return Err(user_schema_migration_error(
            "case-work conversation requires an active project".to_owned(),
        ));
    }
    get_case_work_conversation(connection, conversation_id, project_id)?.ok_or_else(|| {
        user_schema_migration_error(
            "created case-work conversation could not be reloaded".to_owned(),
        )
    })
}

pub fn list_conversations(
    connection: &rusqlite::Connection,
    limit: u32,
) -> rusqlite::Result<Vec<ConversationRow>> {
    let limit = i64::from(limit.clamp(1, 500));
    let mut statement = connection.prepare(
        "SELECT conversation_id, project_id, scope, title, status, created_at, updated_at
         FROM conversations
         WHERE scope = 'assistant'
         ORDER BY updated_at DESC, conversation_id DESC
         LIMIT ?1",
    )?;
    let rows = statement
        .query_map([limit], conversation_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn list_conversations_for_project(
    connection: &rusqlite::Connection,
    project_id: &str,
    limit: u32,
) -> rusqlite::Result<Vec<ConversationRow>> {
    let limit = i64::from(limit.clamp(1, 500));
    let mut statement = connection.prepare(
        "SELECT conversation_id, project_id, scope, title, status, created_at, updated_at
         FROM conversations
         WHERE project_id = ?1 AND scope = 'assistant'
         ORDER BY updated_at DESC, conversation_id DESC
         LIMIT ?2",
    )?;
    let rows = statement
        .query_map(params![project_id, limit], conversation_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_conversation(
    connection: &rusqlite::Connection,
    conversation_id: &str,
) -> rusqlite::Result<Option<ConversationRow>> {
    get_conversation_in_scope(
        connection,
        conversation_id,
        None,
        ConversationScope::Assistant,
    )
}

pub fn list_case_work_conversations_for_project(
    connection: &rusqlite::Connection,
    project_id: &str,
    limit: u32,
) -> rusqlite::Result<Vec<ConversationRow>> {
    let limit = i64::from(limit.clamp(1, 500));
    let mut statement = connection.prepare(
        "SELECT conversation_id, project_id, scope, title, status, created_at, updated_at
         FROM conversations
         WHERE project_id = ?1 AND scope = 'case_work'
         ORDER BY updated_at DESC, conversation_id DESC
         LIMIT ?2",
    )?;
    let rows = statement
        .query_map(params![project_id, limit], conversation_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn get_case_work_conversation(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    project_id: &str,
) -> rusqlite::Result<Option<ConversationRow>> {
    get_conversation_in_scope(
        connection,
        conversation_id,
        Some(project_id),
        ConversationScope::CaseWork,
    )
}

fn get_conversation_in_scope(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    project_id: Option<&str>,
    scope: ConversationScope,
) -> rusqlite::Result<Option<ConversationRow>> {
    connection
        .query_row(
            "SELECT conversation_id, project_id, scope, title, status, created_at, updated_at
             FROM conversations
             WHERE conversation_id = ?1
               AND scope = ?2
               AND (?3 IS NULL OR project_id = ?3)",
            params![conversation_id, scope.as_str(), project_id],
            conversation_from_row,
        )
        .optional()
}

pub fn bind_conversation_to_case(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    project_id: &str,
) -> rusqlite::Result<bool> {
    let transaction = connection.unchecked_transaction()?;
    let changed = transaction.execute(
        "UPDATE conversations
         SET project_id = ?2, updated_at = CURRENT_TIMESTAMP
         WHERE conversation_id = ?1
           AND scope = 'assistant'
           AND status = 'open'
           AND (project_id IS NULL OR project_id = ?2)
           AND NOT EXISTS (
               SELECT 1 FROM artifacts
               WHERE conversation_id = ?1
                 AND project_id IS NOT NULL
                 AND project_id != ?2
           )
           AND NOT EXISTS (
               SELECT 1
               FROM messages AS message
               JOIN artifacts AS artifact ON artifact.artifact_id = message.artifact_id
               WHERE message.conversation_id = ?1
                 AND artifact.project_id IS NOT NULL
                 AND artifact.project_id != ?2
           )
           AND NOT EXISTS (
               SELECT 1
               FROM message_attachments AS link
               JOIN messages AS message ON message.message_id = link.message_id
               JOIN attachments AS attachment ON attachment.attachment_id = link.attachment_id
               WHERE message.conversation_id = ?1
                 AND attachment.project_id IS NOT NULL
                 AND attachment.project_id != ?2
           )
           AND NOT EXISTS (
               SELECT 1 FROM legal_answer_records
               WHERE conversation_id = ?1
                 AND project_id IS NOT NULL
                 AND project_id != ?2
           )",
        params![conversation_id, project_id],
    )?;
    if changed != 1 {
        return Ok(false);
    }
    transaction.execute(
        "UPDATE legal_answer_records
         SET project_id = ?2
         WHERE conversation_id = ?1 AND project_id IS NULL",
        params![conversation_id, project_id],
    )?;
    transaction.commit()?;
    Ok(true)
}

pub fn archive_conversation(
    connection: &rusqlite::Connection,
    conversation_id: &str,
) -> rusqlite::Result<bool> {
    let changed = connection.execute(
        "UPDATE conversations
         SET status = 'archived', updated_at = CURRENT_TIMESTAMP
         WHERE conversation_id = ?1 AND scope = 'assistant' AND status = 'open'",
        [conversation_id],
    )?;
    Ok(changed == 1)
}

pub fn archive_case_work_conversation(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    project_id: &str,
) -> rusqlite::Result<bool> {
    let changed = connection.execute(
        "UPDATE conversations
         SET status = 'archived', updated_at = CURRENT_TIMESTAMP
         WHERE conversation_id = ?1
           AND project_id = ?2
           AND scope = 'case_work'
           AND status = 'open'",
        params![conversation_id, project_id],
    )?;
    Ok(changed == 1)
}

pub fn create_message(
    connection: &rusqlite::Connection,
    message: &NewMessageRow,
) -> rusqlite::Result<MessageRow> {
    if let Some(run_id) = message.run_id.as_deref() {
        let run_matches: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM agent_runs
                 WHERE run_id = ?1 AND conversation_id = ?2
             )",
            params![run_id, message.conversation_id],
            |row| row.get(0),
        )?;
        if !run_matches {
            return Err(user_schema_migration_error(
                "message run must belong to the same conversation".to_owned(),
            ));
        }
    }
    connection.execute(
        "INSERT INTO messages (
             message_id, conversation_id, role, kind, text_summary, artifact_id, run_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            message.message_id,
            message.conversation_id,
            message.role,
            message.kind,
            message.text_summary,
            message.artifact_id,
            message.run_id
        ],
    )?;
    get_message(connection, &message.message_id)?.ok_or_else(|| {
        user_schema_migration_error("created message could not be reloaded".to_owned())
    })
}

pub fn get_message(
    connection: &rusqlite::Connection,
    message_id: &str,
) -> rusqlite::Result<Option<MessageRow>> {
    connection
        .query_row(
            "SELECT message_id, conversation_id, role, kind, text_summary,
                    artifact_id, run_id, created_at
             FROM messages WHERE message_id = ?1",
            [message_id],
            message_from_row,
        )
        .optional()
}

pub fn list_messages(
    connection: &rusqlite::Connection,
    conversation_id: &str,
) -> rusqlite::Result<Vec<MessageRow>> {
    let mut statement = connection.prepare(
        "SELECT message_id, conversation_id, role, kind, text_summary,
                artifact_id, run_id, created_at
         FROM messages
         WHERE conversation_id = ?1
         ORDER BY created_at ASC, message_id ASC",
    )?;
    let rows = statement
        .query_map([conversation_id], message_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn insert_attachment(
    connection: &rusqlite::Connection,
    attachment: &NewAttachmentRow,
) -> rusqlite::Result<AttachmentInsertResult> {
    let changed = connection.execute(
        "INSERT INTO attachments (
             attachment_id, project_id, original_name, extension, detected_mime,
             sha256, size_bytes, content_blob, extraction_status, extracted_text,
             segments_json, error_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(sha256) DO NOTHING",
        params![
            attachment.attachment_id,
            attachment.project_id,
            attachment.original_name,
            attachment.extension,
            attachment.detected_mime,
            attachment.sha256,
            attachment.size_bytes,
            attachment.content_blob,
            attachment.extraction_status,
            attachment.extracted_text,
            attachment.segments_json,
            attachment.error_code
        ],
    )?;
    let persisted = get_attachment_by_sha256(connection, &attachment.sha256)?.ok_or_else(|| {
        user_schema_migration_error("persisted attachment could not be reloaded".to_owned())
    })?;
    Ok(if changed == 1 {
        AttachmentInsertResult::Inserted(persisted)
    } else {
        AttachmentInsertResult::Existing(persisted)
    })
}

pub fn get_attachment(
    connection: &rusqlite::Connection,
    attachment_id: &str,
) -> rusqlite::Result<Option<AttachmentRow>> {
    connection
        .query_row(
            "SELECT attachment_id, project_id, original_name, extension, detected_mime,
                    sha256, size_bytes, content_blob, extraction_status, extracted_text,
                    segments_json, error_code, created_at
             FROM attachments WHERE attachment_id = ?1",
            [attachment_id],
            attachment_from_row,
        )
        .optional()
}

pub fn get_attachment_by_sha256(
    connection: &rusqlite::Connection,
    sha256: &str,
) -> rusqlite::Result<Option<AttachmentRow>> {
    connection
        .query_row(
            "SELECT attachment_id, project_id, original_name, extension, detected_mime,
                    sha256, size_bytes, content_blob, extraction_status, extracted_text,
                    segments_json, error_code, created_at
             FROM attachments WHERE sha256 = ?1",
            [sha256],
            attachment_from_row,
        )
        .optional()
}

pub fn update_attachment_extraction(
    connection: &rusqlite::Connection,
    attachment_id: &str,
    expected_status: &str,
    extraction_status: &str,
    extracted_text: Option<&str>,
    segments_json: &str,
    error_code: Option<&str>,
) -> rusqlite::Result<bool> {
    let changed = connection.execute(
        "UPDATE attachments
         SET extraction_status = ?3,
             extracted_text = ?4,
             segments_json = ?5,
             error_code = ?6
         WHERE attachment_id = ?1 AND extraction_status = ?2",
        params![
            attachment_id,
            expected_status,
            extraction_status,
            extracted_text,
            segments_json,
            error_code
        ],
    )?;
    Ok(changed == 1)
}

pub fn delete_attachment(
    connection: &mut rusqlite::Connection,
    attachment_id: &str,
) -> rusqlite::Result<AttachmentDeleteResult> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let result = delete_attachment_in_transaction(&transaction, attachment_id)?;
    transaction.commit()?;
    Ok(result)
}

/// Permanently deletes an attachment only when it is currently linked to the
/// supplied conversation and has no other message, artifact, proposal, or case
/// reference. The conversation links are removed and the BLOB is deleted in
/// one IMMEDIATE transaction; an in-use result rolls the link removal back.
pub fn delete_attachment_from_conversation(
    connection: &mut rusqlite::Connection,
    conversation_id: &str,
    attachment_id: &str,
) -> rusqlite::Result<AttachmentDeleteResult> {
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let linked: bool = transaction.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM message_attachments AS link
             JOIN messages AS message ON message.message_id = link.message_id
             JOIN conversations AS conversation
               ON conversation.conversation_id = message.conversation_id
             WHERE link.attachment_id = ?1
               AND message.conversation_id = ?2
               AND conversation.status = 'open'
         )",
        params![attachment_id, conversation_id],
        |row| row.get(0),
    )?;
    if !linked {
        transaction.commit()?;
        return Ok(AttachmentDeleteResult::NotFound);
    }
    transaction.execute(
        "DELETE FROM message_attachments
         WHERE attachment_id = ?1
           AND message_id IN (
               SELECT message_id FROM messages WHERE conversation_id = ?2
           )",
        params![attachment_id, conversation_id],
    )?;
    let result = delete_attachment_in_transaction(&transaction, attachment_id)?;
    if result == AttachmentDeleteResult::Deleted {
        transaction.commit()?;
    } else {
        transaction.rollback()?;
    }
    Ok(result)
}

fn delete_attachment_in_transaction(
    connection: &rusqlite::Connection,
    attachment_id: &str,
) -> rusqlite::Result<AttachmentDeleteResult> {
    if get_attachment(connection, attachment_id)?.is_none() {
        return Ok(AttachmentDeleteResult::NotFound);
    }
    let storage_reference = attachment_storage_reference(attachment_id);
    let legacy_double_prefixed_reference = format!("attachment:{storage_reference}");
    let in_use: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM message_attachments WHERE attachment_id = ?1
             UNION ALL
             SELECT 1 FROM case_files
             WHERE storage_reference IN (?1, ?2, ?3)
             UNION ALL
             SELECT 1
             FROM artifact_versions AS version, json_tree(version.source_refs_json) AS source
             WHERE source.atom = ?1
             UNION ALL
             SELECT 1
             FROM case_change_proposals AS proposal, json_tree(proposal.source_refs_json) AS source
             WHERE source.atom = ?1
         )",
        params![
            attachment_id,
            storage_reference,
            legacy_double_prefixed_reference
        ],
        |row| row.get(0),
    )?;
    if in_use {
        return Ok(AttachmentDeleteResult::InUse);
    }
    let deleted = connection.execute(
        "DELETE FROM attachments WHERE attachment_id = ?1",
        [attachment_id],
    )?;
    Ok(if deleted == 1 {
        AttachmentDeleteResult::Deleted
    } else {
        AttachmentDeleteResult::NotFound
    })
}

/// Canonical logical reference used by `case_files` for an attachment BLOB.
/// Stage-8 attachment identifiers already carry the `attachment:` namespace;
/// legacy bare identifiers are normalized exactly once.
pub fn attachment_storage_reference(attachment_id: &str) -> String {
    if attachment_id.starts_with("attachment:") {
        attachment_id.to_owned()
    } else {
        format!("attachment:{attachment_id}")
    }
}

/// Returns whether an unclaimed attachment can be assigned to `project_id`
/// without making any existing message link cross-project. Every conversation
/// that currently references the attachment must already be bound to that
/// exact case before the claim is allowed.
pub fn attachment_can_be_claimed_for_case(
    connection: &rusqlite::Connection,
    attachment_id: &str,
    project_id: &str,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM attachments AS attachment
             WHERE attachment.attachment_id = ?1
               AND attachment.project_id IS NULL
               AND NOT EXISTS (
                   SELECT 1
                   FROM message_attachments AS link
                   JOIN messages AS message ON message.message_id = link.message_id
                   JOIN conversations AS conversation
                     ON conversation.conversation_id = message.conversation_id
                   WHERE link.attachment_id = attachment.attachment_id
                     AND conversation.project_id IS NOT ?2
               )
         )",
        params![attachment_id, project_id],
        |row| row.get(0),
    )
}

/// Atomically claims a case-neutral attachment for one case. This is purposely
/// not idempotent: only the `NULL -> project` transition succeeds, so two case
/// transfer proposals cannot both claim the same attachment.
pub fn claim_attachment_for_case(
    connection: &rusqlite::Connection,
    attachment_id: &str,
    project_id: &str,
) -> rusqlite::Result<bool> {
    let changed = connection.execute(
        "UPDATE attachments
         SET project_id = ?2
         WHERE attachment_id = ?1
           AND project_id IS NULL
           AND NOT EXISTS (
               SELECT 1
               FROM message_attachments AS link
               JOIN messages AS message ON message.message_id = link.message_id
               JOIN conversations AS conversation
                 ON conversation.conversation_id = message.conversation_id
               WHERE link.attachment_id = attachments.attachment_id
                 AND conversation.project_id IS NOT ?2
           )",
        params![attachment_id, project_id],
    )?;
    Ok(changed == 1)
}

pub fn attach_to_message(
    connection: &rusqlite::Connection,
    message_id: &str,
    attachment_id: &str,
    ordinal: i64,
) -> rusqlite::Result<()> {
    let changed = connection.execute(
        "INSERT INTO message_attachments (message_id, attachment_id, ordinal)
         SELECT message.message_id, attachment.attachment_id, ?3
         FROM messages AS message
         JOIN conversations AS conversation
           ON conversation.conversation_id = message.conversation_id
         JOIN attachments AS attachment ON attachment.attachment_id = ?2
         WHERE message.message_id = ?1
           AND (
               attachment.project_id IS NULL
               OR attachment.project_id = conversation.project_id
           )",
        params![message_id, attachment_id, ordinal],
    )?;
    if changed != 1 {
        return Err(user_schema_migration_error(
            "message or attachment is missing, or attachment ownership does not match the conversation"
                .to_owned(),
        ));
    }
    Ok(())
}

pub fn list_message_attachments(
    connection: &rusqlite::Connection,
    message_id: &str,
) -> rusqlite::Result<Vec<MessageAttachmentRow>> {
    let mut statement = connection.prepare(
        "SELECT message_id, attachment_id, ordinal
         FROM message_attachments
         WHERE message_id = ?1
         ORDER BY ordinal ASC, attachment_id ASC",
    )?;
    let rows = statement
        .query_map([message_id], |row| {
            Ok(MessageAttachmentRow {
                message_id: row.get(0)?,
                attachment_id: row.get(1)?,
                ordinal: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn list_attachments_for_message(
    connection: &rusqlite::Connection,
    message_id: &str,
) -> rusqlite::Result<Vec<AttachmentRow>> {
    let mut statement = connection.prepare(
        "SELECT attachment.attachment_id, attachment.project_id, attachment.original_name,
                attachment.extension, attachment.detected_mime, attachment.sha256,
                attachment.size_bytes, attachment.content_blob, attachment.extraction_status,
                attachment.extracted_text, attachment.segments_json, attachment.error_code,
                attachment.created_at
         FROM message_attachments AS link
         JOIN attachments AS attachment ON attachment.attachment_id = link.attachment_id
         WHERE link.message_id = ?1
         ORDER BY link.ordinal ASC, attachment.attachment_id ASC",
    )?;
    let rows = statement
        .query_map([message_id], attachment_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn add_conversation_source(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    source_id: &str,
) -> rusqlite::Result<ConversationSourceRow> {
    connection.execute(
        "INSERT INTO conversation_sources (conversation_id, source_id)
         VALUES (?1, ?2)
         ON CONFLICT(conversation_id, source_id) DO NOTHING",
        params![conversation_id, source_id],
    )?;
    connection.query_row(
        "SELECT conversation_id, source_id, created_at
         FROM conversation_sources
         WHERE conversation_id = ?1 AND source_id = ?2",
        params![conversation_id, source_id],
        |row| {
            Ok(ConversationSourceRow {
                conversation_id: row.get(0)?,
                source_id: row.get(1)?,
                created_at: row.get(2)?,
            })
        },
    )
}

pub fn list_conversation_sources(
    connection: &rusqlite::Connection,
    conversation_id: &str,
) -> rusqlite::Result<Vec<ConversationSourceRow>> {
    let mut statement = connection.prepare(
        "SELECT conversation_id, source_id, created_at
         FROM conversation_sources
         WHERE conversation_id = ?1
         ORDER BY created_at ASC, source_id ASC",
    )?;
    let rows = statement
        .query_map([conversation_id], |row| {
            Ok(ConversationSourceRow {
                conversation_id: row.get(0)?,
                source_id: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn create_artifact(
    connection: &rusqlite::Connection,
    artifact: &NewArtifactRow,
    initial_version: &NewArtifactVersionRow,
) -> rusqlite::Result<ArtifactRow> {
    if artifact.artifact_id != initial_version.artifact_id {
        return Err(user_schema_migration_error(
            "initial artifact version belongs to a different artifact".to_owned(),
        ));
    }

    if !connection.is_autocommit() {
        return insert_artifact_with_initial_version(connection, artifact, initial_version);
    }

    let transaction = connection.unchecked_transaction()?;
    let persisted = insert_artifact_with_initial_version(&transaction, artifact, initial_version)?;
    transaction.commit()?;
    Ok(persisted)
}

fn insert_artifact_with_initial_version(
    connection: &rusqlite::Connection,
    artifact: &NewArtifactRow,
    initial_version: &NewArtifactVersionRow,
) -> rusqlite::Result<ArtifactRow> {
    connection.execute(
        "INSERT INTO artifacts (
             artifact_id, conversation_id, project_id, kind, title, status, current_version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
        params![
            artifact.artifact_id,
            artifact.conversation_id,
            artifact.project_id,
            artifact.kind,
            artifact.title,
            artifact.status
        ],
    )?;
    insert_artifact_version(connection, initial_version, 1)?;
    get_artifact(connection, &artifact.artifact_id)?.ok_or_else(|| {
        user_schema_migration_error("created artifact could not be reloaded".to_owned())
    })
}

pub fn get_artifact(
    connection: &rusqlite::Connection,
    artifact_id: &str,
) -> rusqlite::Result<Option<ArtifactRow>> {
    connection
        .query_row(
            "SELECT artifact_id, conversation_id, project_id, kind, title, status,
                    current_version, created_at, updated_at
             FROM artifacts WHERE artifact_id = ?1",
            [artifact_id],
            artifact_from_row,
        )
        .optional()
}

pub fn list_artifacts(
    connection: &rusqlite::Connection,
    conversation_id: Option<&str>,
    limit: u32,
) -> rusqlite::Result<Vec<ArtifactRow>> {
    let limit = i64::from(limit.clamp(1, 500));
    let mut statement = connection.prepare(
        "SELECT artifact_id, conversation_id, project_id, kind, title, status,
                current_version, created_at, updated_at
         FROM artifacts
         WHERE ?1 IS NULL OR conversation_id = ?1
         ORDER BY updated_at DESC, artifact_id DESC
         LIMIT ?2",
    )?;
    let rows = statement
        .query_map(params![conversation_id, limit], artifact_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn list_artifacts_for_project(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<ArtifactRow>> {
    let mut statement = connection.prepare(
        "SELECT artifact_id, conversation_id, project_id, kind, title, status,
                current_version, created_at, updated_at
         FROM artifacts
         WHERE project_id = ?1
         ORDER BY artifact_id ASC",
    )?;
    let rows = statement
        .query_map([project_id], artifact_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn bind_artifact_to_case(
    connection: &rusqlite::Connection,
    artifact_id: &str,
    project_id: &str,
) -> rusqlite::Result<bool> {
    let changed = connection.execute(
        "UPDATE artifacts
         SET project_id = ?2, updated_at = CURRENT_TIMESTAMP
         WHERE artifact_id = ?1
           AND status != 'archived'
           AND project_id IS NULL
           AND (
               conversation_id IS NULL
               OR EXISTS (
                   SELECT 1 FROM conversations
                   WHERE conversations.conversation_id = artifacts.conversation_id
                     AND (
                         conversations.project_id IS NULL
                         OR conversations.project_id = ?2
                     )
               )
           )
           AND NOT EXISTS (
               SELECT 1
               FROM messages AS message
               JOIN conversations AS conversation
                 ON conversation.conversation_id = message.conversation_id
               WHERE message.artifact_id = artifacts.artifact_id
                 AND conversation.project_id IS NOT NULL
                 AND conversation.project_id != ?2
           )",
        params![artifact_id, project_id],
    )?;
    Ok(changed == 1)
}

pub fn get_artifact_version(
    connection: &rusqlite::Connection,
    artifact_id: &str,
    version_number: i64,
) -> rusqlite::Result<Option<ArtifactVersionRow>> {
    connection
        .query_row(
            "SELECT version_id, artifact_id, version_number, content_json, rendered_text,
                    source_refs_json, citation_report_json, provider_snapshot_json, created_at
             FROM artifact_versions
             WHERE artifact_id = ?1 AND version_number = ?2",
            params![artifact_id, version_number],
            artifact_version_from_row,
        )
        .optional()
}

pub fn list_artifact_versions(
    connection: &rusqlite::Connection,
    artifact_id: &str,
) -> rusqlite::Result<Vec<ArtifactVersionRow>> {
    let mut statement = connection.prepare(
        "SELECT version_id, artifact_id, version_number, content_json, rendered_text,
                source_refs_json, citation_report_json, provider_snapshot_json, created_at
         FROM artifact_versions
         WHERE artifact_id = ?1
         ORDER BY version_number DESC",
    )?;
    let rows = statement
        .query_map([artifact_id], artifact_version_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn create_artifact_version(
    connection: &rusqlite::Connection,
    version: &NewArtifactVersionRow,
    expected_current_version: i64,
) -> rusqlite::Result<ArtifactVersionCreateResult> {
    if !connection.is_autocommit() {
        return create_artifact_version_with_cas(connection, version, expected_current_version);
    }
    let transaction = connection.unchecked_transaction()?;
    let result = create_artifact_version_with_cas(&transaction, version, expected_current_version)?;
    if matches!(result, ArtifactVersionCreateResult::Created(_)) {
        transaction.commit()?;
    }
    Ok(result)
}

fn create_artifact_version_with_cas(
    connection: &rusqlite::Connection,
    version: &NewArtifactVersionRow,
    expected_current_version: i64,
) -> rusqlite::Result<ArtifactVersionCreateResult> {
    let artifact = get_artifact(connection, &version.artifact_id)?;
    let Some(artifact) = artifact else {
        return Ok(ArtifactVersionCreateResult::NotFound);
    };
    if artifact.current_version != expected_current_version || artifact.status == "archived" {
        return Ok(ArtifactVersionCreateResult::Conflict);
    }
    let next_version = expected_current_version.checked_add(1).ok_or_else(|| {
        user_schema_migration_error("artifact version number overflowed".to_owned())
    })?;
    insert_artifact_version(connection, version, next_version)?;
    let changed = connection.execute(
        "UPDATE artifacts
         SET current_version = ?3, updated_at = CURRENT_TIMESTAMP
         WHERE artifact_id = ?1 AND current_version = ?2 AND status != 'archived'",
        params![version.artifact_id, expected_current_version, next_version],
    )?;
    if changed != 1 {
        return Ok(ArtifactVersionCreateResult::Conflict);
    }
    let persisted = get_artifact_version(connection, &version.artifact_id, next_version)?
        .ok_or_else(|| {
            user_schema_migration_error("created artifact version could not be reloaded".to_owned())
        })?;
    Ok(ArtifactVersionCreateResult::Created(persisted))
}

fn insert_artifact_version(
    connection: &rusqlite::Connection,
    version: &NewArtifactVersionRow,
    version_number: i64,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO artifact_versions (
             version_id, artifact_id, version_number, content_json, rendered_text,
             source_refs_json, citation_report_json, provider_snapshot_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            version.version_id,
            version.artifact_id,
            version_number,
            version.content_json,
            version.rendered_text,
            version.source_refs_json,
            version.citation_report_json,
            version.provider_snapshot_json
        ],
    )?;
    Ok(())
}

pub fn create_agent_run(
    connection: &rusqlite::Connection,
    run: &NewAgentRunRow,
) -> rusqlite::Result<AgentRunRow> {
    connection.execute(
        "INSERT INTO agent_runs (
             run_id, conversation_id, user_message_id, provider_id,
             provider_snapshot_json, intent, status, budget_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            run.run_id,
            run.conversation_id,
            run.user_message_id,
            run.provider_id,
            run.provider_snapshot_json,
            run.intent,
            run.status,
            run.budget_json
        ],
    )?;
    get_agent_run(connection, &run.run_id)?.ok_or_else(|| {
        user_schema_migration_error("created agent run could not be reloaded".to_owned())
    })
}

pub fn get_agent_run(
    connection: &rusqlite::Connection,
    run_id: &str,
) -> rusqlite::Result<Option<AgentRunRow>> {
    connection
        .query_row(
            "SELECT run_id, conversation_id, user_message_id, assistant_message_id,
                    provider_id, provider_snapshot_json, intent, status, budget_json,
                    error_type, created_at, finished_at
             FROM agent_runs WHERE run_id = ?1",
            [run_id],
            agent_run_from_row,
        )
        .optional()
}

pub fn list_agent_runs(
    connection: &rusqlite::Connection,
    conversation_id: &str,
) -> rusqlite::Result<Vec<AgentRunRow>> {
    let mut statement = connection.prepare(
        "SELECT run_id, conversation_id, user_message_id, assistant_message_id,
                provider_id, provider_snapshot_json, intent, status, budget_json,
                error_type, created_at, finished_at
         FROM agent_runs
         WHERE conversation_id = ?1
         ORDER BY created_at ASC, run_id ASC",
    )?;
    let rows = statement
        .query_map([conversation_id], agent_run_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn compare_and_set_agent_run_status(
    connection: &rusqlite::Connection,
    run_id: &str,
    expected_status: &str,
    new_status: &str,
    assistant_message_id: Option<&str>,
    error_type: Option<&str>,
) -> rusqlite::Result<AgentRunStatusUpdateResult> {
    let changed = connection.execute(
        "UPDATE agent_runs
         SET status = ?3,
             assistant_message_id = COALESCE(?4, assistant_message_id),
             error_type = ?5,
             finished_at = CASE
                 WHEN ?3 IN ('succeeded', 'failed', 'cancelled') THEN CURRENT_TIMESTAMP
                 ELSE NULL
             END
         WHERE run_id = ?1 AND status = ?2",
        params![
            run_id,
            expected_status,
            new_status,
            assistant_message_id,
            error_type
        ],
    )?;
    let persisted = get_agent_run(connection, run_id)?;
    Ok(match (changed, persisted) {
        (1, Some(row)) => AgentRunStatusUpdateResult::Updated(row),
        (_, Some(row)) => AgentRunStatusUpdateResult::Conflict(row),
        (_, None) => AgentRunStatusUpdateResult::NotFound,
    })
}

pub fn create_tool_call(
    connection: &rusqlite::Connection,
    tool_call: &NewToolCallRow,
) -> rusqlite::Result<ToolCallRow> {
    if tool_call.capability_name == "assistant.case_work" {
        let run = get_agent_run(connection, &tool_call.run_id)?.ok_or_else(|| {
            user_schema_migration_error(
                "case assistant tool audit requires an existing run".to_owned(),
            )
        })?;
        validate_case_assistant_tool_audit_contract(
            &tool_call.run_id,
            &run.provider_snapshot_json,
            &tool_call.status,
            &tool_call.input_audit_json,
            &tool_call.output_audit_json,
            &tool_call.source_audit_json,
            None,
        )?;
    }
    connection.execute(
        "INSERT INTO tool_calls (
             tool_call_id, run_id, ordinal, capability_name, status, access_mode,
             requires_confirmation, input_audit_json, output_audit_json, source_audit_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            tool_call.tool_call_id,
            tool_call.run_id,
            tool_call.ordinal,
            tool_call.capability_name,
            tool_call.status,
            tool_call.access_mode,
            if tool_call.requires_confirmation {
                1_i64
            } else {
                0_i64
            },
            tool_call.input_audit_json,
            tool_call.output_audit_json,
            tool_call.source_audit_json
        ],
    )?;
    get_tool_call(connection, &tool_call.tool_call_id)?.ok_or_else(|| {
        user_schema_migration_error("created tool call could not be reloaded".to_owned())
    })
}

pub fn get_tool_call(
    connection: &rusqlite::Connection,
    tool_call_id: &str,
) -> rusqlite::Result<Option<ToolCallRow>> {
    connection
        .query_row(
            "SELECT tool_call_id, run_id, ordinal, capability_name, status, access_mode,
                    requires_confirmation, input_audit_json, output_audit_json,
                    source_audit_json, error_type, started_at, finished_at
             FROM tool_calls WHERE tool_call_id = ?1",
            [tool_call_id],
            tool_call_from_row,
        )
        .optional()
}

pub fn list_tool_calls(
    connection: &rusqlite::Connection,
    run_id: &str,
) -> rusqlite::Result<Vec<ToolCallRow>> {
    let mut statement = connection.prepare(
        "SELECT tool_call_id, run_id, ordinal, capability_name, status, access_mode,
                requires_confirmation, input_audit_json, output_audit_json,
                source_audit_json, error_type, started_at, finished_at
         FROM tool_calls
         WHERE run_id = ?1
         ORDER BY ordinal ASC",
    )?;
    let rows = statement
        .query_map([run_id], tool_call_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn compare_and_set_tool_call_status(
    connection: &rusqlite::Connection,
    tool_call_id: &str,
    expected_status: &str,
    new_status: &str,
    output_audit_json: &str,
    source_audit_json: &str,
    error_type: Option<&str>,
) -> rusqlite::Result<ToolCallStatusUpdateResult> {
    if let Some(current) = get_tool_call(connection, tool_call_id)? {
        if current.status == expected_status && current.capability_name == "assistant.case_work" {
            let run = get_agent_run(connection, &current.run_id)?.ok_or_else(|| {
                user_schema_migration_error(
                    "case assistant tool audit requires an existing run".to_owned(),
                )
            })?;
            validate_case_assistant_tool_audit_contract(
                &current.run_id,
                &run.provider_snapshot_json,
                new_status,
                &current.input_audit_json,
                output_audit_json,
                source_audit_json,
                error_type,
            )?;
        }
    }
    let changed = connection.execute(
        "UPDATE tool_calls
         SET status = ?3,
             output_audit_json = ?4,
             source_audit_json = ?5,
             error_type = ?6,
             finished_at = CASE
                 WHEN ?3 IN ('succeeded', 'failed', 'cancelled') THEN CURRENT_TIMESTAMP
                 ELSE NULL
             END
         WHERE tool_call_id = ?1 AND status = ?2",
        params![
            tool_call_id,
            expected_status,
            new_status,
            output_audit_json,
            source_audit_json,
            error_type
        ],
    )?;
    let persisted = get_tool_call(connection, tool_call_id)?;
    Ok(match (changed, persisted) {
        (1, Some(row)) => ToolCallStatusUpdateResult::Updated(row),
        (_, Some(row)) => ToolCallStatusUpdateResult::Conflict(row),
        (_, None) => ToolCallStatusUpdateResult::NotFound,
    })
}

pub fn create_case_change_proposal(
    connection: &rusqlite::Connection,
    proposal: &NewCaseChangeProposalRow,
) -> rusqlite::Result<CaseChangeProposalRow> {
    connection.execute(
        "INSERT INTO case_change_proposals (
             proposal_id, conversation_id, project_id, run_id, base_case_digest,
             status, changes_json, source_refs_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, 'pending', ?6, ?7)",
        params![
            proposal.proposal_id,
            proposal.conversation_id,
            proposal.project_id,
            proposal.run_id,
            proposal.base_case_digest,
            proposal.changes_json,
            proposal.source_refs_json
        ],
    )?;
    get_case_change_proposal(connection, &proposal.proposal_id)?.ok_or_else(|| {
        user_schema_migration_error("created case change proposal could not be reloaded".to_owned())
    })
}

pub fn get_case_change_proposal(
    connection: &rusqlite::Connection,
    proposal_id: &str,
) -> rusqlite::Result<Option<CaseChangeProposalRow>> {
    connection
        .query_row(
            "SELECT proposal_id, conversation_id, project_id, run_id, base_case_digest,
                    status, changes_json, source_refs_json, created_at, decided_at, applied_at
             FROM case_change_proposals WHERE proposal_id = ?1",
            [proposal_id],
            case_change_proposal_from_row,
        )
        .optional()
}

pub fn list_case_change_proposals(
    connection: &rusqlite::Connection,
    conversation_id: &str,
) -> rusqlite::Result<Vec<CaseChangeProposalRow>> {
    let mut statement = connection.prepare(
        "SELECT proposal_id, conversation_id, project_id, run_id, base_case_digest,
                status, changes_json, source_refs_json, created_at, decided_at, applied_at
         FROM case_change_proposals
         WHERE conversation_id = ?1
         ORDER BY created_at DESC, proposal_id DESC",
    )?;
    let rows = statement
        .query_map([conversation_id], case_change_proposal_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn list_case_change_proposals_for_project(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Vec<CaseChangeProposalRow>> {
    let mut statement = connection.prepare(
        "SELECT proposal_id, conversation_id, project_id, run_id, base_case_digest,
                status, changes_json, source_refs_json, created_at, decided_at, applied_at
         FROM case_change_proposals
         WHERE project_id = ?1
         ORDER BY created_at DESC, proposal_id DESC",
    )?;
    let rows = statement
        .query_map([project_id], case_change_proposal_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Atomically claims a pending proposal for the supplied case/digest. Callers
/// that apply typed case changes can pass a `rusqlite::Transaction` here so
/// the CAS and the confirmed-case writes commit or roll back together.
pub fn compare_and_set_case_change_proposal_status(
    connection: &rusqlite::Connection,
    proposal_id: &str,
    project_id: &str,
    expected_base_case_digest: &str,
    new_status: &str,
) -> rusqlite::Result<CaseChangeProposalStatusUpdateResult> {
    if !matches!(new_status, "applied" | "rejected" | "stale") {
        return Err(user_schema_migration_error(
            "a pending proposal can only become applied, rejected, or stale".to_owned(),
        ));
    }
    let changed = connection.execute(
        "UPDATE case_change_proposals
         SET status = ?5,
             decided_at = CURRENT_TIMESTAMP,
             applied_at = CASE WHEN ?5 = 'applied' THEN CURRENT_TIMESTAMP ELSE NULL END
         WHERE proposal_id = ?1
           AND project_id = ?2
           AND base_case_digest = ?3
           AND status = ?4",
        params![
            proposal_id,
            project_id,
            expected_base_case_digest,
            "pending",
            new_status
        ],
    )?;
    let persisted = get_case_change_proposal(connection, proposal_id)?;
    Ok(match (changed, persisted) {
        (1, Some(row)) => CaseChangeProposalStatusUpdateResult::Updated(row),
        (_, Some(row)) => CaseChangeProposalStatusUpdateResult::Conflict(row),
        (_, None) => CaseChangeProposalStatusUpdateResult::NotFound,
    })
}

fn validate_case_assistant_pending_output_audit_contract(
    connection: &rusqlite::Connection,
    output: &NewCaseAssistantPendingOutputRow,
) -> rusqlite::Result<()> {
    let run = get_agent_run(connection, &output.run_id)?.ok_or_else(|| {
        user_schema_migration_error(
            "case assistant pending output requires its exact run audit".to_owned(),
        )
    })?;
    let tool_calls = list_tool_calls(connection, &output.run_id)?;
    let [tool_call] = tool_calls.as_slice() else {
        return Err(user_schema_migration_error(
            "case assistant pending output requires one exact tool audit".to_owned(),
        ));
    };
    if tool_call.ordinal != 0
        || tool_call.capability_name != "assistant.case_work"
        || tool_call.status != "succeeded"
        || tool_call.access_mode != "write"
        || tool_call.requires_confirmation
        || tool_call.error_type.is_some()
        || tool_call.finished_at.is_none()
    {
        return Err(user_schema_migration_error(
            "case assistant pending output tool lineage is invalid".to_owned(),
        ));
    }
    let audit = validate_case_assistant_tool_audit_contract(
        &output.run_id,
        &run.provider_snapshot_json,
        &tool_call.status,
        &tool_call.input_audit_json,
        &tool_call.output_audit_json,
        &tool_call.source_audit_json,
        tool_call.error_type.as_deref(),
    )?;
    let snapshots = serde_json::from_str::<Vec<serde_json::Value>>(&output.source_snapshots_json)
        .map_err(|_| invalid_case_assistant_tool_audit())?;
    let generation_ids = snapshots
        .iter()
        .map(|snapshot| {
            snapshot
                .get("generationId")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(invalid_case_assistant_tool_audit)
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if audit.project_id != output.project_id
        || audit.conversation_id != output.conversation_id
        || audit.generation_ids != generation_ids
        || audit.source_generation_ids != generation_ids
        || audit.workspace_digest != output.workspace_base_digest
        || audit.output_kind.as_deref() != Some(output.output_kind.as_str())
        || audit.typed_output_sha256.as_deref() != Some(output.output_sha256.as_str())
        || audit.proposal_source_refs_sha256.as_deref()
            != Some(output.expected_proposal_source_refs_sha256.as_str())
        || audit.project_binding_sha256.as_deref() != Some(output.project_binding_sha256.as_str())
        || audit.source_snapshots_sha256.as_deref() != Some(output.source_snapshots_sha256.as_str())
    {
        return Err(user_schema_migration_error(
            "case assistant pending output does not match its closed tool audit".to_owned(),
        ));
    }
    Ok(())
}

pub fn create_case_assistant_pending_output(
    connection: &rusqlite::Connection,
    output: &NewCaseAssistantPendingOutputRow,
) -> rusqlite::Result<CaseAssistantPendingOutputRow> {
    if !is_lower_hex_sha256(&output.project_binding_sha256)
        || !is_lower_hex_sha256(&output.workspace_base_digest)
        || output.output_version < 1
        || output.output_preview.len() > MAX_CASE_ASSISTANT_OUTPUT_PREVIEW_BYTES
        || output.output_preview.contains('\0')
    {
        return Err(user_schema_migration_error(
            "case assistant pending output metadata is invalid".to_owned(),
        ));
    }
    validate_case_assistant_source_snapshots_json(
        &output.source_snapshots_json,
        &output.source_snapshots_sha256,
    )?;
    validate_case_assistant_expected_proposal_source_refs(
        &output.output_kind,
        &output.expected_proposal_source_refs_json,
        &output.expected_proposal_source_refs_sha256,
    )?;
    validate_case_assistant_output_payload_json(
        &output.output_kind,
        &output.output_payload_json,
        &output.output_sha256,
    )?;
    validate_case_assistant_pending_output_audit_contract(connection, output)?;

    connection
        .execute(
            "INSERT INTO case_assistant_pending_outputs (
             pending_output_id, project_id, conversation_id, run_id,
             assistant_message_id, project_binding_sha256,
             source_snapshots_json, source_snapshots_sha256,
             expected_proposal_source_refs_json,
             expected_proposal_source_refs_sha256, output_kind,
             output_payload_json, output_preview, output_sha256, output_version,
             workspace_base_digest, status
         )
         SELECT
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
             ?15, ?16, 'pending'
         FROM conversations AS conversation
         JOIN projects AS project ON project.project_id = conversation.project_id
         WHERE conversation.conversation_id = ?3
           AND conversation.project_id = ?2
           AND conversation.scope = 'case_work'
           AND conversation.status = 'open'
           AND project.status = 'active'",
            params![
                output.pending_output_id,
                output.project_id,
                output.conversation_id,
                output.run_id,
                output.assistant_message_id,
                output.project_binding_sha256,
                output.source_snapshots_json,
                output.source_snapshots_sha256,
                output.expected_proposal_source_refs_json,
                output.expected_proposal_source_refs_sha256,
                output.output_kind,
                output.output_payload_json,
                output.output_preview,
                output.output_sha256,
                output.output_version,
                output.workspace_base_digest,
            ],
        )
        .and_then(|changed| {
            if changed == 1 {
                Ok(changed)
            } else {
                Err(user_schema_migration_error(
                    "case assistant pending output requires an active open case-work scope"
                        .to_owned(),
                ))
            }
        })?;
    get_case_assistant_pending_output(connection, &output.pending_output_id, &output.project_id)?
        .ok_or_else(|| {
            user_schema_migration_error(
                "created case assistant pending output could not be reloaded".to_owned(),
            )
        })
}

pub fn get_case_assistant_pending_output(
    connection: &rusqlite::Connection,
    pending_output_id: &str,
    project_id: &str,
) -> rusqlite::Result<Option<CaseAssistantPendingOutputRow>> {
    connection
        .query_row(
            "SELECT
                 output.pending_output_id, output.project_id, output.conversation_id,
                 output.run_id, output.assistant_message_id,
                 output.project_binding_sha256, output.source_snapshots_json,
                 output.source_snapshots_sha256,
                 output.expected_proposal_source_refs_json,
                 output.expected_proposal_source_refs_sha256, output.output_kind,
                 output.output_payload_json, output.output_preview, output.output_sha256,
                 output.output_version, output.workspace_base_digest, output.status,
                 output.confirmed_artifact_id, output.confirmed_proposal_id,
                 output.confirmation_request_sha256, output.row_version,
                 output.created_at, output.confirmed_at
             FROM case_assistant_pending_outputs AS output
             WHERE output.pending_output_id = ?1 AND output.project_id = ?2",
            params![pending_output_id, project_id],
            case_assistant_pending_output_from_row,
        )
        .optional()
}

pub fn list_case_assistant_pending_outputs(
    connection: &rusqlite::Connection,
    project_id: &str,
    conversation_id: &str,
    limit: u32,
) -> rusqlite::Result<Vec<CaseAssistantPendingOutputRow>> {
    let limit = i64::from(limit.clamp(1, 500));
    let mut statement = connection.prepare(
        "SELECT
             output.pending_output_id, output.project_id, output.conversation_id,
             output.run_id, output.assistant_message_id,
             output.project_binding_sha256, output.source_snapshots_json,
             output.source_snapshots_sha256,
             output.expected_proposal_source_refs_json,
             output.expected_proposal_source_refs_sha256, output.output_kind,
             output.output_payload_json, output.output_preview, output.output_sha256,
             output.output_version, output.workspace_base_digest, output.status,
             output.confirmed_artifact_id, output.confirmed_proposal_id,
             output.confirmation_request_sha256, output.row_version,
             output.created_at, output.confirmed_at
         FROM case_assistant_pending_outputs AS output
         WHERE output.project_id = ?1 AND output.conversation_id = ?2
         ORDER BY output.created_at DESC, output.pending_output_id DESC
         LIMIT ?3",
    )?;
    let rows = statement
        .query_map(
            params![project_id, conversation_id, limit],
            case_assistant_pending_output_from_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Performs the one-way pending-to-confirmed CAS after the caller has applied
/// the proposal or bound the artifact in the same SQLite transaction. This
/// function intentionally neither opens nor commits a transaction.
pub fn compare_and_set_case_assistant_pending_output_confirmed(
    connection: &rusqlite::Connection,
    confirmation: &ConfirmCaseAssistantPendingOutput<'_>,
) -> rusqlite::Result<CaseAssistantPendingOutputConfirmResult> {
    if confirmation.expected_output_version < 1
        || !is_lower_hex_sha256(confirmation.expected_output_sha256)
        || !is_lower_hex_sha256(confirmation.expected_workspace_base_digest)
        || !is_lower_hex_sha256(confirmation.confirmation_request_sha256)
    {
        return Err(user_schema_migration_error(
            "case assistant confirmation CAS metadata is invalid".to_owned(),
        ));
    }
    validate_case_assistant_expected_proposal_source_refs(
        "case_analysis",
        confirmation.expected_proposal_source_refs_json,
        confirmation.expected_proposal_source_refs_sha256,
    )?;
    let (confirmed_artifact_id, confirmed_proposal_id) = match confirmation.target {
        CaseAssistantConfirmationTarget::Artifact(artifact_id) if !artifact_id.is_empty() => {
            (Some(artifact_id.as_str()), None)
        }
        CaseAssistantConfirmationTarget::Proposal(proposal_id) if !proposal_id.is_empty() => {
            (None, Some(proposal_id.as_str()))
        }
        _ => {
            return Err(user_schema_migration_error(
                "case assistant confirmation target is invalid".to_owned(),
            ));
        }
    };
    let changed = connection.execute(
        "UPDATE case_assistant_pending_outputs
         SET status = 'confirmed',
             confirmed_artifact_id = ?7,
             confirmed_proposal_id = ?8,
             confirmation_request_sha256 = ?6,
             row_version = row_version + 1,
             confirmed_at = CURRENT_TIMESTAMP
         WHERE pending_output_id = ?1
           AND project_id = ?2
           AND output_version = ?3
           AND output_sha256 = ?4
           AND workspace_base_digest = ?5
           AND expected_proposal_source_refs_json = ?9
           AND expected_proposal_source_refs_sha256 = ?10
           AND status = 'pending'",
        params![
            confirmation.pending_output_id,
            confirmation.project_id,
            confirmation.expected_output_version,
            confirmation.expected_output_sha256,
            confirmation.expected_workspace_base_digest,
            confirmation.confirmation_request_sha256,
            confirmed_artifact_id,
            confirmed_proposal_id,
            confirmation.expected_proposal_source_refs_json,
            confirmation.expected_proposal_source_refs_sha256,
        ],
    )?;
    let persisted = get_case_assistant_pending_output(
        connection,
        confirmation.pending_output_id,
        confirmation.project_id,
    )?;
    Ok(match (changed, persisted) {
        (1, Some(row)) => CaseAssistantPendingOutputConfirmResult::Confirmed(row),
        (_, Some(row)) => CaseAssistantPendingOutputConfirmResult::Conflict(row),
        (_, None) => CaseAssistantPendingOutputConfirmResult::NotFound,
    })
}

pub fn create_operation_audit(
    connection: &rusqlite::Connection,
    audit: &NewOperationAuditRow,
) -> rusqlite::Result<OperationAuditRow> {
    connection.execute(
        "INSERT INTO operation_audit (
             audit_id, origin, operation, project_id, request_hash,
             idempotency_key_hash, status, details_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'prepared', ?7)",
        params![
            audit.audit_id,
            audit.origin,
            audit.operation,
            audit.project_id,
            audit.request_hash,
            audit.idempotency_key_hash,
            audit.details_json,
        ],
    )?;
    get_operation_audit(connection, &audit.audit_id)?.ok_or_else(|| {
        user_schema_migration_error("created operation audit could not be reloaded".to_owned())
    })
}

pub fn get_operation_audit(
    connection: &rusqlite::Connection,
    audit_id: &str,
) -> rusqlite::Result<Option<OperationAuditRow>> {
    connection
        .query_row(
            "SELECT audit_id, origin, operation, project_id, request_hash,
                    idempotency_key_hash, status, details_json, created_at, finished_at
             FROM operation_audit WHERE audit_id = ?1",
            [audit_id],
            operation_audit_from_row,
        )
        .optional()
}

pub fn get_operation_audit_by_idempotency_key_hash(
    connection: &rusqlite::Connection,
    origin: &str,
    operation: &str,
    idempotency_key_hash: &str,
) -> rusqlite::Result<Option<OperationAuditRow>> {
    connection
        .query_row(
            "SELECT audit_id, origin, operation, project_id, request_hash,
                    idempotency_key_hash, status, details_json, created_at, finished_at
             FROM operation_audit
             WHERE origin = ?1 AND operation = ?2 AND idempotency_key_hash = ?3",
            params![origin, operation, idempotency_key_hash],
            operation_audit_from_row,
        )
        .optional()
}

pub fn compare_and_set_operation_audit_status(
    connection: &rusqlite::Connection,
    audit_id: &str,
    new_status: &str,
    details_json: &str,
) -> rusqlite::Result<OperationAuditStatusUpdateResult> {
    if !matches!(new_status, "succeeded" | "failed") {
        return Err(user_schema_migration_error(
            "a prepared operation audit can only become succeeded or failed".to_owned(),
        ));
    }
    let changed = connection.execute(
        "UPDATE operation_audit
         SET status = ?2, details_json = ?3, finished_at = CURRENT_TIMESTAMP
         WHERE audit_id = ?1 AND status = 'prepared'",
        params![audit_id, new_status, details_json],
    )?;
    let persisted = get_operation_audit(connection, audit_id)?;
    Ok(match (changed, persisted) {
        (1, Some(row)) => OperationAuditStatusUpdateResult::Updated(row),
        (_, Some(row)) => OperationAuditStatusUpdateResult::Conflict(row),
        (_, None) => OperationAuditStatusUpdateResult::NotFound,
    })
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
    let workspace = load_case_workspace_rows(&transaction, project_id)?;
    transaction.commit()?;
    Ok(workspace)
}

/// Loads the case rows shown to the assistant and the optimistic-concurrency
/// digest derived from that exact same SQLite snapshot. Callers preparing an
/// assistant run should use this instead of issuing separate workspace and
/// digest reads, which could otherwise observe different committed states.
pub fn get_case_workspace_rows_with_digest(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Option<(CaseWorkspaceRows, String)>> {
    if !connection.is_autocommit() {
        return load_case_workspace_rows_with_digest(connection, project_id);
    }
    let transaction = connection.unchecked_transaction()?;
    let snapshot = load_case_workspace_rows_with_digest(&transaction, project_id)?;
    transaction.commit()?;
    Ok(snapshot)
}

fn load_case_workspace_rows_with_digest(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Option<(CaseWorkspaceRows, String)>> {
    let Some(workspace) = load_case_workspace_rows(connection, project_id)? else {
        return Ok(None);
    };
    let artifacts = list_artifacts_for_project(connection, project_id)?;
    let digest = case_workspace_digest_from_rows(workspace.clone(), artifacts);
    Ok(Some((workspace, digest)))
}

fn load_case_workspace_rows(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Option<CaseWorkspaceRows>> {
    let project = connection
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
                files: list_case_files(connection, project_id)?,
                parties: list_case_parties(connection, project_id)?,
                facts: list_case_facts(connection, project_id)?,
                evidence: list_evidence_items(connection, project_id)?,
                evidence_links: list_evidence_links(connection, project_id)?,
                fact_issue_links: list_fact_issue_links(connection, project_id)?,
                legal_issues: list_legal_issues(connection, project_id)?,
                legal_basis: list_legal_basis(connection, project_id)?,
                uncertainties: list_case_uncertainties(connection, project_id)?,
            })
        })
        .transpose()?;
    Ok(workspace)
}

/// Returns a deterministic SHA-256 over the complete confirmed case workspace.
/// The encoding is domain-separated, sectioned, length-prefixed, null-aware,
/// and sorted by stable entity IDs. When called inside an existing transaction
/// it uses that snapshot; otherwise it creates one read transaction so an
/// assistant proposal can compare exactly the state the user reviewed.
pub fn case_workspace_digest(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Option<String>> {
    if !connection.is_autocommit() {
        return case_workspace_digest_in_snapshot(connection, project_id);
    }
    let transaction = connection.unchecked_transaction()?;
    let digest = case_workspace_digest_in_snapshot(&transaction, project_id)?;
    transaction.commit()?;
    Ok(digest)
}

fn case_workspace_digest_in_snapshot(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<Option<String>> {
    Ok(load_case_workspace_rows_with_digest(connection, project_id)?.map(|(_, digest)| digest))
}

fn case_workspace_digest_from_rows(
    mut workspace: CaseWorkspaceRows,
    mut artifacts: Vec<ArtifactRow>,
) -> String {
    workspace
        .files
        .sort_by(|left, right| left.file_id.cmp(&right.file_id));
    workspace
        .parties
        .sort_by(|left, right| left.party_id.cmp(&right.party_id));
    workspace
        .facts
        .sort_by(|left, right| left.fact_id.cmp(&right.fact_id));
    workspace
        .evidence
        .sort_by(|left, right| left.evidence_id.cmp(&right.evidence_id));
    workspace
        .evidence_links
        .sort_by(|left, right| left.link_id.cmp(&right.link_id));
    workspace
        .fact_issue_links
        .sort_by(|left, right| left.link_id.cmp(&right.link_id));
    workspace
        .legal_issues
        .sort_by(|left, right| left.issue_id.cmp(&right.issue_id));
    workspace
        .legal_basis
        .sort_by(|left, right| left.basis_id.cmp(&right.basis_id));
    workspace
        .uncertainties
        .sort_by(|left, right| left.uncertainty_id.cmp(&right.uncertainty_id));
    artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let mut hasher = Sha256::new();
    hasher.update(CASE_WORKSPACE_DIGEST_DOMAIN);

    digest_workspace_section(&mut hasher, "projects", 1);
    let project = &workspace.project;
    for value in [
        project.project_id.as_str(),
        project.title.as_str(),
        project.case_type.as_str(),
        project.status.as_str(),
    ] {
        digest_workspace_text(&mut hasher, value);
    }
    digest_workspace_optional_text(&mut hasher, project.opened_on.as_deref());
    for value in [
        project.summary.as_str(),
        project.created_at.as_str(),
        project.updated_at.as_str(),
    ] {
        digest_workspace_text(&mut hasher, value);
    }

    digest_workspace_section(&mut hasher, "case_files", workspace.files.len());
    for row in &workspace.files {
        for value in [
            row.file_id.as_str(),
            row.project_id.as_str(),
            row.title.as_str(),
            row.file_type.as_str(),
            row.storage_reference.as_str(),
            row.summary.as_str(),
            row.created_at.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(&mut hasher, "case_parties", workspace.parties.len());
    for row in &workspace.parties {
        for value in [
            row.party_id.as_str(),
            row.project_id.as_str(),
            row.name.as_str(),
            row.normalized_name.as_str(),
            row.role.as_str(),
            row.contact.as_str(),
            row.notes.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(&mut hasher, "case_facts", workspace.facts.len());
    for row in &workspace.facts {
        digest_workspace_text(&mut hasher, &row.fact_id);
        digest_workspace_text(&mut hasher, &row.project_id);
        digest_workspace_optional_text(&mut hasher, row.occurred_on.as_deref());
        for value in [
            row.title.as_str(),
            row.description.as_str(),
            row.source.as_str(),
            row.confirmation_status.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(&mut hasher, "evidence_items", workspace.evidence.len());
    for row in &workspace.evidence {
        for value in [
            row.evidence_id.as_str(),
            row.project_id.as_str(),
            row.evidence_number.as_str(),
            row.title.as_str(),
            row.source.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
        digest_workspace_optional_text(&mut hasher, row.formed_on.as_deref());
        for value in [
            row.summary.as_str(),
            row.storage_reference.as_str(),
            row.confirmation_status.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(
        &mut hasher,
        "evidence_links",
        workspace.evidence_links.len(),
    );
    for row in &workspace.evidence_links {
        for value in [
            row.link_id.as_str(),
            row.project_id.as_str(),
            row.fact_id.as_str(),
            row.evidence_id.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(
        &mut hasher,
        "fact_issue_links",
        workspace.fact_issue_links.len(),
    );
    for row in &workspace.fact_issue_links {
        for value in [
            row.link_id.as_str(),
            row.project_id.as_str(),
            row.fact_id.as_str(),
            row.issue_id.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(&mut hasher, "legal_issues", workspace.legal_issues.len());
    for row in &workspace.legal_issues {
        for value in [
            row.issue_id.as_str(),
            row.project_id.as_str(),
            row.title.as_str(),
            row.description.as_str(),
            row.claim.as_str(),
            row.status.as_str(),
            row.confirmation_status.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(&mut hasher, "legal_basis", workspace.legal_basis.len());
    for row in &workspace.legal_basis {
        digest_workspace_text(&mut hasher, &row.basis_id);
        digest_workspace_text(&mut hasher, &row.project_id);
        digest_workspace_optional_text(&mut hasher, row.issue_id.as_deref());
        digest_workspace_text(&mut hasher, &row.source_id);
        digest_workspace_text(&mut hasher, &row.status);
        digest_workspace_optional_text(&mut hasher, row.invalid_reason.as_deref());
        digest_workspace_optional_text(&mut hasher, row.case_date.as_deref());
        for value in [
            row.article_id.as_str(),
            row.document_id.as_str(),
            row.version_id.as_str(),
            row.document_title.as_str(),
            row.version_label.as_str(),
            row.article_number.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
        digest_workspace_optional_text(&mut hasher, row.article_title.as_deref());
        for value in [row.canonical_label.as_str(), row.effective_from.as_str()] {
            digest_workspace_text(&mut hasher, value);
        }
        digest_workspace_optional_text(&mut hasher, row.effective_to.as_deref());
        for value in [
            row.version_status.as_str(),
            row.excerpt.as_str(),
            row.note.as_str(),
            row.created_at.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(
        &mut hasher,
        "case_uncertainties",
        workspace.uncertainties.len(),
    );
    for row in &workspace.uncertainties {
        for value in [
            row.uncertainty_id.as_str(),
            row.project_id.as_str(),
            row.description.as_str(),
            row.related_entity_type.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
        digest_workspace_optional_text(&mut hasher, row.related_entity_id.as_deref());
        for value in [
            row.source_file_ids_json.as_str(),
            row.status.as_str(),
            row.resolution.as_str(),
            row.confirmation_status.as_str(),
            row.created_at.as_str(),
            row.updated_at.as_str(),
        ] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    digest_workspace_section(&mut hasher, "artifacts", artifacts.len());
    for row in &artifacts {
        digest_workspace_text(&mut hasher, &row.artifact_id);
        digest_workspace_optional_text(&mut hasher, row.conversation_id.as_deref());
        digest_workspace_optional_text(&mut hasher, row.project_id.as_deref());
        for value in [row.kind.as_str(), row.title.as_str(), row.status.as_str()] {
            digest_workspace_text(&mut hasher, value);
        }
        hasher.update(row.current_version.to_be_bytes());
        for value in [row.created_at.as_str(), row.updated_at.as_str()] {
            digest_workspace_text(&mut hasher, value);
        }
    }

    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn digest_workspace_section(hasher: &mut Sha256, name: &str, row_count: usize) {
    digest_workspace_text(hasher, name);
    hasher.update((row_count as u64).to_be_bytes());
}

fn digest_workspace_text(hasher: &mut Sha256, value: &str) {
    hasher.update([1_u8]);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn digest_workspace_optional_text(hasher: &mut Sha256, value: Option<&str>) {
    match value {
        Some(value) => digest_workspace_text(hasher, value),
        None => hasher.update([0_u8]),
    }
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

/// Inserts a new case project without ever updating an existing project.
/// Bootstrap flows use this after a read-only proposal has been reviewed.
pub fn insert_case_project_if_absent(
    connection: &rusqlite::Connection,
    project: &CaseProjectRow,
) -> rusqlite::Result<bool> {
    let affected_rows = connection.execute(
        "INSERT INTO projects (project_id, title, case_type, status, opened_on, summary)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(project_id) DO NOTHING",
        params![
            project.project_id,
            project.title,
            project.case_type,
            project.status,
            project.opened_on,
            project.summary
        ],
    )?;
    Ok(affected_rows == 1)
}

pub fn delete_case_project(
    connection: &rusqlite::Connection,
    project_id: &str,
    privacy_deletion_id: &str,
) -> rusqlite::Result<bool> {
    if !is_project_deletion_journal_id(privacy_deletion_id) {
        return Err(user_schema_migration_error(
            "case project retirement requires a valid Privacy deletion journal id".to_owned(),
        ));
    }
    with_case_retirement_authority(
        connection,
        project_id,
        CASE_PROJECT_DELETED_RETIREMENT_REASON,
        Some(privacy_deletion_id),
        || {
            const SAVEPOINT: &str = "delete_case_project_atomic";
            connection.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))?;
            let deletion = (|| {
                let retired = connection.execute(
                    "INSERT INTO retired_case_project_ids(
                         project_id,retirement_reason,privacy_deletion_id
                     )
                     SELECT project_id,'case_project_deleted',?2
                     FROM projects
                     WHERE project_id=?1",
                    params![project_id, privacy_deletion_id],
                )?;
                let deleted =
                    connection.execute("DELETE FROM projects WHERE project_id=?1", [project_id])?;
                let retirement_matches = case_project_retirement_matches_privacy_deletion(
                    connection,
                    project_id,
                    privacy_deletion_id,
                )?;
                if retired != deleted || deleted > 1 || (deleted == 1 && !retirement_matches) {
                    return Err(user_schema_migration_error(
                        "case project retirement and physical deletion must be atomic".to_owned(),
                    ));
                }
                Ok(deleted == 1)
            })();
            match deletion {
                Ok(deleted) => match connection.execute_batch(&format!("RELEASE {SAVEPOINT}")) {
                    Ok(()) => Ok(deleted),
                    Err(error) => {
                        let _ = connection.execute_batch(&format!(
                            "ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"
                        ));
                        Err(error)
                    }
                },
                Err(error) => {
                    connection
                        .execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"))?;
                    Err(error)
                }
            }
        },
    )
}

/// Proves that the exact canonical project delete, including all cascades,
/// can commit while leaving the caller's transaction byte-for-byte unchanged.
///
/// Cross-database lifecycle coordination calls this while holding an IMMEDIATE
/// user-database transaction and before committing any Privacy revocation.
pub fn preflight_delete_case_project(
    connection: &rusqlite::Connection,
    project_id: &str,
    privacy_deletion_id: &str,
) -> rusqlite::Result<bool> {
    const SAVEPOINT: &str = "preflight_delete_case_project";
    connection.execute_batch(&format!("SAVEPOINT {SAVEPOINT}"))?;
    let deletion = delete_case_project(connection, project_id, privacy_deletion_id);
    let rollback =
        connection.execute_batch(&format!("ROLLBACK TO {SAVEPOINT}; RELEASE {SAVEPOINT}"));
    match (deletion, rollback) {
        (Ok(deleted), Ok(())) => Ok(deleted),
        (Err(error), Ok(())) => Err(error),
        (_, Err(error)) => Err(error),
    }
}

/// Records retirement after recovering a journal state in which Privacy was
/// durably revoked but an older process had already removed the user project.
/// A live project is never retired through this recovery-only entry point.
pub fn retire_absent_case_project_id_after_privacy_revocation(
    connection: &rusqlite::Connection,
    project_id: &str,
    privacy_deletion_id: &str,
) -> rusqlite::Result<bool> {
    if !is_project_deletion_journal_id(privacy_deletion_id) {
        return Err(user_schema_migration_error(
            "case project recovery requires a valid Privacy deletion journal id".to_owned(),
        ));
    }
    if case_project_id_is_retired(connection, project_id)? {
        return case_project_retirement_matches_privacy_deletion(
            connection,
            project_id,
            privacy_deletion_id,
        );
    }
    with_case_retirement_authority(
        connection,
        project_id,
        PRIVACY_JOURNAL_RECOVERY_RETIREMENT_REASON,
        Some(privacy_deletion_id),
        || {
            connection.execute(
                "INSERT INTO retired_case_project_ids(
                     project_id,retirement_reason,privacy_deletion_id
                 )
                 SELECT ?1,'privacy_journal_recovery',?2
                 WHERE NOT EXISTS(
                     SELECT 1 FROM projects WHERE project_id=?1
                 )
                 ON CONFLICT(project_id) DO NOTHING",
                params![project_id, privacy_deletion_id],
            )?;
            case_project_retirement_matches_privacy_deletion(
                connection,
                project_id,
                privacy_deletion_id,
            )
        },
    )
}

pub fn case_project_id_is_retired(
    connection: &rusqlite::Connection,
    project_id: &str,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM retired_case_project_ids WHERE project_id=?1
         )",
        [project_id],
        |row| row.get(0),
    )
}

pub fn case_project_retirement_matches_privacy_deletion(
    connection: &rusqlite::Connection,
    project_id: &str,
    privacy_deletion_id: &str,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM retired_case_project_ids AS retired
             WHERE retired.project_id=?1
               AND retired.privacy_deletion_id=?2
               AND retired.retirement_reason IN (
                   'case_project_deleted',
                   'privacy_journal_recovery'
               )
               AND NOT EXISTS(
                   SELECT 1 FROM projects WHERE project_id=retired.project_id
               )
         )",
        params![project_id, privacy_deletion_id],
        |row| row.get(0),
    )
}

fn is_project_deletion_journal_id(value: &str) -> bool {
    value.len() == 37
        && value.starts_with("pdel_")
        && value[5..].bytes().all(|byte| byte.is_ascii_hexdigit())
        && value[5..]
            .bytes()
            .all(|byte| !byte.is_ascii_alphabetic() || byte.is_ascii_lowercase())
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

/// Inserts one additive case file and refuses to overwrite an existing ID.
pub fn insert_case_file_if_absent(
    connection: &rusqlite::Connection,
    file: &CaseFileRow,
) -> rusqlite::Result<bool> {
    let affected_rows = connection.execute(
        "INSERT INTO case_files
         (file_id, project_id, title, file_type, storage_reference, summary)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(file_id) DO NOTHING",
        params![
            file.file_id,
            file.project_id,
            file.title,
            file.file_type,
            file.storage_reference,
            file.summary
        ],
    )?;
    Ok(affected_rows == 1)
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
    let conversation_id = format!("{COMPAT_QA_CONVERSATION_ID_PREFIX}{}", record.record_id);
    let user_message_id = format!("{conversation_id}:0-user");
    let assistant_message_id = format!("{conversation_id}:1-assistant");
    let title = bounded_qa_conversation_title(&record.question);
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO conversations (conversation_id, project_id, title, status)
         VALUES (?1, ?2, ?3, 'open')",
        params![conversation_id, record.project_id, title],
    )?;
    transaction.execute(
        "INSERT INTO messages (
             message_id, conversation_id, role, kind, text_summary, artifact_id, run_id
         ) VALUES
             (?1, ?3, 'user', 'text', ?4, NULL, NULL),
             (?2, ?3, 'assistant', 'text', ?5, NULL, NULL)",
        params![
            user_message_id,
            assistant_message_id,
            conversation_id,
            record.question,
            record.answer_text
        ],
    )?;
    insert_legal_answer_record_for_conversation_inner(&transaction, record, &conversation_id)?;
    transaction.commit()?;

    Ok(())
}

pub fn insert_legal_answer_record_for_conversation(
    connection: &rusqlite::Connection,
    record: &LegalAnswerRecordRow,
    conversation_id: &str,
) -> rusqlite::Result<()> {
    validate_provider_audit_snapshot_json(&record.provider_snapshot_json)?;
    insert_legal_answer_record_for_conversation_inner(connection, record, conversation_id)
}

fn insert_legal_answer_record_for_conversation_inner(
    connection: &rusqlite::Connection,
    record: &LegalAnswerRecordRow,
    conversation_id: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "
        INSERT INTO legal_answer_records (
            record_id,
            project_id,
            conversation_id,
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
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        ",
        params![
            record.record_id,
            record.project_id,
            conversation_id,
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

fn bounded_qa_conversation_title(question: &str) -> String {
    let normalized = question.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut characters = normalized.chars();
    let prefix = characters
        .by_ref()
        .take(LEGACY_QA_TITLE_MAX_CHARS)
        .collect::<String>();
    if characters.next().is_some() {
        format!("{prefix}…")
    } else if prefix.is_empty() {
        "旧版法律问答".to_owned()
    } else {
        prefix
    }
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

pub fn list_legal_answer_records_for_conversation(
    connection: &rusqlite::Connection,
    conversation_id: &str,
    limit: u32,
) -> rusqlite::Result<Vec<LegalAnswerRecordRow>> {
    let limit = i64::from(limit.clamp(1, 100));
    let mut statement = connection.prepare(
        "SELECT
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
         WHERE conversation_id = ?1
         ORDER BY created_at DESC, record_id DESC
         LIMIT ?2",
    )?;
    let rows = statement
        .query_map(
            params![conversation_id, limit],
            legal_answer_record_from_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
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

fn conversation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConversationRow> {
    let scope = match row.get::<_, String>(2)?.as_str() {
        "assistant" => ConversationScope::Assistant,
        "case_work" => ConversationScope::CaseWork,
        _ => {
            return Err(user_schema_migration_error(
                "conversation has an invalid authoritative scope".to_owned(),
            ));
        }
    };
    Ok(ConversationRow {
        conversation_id: row.get(0)?,
        project_id: row.get(1)?,
        scope,
        title: row.get(3)?,
        status: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

fn case_assistant_pending_output_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CaseAssistantPendingOutputRow> {
    Ok(CaseAssistantPendingOutputRow {
        pending_output_id: row.get(0)?,
        project_id: row.get(1)?,
        conversation_id: row.get(2)?,
        run_id: row.get(3)?,
        assistant_message_id: row.get(4)?,
        project_binding_sha256: row.get(5)?,
        source_snapshots_json: row.get(6)?,
        source_snapshots_sha256: row.get(7)?,
        expected_proposal_source_refs_json: row.get(8)?,
        expected_proposal_source_refs_sha256: row.get(9)?,
        output_kind: row.get(10)?,
        output_payload_json: row.get(11)?,
        output_preview: row.get(12)?,
        output_sha256: row.get(13)?,
        output_version: row.get(14)?,
        workspace_base_digest: row.get(15)?,
        status: row.get(16)?,
        confirmed_artifact_id: row.get(17)?,
        confirmed_proposal_id: row.get(18)?,
        confirmation_request_sha256: row.get(19)?,
        row_version: row.get(20)?,
        created_at: row.get(21)?,
        confirmed_at: row.get(22)?,
    })
}

fn message_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRow> {
    Ok(MessageRow {
        message_id: row.get(0)?,
        conversation_id: row.get(1)?,
        role: row.get(2)?,
        kind: row.get(3)?,
        text_summary: row.get(4)?,
        artifact_id: row.get(5)?,
        run_id: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn attachment_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttachmentRow> {
    Ok(AttachmentRow {
        attachment_id: row.get(0)?,
        project_id: row.get(1)?,
        original_name: row.get(2)?,
        extension: row.get(3)?,
        detected_mime: row.get(4)?,
        sha256: row.get(5)?,
        size_bytes: row.get(6)?,
        content_blob: row.get(7)?,
        extraction_status: row.get(8)?,
        extracted_text: row.get(9)?,
        segments_json: row.get(10)?,
        error_code: row.get(11)?,
        created_at: row.get(12)?,
    })
}

fn artifact_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArtifactRow> {
    Ok(ArtifactRow {
        artifact_id: row.get(0)?,
        conversation_id: row.get(1)?,
        project_id: row.get(2)?,
        kind: row.get(3)?,
        title: row.get(4)?,
        status: row.get(5)?,
        current_version: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn artifact_version_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArtifactVersionRow> {
    Ok(ArtifactVersionRow {
        version_id: row.get(0)?,
        artifact_id: row.get(1)?,
        version_number: row.get(2)?,
        content_json: row.get(3)?,
        rendered_text: row.get(4)?,
        source_refs_json: row.get(5)?,
        citation_report_json: row.get(6)?,
        provider_snapshot_json: row.get(7)?,
        created_at: row.get(8)?,
    })
}

fn agent_run_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AgentRunRow> {
    Ok(AgentRunRow {
        run_id: row.get(0)?,
        conversation_id: row.get(1)?,
        user_message_id: row.get(2)?,
        assistant_message_id: row.get(3)?,
        provider_id: row.get(4)?,
        provider_snapshot_json: row.get(5)?,
        intent: row.get(6)?,
        status: row.get(7)?,
        budget_json: row.get(8)?,
        error_type: row.get(9)?,
        created_at: row.get(10)?,
        finished_at: row.get(11)?,
    })
}

fn tool_call_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ToolCallRow> {
    let requires_confirmation: i64 = row.get(6)?;
    Ok(ToolCallRow {
        tool_call_id: row.get(0)?,
        run_id: row.get(1)?,
        ordinal: row.get(2)?,
        capability_name: row.get(3)?,
        status: row.get(4)?,
        access_mode: row.get(5)?,
        requires_confirmation: requires_confirmation != 0,
        input_audit_json: row.get(7)?,
        output_audit_json: row.get(8)?,
        source_audit_json: row.get(9)?,
        error_type: row.get(10)?,
        started_at: row.get(11)?,
        finished_at: row.get(12)?,
    })
}

fn case_change_proposal_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<CaseChangeProposalRow> {
    Ok(CaseChangeProposalRow {
        proposal_id: row.get(0)?,
        conversation_id: row.get(1)?,
        project_id: row.get(2)?,
        run_id: row.get(3)?,
        base_case_digest: row.get(4)?,
        status: row.get(5)?,
        changes_json: row.get(6)?,
        source_refs_json: row.get(7)?,
        created_at: row.get(8)?,
        decided_at: row.get(9)?,
        applied_at: row.get(10)?,
    })
}

fn operation_audit_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationAuditRow> {
    Ok(OperationAuditRow {
        audit_id: row.get(0)?,
        origin: row.get(1)?,
        operation: row.get(2)?,
        project_id: row.get(3)?,
        request_hash: row.get(4)?,
        idempotency_key_hash: row.get(5)?,
        status: row.get(6)?,
        details_json: row.get(7)?,
        created_at: row.get(8)?,
        finished_at: row.get(9)?,
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
        name: "retired_case_project_ids",
        canonical_columns: &[
            "project_id",
            "retired_at",
            "retirement_reason",
            "privacy_deletion_id",
        ],
        required_legacy_columns: &[
            "project_id",
            "retired_at",
            "retirement_reason",
            "privacy_deletion_id",
        ],
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
        name: "conversations",
        canonical_columns: &[
            "conversation_id",
            "project_id",
            "scope",
            "title",
            "status",
            "created_at",
            "updated_at",
        ],
        required_legacy_columns: &[
            "conversation_id",
            "project_id",
            "title",
            "status",
            "created_at",
            "updated_at",
        ],
    },
    UserTableMigrationSpec {
        name: "artifacts",
        canonical_columns: &[
            "artifact_id",
            "conversation_id",
            "project_id",
            "kind",
            "title",
            "status",
            "current_version",
            "created_at",
            "updated_at",
        ],
        required_legacy_columns: &[
            "artifact_id",
            "conversation_id",
            "project_id",
            "kind",
            "title",
            "status",
            "current_version",
            "created_at",
            "updated_at",
        ],
    },
    UserTableMigrationSpec {
        name: "artifact_versions",
        canonical_columns: &[
            "version_id",
            "artifact_id",
            "version_number",
            "content_json",
            "rendered_text",
            "source_refs_json",
            "citation_report_json",
            "provider_snapshot_json",
            "created_at",
        ],
        required_legacy_columns: &[
            "version_id",
            "artifact_id",
            "version_number",
            "content_json",
            "rendered_text",
            "source_refs_json",
            "citation_report_json",
            "provider_snapshot_json",
            "created_at",
        ],
    },
    UserTableMigrationSpec {
        name: "attachments",
        canonical_columns: &[
            "attachment_id",
            "project_id",
            "original_name",
            "extension",
            "detected_mime",
            "sha256",
            "size_bytes",
            "content_blob",
            "extraction_status",
            "extracted_text",
            "segments_json",
            "error_code",
            "created_at",
        ],
        required_legacy_columns: &[
            "attachment_id",
            "project_id",
            "original_name",
            "extension",
            "detected_mime",
            "sha256",
            "size_bytes",
            "content_blob",
            "extraction_status",
            "extracted_text",
            "segments_json",
            "error_code",
            "created_at",
        ],
    },
    UserTableMigrationSpec {
        name: "messages",
        canonical_columns: &[
            "message_id",
            "conversation_id",
            "role",
            "kind",
            "text_summary",
            "artifact_id",
            "run_id",
            "created_at",
        ],
        required_legacy_columns: &[
            "message_id",
            "conversation_id",
            "role",
            "kind",
            "text_summary",
            "artifact_id",
            "run_id",
            "created_at",
        ],
    },
    UserTableMigrationSpec {
        name: "message_attachments",
        canonical_columns: &["message_id", "attachment_id", "ordinal"],
        required_legacy_columns: &["message_id", "attachment_id", "ordinal"],
    },
    UserTableMigrationSpec {
        name: "conversation_sources",
        canonical_columns: &["conversation_id", "source_id", "created_at"],
        required_legacy_columns: &["conversation_id", "source_id", "created_at"],
    },
    UserTableMigrationSpec {
        name: "agent_runs",
        canonical_columns: &[
            "run_id",
            "conversation_id",
            "user_message_id",
            "assistant_message_id",
            "provider_id",
            "provider_snapshot_json",
            "intent",
            "status",
            "budget_json",
            "error_type",
            "created_at",
            "finished_at",
        ],
        required_legacy_columns: &[
            "run_id",
            "conversation_id",
            "user_message_id",
            "assistant_message_id",
            "provider_id",
            "provider_snapshot_json",
            "intent",
            "status",
            "budget_json",
            "error_type",
            "created_at",
            "finished_at",
        ],
    },
    UserTableMigrationSpec {
        name: "tool_calls",
        canonical_columns: &[
            "tool_call_id",
            "run_id",
            "ordinal",
            "capability_name",
            "status",
            "access_mode",
            "requires_confirmation",
            "input_audit_json",
            "output_audit_json",
            "source_audit_json",
            "error_type",
            "started_at",
            "finished_at",
        ],
        required_legacy_columns: &[
            "tool_call_id",
            "run_id",
            "ordinal",
            "capability_name",
            "status",
            "access_mode",
            "requires_confirmation",
            "input_audit_json",
            "output_audit_json",
            "source_audit_json",
            "error_type",
            "started_at",
            "finished_at",
        ],
    },
    UserTableMigrationSpec {
        name: "case_change_proposals",
        canonical_columns: &[
            "proposal_id",
            "conversation_id",
            "project_id",
            "run_id",
            "base_case_digest",
            "status",
            "changes_json",
            "source_refs_json",
            "created_at",
            "decided_at",
            "applied_at",
        ],
        required_legacy_columns: &[
            "proposal_id",
            "conversation_id",
            "project_id",
            "run_id",
            "base_case_digest",
            "status",
            "changes_json",
            "source_refs_json",
            "created_at",
            "decided_at",
            "applied_at",
        ],
    },
    UserTableMigrationSpec {
        name: "case_assistant_pending_outputs",
        canonical_columns: &[
            "pending_output_id",
            "project_id",
            "conversation_id",
            "run_id",
            "assistant_message_id",
            "project_binding_sha256",
            "source_snapshots_json",
            "source_snapshots_sha256",
            "expected_proposal_source_refs_json",
            "expected_proposal_source_refs_sha256",
            "output_kind",
            "output_payload_json",
            "output_preview",
            "output_sha256",
            "output_version",
            "workspace_base_digest",
            "status",
            "confirmed_artifact_id",
            "confirmed_proposal_id",
            "confirmation_request_sha256",
            "row_version",
            "created_at",
            "confirmed_at",
        ],
        required_legacy_columns: &[
            "pending_output_id",
            "project_id",
            "conversation_id",
            "run_id",
            "assistant_message_id",
            "project_binding_sha256",
            "source_snapshots_json",
            "source_snapshots_sha256",
            "output_kind",
            "output_payload_json",
            "output_preview",
            "output_sha256",
            "output_version",
            "workspace_base_digest",
            "status",
            "confirmed_artifact_id",
            "confirmed_proposal_id",
            "confirmation_request_sha256",
            "row_version",
            "created_at",
            "confirmed_at",
        ],
    },
    UserTableMigrationSpec {
        name: "operation_audit",
        canonical_columns: &[
            "audit_id",
            "origin",
            "operation",
            "project_id",
            "request_hash",
            "idempotency_key_hash",
            "status",
            "details_json",
            "created_at",
            "finished_at",
        ],
        required_legacy_columns: &[
            "audit_id",
            "origin",
            "operation",
            "project_id",
            "request_hash",
            "idempotency_key_hash",
            "status",
            "details_json",
            "created_at",
            "finished_at",
        ],
    },
    UserTableMigrationSpec {
        name: "legal_answer_records",
        canonical_columns: &[
            "record_id",
            "project_id",
            "conversation_id",
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
    "idx_conversations_updated",
    "idx_conversations_project_updated",
    "idx_artifacts_conversation_updated",
    "idx_artifacts_project_updated",
    "idx_artifact_versions_created",
    "idx_attachments_project_created",
    "idx_messages_conversation_created",
    "idx_messages_run",
    "idx_message_attachments_attachment",
    "idx_conversation_sources_source",
    "idx_agent_runs_conversation_created",
    "idx_agent_runs_status",
    "idx_tool_calls_status",
    "idx_case_change_proposals_conversation_created",
    "idx_case_change_proposals_project_status",
    "idx_case_assistant_pending_outputs_conversation_created",
    "idx_case_assistant_pending_outputs_project_status",
    "idx_operation_audit_idempotency",
    "idx_operation_audit_project_created",
    "idx_legal_answer_records_created",
    "idx_legal_answer_records_project_created",
    "idx_legal_answer_records_conversation_created",
    "idx_document_generation_project_exported",
];

const USER_SCHEMA_TRIGGER_NAMES: &[&str] = &[
    "trg_retired_case_project_ids_authorized_insert",
    "trg_retired_case_project_ids_no_update",
    "trg_retired_case_project_ids_no_delete",
    "trg_projects_reject_retired_id",
    "trg_projects_require_retirement_before_delete",
    "trg_legal_basis_issue_project_insert",
    "trg_legal_basis_issue_project_update",
    "trg_projects_detach_assistant_data_before_delete",
    "trg_artifacts_scope_insert",
    "trg_artifacts_scope_update",
    "trg_messages_artifact_run_scope_insert",
    "trg_messages_artifact_run_scope_update",
    "trg_agent_runs_message_scope_insert",
    "trg_agent_runs_message_scope_update",
    "trg_case_change_proposals_scope_insert",
    "trg_case_change_proposals_scope_update",
    "trg_conversations_scope_immutable",
    "trg_case_assistant_pending_outputs_closed_contract_insert",
    "trg_case_assistant_pending_outputs_scope_insert",
    "trg_case_assistant_pending_outputs_append_preserving",
    "trg_case_assistant_pending_outputs_confirmation_target",
    "trg_case_assistant_pending_outputs_no_delete",
    "trg_case_assistant_run_provider_audit_insert",
    "trg_case_assistant_run_provider_audit_update",
    "trg_case_assistant_tool_audit_insert",
    "trg_case_assistant_tool_audit_update",
    "trg_case_assistant_live_conversation_no_delete",
    "trg_case_assistant_live_run_no_delete",
    "trg_case_assistant_live_run_lineage_immutable",
    "trg_case_assistant_live_message_no_delete",
    "trg_case_assistant_live_message_lineage_immutable",
    "trg_case_assistant_live_message_attachment_no_insert",
    "trg_case_assistant_live_message_attachment_no_update",
    "trg_case_assistant_live_tool_call_no_insert",
    "trg_case_assistant_live_tool_call_no_delete",
    "trg_case_assistant_live_tool_call_immutable",
    "trg_case_assistant_confirmed_artifact_scope_immutable",
    "trg_case_assistant_confirmed_artifact_no_delete",
    "trg_case_assistant_confirmed_artifact_v1_immutable",
    "trg_case_assistant_confirmed_artifact_v1_no_delete",
    "trg_case_assistant_confirmed_proposal_scope_immutable",
    "trg_case_assistant_confirmed_proposal_no_delete",
    "trg_legal_answer_records_scope_insert",
    "trg_legal_answer_records_scope_update",
];

const LEGACY_USER_TABLE_DROP_ORDER: &[&str] = &[
    "case_assistant_pending_outputs",
    "tool_calls",
    "case_change_proposals",
    "operation_audit",
    "message_attachments",
    "conversation_sources",
    "artifact_versions",
    "legal_answer_records",
    "agent_runs",
    "messages",
    "artifacts",
    "attachments",
    "case_extraction_confirmations",
    "pending_extraction_reviews",
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
    "conversations",
    "projects",
    "retired_case_project_ids",
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

fn copy_legacy_retired_case_project_ids(
    transaction: &rusqlite::Transaction<'_>,
    spec: &UserTableMigrationSpec,
) -> rusqlite::Result<()> {
    debug_assert_eq!(spec.name, "retired_case_project_ids");
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

    let retired_rows = {
        let mut statement = transaction.prepare(&format!(
            "SELECT project_id,retired_at,retirement_reason,privacy_deletion_id
             FROM \"{legacy_name}\"
             ORDER BY project_id"
        ))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    for (project_id, retired_at, retirement_reason, privacy_deletion_id) in &retired_rows {
        let copied = with_case_retirement_authority(
            transaction,
            project_id,
            retirement_reason,
            privacy_deletion_id.as_deref(),
            || {
                transaction.execute(
                    "INSERT INTO retired_case_project_ids(
                         project_id,retired_at,retirement_reason,privacy_deletion_id
                     )
                     VALUES (?1,?2,?3,?4)",
                    params![
                        project_id,
                        retired_at,
                        retirement_reason,
                        privacy_deletion_id
                    ],
                )
            },
        )?;
        if copied != 1 {
            return Err(user_schema_migration_error(format!(
                "legacy retirement tombstone {project_id} was not copied exactly once"
            )));
        }
    }

    Ok(())
}

fn copy_legacy_messages_without_runs(
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
        .filter(|column| **column != "run_id")
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
            "INSERT INTO messages ({column_list})
             SELECT {column_list} FROM \"{legacy_name}\""
        ),
        [],
    )?;
    if i64::try_from(copied).ok() != Some(source_count) {
        return Err(user_schema_migration_error(
            "legacy messages row count changed during migration".to_owned(),
        ));
    }
    Ok(())
}

fn legacy_case_assistant_expected_proposal_source_refs(
    transaction: &rusqlite::Transaction<'_>,
    run_id: &str,
    output_kind: &str,
) -> rusqlite::Result<String> {
    let pending_table = legacy_user_table_name("case_assistant_pending_outputs");
    if !sqlite_table_exists(transaction, &pending_table)? {
        return Ok("[]".to_owned());
    }
    let pending_columns = table_columns(transaction, &pending_table)?;
    let has_expected_refs = pending_columns.contains("expected_proposal_source_refs_json");
    let has_expected_refs_sha = pending_columns.contains("expected_proposal_source_refs_sha256");
    if has_expected_refs != has_expected_refs_sha {
        return Err(user_schema_migration_error(
            "legacy case assistant pending output has a partial proposal provenance binding"
                .to_owned(),
        ));
    }

    if has_expected_refs {
        let mut statement = transaction.prepare(&format!(
            "SELECT
                 expected_proposal_source_refs_json,
                 expected_proposal_source_refs_sha256
             FROM \"{pending_table}\"
             WHERE run_id = ?1 AND output_kind = ?2
             ORDER BY pending_output_id"
        ))?;
        let bindings = statement
            .query_map(params![run_id, output_kind], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut expected: Option<String> = None;
        for (source_refs_json, source_refs_sha256) in bindings {
            validate_case_assistant_expected_proposal_source_refs(
                output_kind,
                &source_refs_json,
                &source_refs_sha256,
            )?;
            if expected
                .as_deref()
                .is_some_and(|expected| expected != source_refs_json)
            {
                return Err(user_schema_migration_error(
                    "legacy case assistant run has ambiguous proposal provenance bindings"
                        .to_owned(),
                ));
            }
            expected = Some(source_refs_json);
        }
        return Ok(expected.unwrap_or_else(|| "[]".to_owned()));
    }

    if output_kind != "case_analysis" {
        return Ok("[]".to_owned());
    }

    let proposal_table = legacy_user_table_name("case_change_proposals");
    let confirmed_outputs = {
        let mut statement = transaction.prepare(&format!(
            "SELECT
                 pending_output_id, confirmed_proposal_id, project_id,
                 conversation_id, workspace_base_digest, output_payload_json
             FROM \"{pending_table}\"
             WHERE run_id = ?1
               AND output_kind = 'case_analysis'
               AND status = 'confirmed'
             ORDER BY pending_output_id"
        ))?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    if confirmed_outputs.is_empty() {
        return Ok("[]".to_owned());
    }
    if !sqlite_table_exists(transaction, &proposal_table)? {
        return Err(user_schema_migration_error(
            "confirmed legacy case assistant analysis is missing its proposal table".to_owned(),
        ));
    }

    let mut expected: Option<String> = None;
    for (
        pending_output_id,
        proposal_id,
        project_id,
        conversation_id,
        workspace_base_digest,
        output_payload_json,
    ) in confirmed_outputs
    {
        let proposal_id = proposal_id.ok_or_else(|| {
            user_schema_migration_error(format!(
                "confirmed legacy case assistant analysis {pending_output_id} is missing its proposal"
            ))
        })?;
        let matches = {
            let mut statement = transaction.prepare(&format!(
                "SELECT source_refs_json
                 FROM \"{proposal_table}\"
                 WHERE proposal_id = ?1
                   AND project_id = ?2
                   AND conversation_id = ?3
                   AND run_id = ?4
                   AND status = 'applied'
                   AND base_case_digest = ?5
                   AND json(changes_json) =
                       json(json_extract(?6, '$.content'))"
            ))?;
            let rows = statement
                .query_map(
                    params![
                        proposal_id,
                        project_id,
                        conversation_id,
                        run_id,
                        workspace_base_digest,
                        output_payload_json,
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let [source_refs_json] = matches.as_slice() else {
            return Err(user_schema_migration_error(format!(
                "confirmed legacy case assistant analysis {pending_output_id} has a missing or ambiguous applied proposal"
            )));
        };
        validate_case_assistant_expected_proposal_source_refs(
            "case_analysis",
            source_refs_json,
            &sha256_hex(source_refs_json.as_bytes()),
        )?;
        if expected
            .as_deref()
            .is_some_and(|expected| expected != source_refs_json)
        {
            return Err(user_schema_migration_error(
                "legacy case assistant run has ambiguous applied proposal provenance".to_owned(),
            ));
        }
        expected = Some(source_refs_json.clone());
    }
    Ok(expected.unwrap_or_else(|| "[]".to_owned()))
}

fn migrate_legacy_case_assistant_tool_output_audit(
    transaction: &rusqlite::Transaction<'_>,
    tool_call: &ToolCallRow,
) -> rusqlite::Result<String> {
    if tool_call.capability_name != "assistant.case_work" || tool_call.status != "succeeded" {
        return Ok(tool_call.output_audit_json.clone());
    }
    let mut output = canonical_json_value(
        &tool_call.output_audit_json,
        MAX_CASE_ASSISTANT_TOOL_AUDIT_BYTES,
    )?;
    let output_object = output
        .as_object_mut()
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    let output_kind = output_object
        .get("outputIds")
        .and_then(serde_json::Value::as_object)
        .and_then(|output_ids| output_ids.get("pendingOutputKind"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(invalid_case_assistant_tool_audit)?
        .to_owned();
    let output_hashes = output_object
        .get_mut("outputHashes")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid_case_assistant_tool_audit)?;
    if output_hashes.contains_key("proposalSourceRefsSha256") {
        return Ok(tool_call.output_audit_json.clone());
    }
    let expected_refs = legacy_case_assistant_expected_proposal_source_refs(
        transaction,
        &tool_call.run_id,
        &output_kind,
    )?;
    output_hashes.insert(
        "proposalSourceRefsSha256".to_owned(),
        serde_json::Value::String(sha256_hex(expected_refs.as_bytes())),
    );
    serde_json::to_string(&output).map_err(|_| {
        user_schema_migration_error(
            "legacy case assistant tool audit could not be canonically encoded".to_owned(),
        )
    })
}

fn copy_legacy_tool_calls(
    transaction: &rusqlite::Transaction<'_>,
    spec: &UserTableMigrationSpec,
) -> rusqlite::Result<()> {
    debug_assert_eq!(spec.name, "tool_calls");
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

    let tool_calls = {
        let mut statement = transaction.prepare(&format!(
            "SELECT
                 tool_call_id, run_id, ordinal, capability_name, status,
                 access_mode, requires_confirmation, input_audit_json,
                 output_audit_json, source_audit_json, error_type,
                 started_at, finished_at
             FROM \"{legacy_name}\"
             ORDER BY tool_call_id"
        ))?;
        let rows = statement
            .query_map([], tool_call_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    for tool_call in tool_calls {
        let migrated_output_audit =
            migrate_legacy_case_assistant_tool_output_audit(transaction, &tool_call)?;
        let copied = transaction.execute(
            "INSERT INTO tool_calls (
                 tool_call_id, run_id, ordinal, capability_name, status,
                 access_mode, requires_confirmation, input_audit_json,
                 output_audit_json, source_audit_json, error_type,
                 started_at, finished_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                tool_call.tool_call_id,
                tool_call.run_id,
                tool_call.ordinal,
                tool_call.capability_name,
                tool_call.status,
                tool_call.access_mode,
                tool_call.requires_confirmation,
                tool_call.input_audit_json,
                migrated_output_audit,
                tool_call.source_audit_json,
                tool_call.error_type,
                tool_call.started_at,
                tool_call.finished_at,
            ],
        )?;
        if copied != 1 {
            return Err(user_schema_migration_error(format!(
                "legacy tool call {} was not copied exactly once",
                tool_call.tool_call_id
            )));
        }
    }
    Ok(())
}

fn copy_legacy_case_assistant_pending_outputs(
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
    let has_expected_refs = source_columns.contains("expected_proposal_source_refs_json");
    let has_expected_refs_sha = source_columns.contains("expected_proposal_source_refs_sha256");
    if has_expected_refs != has_expected_refs_sha {
        return Err(user_schema_migration_error(
            "legacy case assistant pending output has a partial proposal provenance binding"
                .to_owned(),
        ));
    }
    let migrated_expected_refs = if has_expected_refs {
        "source.expected_proposal_source_refs_json".to_owned()
    } else {
        "CASE
             WHEN source.output_kind = 'case_analysis'
              AND source.status = 'confirmed'
             THEN (
                 SELECT proposal.source_refs_json
                 FROM case_change_proposals AS proposal
                 WHERE proposal.proposal_id = source.confirmed_proposal_id
                   AND proposal.project_id = source.project_id
                    AND proposal.conversation_id = source.conversation_id
                    AND proposal.run_id = source.run_id
                    AND proposal.status = 'applied'
                    AND proposal.base_case_digest =
                        source.workspace_base_digest
                    AND json(proposal.changes_json) =
                        json(json_extract(
                            source.output_payload_json,
                            '$.content'
                        ))
              )
             ELSE '[]'
         END"
        .to_owned()
    };
    let migrated_expected_refs_sha = if has_expected_refs_sha {
        "source.expected_proposal_source_refs_sha256".to_owned()
    } else {
        format!("case_assistant_sha256({migrated_expected_refs})")
    };

    let source_count: i64 = transaction.query_row(
        &format!("SELECT COUNT(*) FROM \"{legacy_name}\""),
        [],
        |row| row.get(0),
    )?;
    let inserted = transaction.execute(
        &format!(
            "INSERT INTO case_assistant_pending_outputs (
                 pending_output_id, project_id, conversation_id, run_id,
                 assistant_message_id, project_binding_sha256,
                 source_snapshots_json, source_snapshots_sha256,
                 expected_proposal_source_refs_json,
                 expected_proposal_source_refs_sha256, output_kind,
                 output_payload_json, output_preview, output_sha256, output_version,
                 workspace_base_digest, status, row_version, created_at
             )
             SELECT
                 pending_output_id, project_id, conversation_id, run_id,
                 assistant_message_id, project_binding_sha256,
                 source_snapshots_json, source_snapshots_sha256,
                 {migrated_expected_refs},
                 {migrated_expected_refs_sha}, output_kind,
                 output_payload_json, output_preview, output_sha256, output_version,
                 workspace_base_digest, 'pending', 1, created_at
             FROM \"{legacy_name}\" AS source"
        ),
        [],
    )?;
    if i64::try_from(inserted).ok() != Some(source_count) {
        return Err(user_schema_migration_error(
            "legacy case assistant pending output count changed during migration".to_owned(),
        ));
    }

    transaction.execute(
        &format!(
            "UPDATE case_assistant_pending_outputs AS destination
             SET status = 'confirmed',
                 confirmed_artifact_id = (
                     SELECT source.confirmed_artifact_id
                     FROM \"{legacy_name}\" AS source
                     WHERE source.pending_output_id = destination.pending_output_id
                 ),
                 confirmed_proposal_id = (
                     SELECT source.confirmed_proposal_id
                     FROM \"{legacy_name}\" AS source
                     WHERE source.pending_output_id = destination.pending_output_id
                 ),
                 confirmation_request_sha256 = (
                     SELECT source.confirmation_request_sha256
                     FROM \"{legacy_name}\" AS source
                     WHERE source.pending_output_id = destination.pending_output_id
                 ),
                 row_version = row_version + 1,
                 confirmed_at = (
                     SELECT source.confirmed_at
                     FROM \"{legacy_name}\" AS source
                     WHERE source.pending_output_id = destination.pending_output_id
                 )
             WHERE pending_output_id IN (
                 SELECT pending_output_id
                 FROM \"{legacy_name}\"
                 WHERE status = 'confirmed'
             )"
        ),
        [],
    )?;

    let differences = spec
        .canonical_columns
        .iter()
        .map(|column| match *column {
            "expected_proposal_source_refs_json" if !has_expected_refs => format!(
                "destination.expected_proposal_source_refs_json IS NOT ({migrated_expected_refs})"
            ),
            "expected_proposal_source_refs_sha256" if !has_expected_refs_sha => format!(
                "destination.expected_proposal_source_refs_sha256 IS NOT \
                 ({migrated_expected_refs_sha})"
            ),
            _ => format!("destination.\"{column}\" IS NOT source.\"{column}\""),
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    let changed: bool = transaction.query_row(
        &format!(
            "SELECT EXISTS(
                 SELECT 1
                 FROM \"{legacy_name}\" AS source
                 LEFT JOIN case_assistant_pending_outputs AS destination
                   ON destination.pending_output_id = source.pending_output_id
                 WHERE destination.pending_output_id IS NULL OR {differences}
             )"
        ),
        [],
        |row| row.get(0),
    )?;
    if changed {
        return Err(user_schema_migration_error(
            "legacy case assistant pending output lineage changed during migration".to_owned(),
        ));
    }
    Ok(())
}

const CASE_ASSISTANT_PENDING_OUTPUT_MIGRATION_TRIGGER_NAMES: [&str; 4] = [
    "trg_case_assistant_pending_outputs_closed_contract_insert",
    "trg_case_assistant_pending_outputs_scope_insert",
    "trg_case_assistant_pending_outputs_append_preserving",
    "trg_case_assistant_pending_outputs_confirmation_target",
];

fn suspend_case_assistant_pending_output_migration_triggers(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<Vec<String>> {
    let mut definitions =
        Vec::with_capacity(CASE_ASSISTANT_PENDING_OUTPUT_MIGRATION_TRIGGER_NAMES.len());
    for trigger_name in CASE_ASSISTANT_PENDING_OUTPUT_MIGRATION_TRIGGER_NAMES {
        let definition = transaction.query_row(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
            [trigger_name],
            |row| row.get::<_, String>(0),
        )?;
        transaction.execute(&format!("DROP TRIGGER \"{trigger_name}\""), [])?;
        definitions.push(definition);
    }
    Ok(definitions)
}

fn restore_case_assistant_pending_output_migration_triggers(
    transaction: &rusqlite::Transaction<'_>,
    definitions: &[String],
) -> rusqlite::Result<()> {
    for definition in definitions {
        transaction.execute_batch(definition)?;
    }
    Ok(())
}

fn restore_legacy_message_runs(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let legacy_name = legacy_user_table_name("messages");
    transaction.execute(
        &format!(
            "UPDATE messages
             SET run_id = (
                 SELECT source.run_id FROM \"{legacy_name}\" AS source
                 WHERE source.message_id = messages.message_id
             )"
        ),
        [],
    )?;
    let changed: bool = transaction.query_row(
        &format!(
            "SELECT EXISTS(
                 SELECT 1
                 FROM \"{legacy_name}\" AS source
                 JOIN messages AS destination USING (message_id)
                 WHERE destination.run_id IS NOT source.run_id
             )"
        ),
        [],
        |row| row.get(0),
    )?;
    if changed {
        return Err(user_schema_migration_error(
            "legacy message run ownership changed during migration".to_owned(),
        ));
    }
    Ok(())
}

fn copy_legacy_legal_answers(
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

    let mut destination_columns = Vec::new();
    let mut select_expressions = Vec::new();
    for column in spec.canonical_columns {
        if *column == "project_id" {
            if source_columns.contains("project_id") {
                destination_columns.push("\"project_id\"".to_owned());
                select_expressions.push("NULLIF(project_id, '')".to_owned());
            }
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
        [],
    )?;
    if i64::try_from(copied).ok() != Some(source_count) {
        return Err(user_schema_migration_error(format!(
            "legacy table {} row count changed during migration",
            spec.name
        )));
    }

    let destination_count: i64 =
        transaction.query_row("SELECT COUNT(*) FROM legal_answer_records", [], |row| {
            row.get(0)
        })?;
    if destination_count != source_count {
        return Err(user_schema_migration_error(
            "legacy legal answer count changed during migration".to_owned(),
        ));
    }

    for column in spec
        .canonical_columns
        .iter()
        .filter(|column| source_columns.contains(**column) && **column != "conversation_id")
    {
        let values_differ = if *column == "project_id" {
            "NOT (
                    (source.project_id IS NULL OR source.project_id = '')
                    AND destination.project_id IS NULL
                 ) AND destination.project_id IS NOT source.project_id"
                .to_owned()
        } else {
            format!("destination.\"{column}\" IS NOT source.\"{column}\"")
        };
        let changed: bool = transaction.query_row(
            &format!(
                "SELECT EXISTS(
                    SELECT 1
                    FROM \"{legacy_name}\" AS source
                    LEFT JOIN legal_answer_records AS destination
                      ON destination.record_id = source.record_id
                    WHERE destination.record_id IS NULL OR ({values_differ})
                )"
            ),
            [],
            |row| row.get(0),
        )?;
        if changed {
            return Err(user_schema_migration_error(format!(
                "legacy legal answer column {column} changed during migration"
            )));
        }
    }

    Ok(())
}

fn create_legacy_qa_conversations(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let pending = {
        let mut statement = transaction.prepare(
            "SELECT record_id, project_id, question, answer_text, created_at
             FROM legal_answer_records
             WHERE conversation_id IS NULL
             ORDER BY record_id ASC",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    for (record_id, project_id, question, answer_text, created_at) in pending {
        let conversation_id = format!("{LEGACY_QA_CONVERSATION_ID_PREFIX}{record_id}");
        let user_message_id = format!("{conversation_id}:0-user");
        let assistant_message_id = format!("{conversation_id}:1-assistant");
        let title = bounded_qa_conversation_title(&question);
        transaction.execute(
            "INSERT INTO conversations (
                 conversation_id, project_id, title, status, created_at, updated_at
             ) VALUES (?1, ?2, ?3, 'open', ?4, ?4)",
            params![conversation_id, project_id, title, created_at],
        )?;
        transaction.execute(
            "INSERT INTO messages (
                 message_id, conversation_id, role, kind, text_summary,
                 artifact_id, run_id, created_at
             ) VALUES
                 (?1, ?3, 'user', 'text', ?4, NULL, NULL, ?6),
                 (?2, ?3, 'assistant', 'text', ?5, NULL, NULL, ?6)",
            params![
                user_message_id,
                assistant_message_id,
                conversation_id,
                question,
                answer_text,
                created_at
            ],
        )?;
        let changed = transaction.execute(
            "UPDATE legal_answer_records
             SET conversation_id = ?2
             WHERE record_id = ?1 AND conversation_id IS NULL",
            params![record_id, conversation_id],
        )?;
        if changed != 1 {
            return Err(user_schema_migration_error(format!(
                "legacy legal answer {record_id} could not be bound to its deterministic conversation"
            )));
        }
    }

    let unbound_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM legal_answer_records WHERE conversation_id IS NULL",
        [],
        |row| row.get(0),
    )?;
    if unbound_count != 0 {
        return Err(user_schema_migration_error(
            "legacy legal answers remain without deterministic conversations".to_owned(),
        ));
    }

    Ok(())
}

fn is_precise_legacy_quarantine_project_id(project_id: &str) -> bool {
    if project_id == LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX {
        return true;
    }
    let Some(suffix) = project_id
        .strip_prefix(LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX)
        .and_then(|suffix| suffix.strip_prefix('-'))
    else {
        return false;
    };
    suffix
        .parse::<u32>()
        .ok()
        .filter(|number| *number > 0)
        .is_some_and(|number| number.to_string() == suffix)
}

fn quarantine_project_has_other_business_children(
    transaction: &rusqlite::Transaction<'_>,
    project_id: &str,
) -> rusqlite::Result<bool> {
    transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM case_files WHERE project_id = ?1
             UNION ALL SELECT 1 FROM pending_extraction_reviews WHERE project_id = ?1
             UNION ALL SELECT 1 FROM case_extraction_confirmations WHERE project_id = ?1
             UNION ALL SELECT 1 FROM case_parties WHERE project_id = ?1
             UNION ALL SELECT 1 FROM case_facts WHERE project_id = ?1
             UNION ALL SELECT 1 FROM evidence_items WHERE project_id = ?1
             UNION ALL SELECT 1 FROM evidence_links WHERE project_id = ?1
             UNION ALL SELECT 1 FROM legal_issues WHERE project_id = ?1
             UNION ALL SELECT 1 FROM fact_issue_links WHERE project_id = ?1
             UNION ALL SELECT 1 FROM case_uncertainties WHERE project_id = ?1
             UNION ALL SELECT 1 FROM legal_basis WHERE project_id = ?1
             UNION ALL SELECT 1 FROM document_generation_records WHERE project_id = ?1
             UNION ALL SELECT 1 FROM conversations WHERE project_id = ?1
             UNION ALL SELECT 1 FROM artifacts WHERE project_id = ?1
             UNION ALL SELECT 1 FROM attachments WHERE project_id = ?1
             UNION ALL SELECT 1 FROM case_change_proposals WHERE project_id = ?1
         )",
        [project_id],
        |row| row.get(0),
    )
}

fn migrate_precise_legacy_answer_quarantines(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    let candidates = {
        let mut statement = transaction.prepare(
            "SELECT project_id, title, case_type, status, opened_on, summary
             FROM projects
             WHERE project_id LIKE ?1
             ORDER BY project_id ASC",
        )?;
        let prefix_pattern = format!("{LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX}%");
        let rows = statement
            .query_map([prefix_pattern], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    for (project_id, title, case_type, status, opened_on, summary) in candidates {
        if !is_precise_legacy_quarantine_project_id(&project_id)
            || title != LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE
        {
            continue;
        }
        if case_type != "migration_quarantine"
            || status != "archived"
            || opened_on.is_some()
            || summary != LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY
        {
            return Err(user_schema_migration_error(format!(
                "reserved legacy answer quarantine project {project_id} has ambiguous metadata"
            )));
        }

        let answer_conversations = {
            let mut statement = transaction.prepare(
                "SELECT record_id, conversation_id
                 FROM legal_answer_records
                 WHERE project_id = ?1
                 ORDER BY record_id ASC",
            )?;
            let rows = statement
                .query_map([&project_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        for (record_id, conversation_id) in &answer_conversations {
            let expected = format!("{LEGACY_QA_CONVERSATION_ID_PREFIX}{record_id}");
            if conversation_id != &expected {
                return Err(user_schema_migration_error(format!(
                    "legacy quarantine answer {record_id} has a non-deterministic conversation"
                )));
            }
        }

        for (_, conversation_id) in &answer_conversations {
            let changed = transaction.execute(
                "UPDATE conversations
                 SET project_id = NULL, updated_at = CURRENT_TIMESTAMP
                 WHERE conversation_id = ?1 AND project_id = ?2",
                params![conversation_id, project_id],
            )?;
            if changed != 1 {
                return Err(user_schema_migration_error(format!(
                    "legacy quarantine conversation {conversation_id} has ambiguous ownership"
                )));
            }
        }
        transaction.execute(
            "UPDATE legal_answer_records SET project_id = NULL WHERE project_id = ?1",
            [&project_id],
        )?;

        if !quarantine_project_has_other_business_children(transaction, &project_id)? {
            with_case_retirement_authority(
                transaction,
                &project_id,
                LEGACY_MIGRATION_CLEANUP_RETIREMENT_REASON,
                None,
                || {
                    let retired = transaction.execute(
                        "INSERT INTO retired_case_project_ids(
                             project_id,retirement_reason
                         )
                         SELECT project_id,'legacy_migration_cleanup'
                         FROM projects
                         WHERE project_id = ?1
                           AND title = ?2
                           AND case_type = 'migration_quarantine'
                           AND status = 'archived'
                           AND opened_on IS NULL
                           AND summary = ?3",
                        params![
                            project_id,
                            LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE,
                            LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY
                        ],
                    )?;
                    if retired != 1 {
                        return Err(user_schema_migration_error(format!(
                            "legacy quarantine project {project_id} changed before retirement"
                        )));
                    }
                    let deleted = transaction.execute(
                        "DELETE FROM projects
                         WHERE project_id = ?1
                           AND title = ?2
                           AND case_type = 'migration_quarantine'
                           AND status = 'archived'
                           AND opened_on IS NULL
                           AND summary = ?3",
                        params![
                            project_id,
                            LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE,
                            LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY
                        ],
                    )?;
                    if deleted != 1 {
                        return Err(user_schema_migration_error(format!(
                            "legacy quarantine project {project_id} changed during migration"
                        )));
                    }
                    Ok(())
                },
            )?;
        }
    }

    Ok(())
}

fn migrate_staged_user_tables(
    transaction: &rusqlite::Transaction<'_>,
    staged: &HashSet<&str>,
) -> rusqlite::Result<()> {
    let mut message_runs_restored = false;
    for spec in USER_TABLE_MIGRATION_SPECS {
        if staged.contains(spec.name) {
            if spec.name == "case_assistant_pending_outputs"
                && staged.contains("messages")
                && !message_runs_restored
            {
                restore_legacy_message_runs(transaction)?;
                message_runs_restored = true;
            }
            if spec.name == "legal_answer_records" {
                copy_legacy_legal_answers(transaction, spec)?;
            } else if spec.name == "messages" {
                copy_legacy_messages_without_runs(transaction, spec)?;
            } else if spec.name == "tool_calls" {
                copy_legacy_tool_calls(transaction, spec)?;
            } else if spec.name == "case_assistant_pending_outputs" {
                copy_legacy_case_assistant_pending_outputs(transaction, spec)?;
            } else if spec.name == "retired_case_project_ids" {
                copy_legacy_retired_case_project_ids(transaction, spec)?;
            } else {
                copy_legacy_user_table(transaction, spec)?;
            }
        }
    }
    if staged.contains("messages") && !message_runs_restored {
        restore_legacy_message_runs(transaction)?;
    }

    create_legacy_qa_conversations(transaction)?;
    migrate_precise_legacy_answer_quarantines(transaction)?;

    validate_project_scoped_relations(transaction)?;
    validate_assistant_scoped_relations(transaction)?;

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

    let reused_retired_project_id: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM retired_case_project_ids AS retired
             JOIN projects AS project
               ON project.project_id = retired.project_id
         )",
        [],
        |row| row.get(0),
    )?;
    if reused_retired_project_id {
        return Err(user_schema_migration_error(
            "retired case project ids cannot have a live project".to_owned(),
        ));
    }

    Ok(())
}

fn validate_assistant_scoped_relations(connection: &rusqlite::Connection) -> rusqlite::Result<()> {
    let invalid_artifact_version: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM artifacts AS artifact
             LEFT JOIN artifact_versions AS version
               ON version.artifact_id = artifact.artifact_id
              AND version.version_number = artifact.current_version
             WHERE version.version_id IS NULL
                OR EXISTS (
                    SELECT 1 FROM artifact_versions AS future
                    WHERE future.artifact_id = artifact.artifact_id
                      AND future.version_number > artifact.current_version
                )
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_artifact_version {
        return Err(user_schema_migration_error(
            "artifact current_version must identify its greatest persisted version".to_owned(),
        ));
    }

    let invalid_artifact_scope: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM artifacts AS artifact
             JOIN conversations AS conversation
               ON conversation.conversation_id = artifact.conversation_id
             WHERE artifact.project_id IS NOT NULL
               AND conversation.project_id IS NOT NULL
               AND artifact.project_id != conversation.project_id
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_artifact_scope {
        return Err(user_schema_migration_error(
            "artifact project must match its bound conversation".to_owned(),
        ));
    }

    let invalid_message_scope: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM messages AS message
             JOIN conversations AS conversation
               ON conversation.conversation_id = message.conversation_id
             LEFT JOIN artifacts AS artifact ON artifact.artifact_id = message.artifact_id
             LEFT JOIN agent_runs AS run ON run.run_id = message.run_id
             WHERE (message.artifact_id IS NOT NULL AND (
                       artifact.artifact_id IS NULL
                       OR (
                           artifact.conversation_id IS NOT NULL
                           AND artifact.conversation_id != message.conversation_id
                       )
                       OR (
                           conversation.project_id IS NOT NULL
                           AND artifact.project_id IS NOT NULL
                           AND artifact.project_id != conversation.project_id
                       )
                   ))
                OR (message.run_id IS NOT NULL AND (
                       run.run_id IS NULL OR run.conversation_id != message.conversation_id
                   ))
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_message_scope {
        return Err(user_schema_migration_error(
            "message artifact and run references must remain in conversation scope".to_owned(),
        ));
    }

    let invalid_run_scope: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM agent_runs AS run
             LEFT JOIN messages AS user_message
               ON user_message.message_id = run.user_message_id
              AND user_message.conversation_id = run.conversation_id
             LEFT JOIN messages AS assistant_message
               ON assistant_message.message_id = run.assistant_message_id
              AND assistant_message.conversation_id = run.conversation_id
             WHERE user_message.message_id IS NULL
                OR (run.assistant_message_id IS NOT NULL AND assistant_message.message_id IS NULL)
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_run_scope {
        return Err(user_schema_migration_error(
            "agent run messages must remain in conversation scope".to_owned(),
        ));
    }

    let invalid_attachment_scope: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM message_attachments AS link
             JOIN messages AS message ON message.message_id = link.message_id
             JOIN conversations AS conversation
               ON conversation.conversation_id = message.conversation_id
             JOIN attachments AS attachment ON attachment.attachment_id = link.attachment_id
             WHERE attachment.project_id IS NOT NULL
               AND attachment.project_id IS NOT conversation.project_id
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_attachment_scope {
        return Err(user_schema_migration_error(
            "message attachments must match conversation project ownership".to_owned(),
        ));
    }

    let invalid_proposal_scope: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM case_change_proposals AS proposal
             LEFT JOIN conversations AS conversation
               ON conversation.conversation_id = proposal.conversation_id
              AND conversation.project_id = proposal.project_id
             LEFT JOIN agent_runs AS run
               ON run.run_id = proposal.run_id
              AND run.conversation_id = proposal.conversation_id
             WHERE conversation.conversation_id IS NULL
                OR (proposal.run_id IS NOT NULL AND run.run_id IS NULL)
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_proposal_scope {
        return Err(user_schema_migration_error(
            "case proposals must match conversation, project, and run ownership".to_owned(),
        ));
    }

    let invalid_answer_scope: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM legal_answer_records AS answer
             LEFT JOIN conversations AS conversation
               ON conversation.conversation_id = answer.conversation_id
             WHERE answer.conversation_id IS NOT NULL
               AND (
                   conversation.conversation_id IS NULL
                   OR conversation.project_id IS NOT answer.project_id
               )
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_answer_scope {
        return Err(user_schema_migration_error(
            "legal answer project must match its conversation".to_owned(),
        ));
    }

    validate_case_assistant_pending_output_relations(connection)?;

    Ok(())
}

fn validate_case_assistant_pending_output_relations(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<()> {
    validate_case_assistant_closed_audit_contracts(connection)?;
    let invalid_scope: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM case_assistant_pending_outputs AS output
             LEFT JOIN retired_case_project_ids AS retired
               ON retired.project_id = output.project_id
             WHERE NOT (
                 (
                     retired.project_id IS NULL
                     AND EXISTS (
                         SELECT 1 FROM projects
                         WHERE project_id = output.project_id
                     )
                     AND EXISTS (
                         SELECT 1
                         FROM conversations AS conversation
                         JOIN agent_runs AS run
                           ON run.run_id = output.run_id
                          AND run.conversation_id = conversation.conversation_id
                         JOIN tool_calls AS tool_call
                           ON tool_call.run_id = run.run_id
                          AND tool_call.ordinal = 0
                          AND tool_call.capability_name = 'assistant.case_work'
                          AND tool_call.status = 'succeeded'
                          AND tool_call.access_mode = 'write'
                          AND tool_call.requires_confirmation = 0
                          AND tool_call.error_type IS NULL
                          AND tool_call.finished_at IS NOT NULL
                         JOIN messages AS user_message
                           ON user_message.message_id = run.user_message_id
                          AND user_message.conversation_id =
                              conversation.conversation_id
                          AND user_message.role = 'user'
                          AND user_message.kind = 'text'
                          AND user_message.artifact_id IS NULL
                          AND user_message.run_id IS NULL
                         JOIN messages AS message
                           ON message.message_id = output.assistant_message_id
                          AND message.conversation_id = conversation.conversation_id
                          AND message.run_id = run.run_id
                          AND message.role = 'assistant'
                          AND message.kind = 'text'
                          AND message.artifact_id IS NULL
                          AND message.text_summary = output.output_preview
                         WHERE conversation.conversation_id = output.conversation_id
                           AND conversation.project_id = output.project_id
                           AND conversation.scope = 'case_work'
                           AND run.assistant_message_id =
                               output.assistant_message_id
                           AND run.intent = 'interactive_case_work'
                           AND run.status = 'succeeded'
                           AND run.error_type IS NULL
                           AND run.finished_at IS NOT NULL
                           AND NOT EXISTS (
                               SELECT 1
                               FROM tool_calls AS other_tool_call
                               WHERE other_tool_call.run_id = run.run_id
                                 AND other_tool_call.tool_call_id
                                     <> tool_call.tool_call_id
                           )
                           AND NOT EXISTS (
                               SELECT 1
                               FROM message_attachments AS attachment
                               WHERE attachment.message_id IN (
                                   run.user_message_id,
                                   output.assistant_message_id
                               )
                           )
                     )
                     AND (
                         (
                             output.status = 'pending'
                             AND output.row_version = 1
                         )
                         OR (
                             output.status = 'confirmed'
                             AND output.row_version = 2
                             AND (
                                 (
                                     output.output_kind = 'case_analysis'
                                     AND EXISTS (
                                         SELECT 1
                                         FROM case_change_proposals AS proposal
                                         WHERE proposal.proposal_id =
                                                   output.confirmed_proposal_id
                                           AND proposal.project_id = output.project_id
                                           AND proposal.conversation_id =
                                                   output.conversation_id
                                           AND proposal.run_id = output.run_id
                                           AND proposal.status = 'applied'
                                           AND proposal.base_case_digest =
                                               output.workspace_base_digest
                                            AND json(proposal.changes_json) =
                                                json(json_extract(
                                                    output.output_payload_json,
                                                    '$.content'
                                                ))
                                            AND proposal.source_refs_json =
                                                output.expected_proposal_source_refs_json
                                            AND NOT EXISTS (
                                               SELECT 1
                                               FROM json_each(
                                                   proposal.source_refs_json
                                               ) AS source
                                               WHERE source.type <> 'text'
                                                  OR length(source.value) = 0
                                           )
                                           AND NOT EXISTS (
                                               SELECT 1
                                               FROM json_each(
                                                   proposal.source_refs_json
                                               ) AS current
                                               JOIN json_each(
                                                   proposal.source_refs_json
                                               ) AS previous
                                                 ON CAST(previous.key AS INTEGER) =
                                                    CAST(current.key AS INTEGER) - 1
                                               WHERE CAST(
                                                   previous.value AS TEXT
                                               ) >= CAST(current.value AS TEXT)
                                           )
                                           AND NOT EXISTS (
                                               SELECT 1
                                               FROM json_tree(
                                                   proposal.changes_json
                                               ) AS referenced
                                               LEFT JOIN json_tree(
                                                   proposal.changes_json
                                               ) AS container
                                                 ON container.id =
                                                    referenced.parent
                                               WHERE (
                                                       referenced.key =
                                                           'sourceRef'
                                                       OR referenced.key IN (
                                                           'attachmentId',
                                                           'artifactId'
                                                       )
                                                       OR (
                                                           container.key =
                                                               'sourceRefs'
                                                           AND container.type =
                                                               'array'
                                                       )
                                                     )
                                                 AND referenced.type = 'text'
                                                 AND NOT EXISTS (
                                                     SELECT 1
                                                     FROM json_each(
                                                         proposal.source_refs_json
                                                     ) AS canonical_source
                                                     WHERE canonical_source.value =
                                                           referenced.value
                                                 )
                                           )
                                     )
                                 )
                                 OR (
                                     output.output_kind IN (
                                         'case_document',
                                         'case_diagram'
                                     )
                                     AND EXISTS (
                                         SELECT 1
                                         FROM artifacts AS artifact
                                         JOIN artifact_versions AS version
                                           ON version.artifact_id =
                                              artifact.artifact_id
                                          AND version.version_number = 1
                                         JOIN agent_runs AS confirmed_run
                                           ON confirmed_run.run_id =
                                              output.run_id
                                         WHERE artifact.artifact_id =
                                                   output.confirmed_artifact_id
                                           AND artifact.project_id = output.project_id
                                           AND artifact.conversation_id =
                                                   output.conversation_id
                                           AND artifact.status <> 'archived'
                                           AND artifact.kind =
                                               CASE output.output_kind
                                                   WHEN 'case_document' THEN 'document'
                                                   WHEN 'case_diagram' THEN 'map'
                                               END
                                           AND version.rendered_text =
                                               output.output_preview
                                           AND json(version.content_json) =
                                               json(json_extract(
                                                   output.output_payload_json,
                                                   '$.content'
                                               ))
                                           AND json(
                                               version.provider_snapshot_json
                                           ) = json(
                                               confirmed_run.provider_snapshot_json
                                           )
                                     )
                                 )
                             )
                         )
                     )
                 )
                 OR (
                     retired.project_id IS NOT NULL
                     AND NOT EXISTS (
                         SELECT 1 FROM projects
                         WHERE project_id = output.project_id
                     )
                     AND (
                         (output.status = 'pending' AND output.row_version = 1)
                         OR (output.status = 'confirmed' AND output.row_version = 2)
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM conversations
                         WHERE conversation_id = output.conversation_id
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM agent_runs
                         WHERE run_id = output.run_id
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM tool_calls
                         WHERE run_id = output.run_id
                     )
                     AND NOT EXISTS (
                         SELECT 1 FROM messages
                         WHERE message_id = output.assistant_message_id
                     )
                     AND (
                         output.confirmed_artifact_id IS NULL
                         OR NOT EXISTS (
                             SELECT 1 FROM artifacts
                             WHERE artifact_id = output.confirmed_artifact_id
                         )
                     )
                     AND (
                         output.confirmed_proposal_id IS NULL
                         OR NOT EXISTS (
                             SELECT 1 FROM case_change_proposals
                             WHERE proposal_id = output.confirmed_proposal_id
                         )
                     )
                 )
             )
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid_scope {
        return Err(user_schema_migration_error(
            "case assistant pending output lineage is outside its case-work scope".to_owned(),
        ));
    }

    let mut statement = connection.prepare(
        "SELECT
             pending_output_id, project_id, conversation_id, run_id,
             assistant_message_id, project_binding_sha256, source_snapshots_json,
             source_snapshots_sha256, expected_proposal_source_refs_json,
             expected_proposal_source_refs_sha256, output_kind, output_payload_json,
             output_preview, output_sha256, output_version, workspace_base_digest, status,
             confirmed_artifact_id, confirmed_proposal_id, confirmation_request_sha256,
             row_version, created_at, confirmed_at
         FROM case_assistant_pending_outputs
         ORDER BY pending_output_id",
    )?;
    let outputs = statement
        .query_map([], case_assistant_pending_output_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for output in outputs {
        if !is_lower_hex_sha256(&output.project_binding_sha256)
            || !is_lower_hex_sha256(&output.workspace_base_digest)
            || output.output_version < 1
            || output.output_preview.len() > MAX_CASE_ASSISTANT_OUTPUT_PREVIEW_BYTES
            || output.output_preview.contains('\0')
            || output
                .confirmation_request_sha256
                .as_deref()
                .is_some_and(|hash| !is_lower_hex_sha256(hash))
        {
            return Err(user_schema_migration_error(
                "case assistant pending output contains invalid bounded metadata".to_owned(),
            ));
        }
        validate_case_assistant_source_snapshots_json(
            &output.source_snapshots_json,
            &output.source_snapshots_sha256,
        )?;
        validate_case_assistant_expected_proposal_source_refs(
            &output.output_kind,
            &output.expected_proposal_source_refs_json,
            &output.expected_proposal_source_refs_sha256,
        )?;
        validate_case_assistant_output_payload_json(
            &output.output_kind,
            &output.output_payload_json,
            &output.output_sha256,
        )?;
    }
    Ok(())
}

fn validate_case_assistant_closed_audit_contracts(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<()> {
    let mut run_statement = connection.prepare(
        "SELECT provider_snapshot_json
         FROM agent_runs
         WHERE intent = 'interactive_case_work'",
    )?;
    let provider_snapshots = run_statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for provider_snapshot in provider_snapshots {
        validate_provider_audit_snapshot_json(&provider_snapshot)?;
    }

    let mut tool_statement = connection.prepare(
        "SELECT
             tool.tool_call_id, tool.run_id, tool.ordinal, tool.capability_name,
             tool.status, tool.access_mode, tool.requires_confirmation,
             tool.input_audit_json, tool.output_audit_json, tool.source_audit_json,
             tool.error_type, tool.started_at, tool.finished_at
         FROM tool_calls AS tool
         WHERE tool.capability_name = 'assistant.case_work'",
    )?;
    let tool_calls = tool_statement
        .query_map([], tool_call_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for tool_call in tool_calls {
        let run = get_agent_run(connection, &tool_call.run_id)?.ok_or_else(|| {
            user_schema_migration_error("case assistant tool audit is missing its run".to_owned())
        })?;
        validate_case_assistant_tool_audit_contract(
            &tool_call.run_id,
            &run.provider_snapshot_json,
            &tool_call.status,
            &tool_call.input_audit_json,
            &tool_call.output_audit_json,
            &tool_call.source_audit_json,
            tool_call.error_type.as_deref(),
        )?;
    }

    let mut output_statement = connection.prepare(
        "SELECT
             output.pending_output_id, output.project_id, output.conversation_id,
             output.run_id, output.assistant_message_id,
             output.project_binding_sha256, output.source_snapshots_json,
             output.source_snapshots_sha256,
             output.expected_proposal_source_refs_json,
             output.expected_proposal_source_refs_sha256, output.output_kind,
             output.output_payload_json, output.output_preview, output.output_sha256,
             output.output_version, output.workspace_base_digest, output.status,
             output.confirmed_artifact_id, output.confirmed_proposal_id,
             output.confirmation_request_sha256, output.row_version,
             output.created_at, output.confirmed_at
         FROM case_assistant_pending_outputs AS output
         LEFT JOIN retired_case_project_ids AS retired
           ON retired.project_id = output.project_id
         WHERE retired.project_id IS NULL",
    )?;
    let outputs = output_statement
        .query_map([], case_assistant_pending_output_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for output in outputs {
        validate_case_assistant_pending_output_audit_contract(
            connection,
            &NewCaseAssistantPendingOutputRow {
                pending_output_id: output.pending_output_id,
                project_id: output.project_id,
                conversation_id: output.conversation_id,
                run_id: output.run_id,
                assistant_message_id: output.assistant_message_id,
                project_binding_sha256: output.project_binding_sha256,
                source_snapshots_json: output.source_snapshots_json,
                source_snapshots_sha256: output.source_snapshots_sha256,
                expected_proposal_source_refs_json: output.expected_proposal_source_refs_json,
                expected_proposal_source_refs_sha256: output.expected_proposal_source_refs_sha256,
                output_kind: output.output_kind,
                output_payload_json: output.output_payload_json,
                output_preview: output.output_preview,
                output_sha256: output.output_sha256,
                output_version: output.output_version,
                workspace_base_digest: output.workspace_base_digest,
            },
        )?;
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
    validate_assistant_scoped_relations(connection)?;
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

fn user_internal_schema_objects(
    connection: &rusqlite::Connection,
) -> Result<Vec<UserSchemaObject>, DatabaseInitError> {
    let mut statement = connection.prepare(
        "
        SELECT type, name, tbl_name, COALESCE(sql, '')
        FROM sqlite_master
        WHERE type IN ('table', 'index', 'trigger', 'view')
          AND name LIKE 'sqlite_%'
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
    // in a separate empty database. Application objects and SQLite-owned
    // autoindexes are compared separately so ANALYZE/sqlite_stat* or any other
    // unexpected internal object cannot hide behind a blanket sqlite_% filter.
    let mut canonical = rusqlite::Connection::open_in_memory()?;
    configure_user_database_connection(&canonical)?;
    run_user_migrations(&mut canonical)?;

    if user_schema_objects(connection)? != user_schema_objects(&canonical)?
        || user_internal_schema_objects(connection)? != user_internal_schema_objects(&canonical)?
    {
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

fn install_case_assistant_closed_audit_triggers(
    transaction: &rusqlite::Transaction<'_>,
) -> rusqlite::Result<()> {
    const PROVIDER_AUDIT_INVALID_SQL: &str = r#"
        length(CAST(NEW.provider_snapshot_json AS BLOB)) > 65536
        OR NOT json_valid(NEW.provider_snapshot_json)
        OR json_type(NEW.provider_snapshot_json) <> 'object'
        OR json(NEW.provider_snapshot_json) <> NEW.provider_snapshot_json
        OR json_remove(
               NEW.provider_snapshot_json,
               '$.kind', '$.modelId', '$.baseUrl',
               '$.capabilities', '$.options'
           ) <> '{}'
        OR COALESCE(json_type(NEW.provider_snapshot_json, '$.kind') <> 'text', 1)
        OR json_extract(NEW.provider_snapshot_json, '$.kind') NOT IN (
               'silicon_flow', 'volcengine_ark', 'deep_seek', 'qwen', 'custom'
           )
        OR COALESCE(json_type(NEW.provider_snapshot_json, '$.modelId') <> 'text', 1)
        OR length(CAST(json_extract(
               NEW.provider_snapshot_json, '$.modelId'
           ) AS BLOB)) NOT BETWEEN 1 AND 512
        OR instr(json_extract(NEW.provider_snapshot_json, '$.modelId'), char(0)) > 0
        OR instr(json_extract(NEW.provider_snapshot_json, '$.modelId'), char(10)) > 0
        OR instr(json_extract(NEW.provider_snapshot_json, '$.modelId'), char(13)) > 0
        OR COALESCE(json_type(NEW.provider_snapshot_json, '$.baseUrl') <> 'text', 1)
        OR length(CAST(json_extract(
               NEW.provider_snapshot_json, '$.baseUrl'
           ) AS BLOB)) NOT BETWEEN 1 AND 2048
        OR instr(json_extract(NEW.provider_snapshot_json, '$.baseUrl'), char(0)) > 0
        OR instr(json_extract(NEW.provider_snapshot_json, '$.baseUrl'), char(10)) > 0
        OR instr(json_extract(NEW.provider_snapshot_json, '$.baseUrl'), char(13)) > 0
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.capabilities') <> 'object',
               1
           )
        OR json_remove(
               json_extract(NEW.provider_snapshot_json, '$.capabilities'),
               '$.chat', '$.streaming', '$.customModelId',
               '$.customBaseUrl', '$.reasoning'
           ) <> '{}'
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.capabilities.chat')
                   NOT IN ('true', 'false'),
               1
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.capabilities.streaming')
                   NOT IN ('true', 'false'),
               1
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.capabilities.customModelId')
                   NOT IN ('true', 'false'),
               1
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.capabilities.customBaseUrl')
                   NOT IN ('true', 'false'),
               1
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.capabilities.reasoning')
                   NOT IN ('true', 'false'),
               1
           )
        OR COALESCE(json_type(NEW.provider_snapshot_json, '$.options') <> 'object', 1)
        OR json_remove(
               json_extract(NEW.provider_snapshot_json, '$.options'),
               '$.thinking', '$.enableThinking', '$.thinkingBudget',
               '$.reasoningEffort', '$.endpointId', '$.workspaceId',
               '$.allowPrivateNetwork'
           ) <> '{}'
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.options.thinking')
                   NOT IN ('null', 'true', 'false'),
               1
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.options.enableThinking')
                   NOT IN ('null', 'true', 'false'),
               1
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.options.thinkingBudget')
                   NOT IN ('null', 'integer'),
               1
           )
        OR (
               json_type(NEW.provider_snapshot_json, '$.options.thinkingBudget') = 'integer'
               AND (
                   json_extract(
                       NEW.provider_snapshot_json, '$.options.thinkingBudget'
                   ) < 0
                   OR json_extract(
                       NEW.provider_snapshot_json, '$.options.thinkingBudget'
                   ) > 4294967295
               )
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.options.reasoningEffort')
                   NOT IN ('null', 'text'),
               1
           )
        OR (
               json_type(NEW.provider_snapshot_json, '$.options.reasoningEffort') = 'text'
               AND json_extract(
                   NEW.provider_snapshot_json, '$.options.reasoningEffort'
               ) NOT IN ('low', 'medium', 'high', 'max')
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.options.endpointId')
                   NOT IN ('null', 'text'),
               1
           )
        OR (
               json_type(NEW.provider_snapshot_json, '$.options.endpointId') = 'text'
               AND length(CAST(json_extract(
                   NEW.provider_snapshot_json, '$.options.endpointId'
               ) AS BLOB)) NOT BETWEEN 1 AND 512
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.options.workspaceId')
                   NOT IN ('null', 'text'),
               1
           )
        OR (
               json_type(NEW.provider_snapshot_json, '$.options.workspaceId') = 'text'
               AND length(CAST(json_extract(
                   NEW.provider_snapshot_json, '$.options.workspaceId'
               ) AS BLOB)) NOT BETWEEN 1 AND 512
           )
        OR COALESCE(
               json_type(NEW.provider_snapshot_json, '$.options.allowPrivateNetwork')
                   NOT IN ('null', 'true', 'false'),
               1
           )
    "#;
    for (name, event) in [
        ("trg_case_assistant_run_provider_audit_insert", "INSERT"),
        ("trg_case_assistant_run_provider_audit_update", "UPDATE"),
    ] {
        transaction.execute_batch(&format!(
            "CREATE TRIGGER IF NOT EXISTS {name}
             BEFORE {event} ON agent_runs
             WHEN NEW.intent = 'interactive_case_work'
              AND ({PROVIDER_AUDIT_INVALID_SQL})
             BEGIN
                 SELECT RAISE(
                     ABORT,
                     'case assistant provider audit must use the fixed no-credential schema'
                 );
             END;"
        ))?;
    }

    const TOOL_AUDIT_INVALID_SQL: &str = r#"
        length(CAST(NEW.input_audit_json AS BLOB)) > 65536
        OR length(CAST(NEW.output_audit_json AS BLOB)) > 65536
        OR length(CAST(NEW.source_audit_json AS BLOB)) > 65536
        OR NOT json_valid(NEW.input_audit_json)
        OR json_type(NEW.input_audit_json) <> 'object'
        OR json(NEW.input_audit_json) <> NEW.input_audit_json
        OR json_remove(
               NEW.input_audit_json,
               '$.requestId', '$.runId', '$.capability', '$.classification',
               '$.inputIds', '$.inputHashes', '$.inputCounts',
               '$.providerSnapshot', '$.confirmation', '$.status'
           ) <> '{}'
        OR EXISTS (
               SELECT 1
               FROM (
                   SELECT '$.requestId' AS path, 'text' AS expected_type
                   UNION ALL SELECT '$.runId', 'text'
                   UNION ALL SELECT '$.capability', 'text'
                   UNION ALL SELECT '$.classification', 'text'
                   UNION ALL SELECT '$.inputIds', 'object'
                   UNION ALL SELECT '$.inputIds.projectId', 'text'
                   UNION ALL SELECT '$.inputIds.conversationId', 'text'
                   UNION ALL SELECT '$.inputIds.redactionGenerationIds', 'array'
                   UNION ALL SELECT '$.inputHashes', 'object'
                   UNION ALL SELECT '$.inputHashes.promptSha256', 'text'
                   UNION ALL SELECT '$.inputHashes.historySha256', 'text'
                   UNION ALL SELECT '$.inputHashes.minimalContextSha256', 'text'
                   UNION ALL SELECT '$.inputHashes.generationSetSha256', 'text'
                   UNION ALL SELECT '$.inputHashes.workspaceDigest', 'text'
                   UNION ALL SELECT '$.inputCounts', 'object'
                   UNION ALL SELECT '$.inputCounts.promptBytes', 'integer'
                   UNION ALL SELECT '$.inputCounts.historyMessages', 'integer'
                   UNION ALL SELECT '$.inputCounts.historyBytes', 'integer'
                   UNION ALL SELECT '$.inputCounts.generationCount', 'integer'
                   UNION ALL SELECT '$.inputCounts.knownBodyBytes', 'integer'
                   UNION ALL SELECT '$.providerSnapshot', 'object'
                   UNION ALL SELECT '$.confirmation', 'object'
                   UNION ALL SELECT '$.confirmation.writebackRequired', 'true'
                   UNION ALL SELECT '$.confirmation.received', 'false'
                   UNION ALL SELECT '$.status', 'text'
               ) AS required
               WHERE COALESCE(
                   json_type(NEW.input_audit_json, required.path)
                       <> required.expected_type,
                   1
               )
           )
        OR COALESCE(json_type(NEW.input_audit_json, '$.requestId') <> 'text', 1)
        OR json_extract(NEW.input_audit_json, '$.requestId') <> NEW.run_id
        OR COALESCE(json_type(NEW.input_audit_json, '$.runId') <> 'text', 1)
        OR json_extract(NEW.input_audit_json, '$.runId') <> NEW.run_id
        OR json_extract(NEW.input_audit_json, '$.capability') <> 'assistant.case_work'
        OR json_extract(
               NEW.input_audit_json, '$.classification'
           ) <> 'case_redacted_approved'
        OR json_extract(NEW.input_audit_json, '$.status') <> 'running'
        OR COALESCE(json_type(NEW.input_audit_json, '$.inputIds') <> 'object', 1)
        OR json_remove(
               json_extract(NEW.input_audit_json, '$.inputIds'),
               '$.projectId', '$.conversationId', '$.redactionGenerationIds'
           ) <> '{}'
        OR COALESCE(
               json_type(NEW.input_audit_json, '$.inputIds.projectId') <> 'text',
               1
           )
        OR length(CAST(json_extract(
               NEW.input_audit_json, '$.inputIds.projectId'
           ) AS BLOB)) NOT BETWEEN 1 AND 128
        OR instr(json_extract(
               NEW.input_audit_json, '$.inputIds.projectId'
           ), '/') > 0
        OR instr(json_extract(
               NEW.input_audit_json, '$.inputIds.projectId'
           ), char(92)) > 0
        OR COALESCE(
               json_type(NEW.input_audit_json, '$.inputIds.conversationId') <> 'text',
               1
           )
        OR length(CAST(json_extract(
               NEW.input_audit_json, '$.inputIds.conversationId'
           ) AS BLOB)) NOT BETWEEN 1 AND 128
        OR instr(json_extract(
               NEW.input_audit_json, '$.inputIds.conversationId'
           ), '/') > 0
        OR instr(json_extract(
               NEW.input_audit_json, '$.inputIds.conversationId'
           ), char(92)) > 0
        OR COALESCE(
               json_type(
                   NEW.input_audit_json,
                   '$.inputIds.redactionGenerationIds'
               ) <> 'array',
               1
           )
        OR json_array_length(
               NEW.input_audit_json,
               '$.inputIds.redactionGenerationIds'
           ) NOT BETWEEN 1 AND 16
        OR EXISTS (
               SELECT 1
               FROM json_each(
                   NEW.input_audit_json,
                   '$.inputIds.redactionGenerationIds'
               ) AS identifier
               WHERE identifier.type <> 'text'
                  OR length(CAST(identifier.value AS BLOB)) NOT BETWEEN 1 AND 128
                  OR instr(CAST(identifier.value AS TEXT), '/') > 0
                  OR instr(CAST(identifier.value AS TEXT), char(92)) > 0
                  OR instr(CAST(identifier.value AS TEXT), char(0)) > 0
           )
        OR EXISTS (
               SELECT 1
               FROM json_each(
                   NEW.input_audit_json,
                   '$.inputIds.redactionGenerationIds'
               ) AS current
               JOIN json_each(
                   NEW.input_audit_json,
                   '$.inputIds.redactionGenerationIds'
               ) AS previous
                 ON CAST(previous.key AS INTEGER) =
                    CAST(current.key AS INTEGER) - 1
               WHERE CAST(previous.value AS TEXT) >= CAST(current.value AS TEXT)
           )
        OR COALESCE(
               json_type(NEW.input_audit_json, '$.inputHashes') <> 'object',
               1
           )
        OR json_remove(
               json_extract(NEW.input_audit_json, '$.inputHashes'),
               '$.promptSha256', '$.historySha256', '$.minimalContextSha256',
               '$.generationSetSha256', '$.workspaceDigest'
           ) <> '{}'
        OR EXISTS (
               SELECT 1
               FROM json_each(NEW.input_audit_json, '$.inputHashes') AS hash
               WHERE hash.type <> 'text'
                  OR length(CAST(hash.value AS TEXT)) <> 64
                  OR CAST(hash.value AS TEXT) GLOB '*[^0-9a-f]*'
           )
        OR COALESCE(
               json_type(NEW.input_audit_json, '$.inputCounts') <> 'object',
               1
           )
        OR json_remove(
               json_extract(NEW.input_audit_json, '$.inputCounts'),
               '$.promptBytes', '$.historyMessages', '$.historyBytes',
               '$.generationCount', '$.knownBodyBytes'
           ) <> '{}'
        OR EXISTS (
               SELECT 1
               FROM json_each(NEW.input_audit_json, '$.inputCounts') AS count
               WHERE count.type <> 'integer'
                  OR CAST(count.value AS INTEGER) < 0
                  OR CAST(count.value AS INTEGER) > 16777216
           )
        OR json_extract(
               NEW.input_audit_json, '$.inputCounts.generationCount'
           ) <> json_array_length(
               NEW.input_audit_json,
               '$.inputIds.redactionGenerationIds'
           )
        OR COALESCE(
               json_type(NEW.input_audit_json, '$.providerSnapshot') <> 'object',
               1
           )
        OR EXISTS (
               SELECT fullkey, type, atom
               FROM json_tree(json_extract(
                   NEW.input_audit_json, '$.providerSnapshot'
               ))
               EXCEPT
               SELECT fullkey, type, atom
               FROM json_tree((
                   SELECT run.provider_snapshot_json
                   FROM agent_runs AS run
                   WHERE run.run_id = NEW.run_id
               ))
           )
        OR EXISTS (
               SELECT fullkey, type, atom
               FROM json_tree((
                   SELECT run.provider_snapshot_json
                   FROM agent_runs AS run
                   WHERE run.run_id = NEW.run_id
               ))
               EXCEPT
               SELECT fullkey, type, atom
               FROM json_tree(json_extract(
                   NEW.input_audit_json, '$.providerSnapshot'
               ))
           )
        OR COALESCE(
               json_type(NEW.input_audit_json, '$.confirmation') <> 'object',
               1
           )
        OR json_remove(
               json_extract(NEW.input_audit_json, '$.confirmation'),
               '$.writebackRequired', '$.received'
           ) <> '{}'
        OR json_type(
               NEW.input_audit_json, '$.confirmation.writebackRequired'
           ) <> 'true'
        OR json_type(
               NEW.input_audit_json, '$.confirmation.received'
           ) <> 'false'
        OR NOT COALESCE((
            (
                NEW.status = 'running'
                AND NEW.output_audit_json = '{}'
                AND NEW.source_audit_json = '{}'
                AND NEW.error_type IS NULL
            )
            OR
            (
                NEW.status = 'succeeded'
                AND NEW.error_type IS NULL
                AND json_valid(NEW.output_audit_json)
                AND json_type(NEW.output_audit_json) = 'object'
                AND json(NEW.output_audit_json) = NEW.output_audit_json
                AND json_remove(
                    NEW.output_audit_json,
                    '$.outputIds', '$.outputHashes', '$.outputCounts',
                    '$.status', '$.confirmation'
                ) = '{}'
                AND NOT EXISTS (
                    SELECT 1
                    FROM (
                        SELECT '$.outputIds' AS path, 'object' AS expected_type
                        UNION ALL SELECT '$.outputIds.pendingOutputKind', 'text'
                        UNION ALL SELECT '$.outputHashes', 'object'
                        UNION ALL SELECT '$.outputHashes.providerOutputSha256', 'text'
                        UNION ALL SELECT '$.outputHashes.typedOutputSha256', 'text'
                        UNION ALL SELECT '$.outputHashes.approvedEnvelopeSha256', 'text'
                        UNION ALL SELECT '$.outputHashes.proposalSourceRefsSha256', 'text'
                        UNION ALL SELECT '$.outputCounts', 'object'
                        UNION ALL SELECT '$.outputCounts.approvedEnvelopeBytes', 'integer'
                        UNION ALL SELECT '$.outputCounts.bytes', 'integer'
                        UNION ALL SELECT '$.outputCounts.items', 'integer'
                        UNION ALL SELECT '$.status', 'text'
                        UNION ALL SELECT '$.confirmation', 'object'
                        UNION ALL SELECT '$.confirmation.writebackRequired', 'true'
                        UNION ALL SELECT '$.confirmation.received', 'false'
                    ) AS required
                    WHERE COALESCE(
                        json_type(NEW.output_audit_json, required.path)
                            <> required.expected_type,
                        1
                    )
                )
                AND json_extract(
                    NEW.output_audit_json, '$.status'
                ) = 'succeeded'
                AND json_remove(
                    json_extract(NEW.output_audit_json, '$.outputIds'),
                    '$.pendingOutputKind'
                ) = '{}'
                AND json_extract(
                    NEW.output_audit_json, '$.outputIds.pendingOutputKind'
                ) IN ('case_analysis', 'case_document', 'case_diagram')
                AND json_remove(
                    json_extract(NEW.output_audit_json, '$.outputHashes'),
                    '$.providerOutputSha256', '$.typedOutputSha256',
                    '$.approvedEnvelopeSha256',
                    '$.proposalSourceRefsSha256'
                ) = '{}'
                AND NOT EXISTS (
                    SELECT 1
                    FROM json_each(
                        NEW.output_audit_json, '$.outputHashes'
                    ) AS hash
                    WHERE hash.type <> 'text'
                       OR length(CAST(hash.value AS TEXT)) <> 64
                       OR CAST(hash.value AS TEXT) GLOB '*[^0-9a-f]*'
                )
                AND json_remove(
                    json_extract(NEW.output_audit_json, '$.outputCounts'),
                    '$.approvedEnvelopeBytes', '$.bytes', '$.items'
                ) = '{}'
                AND NOT EXISTS (
                    SELECT 1
                    FROM json_each(
                        NEW.output_audit_json, '$.outputCounts'
                    ) AS count
                    WHERE count.type <> 'integer'
                       OR CAST(count.value AS INTEGER) < 0
                       OR CAST(count.value AS INTEGER) > 16777216
                )
                AND json_extract(
                    NEW.output_audit_json, '$.outputCounts.items'
                ) = 1
                AND json_remove(
                    json_extract(NEW.output_audit_json, '$.confirmation'),
                    '$.writebackRequired', '$.received'
                ) = '{}'
                AND json_type(
                    NEW.output_audit_json,
                    '$.confirmation.writebackRequired'
                ) = 'true'
                AND json_type(
                    NEW.output_audit_json,
                    '$.confirmation.received'
                ) = 'false'
                AND json_valid(NEW.source_audit_json)
                AND json_type(NEW.source_audit_json) = 'object'
                AND json(NEW.source_audit_json) = NEW.source_audit_json
                AND json_remove(
                    NEW.source_audit_json,
                    '$.classification', '$.sourceRefs', '$.inputHashes',
                    '$.providerSnapshot', '$.confirmation'
                ) = '{}'
                AND NOT EXISTS (
                    SELECT 1
                    FROM (
                        SELECT '$.classification' AS path, 'text' AS expected_type
                        UNION ALL SELECT '$.sourceRefs', 'array'
                        UNION ALL SELECT '$.inputHashes', 'object'
                        UNION ALL SELECT '$.inputHashes.projectBindingSha256', 'text'
                        UNION ALL SELECT '$.inputHashes.sourceSnapshotsSha256', 'text'
                        UNION ALL SELECT '$.inputHashes.aggregateSourceSha256', 'text'
                        UNION ALL SELECT '$.inputHashes.aggregateExtractionSha256', 'text'
                        UNION ALL SELECT '$.inputHashes.aggregateRedactedContentSha256', 'text'
                        UNION ALL SELECT '$.providerSnapshot', 'object'
                        UNION ALL SELECT '$.confirmation', 'object'
                        UNION ALL SELECT '$.confirmation.writebackRequired', 'true'
                        UNION ALL SELECT '$.confirmation.received', 'false'
                    ) AS required
                    WHERE COALESCE(
                        json_type(NEW.source_audit_json, required.path)
                            <> required.expected_type,
                        1
                    )
                )
                AND json_extract(
                    NEW.source_audit_json, '$.classification'
                ) = 'case_redacted_approved'
                AND json_type(
                    NEW.source_audit_json, '$.sourceRefs'
                ) = 'array'
                AND json_array_length(
                    NEW.source_audit_json, '$.sourceRefs'
                ) BETWEEN 1 AND 16
                AND NOT EXISTS (
                    SELECT 1
                    FROM json_each(
                        NEW.source_audit_json, '$.sourceRefs'
                    ) AS identifier
                    WHERE identifier.type <> 'text'
                       OR length(CAST(identifier.value AS BLOB))
                          NOT BETWEEN 1 AND 128
                       OR instr(CAST(identifier.value AS TEXT), '/') > 0
                       OR instr(CAST(identifier.value AS TEXT), char(92)) > 0
                       OR instr(CAST(identifier.value AS TEXT), char(0)) > 0
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM json_each(
                        NEW.source_audit_json, '$.sourceRefs'
                    ) AS current
                    JOIN json_each(
                        NEW.source_audit_json, '$.sourceRefs'
                    ) AS previous
                      ON CAST(previous.key AS INTEGER) =
                         CAST(current.key AS INTEGER) - 1
                    WHERE CAST(previous.value AS TEXT) >=
                          CAST(current.value AS TEXT)
                )
                AND json_remove(
                    json_extract(NEW.source_audit_json, '$.inputHashes'),
                    '$.projectBindingSha256', '$.sourceSnapshotsSha256',
                    '$.aggregateSourceSha256', '$.aggregateExtractionSha256',
                    '$.aggregateRedactedContentSha256'
                ) = '{}'
                AND NOT EXISTS (
                    SELECT 1
                    FROM json_each(
                        NEW.source_audit_json, '$.inputHashes'
                    ) AS hash
                    WHERE hash.type <> 'text'
                       OR length(CAST(hash.value AS TEXT)) <> 64
                       OR CAST(hash.value AS TEXT) GLOB '*[^0-9a-f]*'
                )
                AND NOT EXISTS (
                    SELECT fullkey, type, atom
                    FROM json_tree(json_extract(
                        NEW.source_audit_json, '$.providerSnapshot'
                    ))
                    EXCEPT
                    SELECT fullkey, type, atom
                    FROM json_tree((
                        SELECT run.provider_snapshot_json
                        FROM agent_runs AS run
                        WHERE run.run_id = NEW.run_id
                    ))
                )
                AND NOT EXISTS (
                    SELECT fullkey, type, atom
                    FROM json_tree((
                        SELECT run.provider_snapshot_json
                        FROM agent_runs AS run
                        WHERE run.run_id = NEW.run_id
                    ))
                    EXCEPT
                    SELECT fullkey, type, atom
                    FROM json_tree(json_extract(
                        NEW.source_audit_json, '$.providerSnapshot'
                    ))
                )
                AND json_remove(
                    json_extract(NEW.source_audit_json, '$.confirmation'),
                    '$.writebackRequired', '$.received'
                ) = '{}'
                AND json_type(
                    NEW.source_audit_json,
                    '$.confirmation.writebackRequired'
                ) = 'true'
                AND json_type(
                    NEW.source_audit_json,
                    '$.confirmation.received'
                ) = 'false'
            )
            OR
            (
                NEW.status IN ('failed', 'cancelled')
                AND NEW.error_type IS NOT NULL
                AND length(CAST(NEW.error_type AS BLOB)) BETWEEN 1 AND 128
                AND json_valid(NEW.output_audit_json)
                AND json_type(NEW.output_audit_json) = 'object'
                AND json(NEW.output_audit_json) = NEW.output_audit_json
                AND json_remove(
                    NEW.output_audit_json,
                    '$.outputCounts', '$.status', '$.errorType'
                ) = '{}'
                AND NOT EXISTS (
                    SELECT 1
                    FROM (
                        SELECT '$.outputCounts' AS path, 'object' AS expected_type
                        UNION ALL SELECT '$.outputCounts.items', 'integer'
                        UNION ALL SELECT '$.status', 'text'
                        UNION ALL SELECT '$.errorType', 'text'
                    ) AS required
                    WHERE COALESCE(
                        json_type(NEW.output_audit_json, required.path)
                            <> required.expected_type,
                        1
                    )
                )
                AND json_extract(
                    NEW.output_audit_json, '$.status'
                ) = NEW.status
                AND json_extract(
                    NEW.output_audit_json, '$.errorType'
                ) = NEW.error_type
                AND json_remove(
                    json_extract(NEW.output_audit_json, '$.outputCounts'),
                    '$.items'
                ) = '{}'
                AND json_extract(
                    NEW.output_audit_json, '$.outputCounts.items'
                ) = 0
                AND json_valid(NEW.source_audit_json)
                AND json_type(NEW.source_audit_json) = 'object'
                AND json(NEW.source_audit_json) = NEW.source_audit_json
                AND json_remove(
                    NEW.source_audit_json,
                    '$.sourceRefs', '$.providerSnapshot', '$.confirmation'
                ) = '{}'
                AND NOT EXISTS (
                    SELECT 1
                    FROM (
                        SELECT '$.sourceRefs' AS path, 'array' AS expected_type
                        UNION ALL SELECT '$.providerSnapshot', 'object'
                        UNION ALL SELECT '$.confirmation', 'object'
                        UNION ALL SELECT '$.confirmation.received', 'false'
                    ) AS required
                    WHERE COALESCE(
                        json_type(NEW.source_audit_json, required.path)
                            <> required.expected_type,
                        1
                    )
                )
                AND json_type(
                    NEW.source_audit_json, '$.sourceRefs'
                ) = 'array'
                AND json_array_length(
                    NEW.source_audit_json, '$.sourceRefs'
                ) BETWEEN 1 AND 16
                AND NOT EXISTS (
                    SELECT 1
                    FROM json_each(
                        NEW.source_audit_json, '$.sourceRefs'
                    ) AS identifier
                    WHERE identifier.type <> 'text'
                       OR length(CAST(identifier.value AS BLOB))
                          NOT BETWEEN 1 AND 128
                       OR instr(CAST(identifier.value AS TEXT), '/') > 0
                       OR instr(CAST(identifier.value AS TEXT), char(92)) > 0
                       OR instr(CAST(identifier.value AS TEXT), char(0)) > 0
                )
                AND NOT EXISTS (
                    SELECT fullkey, type, atom
                    FROM json_tree(json_extract(
                        NEW.source_audit_json, '$.providerSnapshot'
                    ))
                    EXCEPT
                    SELECT fullkey, type, atom
                    FROM json_tree((
                        SELECT run.provider_snapshot_json
                        FROM agent_runs AS run
                        WHERE run.run_id = NEW.run_id
                    ))
                )
                AND NOT EXISTS (
                    SELECT fullkey, type, atom
                    FROM json_tree((
                        SELECT run.provider_snapshot_json
                        FROM agent_runs AS run
                        WHERE run.run_id = NEW.run_id
                    ))
                    EXCEPT
                    SELECT fullkey, type, atom
                    FROM json_tree(json_extract(
                        NEW.source_audit_json, '$.providerSnapshot'
                    ))
                )
                AND json_remove(
                    json_extract(NEW.source_audit_json, '$.confirmation'),
                    '$.received'
                ) = '{}'
                AND json_type(
                    NEW.source_audit_json, '$.confirmation.received'
                ) = 'false'
            )
        ), 0)
    "#;
    for (name, event) in [
        ("trg_case_assistant_tool_audit_insert", "INSERT"),
        ("trg_case_assistant_tool_audit_update", "UPDATE"),
    ] {
        transaction.execute_batch(&format!(
            "CREATE TRIGGER IF NOT EXISTS {name}
             BEFORE {event} ON tool_calls
             WHEN NEW.capability_name = 'assistant.case_work'
              AND ({TOOL_AUDIT_INVALID_SQL})
             BEGIN
                 SELECT RAISE(
                     ABORT,
                     'case assistant tool audit must use the fixed no-body schema'
                 );
             END;"
        ))?;
    }
    Ok(())
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
        // v9 contains a deliberate message/run cycle. Deferring foreign keys
        // keeps the staged copy deterministic while the final transaction is
        // still proven by foreign_key_check before commit.
        transaction.pragma_update(None, "defer_foreign_keys", "ON")?;
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

        CREATE TABLE IF NOT EXISTS retired_case_project_ids (
            project_id TEXT PRIMARY KEY CHECK (length(project_id) > 0),
            retired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            retirement_reason TEXT NOT NULL CHECK (
                retirement_reason IN (
                    'case_project_deleted',
                    'legacy_migration_cleanup',
                    'privacy_journal_recovery'
                )
            ),
            privacy_deletion_id TEXT UNIQUE,
            CHECK (
                (
                    retirement_reason = 'legacy_migration_cleanup'
                    AND privacy_deletion_id IS NULL
                )
                OR
                (
                    retirement_reason IN (
                        'case_project_deleted',
                        'privacy_journal_recovery'
                    )
                    AND length(privacy_deletion_id) = 37
                    AND substr(privacy_deletion_id,1,5) = 'pdel_'
                    AND substr(privacy_deletion_id,6)
                        NOT GLOB '*[^0-9a-f]*'
                )
            )
        );

        CREATE TRIGGER IF NOT EXISTS trg_retired_case_project_ids_authorized_insert
        BEFORE INSERT ON retired_case_project_ids
        WHEN COALESCE(
            case_retirement_authorized(
                NEW.project_id,
                NEW.retirement_reason,
                NEW.privacy_deletion_id
            ),
            0
        ) <> 1
        BEGIN
            SELECT RAISE(ABORT, 'case project retirement is not authorized');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_retired_case_project_ids_no_update
        BEFORE UPDATE ON retired_case_project_ids
        BEGIN
            SELECT RAISE(ABORT, 'retired case project id is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_retired_case_project_ids_no_delete
        BEFORE DELETE ON retired_case_project_ids
        BEGIN
            SELECT RAISE(ABORT, 'retired case project id is append only');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_projects_reject_retired_id
        BEFORE INSERT ON projects
        WHEN EXISTS (
            SELECT 1 FROM retired_case_project_ids AS retired
            WHERE retired.project_id = NEW.project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'retired case project id cannot be reused');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_projects_require_retirement_before_delete
        BEFORE DELETE ON projects
        WHEN NOT EXISTS (
            SELECT 1 FROM retired_case_project_ids AS retired
            WHERE retired.project_id = OLD.project_id
              AND case_retirement_authorized(
                    retired.project_id,
                    retired.retirement_reason,
                    retired.privacy_deletion_id
                  ) = 1
        )
        BEGIN
            SELECT RAISE(ABORT, 'case project must be retired before physical deletion');
        END;

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

        CREATE TABLE IF NOT EXISTS conversations (
            conversation_id TEXT PRIMARY KEY CHECK (length(conversation_id) > 0),
            project_id TEXT,
            scope TEXT NOT NULL DEFAULT 'assistant' CHECK (
                scope IN ('assistant', 'case_work')
            ),
            title TEXT NOT NULL CHECK (length(title) > 0),
            status TEXT NOT NULL CHECK (status IN ('open', 'archived')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE SET NULL,
            CHECK (project_id IS NULL OR length(project_id) > 0),
            CHECK (scope = 'assistant' OR project_id IS NOT NULL)
        );

        CREATE TRIGGER IF NOT EXISTS trg_conversations_scope_immutable
        BEFORE UPDATE OF scope, project_id ON conversations
        WHEN NEW.scope IS NOT OLD.scope
          OR (OLD.scope = 'case_work' AND NEW.project_id IS NOT OLD.project_id)
        BEGIN
            SELECT RAISE(ABORT, 'conversation scope and case-work ownership are immutable');
        END;

        CREATE TABLE IF NOT EXISTS artifacts (
            artifact_id TEXT PRIMARY KEY CHECK (length(artifact_id) > 0),
            conversation_id TEXT,
            project_id TEXT,
            kind TEXT NOT NULL CHECK (kind IN ('research', 'document', 'map')),
            title TEXT NOT NULL CHECK (length(title) > 0),
            status TEXT NOT NULL CHECK (status IN ('draft', 'final', 'archived')),
            current_version INTEGER NOT NULL CHECK (current_version >= 1),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(conversation_id) ON DELETE SET NULL,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE SET NULL,
            CHECK (conversation_id IS NULL OR length(conversation_id) > 0),
            CHECK (project_id IS NULL OR length(project_id) > 0)
        );

        CREATE TABLE IF NOT EXISTS artifact_versions (
            version_id TEXT PRIMARY KEY CHECK (length(version_id) > 0),
            artifact_id TEXT NOT NULL,
            version_number INTEGER NOT NULL CHECK (version_number >= 1),
            content_json TEXT NOT NULL CHECK (json_valid(content_json)),
            rendered_text TEXT NOT NULL DEFAULT '',
            source_refs_json TEXT NOT NULL DEFAULT '[]' CHECK (
                json_valid(source_refs_json) AND json_type(source_refs_json) = 'array'
            ),
            citation_report_json TEXT NOT NULL DEFAULT '{}' CHECK (
                json_valid(citation_report_json)
            ),
            provider_snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK (
                json_valid(provider_snapshot_json) AND length(provider_snapshot_json) <= 65536
            ),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id) ON DELETE CASCADE,
            UNIQUE(artifact_id, version_number)
        );

        CREATE TABLE IF NOT EXISTS attachments (
            attachment_id TEXT PRIMARY KEY CHECK (length(attachment_id) > 0),
            project_id TEXT,
            original_name TEXT NOT NULL CHECK (length(original_name) > 0),
            extension TEXT NOT NULL DEFAULT '',
            detected_mime TEXT NOT NULL CHECK (length(detected_mime) > 0),
            sha256 TEXT NOT NULL UNIQUE CHECK (length(sha256) = 64),
            size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
            content_blob BLOB NOT NULL,
            extraction_status TEXT NOT NULL CHECK (
                extraction_status IN ('pending', 'succeeded', 'failed', 'unsupported')
            ),
            extracted_text TEXT,
            segments_json TEXT NOT NULL DEFAULT '[]' CHECK (
                json_valid(segments_json) AND json_type(segments_json) = 'array'
            ),
            error_code TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE SET NULL,
            CHECK (project_id IS NULL OR length(project_id) > 0),
            CHECK (size_bytes = length(content_blob)),
            CHECK (error_code IS NULL OR length(error_code) > 0)
        );

        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT PRIMARY KEY CHECK (length(message_id) > 0),
            conversation_id TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('user', 'assistant', 'system', 'tool')),
            kind TEXT NOT NULL CHECK (kind IN ('text', 'artifact_ref', 'proposal_ref')),
            text_summary TEXT NOT NULL DEFAULT '',
            artifact_id TEXT,
            run_id TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(conversation_id) ON DELETE CASCADE,
            FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id) ON DELETE SET NULL,
            FOREIGN KEY(run_id) REFERENCES agent_runs(run_id) ON DELETE SET NULL
                DEFERRABLE INITIALLY DEFERRED,
            CHECK (artifact_id IS NULL OR length(artifact_id) > 0),
            CHECK (run_id IS NULL OR length(run_id) > 0)
        );

        CREATE TABLE IF NOT EXISTS message_attachments (
            message_id TEXT NOT NULL,
            attachment_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
            PRIMARY KEY(message_id, attachment_id),
            FOREIGN KEY(message_id) REFERENCES messages(message_id) ON DELETE CASCADE,
            FOREIGN KEY(attachment_id) REFERENCES attachments(attachment_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS conversation_sources (
            conversation_id TEXT NOT NULL,
            source_id TEXT NOT NULL CHECK (length(source_id) > 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(conversation_id, source_id),
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(conversation_id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS agent_runs (
            run_id TEXT PRIMARY KEY CHECK (length(run_id) > 0),
            conversation_id TEXT NOT NULL,
            user_message_id TEXT NOT NULL,
            assistant_message_id TEXT,
            provider_id TEXT,
            provider_snapshot_json TEXT NOT NULL DEFAULT '{}' CHECK (
                json_valid(provider_snapshot_json) AND length(provider_snapshot_json) <= 65536
            ),
            intent TEXT NOT NULL CHECK (length(intent) > 0),
            status TEXT NOT NULL CHECK (
                status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
            ),
            budget_json TEXT NOT NULL CHECK (json_valid(budget_json)),
            error_type TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(conversation_id) ON DELETE CASCADE,
            FOREIGN KEY(user_message_id) REFERENCES messages(message_id) ON DELETE CASCADE
                DEFERRABLE INITIALLY DEFERRED,
            FOREIGN KEY(assistant_message_id) REFERENCES messages(message_id) ON DELETE SET NULL
                DEFERRABLE INITIALLY DEFERRED,
            FOREIGN KEY(provider_id) REFERENCES provider_profiles(id) ON DELETE SET NULL,
            CHECK (assistant_message_id IS NULL OR length(assistant_message_id) > 0),
            CHECK (provider_id IS NULL OR length(provider_id) > 0),
            CHECK (error_type IS NULL OR length(error_type) > 0),
            CHECK (
                (status IN ('queued', 'running') AND finished_at IS NULL)
                OR (status IN ('succeeded', 'failed', 'cancelled') AND finished_at IS NOT NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS tool_calls (
            tool_call_id TEXT PRIMARY KEY CHECK (length(tool_call_id) > 0),
            run_id TEXT NOT NULL,
            ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
            capability_name TEXT NOT NULL CHECK (length(capability_name) > 0),
            status TEXT NOT NULL CHECK (
                status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')
            ),
            access_mode TEXT NOT NULL CHECK (access_mode IN ('read', 'write')),
            requires_confirmation INTEGER NOT NULL CHECK (requires_confirmation IN (0, 1)),
            input_audit_json TEXT NOT NULL CHECK (json_valid(input_audit_json)),
            output_audit_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(output_audit_json)),
            source_audit_json TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(source_audit_json)),
            error_type TEXT,
            started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            FOREIGN KEY(run_id) REFERENCES agent_runs(run_id) ON DELETE CASCADE,
            UNIQUE(run_id, ordinal),
            CHECK (error_type IS NULL OR length(error_type) > 0),
            CHECK (
                (status IN ('queued', 'running') AND finished_at IS NULL)
                OR (status IN ('succeeded', 'failed', 'cancelled') AND finished_at IS NOT NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS case_change_proposals (
            proposal_id TEXT PRIMARY KEY CHECK (length(proposal_id) > 0),
            conversation_id TEXT NOT NULL,
            project_id TEXT NOT NULL,
            run_id TEXT,
            base_case_digest TEXT NOT NULL CHECK (length(base_case_digest) = 64),
            status TEXT NOT NULL CHECK (
                status IN ('pending', 'applied', 'rejected', 'stale')
            ),
            changes_json TEXT NOT NULL CHECK (json_valid(changes_json)),
            source_refs_json TEXT NOT NULL DEFAULT '[]' CHECK (
                json_valid(source_refs_json) AND json_type(source_refs_json) = 'array'
            ),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            decided_at TEXT,
            applied_at TEXT,
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(conversation_id) ON DELETE CASCADE,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE CASCADE,
            FOREIGN KEY(run_id) REFERENCES agent_runs(run_id) ON DELETE SET NULL,
            CHECK (run_id IS NULL OR length(run_id) > 0),
            CHECK (
                (status = 'pending' AND decided_at IS NULL AND applied_at IS NULL)
                OR (status IN ('rejected', 'stale') AND decided_at IS NOT NULL AND applied_at IS NULL)
                OR (status = 'applied' AND decided_at IS NOT NULL AND applied_at IS NOT NULL)
            )
        );

        CREATE TABLE IF NOT EXISTS case_assistant_pending_outputs (
            pending_output_id TEXT PRIMARY KEY CHECK (
                length(pending_output_id) BETWEEN 1 AND 128
            ),
            project_id TEXT NOT NULL CHECK (length(project_id) BETWEEN 1 AND 128),
            conversation_id TEXT NOT NULL CHECK (
                length(conversation_id) BETWEEN 1 AND 128
            ),
            run_id TEXT NOT NULL UNIQUE CHECK (length(run_id) BETWEEN 1 AND 128),
            assistant_message_id TEXT NOT NULL UNIQUE CHECK (
                length(assistant_message_id) BETWEEN 1 AND 128
            ),
            project_binding_sha256 TEXT NOT NULL CHECK (
                length(project_binding_sha256) = 64
                AND project_binding_sha256 NOT GLOB '*[^0-9a-f]*'
            ),
            source_snapshots_json TEXT NOT NULL CHECK (
                json_valid(source_snapshots_json)
                AND json_type(source_snapshots_json) = 'array'
                AND length(CAST(source_snapshots_json AS BLOB)) BETWEEN 1 AND 262144
            ),
            source_snapshots_sha256 TEXT NOT NULL CHECK (
                length(source_snapshots_sha256) = 64
                AND source_snapshots_sha256 NOT GLOB '*[^0-9a-f]*'
            ),
            expected_proposal_source_refs_json TEXT NOT NULL CHECK (
                json_valid(expected_proposal_source_refs_json)
                AND json_type(expected_proposal_source_refs_json) = 'array'
                AND length(CAST(expected_proposal_source_refs_json AS BLOB))
                    BETWEEN 2 AND 262144
            ),
            expected_proposal_source_refs_sha256 TEXT NOT NULL CHECK (
                length(expected_proposal_source_refs_sha256) = 64
                AND expected_proposal_source_refs_sha256 NOT GLOB '*[^0-9a-f]*'
            ),
            output_kind TEXT NOT NULL CHECK (
                output_kind IN ('case_analysis', 'case_document', 'case_diagram')
            ),
            output_payload_json TEXT NOT NULL CHECK (
                json_valid(output_payload_json)
                AND json_type(output_payload_json) = 'object'
                AND length(CAST(output_payload_json AS BLOB)) BETWEEN 1 AND 2097152
            ),
            output_preview TEXT NOT NULL DEFAULT '' CHECK (
                length(CAST(output_preview AS BLOB)) <= 16384
                AND instr(output_preview, char(0)) = 0
            ),
            output_sha256 TEXT NOT NULL CHECK (
                length(output_sha256) = 64
                AND output_sha256 NOT GLOB '*[^0-9a-f]*'
            ),
            output_version INTEGER NOT NULL CHECK (output_version > 0),
            workspace_base_digest TEXT NOT NULL CHECK (
                length(workspace_base_digest) = 64
                AND workspace_base_digest NOT GLOB '*[^0-9a-f]*'
            ),
            status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed')),
            confirmed_artifact_id TEXT,
            confirmed_proposal_id TEXT,
            confirmation_request_sha256 TEXT CHECK (
                confirmation_request_sha256 IS NULL
                OR (
                    length(confirmation_request_sha256) = 64
                    AND confirmation_request_sha256 NOT GLOB '*[^0-9a-f]*'
                )
            ),
            row_version INTEGER NOT NULL DEFAULT 1 CHECK (row_version > 0),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            confirmed_at TEXT,
            CHECK (
                output_kind = 'case_analysis'
                OR expected_proposal_source_refs_json = '[]'
            ),
            CHECK (
                (status = 'pending'
                 AND confirmed_artifact_id IS NULL
                 AND confirmed_proposal_id IS NULL
                 AND confirmation_request_sha256 IS NULL
                 AND confirmed_at IS NULL)
                OR
                (status = 'confirmed'
                 AND confirmation_request_sha256 IS NOT NULL
                 AND confirmed_at IS NOT NULL
                 AND (
                     (output_kind = 'case_analysis'
                      AND confirmed_artifact_id IS NULL
                      AND confirmed_proposal_id IS NOT NULL)
                     OR
                     (output_kind IN ('case_document', 'case_diagram')
                      AND confirmed_artifact_id IS NOT NULL
                      AND confirmed_proposal_id IS NULL)
                 ))
            )
        );

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_pending_outputs_closed_contract_insert
        BEFORE INSERT ON case_assistant_pending_outputs
        WHEN NOT json_valid(NEW.source_snapshots_json)
          OR json_type(NEW.source_snapshots_json) <> 'array'
          OR json(NEW.source_snapshots_json) <> NEW.source_snapshots_json
          OR json_array_length(NEW.source_snapshots_json) NOT BETWEEN 1 AND 64
          OR case_assistant_sha256(NEW.source_snapshots_json) <>
             NEW.source_snapshots_sha256
          OR EXISTS (
              SELECT 1
              FROM json_each(NEW.source_snapshots_json) AS snapshot
              WHERE snapshot.type <> 'object'
                 OR json_remove(
                        snapshot.value,
                        '$.approvedPayloadSha256', '$.extractionSha256',
                        '$.generationId', '$.generationNumber',
                        '$.generationRowVersion', '$.materialId', '$.ordinal',
                        '$.redactedContentSha256', '$.riskRevision',
                        '$.riskRevisionHash', '$.selectionId',
                        '$.selectionRowVersion'
                    ) <> '{}'
                 OR COALESCE(
                        json_type(snapshot.value, '$.approvedPayloadSha256') <> 'text',
                        1
                    )
                 OR COALESCE(
                        json_type(snapshot.value, '$.extractionSha256') <> 'text',
                        1
                    )
                 OR COALESCE(
                        json_type(snapshot.value, '$.redactedContentSha256') <> 'text',
                        1
                    )
                 OR COALESCE(
                        json_type(snapshot.value, '$.riskRevisionHash') <> 'text',
                        1
                    )
                 OR EXISTS (
                        SELECT 1
                        FROM (
                            SELECT json_extract(
                                snapshot.value, '$.approvedPayloadSha256'
                            ) AS value
                            UNION ALL SELECT json_extract(
                                snapshot.value, '$.extractionSha256'
                            )
                            UNION ALL SELECT json_extract(
                                snapshot.value, '$.redactedContentSha256'
                            )
                            UNION ALL SELECT json_extract(
                                snapshot.value, '$.riskRevisionHash'
                            )
                        ) AS hash
                        WHERE length(CAST(hash.value AS TEXT)) <> 64
                           OR CAST(hash.value AS TEXT) GLOB '*[^0-9a-f]*'
                    )
                 OR COALESCE(
                        json_type(snapshot.value, '$.generationId') <> 'text',
                        1
                    )
                 OR COALESCE(
                        json_type(snapshot.value, '$.materialId') <> 'text',
                        1
                    )
                 OR COALESCE(
                        json_type(snapshot.value, '$.selectionId') <> 'text',
                        1
                    )
                 OR length(CAST(json_extract(
                        snapshot.value, '$.generationId'
                    ) AS BLOB)) NOT BETWEEN 1 AND 128
                 OR length(CAST(json_extract(
                        snapshot.value, '$.materialId'
                    ) AS BLOB)) NOT BETWEEN 1 AND 128
                 OR length(CAST(json_extract(
                        snapshot.value, '$.selectionId'
                    ) AS BLOB)) NOT BETWEEN 1 AND 128
                 OR COALESCE(
                        json_type(snapshot.value, '$.ordinal') <> 'integer',
                        1
                    )
                 OR json_extract(snapshot.value, '$.ordinal') <>
                    CAST(snapshot.key AS INTEGER)
                 OR EXISTS (
                        SELECT 1
                        FROM (
                            SELECT '$.generationNumber' AS path
                            UNION ALL SELECT '$.generationRowVersion'
                            UNION ALL SELECT '$.riskRevision'
                            UNION ALL SELECT '$.selectionRowVersion'
                        ) AS positive_integer
                        WHERE COALESCE(
                            json_type(snapshot.value, positive_integer.path)
                                <> 'integer',
                            1
                        )
                           OR json_extract(
                               snapshot.value, positive_integer.path
                           ) <= 0
                    )
          )
          OR EXISTS (
              SELECT 1
              FROM json_each(NEW.source_snapshots_json) AS left_snapshot
              JOIN json_each(NEW.source_snapshots_json) AS right_snapshot
                ON CAST(left_snapshot.key AS INTEGER) <
                   CAST(right_snapshot.key AS INTEGER)
              WHERE json_extract(left_snapshot.value, '$.generationId') =
                    json_extract(right_snapshot.value, '$.generationId')
                 OR json_extract(left_snapshot.value, '$.materialId') =
                    json_extract(right_snapshot.value, '$.materialId')
                 OR json_extract(left_snapshot.value, '$.selectionId') =
                    json_extract(right_snapshot.value, '$.selectionId')
          )
          OR NOT json_valid(NEW.expected_proposal_source_refs_json)
          OR json_type(NEW.expected_proposal_source_refs_json) <> 'array'
          OR json(NEW.expected_proposal_source_refs_json) <>
             NEW.expected_proposal_source_refs_json
          OR case_assistant_sha256(
                 NEW.expected_proposal_source_refs_json
             ) <> NEW.expected_proposal_source_refs_sha256
          OR (
              NEW.output_kind <> 'case_analysis'
              AND NEW.expected_proposal_source_refs_json <> '[]'
          )
          OR EXISTS (
              WITH RECURSIVE control_code(value) AS (
                  SELECT 0
                  UNION ALL
                  SELECT value + 1 FROM control_code WHERE value < 31
              )
              SELECT 1
              FROM json_each(
                  NEW.expected_proposal_source_refs_json
              ) AS source_ref
              WHERE source_ref.type <> 'text'
                 OR length(CAST(source_ref.value AS BLOB))
                    NOT BETWEEN 1 AND 256
                 OR instr(
                        CAST(source_ref.value AS TEXT),
                        char(127)
                    ) > 0
                 OR EXISTS (
                        SELECT 1
                        FROM control_code
                        WHERE instr(
                            CAST(source_ref.value AS TEXT),
                            char(control_code.value)
                        ) > 0
                    )
          )
          OR EXISTS (
              SELECT 1
              FROM json_each(
                  NEW.expected_proposal_source_refs_json
              ) AS current
              JOIN json_each(
                  NEW.expected_proposal_source_refs_json
              ) AS previous
                ON CAST(previous.key AS INTEGER) =
                   CAST(current.key AS INTEGER) - 1
              WHERE CAST(previous.value AS TEXT) >=
                    CAST(current.value AS TEXT)
          )
          OR NOT json_valid(NEW.output_payload_json)
          OR json_type(NEW.output_payload_json) <> 'object'
          OR json(NEW.output_payload_json) <> NEW.output_payload_json
          OR json_remove(
                 NEW.output_payload_json,
                 '$.content', '$.outputKind', '$.schemaVersion'
             ) <> '{}'
          OR COALESCE(
                 json_type(NEW.output_payload_json, '$.outputKind') <> 'text',
                 1
             )
          OR json_extract(NEW.output_payload_json, '$.outputKind') <>
             NEW.output_kind
          OR COALESCE(
                 json_type(NEW.output_payload_json, '$.schemaVersion') <> 'integer',
                 1
             )
          OR json_extract(NEW.output_payload_json, '$.schemaVersion') <> 1
          OR json_type(NEW.output_payload_json, '$.content') IS NULL
          OR json_type(NEW.output_payload_json, '$.content') = 'null'
          OR case_assistant_sha256(NEW.output_payload_json) <> NEW.output_sha256
          OR NOT EXISTS (
              SELECT 1
              FROM tool_calls AS tool_call
              WHERE tool_call.run_id = NEW.run_id
                AND tool_call.ordinal = 0
                AND tool_call.capability_name = 'assistant.case_work'
                AND json_extract(
                    tool_call.input_audit_json,
                    '$.inputIds.projectId'
                ) = NEW.project_id
                AND json_extract(
                    tool_call.input_audit_json,
                    '$.inputIds.conversationId'
                ) = NEW.conversation_id
                AND json_extract(
                    tool_call.input_audit_json,
                    '$.inputHashes.workspaceDigest'
                ) = NEW.workspace_base_digest
                AND json_extract(
                    tool_call.output_audit_json,
                    '$.outputIds.pendingOutputKind'
                ) = NEW.output_kind
                AND json_extract(
                    tool_call.output_audit_json,
                    '$.outputHashes.typedOutputSha256'
                ) = NEW.output_sha256
                AND json_extract(
                    tool_call.output_audit_json,
                    '$.outputHashes.proposalSourceRefsSha256'
                ) = NEW.expected_proposal_source_refs_sha256
                AND json_extract(
                    tool_call.source_audit_json,
                    '$.inputHashes.projectBindingSha256'
                ) = NEW.project_binding_sha256
                AND json_extract(
                    tool_call.source_audit_json,
                    '$.inputHashes.sourceSnapshotsSha256'
                ) = NEW.source_snapshots_sha256
                AND json_array_length(
                    tool_call.input_audit_json,
                    '$.inputIds.redactionGenerationIds'
                ) = json_array_length(NEW.source_snapshots_json)
                AND json_array_length(
                    tool_call.source_audit_json,
                    '$.sourceRefs'
                ) = json_array_length(NEW.source_snapshots_json)
                AND NOT EXISTS (
                    SELECT 1
                    FROM json_each(NEW.source_snapshots_json) AS snapshot
                    WHERE json_extract(
                              tool_call.input_audit_json,
                              '$.inputIds.redactionGenerationIds[' ||
                                  snapshot.key || ']'
                          ) <> json_extract(snapshot.value, '$.generationId')
                       OR json_extract(
                              tool_call.source_audit_json,
                              '$.sourceRefs[' || snapshot.key || ']'
                          ) <> json_extract(snapshot.value, '$.generationId')
                )
          )
        BEGIN
            SELECT RAISE(
                ABORT,
                'case assistant pending output must match its closed hashed audit'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_pending_outputs_scope_insert
        BEFORE INSERT ON case_assistant_pending_outputs
        WHEN NEW.status <> 'pending'
          OR NEW.row_version <> 1
          OR NEW.confirmed_artifact_id IS NOT NULL
          OR NEW.confirmed_proposal_id IS NOT NULL
          OR NEW.confirmation_request_sha256 IS NOT NULL
          OR NEW.confirmed_at IS NOT NULL
          OR NOT EXISTS (
              SELECT 1
              FROM conversations AS conversation
              JOIN agent_runs AS run
                ON run.run_id = NEW.run_id
               AND run.conversation_id = conversation.conversation_id
              JOIN tool_calls AS tool_call
                ON tool_call.run_id = run.run_id
               AND tool_call.ordinal = 0
               AND tool_call.capability_name = 'assistant.case_work'
               AND tool_call.status = 'succeeded'
               AND tool_call.access_mode = 'write'
               AND tool_call.requires_confirmation = 0
               AND tool_call.error_type IS NULL
               AND tool_call.finished_at IS NOT NULL
              JOIN messages AS user_message
                ON user_message.message_id = run.user_message_id
               AND user_message.conversation_id = conversation.conversation_id
               AND user_message.role = 'user'
               AND user_message.kind = 'text'
               AND user_message.artifact_id IS NULL
               AND user_message.run_id IS NULL
              JOIN messages AS message
                ON message.message_id = NEW.assistant_message_id
               AND message.conversation_id = conversation.conversation_id
               AND message.run_id = run.run_id
               AND message.role = 'assistant'
               AND message.kind = 'text'
               AND message.artifact_id IS NULL
               AND message.text_summary = NEW.output_preview
              WHERE conversation.conversation_id = NEW.conversation_id
                AND conversation.project_id = NEW.project_id
                AND conversation.scope = 'case_work'
                AND run.assistant_message_id = NEW.assistant_message_id
                AND run.intent = 'interactive_case_work'
                AND run.status = 'succeeded'
                AND run.error_type IS NULL
                AND run.finished_at IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM tool_calls AS other_tool_call
                    WHERE other_tool_call.run_id = run.run_id
                      AND other_tool_call.tool_call_id <> tool_call.tool_call_id
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM message_attachments AS attachment
                    WHERE attachment.message_id IN (
                        run.user_message_id,
                        NEW.assistant_message_id
                    )
                )
          )
        BEGIN
            SELECT RAISE(
                ABORT,
                'case assistant pending output must match a successful case-work run'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_pending_outputs_append_preserving
        BEFORE UPDATE ON case_assistant_pending_outputs
        WHEN NEW.pending_output_id IS NOT OLD.pending_output_id
          OR NEW.project_id IS NOT OLD.project_id
          OR NEW.conversation_id IS NOT OLD.conversation_id
          OR NEW.run_id IS NOT OLD.run_id
          OR NEW.assistant_message_id IS NOT OLD.assistant_message_id
          OR NEW.project_binding_sha256 IS NOT OLD.project_binding_sha256
          OR NEW.source_snapshots_json IS NOT OLD.source_snapshots_json
          OR NEW.source_snapshots_sha256 IS NOT OLD.source_snapshots_sha256
          OR NEW.expected_proposal_source_refs_json IS NOT
             OLD.expected_proposal_source_refs_json
          OR NEW.expected_proposal_source_refs_sha256 IS NOT
             OLD.expected_proposal_source_refs_sha256
          OR NEW.output_kind IS NOT OLD.output_kind
          OR NEW.output_payload_json IS NOT OLD.output_payload_json
          OR NEW.output_preview IS NOT OLD.output_preview
          OR NEW.output_sha256 IS NOT OLD.output_sha256
          OR NEW.output_version IS NOT OLD.output_version
          OR NEW.workspace_base_digest IS NOT OLD.workspace_base_digest
          OR NEW.created_at IS NOT OLD.created_at
          OR OLD.status <> 'pending'
          OR NEW.status <> 'confirmed'
          OR NEW.confirmation_request_sha256 IS NULL
          OR NEW.confirmed_at IS NULL
          OR NEW.row_version <> OLD.row_version + 1
        BEGIN
            SELECT RAISE(ABORT, 'case assistant pending output history is append preserving');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_pending_outputs_confirmation_target
        BEFORE UPDATE OF status, confirmed_artifact_id, confirmed_proposal_id
        ON case_assistant_pending_outputs
        WHEN NEW.status = 'confirmed' AND (
            (
                NEW.output_kind = 'case_analysis'
                AND NOT EXISTS (
                    SELECT 1 FROM case_change_proposals AS proposal
                    WHERE proposal.proposal_id = NEW.confirmed_proposal_id
                      AND proposal.project_id = NEW.project_id
                      AND proposal.conversation_id = NEW.conversation_id
                      AND proposal.run_id = NEW.run_id
                      AND proposal.status = 'applied'
                      AND proposal.base_case_digest =
                          NEW.workspace_base_digest
                      AND json(proposal.changes_json) =
                          json(json_extract(
                              NEW.output_payload_json,
                              '$.content'
                          ))
                      AND proposal.source_refs_json =
                          NEW.expected_proposal_source_refs_json
                      AND NOT EXISTS (
                          SELECT 1
                          FROM json_each(proposal.source_refs_json) AS source
                          WHERE source.type <> 'text'
                             OR length(source.value) = 0
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM json_each(proposal.source_refs_json) AS current
                          JOIN json_each(proposal.source_refs_json) AS previous
                            ON CAST(previous.key AS INTEGER) =
                               CAST(current.key AS INTEGER) - 1
                          WHERE CAST(previous.value AS TEXT) >=
                                CAST(current.value AS TEXT)
                      )
                      AND NOT EXISTS (
                          SELECT 1
                          FROM json_tree(proposal.changes_json) AS referenced
                          LEFT JOIN json_tree(proposal.changes_json) AS container
                            ON container.id = referenced.parent
                          WHERE (
                                  referenced.key = 'sourceRef'
                                  OR referenced.key IN (
                                      'attachmentId',
                                      'artifactId'
                                  )
                                  OR (
                                      container.key = 'sourceRefs'
                                      AND container.type = 'array'
                                  )
                                )
                            AND referenced.type = 'text'
                            AND NOT EXISTS (
                                SELECT 1
                                FROM json_each(
                                    proposal.source_refs_json
                                ) AS canonical_source
                                WHERE canonical_source.value =
                                      referenced.value
                            )
                      )
                )
            )
            OR
            (
                NEW.output_kind IN ('case_document', 'case_diagram')
                AND NOT EXISTS (
                    SELECT 1
                    FROM artifacts AS artifact
                    JOIN artifact_versions AS version
                      ON version.artifact_id = artifact.artifact_id
                     AND version.version_number = 1
                    JOIN agent_runs AS run ON run.run_id = NEW.run_id
                    WHERE artifact.artifact_id = NEW.confirmed_artifact_id
                      AND artifact.project_id = NEW.project_id
                      AND artifact.conversation_id = NEW.conversation_id
                      AND artifact.status <> 'archived'
                      AND artifact.current_version = 1
                      AND artifact.kind = CASE NEW.output_kind
                          WHEN 'case_document' THEN 'document'
                          WHEN 'case_diagram' THEN 'map'
                      END
                      AND version.rendered_text = NEW.output_preview
                      AND json(version.content_json) =
                          json(json_extract(
                              NEW.output_payload_json,
                              '$.content'
                          ))
                      AND json(version.provider_snapshot_json) =
                          json(run.provider_snapshot_json)
                )
            )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'case assistant confirmation target does not match its pending output'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_pending_outputs_no_delete
        BEFORE DELETE ON case_assistant_pending_outputs
        BEGIN
            SELECT RAISE(ABORT, 'case assistant pending output history is append preserving');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_conversation_no_delete
        BEFORE DELETE ON conversations
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.conversation_id = OLD.conversation_id
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'live case assistant conversation lineage cannot be deleted'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_run_no_delete
        BEFORE DELETE ON agent_runs
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.run_id = OLD.run_id
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'live case assistant run lineage cannot be deleted');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_run_lineage_immutable
        BEFORE UPDATE OF
            run_id, conversation_id, user_message_id, assistant_message_id,
            provider_snapshot_json, intent, status, budget_json, error_type,
            created_at, finished_at
        ON agent_runs
        WHEN (
            NEW.run_id IS NOT OLD.run_id
            OR NEW.conversation_id IS NOT OLD.conversation_id
            OR NEW.user_message_id IS NOT OLD.user_message_id
            OR NEW.assistant_message_id IS NOT OLD.assistant_message_id
            OR NEW.provider_snapshot_json IS NOT OLD.provider_snapshot_json
            OR NEW.intent IS NOT OLD.intent
            OR NEW.status IS NOT OLD.status
            OR NEW.budget_json IS NOT OLD.budget_json
            OR NEW.error_type IS NOT OLD.error_type
            OR NEW.created_at IS NOT OLD.created_at
            OR NEW.finished_at IS NOT OLD.finished_at
        )
        AND EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.run_id = OLD.run_id
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'live case assistant run lineage is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_message_no_delete
        BEFORE DELETE ON messages
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            JOIN agent_runs AS run ON run.run_id = output.run_id
            WHERE (
                    output.assistant_message_id = OLD.message_id
                    OR run.user_message_id = OLD.message_id
                    OR run.assistant_message_id = OLD.message_id
                  )
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'live case assistant message lineage cannot be deleted');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_message_lineage_immutable
        BEFORE UPDATE OF
            message_id, conversation_id, role, kind, text_summary,
            artifact_id, run_id, created_at
        ON messages
        WHEN (
            NEW.message_id IS NOT OLD.message_id
            OR NEW.conversation_id IS NOT OLD.conversation_id
            OR NEW.role IS NOT OLD.role
            OR NEW.kind IS NOT OLD.kind
            OR NEW.text_summary IS NOT OLD.text_summary
            OR NEW.artifact_id IS NOT OLD.artifact_id
            OR NEW.run_id IS NOT OLD.run_id
            OR NEW.created_at IS NOT OLD.created_at
        )
        AND EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            JOIN agent_runs AS run ON run.run_id = output.run_id
            WHERE (
                    output.assistant_message_id = OLD.message_id
                    OR run.user_message_id = OLD.message_id
                    OR run.assistant_message_id = OLD.message_id
                  )
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'live case assistant message lineage is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_message_attachment_no_insert
        BEFORE INSERT ON message_attachments
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            JOIN agent_runs AS run ON run.run_id = output.run_id
            WHERE NEW.message_id IN (
                    run.user_message_id,
                    output.assistant_message_id
                  )
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'live case assistant messages cannot gain attachments'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_message_attachment_no_update
        BEFORE UPDATE ON message_attachments
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            JOIN agent_runs AS run ON run.run_id = output.run_id
            WHERE NEW.message_id IN (
                    run.user_message_id,
                    output.assistant_message_id
                  )
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'live case assistant messages cannot gain attachments'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_tool_call_no_insert
        BEFORE INSERT ON tool_calls
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.run_id = NEW.run_id
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'live case assistant run cannot gain tool audits');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_tool_call_no_delete
        BEFORE DELETE ON tool_calls
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.run_id = OLD.run_id
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'live case assistant tool audit cannot be deleted');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_live_tool_call_immutable
        BEFORE UPDATE ON tool_calls
        WHEN (
            NEW.tool_call_id IS NOT OLD.tool_call_id
            OR NEW.run_id IS NOT OLD.run_id
            OR NEW.ordinal IS NOT OLD.ordinal
            OR NEW.capability_name IS NOT OLD.capability_name
            OR NEW.status IS NOT OLD.status
            OR NEW.access_mode IS NOT OLD.access_mode
            OR NEW.requires_confirmation IS NOT OLD.requires_confirmation
            OR NEW.input_audit_json IS NOT OLD.input_audit_json
            OR NEW.output_audit_json IS NOT OLD.output_audit_json
            OR NEW.source_audit_json IS NOT OLD.source_audit_json
            OR NEW.error_type IS NOT OLD.error_type
            OR NEW.started_at IS NOT OLD.started_at
            OR NEW.finished_at IS NOT OLD.finished_at
        )
        AND EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.run_id = OLD.run_id
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(ABORT, 'live case assistant tool audit is immutable');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_confirmed_artifact_scope_immutable
        BEFORE UPDATE OF artifact_id, conversation_id, project_id, kind, status ON artifacts
        WHEN EXISTS (
            SELECT 1 FROM case_assistant_pending_outputs AS output
            WHERE output.confirmed_artifact_id = OLD.artifact_id
              AND output.status = 'confirmed'
              AND (
                  NEW.artifact_id IS NOT OLD.artifact_id
                  OR NEW.conversation_id IS NOT OLD.conversation_id
                  OR NEW.project_id IS NOT OLD.project_id
                  OR NEW.kind IS NOT OLD.kind
                  OR NEW.status = 'archived'
              )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'confirmed case assistant artifact scope is immutable'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_confirmed_artifact_no_delete
        BEFORE DELETE ON artifacts
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.confirmed_artifact_id = OLD.artifact_id
              AND output.status = 'confirmed'
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'live confirmed case assistant artifact cannot be deleted'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_confirmed_artifact_v1_immutable
        BEFORE UPDATE ON artifact_versions
        WHEN OLD.version_number = 1
          AND (
              NEW.version_id IS NOT OLD.version_id
              OR NEW.artifact_id IS NOT OLD.artifact_id
              OR NEW.version_number IS NOT OLD.version_number
              OR NEW.content_json IS NOT OLD.content_json
              OR NEW.rendered_text IS NOT OLD.rendered_text
              OR NEW.source_refs_json IS NOT OLD.source_refs_json
              OR NEW.citation_report_json IS NOT OLD.citation_report_json
              OR NEW.provider_snapshot_json IS NOT OLD.provider_snapshot_json
              OR NEW.created_at IS NOT OLD.created_at
          )
          AND EXISTS (
              SELECT 1
              FROM case_assistant_pending_outputs AS output
              WHERE output.confirmed_artifact_id = OLD.artifact_id
                AND output.status = 'confirmed'
                AND NOT EXISTS (
                    SELECT 1 FROM retired_case_project_ids AS retired
                    WHERE retired.project_id = output.project_id
                      AND case_retirement_authorized(
                            retired.project_id,
                            retired.retirement_reason,
                            retired.privacy_deletion_id
                          ) = 1
                )
          )
        BEGIN
            SELECT RAISE(
                ABORT,
                'confirmed case assistant artifact version one is immutable'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_confirmed_artifact_v1_no_delete
        BEFORE DELETE ON artifact_versions
        WHEN OLD.version_number = 1
          AND EXISTS (
              SELECT 1
              FROM case_assistant_pending_outputs AS output
              WHERE output.confirmed_artifact_id = OLD.artifact_id
                AND output.status = 'confirmed'
                AND NOT EXISTS (
                    SELECT 1 FROM retired_case_project_ids AS retired
                    WHERE retired.project_id = output.project_id
                      AND case_retirement_authorized(
                            retired.project_id,
                            retired.retirement_reason,
                            retired.privacy_deletion_id
                          ) = 1
                )
          )
        BEGIN
            SELECT RAISE(
                ABORT,
                'confirmed case assistant artifact version one cannot be deleted'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_confirmed_proposal_scope_immutable
        BEFORE UPDATE OF
            proposal_id, conversation_id, project_id, run_id, base_case_digest,
            status, changes_json, source_refs_json, created_at, decided_at, applied_at
        ON case_change_proposals
        WHEN EXISTS (
            SELECT 1 FROM case_assistant_pending_outputs AS output
            WHERE output.confirmed_proposal_id = OLD.proposal_id
              AND output.status = 'confirmed'
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
              AND (
                  NEW.proposal_id IS NOT OLD.proposal_id
                  OR NEW.conversation_id IS NOT OLD.conversation_id
                  OR NEW.project_id IS NOT OLD.project_id
                  OR NEW.run_id IS NOT OLD.run_id
                  OR NEW.base_case_digest IS NOT OLD.base_case_digest
                  OR NEW.status IS NOT OLD.status
                  OR NEW.changes_json IS NOT OLD.changes_json
                  OR NEW.source_refs_json IS NOT OLD.source_refs_json
                  OR NEW.created_at IS NOT OLD.created_at
                  OR NEW.decided_at IS NOT OLD.decided_at
                  OR NEW.applied_at IS NOT OLD.applied_at
              )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'confirmed case assistant proposal scope is immutable'
            );
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_assistant_confirmed_proposal_no_delete
        BEFORE DELETE ON case_change_proposals
        WHEN EXISTS (
            SELECT 1
            FROM case_assistant_pending_outputs AS output
            WHERE output.confirmed_proposal_id = OLD.proposal_id
              AND output.status = 'confirmed'
              AND NOT EXISTS (
                  SELECT 1 FROM retired_case_project_ids AS retired
                  WHERE retired.project_id = output.project_id
                    AND case_retirement_authorized(
                          retired.project_id,
                          retired.retirement_reason,
                          retired.privacy_deletion_id
                        ) = 1
              )
        )
        BEGIN
            SELECT RAISE(
                ABORT,
                'live confirmed case assistant proposal cannot be deleted'
            );
        END;

        CREATE TABLE IF NOT EXISTS operation_audit (
            audit_id TEXT PRIMARY KEY CHECK (length(audit_id) > 0),
            origin TEXT NOT NULL CHECK (origin IN ('desktop', 'mcp')),
            operation TEXT NOT NULL CHECK (length(operation) > 0),
            project_id TEXT,
            request_hash TEXT NOT NULL CHECK (length(request_hash) = 64),
            idempotency_key_hash TEXT CHECK (
                idempotency_key_hash IS NULL OR length(idempotency_key_hash) = 64
            ),
            status TEXT NOT NULL CHECK (
                status IN ('prepared', 'succeeded', 'failed')
            ),
            details_json TEXT NOT NULL DEFAULT '{}' CHECK (
                json_valid(details_json)
                AND json_type(details_json) = 'object'
                AND length(details_json) <= 65536
            ),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT,
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE SET NULL,
            CHECK (project_id IS NULL OR length(project_id) > 0),
            CHECK (
                (status = 'prepared' AND finished_at IS NULL)
                OR (status IN ('succeeded', 'failed') AND finished_at IS NOT NULL)
            )
        );

        CREATE TRIGGER IF NOT EXISTS trg_artifacts_scope_insert
        BEFORE INSERT ON artifacts
        WHEN NEW.conversation_id IS NOT NULL
          AND NEW.project_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM conversations
              WHERE conversation_id = NEW.conversation_id
                AND (project_id IS NULL OR project_id = NEW.project_id)
          )
        BEGIN
            SELECT RAISE(ABORT, 'artifact project must match its bound conversation');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_artifacts_scope_update
        BEFORE UPDATE OF conversation_id, project_id ON artifacts
        WHEN NEW.conversation_id IS NOT NULL
          AND NEW.project_id IS NOT NULL
          AND NOT EXISTS (
              SELECT 1 FROM conversations
              WHERE conversation_id = NEW.conversation_id
                AND (project_id IS NULL OR project_id = NEW.project_id)
          )
        BEGIN
            SELECT RAISE(ABORT, 'artifact project must match its bound conversation');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_messages_artifact_run_scope_insert
        BEFORE INSERT ON messages
        WHEN (
            NEW.artifact_id IS NOT NULL AND NOT EXISTS (
                SELECT 1
                FROM artifacts AS artifact
                JOIN conversations AS conversation
                  ON conversation.conversation_id = NEW.conversation_id
                WHERE artifact.artifact_id = NEW.artifact_id
                  AND (
                      artifact.conversation_id IS NULL
                      OR artifact.conversation_id = NEW.conversation_id
                  )
                  AND (
                      conversation.project_id IS NULL
                      OR artifact.project_id IS NULL
                      OR artifact.project_id = conversation.project_id
                  )
            )
        ) OR (
            NEW.run_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM agent_runs
                WHERE run_id = NEW.run_id AND conversation_id = NEW.conversation_id
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'message artifact and run must remain in conversation scope');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_messages_artifact_run_scope_update
        BEFORE UPDATE OF conversation_id, artifact_id, run_id ON messages
        WHEN (
            NEW.artifact_id IS NOT NULL AND NOT EXISTS (
                SELECT 1
                FROM artifacts AS artifact
                JOIN conversations AS conversation
                  ON conversation.conversation_id = NEW.conversation_id
                WHERE artifact.artifact_id = NEW.artifact_id
                  AND (
                      artifact.conversation_id IS NULL
                      OR artifact.conversation_id = NEW.conversation_id
                  )
                  AND (
                      conversation.project_id IS NULL
                      OR artifact.project_id IS NULL
                      OR artifact.project_id = conversation.project_id
                  )
            )
        ) OR (
            NEW.run_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM agent_runs
                WHERE run_id = NEW.run_id AND conversation_id = NEW.conversation_id
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'message artifact and run must remain in conversation scope');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_agent_runs_message_scope_insert
        BEFORE INSERT ON agent_runs
        WHEN NOT EXISTS (
            SELECT 1 FROM messages
            WHERE message_id = NEW.user_message_id
              AND conversation_id = NEW.conversation_id
        ) OR (
            NEW.assistant_message_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM messages
                WHERE message_id = NEW.assistant_message_id
                  AND conversation_id = NEW.conversation_id
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'agent run messages must belong to the same conversation');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_agent_runs_message_scope_update
        BEFORE UPDATE OF conversation_id, user_message_id, assistant_message_id ON agent_runs
        WHEN NOT EXISTS (
            SELECT 1 FROM messages
            WHERE message_id = NEW.user_message_id
              AND conversation_id = NEW.conversation_id
        ) OR (
            NEW.assistant_message_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM messages
                WHERE message_id = NEW.assistant_message_id
                  AND conversation_id = NEW.conversation_id
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'agent run messages must belong to the same conversation');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_change_proposals_scope_insert
        BEFORE INSERT ON case_change_proposals
        WHEN NOT EXISTS (
            SELECT 1 FROM conversations
            WHERE conversation_id = NEW.conversation_id AND project_id = NEW.project_id
        ) OR (
            NEW.run_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM agent_runs
                WHERE run_id = NEW.run_id AND conversation_id = NEW.conversation_id
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'case proposal must match its conversation, project, and run');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_case_change_proposals_scope_update
        BEFORE UPDATE OF conversation_id, project_id, run_id ON case_change_proposals
        WHEN NOT EXISTS (
            SELECT 1 FROM conversations
            WHERE conversation_id = NEW.conversation_id AND project_id = NEW.project_id
        ) OR (
            NEW.run_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM agent_runs
                WHERE run_id = NEW.run_id AND conversation_id = NEW.conversation_id
            )
        )
        BEGIN
            SELECT RAISE(ABORT, 'case proposal must match its conversation, project, and run');
        END;

        CREATE INDEX IF NOT EXISTS idx_conversations_updated
            ON conversations(updated_at);
        CREATE INDEX IF NOT EXISTS idx_conversations_project_updated
            ON conversations(project_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_artifacts_conversation_updated
            ON artifacts(conversation_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_artifacts_project_updated
            ON artifacts(project_id, updated_at);
        CREATE INDEX IF NOT EXISTS idx_artifact_versions_created
            ON artifact_versions(artifact_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_attachments_project_created
            ON attachments(project_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_conversation_created
            ON messages(conversation_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_messages_run
            ON messages(run_id);
        CREATE INDEX IF NOT EXISTS idx_message_attachments_attachment
            ON message_attachments(attachment_id);
        CREATE INDEX IF NOT EXISTS idx_conversation_sources_source
            ON conversation_sources(source_id);
        CREATE INDEX IF NOT EXISTS idx_agent_runs_conversation_created
            ON agent_runs(conversation_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_agent_runs_status
            ON agent_runs(status, created_at);
        CREATE INDEX IF NOT EXISTS idx_tool_calls_status
            ON tool_calls(status, started_at);
        CREATE INDEX IF NOT EXISTS idx_case_change_proposals_conversation_created
            ON case_change_proposals(conversation_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_case_change_proposals_project_status
            ON case_change_proposals(project_id, status, created_at);
        CREATE INDEX IF NOT EXISTS idx_case_assistant_pending_outputs_conversation_created
            ON case_assistant_pending_outputs(conversation_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_case_assistant_pending_outputs_project_status
            ON case_assistant_pending_outputs(project_id, status, created_at);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_operation_audit_idempotency
            ON operation_audit(origin, operation, idempotency_key_hash)
            WHERE idempotency_key_hash IS NOT NULL;
        CREATE INDEX IF NOT EXISTS idx_operation_audit_project_created
            ON operation_audit(project_id, created_at);

        CREATE TABLE IF NOT EXISTS legal_answer_records (
            record_id TEXT PRIMARY KEY CHECK (length(record_id) > 0),
            project_id TEXT,
            conversation_id TEXT,
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
            FOREIGN KEY(project_id) REFERENCES projects(project_id) ON DELETE SET NULL,
            FOREIGN KEY(conversation_id)
                REFERENCES conversations(conversation_id) ON DELETE SET NULL,
            CHECK (project_id IS NULL OR length(project_id) > 0),
            CHECK (conversation_id IS NULL OR length(conversation_id) > 0)
        );

        CREATE TRIGGER IF NOT EXISTS trg_legal_answer_records_scope_insert
        BEFORE INSERT ON legal_answer_records
        WHEN NEW.conversation_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM conversations
            WHERE conversation_id = NEW.conversation_id AND project_id IS NEW.project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'legal answer project must match its conversation');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_legal_answer_records_scope_update
        BEFORE UPDATE OF project_id, conversation_id ON legal_answer_records
        WHEN NEW.conversation_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM conversations
            WHERE conversation_id = NEW.conversation_id AND project_id IS NEW.project_id
        )
        BEGIN
            SELECT RAISE(ABORT, 'legal answer project must match its conversation');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_projects_detach_assistant_data_before_delete
        BEFORE DELETE ON projects
        BEGIN
            DELETE FROM artifacts
            WHERE conversation_id IN (
                SELECT conversation_id
                FROM conversations
                WHERE project_id = OLD.project_id AND scope = 'case_work'
            );
            DELETE FROM conversations
            WHERE project_id = OLD.project_id AND scope = 'case_work';
            UPDATE conversations
            SET project_id = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE project_id = OLD.project_id AND scope = 'assistant';
            UPDATE legal_answer_records SET project_id = NULL WHERE project_id = OLD.project_id;
        END;

        CREATE INDEX IF NOT EXISTS idx_legal_answer_records_created
            ON legal_answer_records(created_at);
        CREATE INDEX IF NOT EXISTS idx_legal_answer_records_project_created
            ON legal_answer_records(project_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_legal_answer_records_conversation_created
            ON legal_answer_records(conversation_id, created_at);

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
    install_case_assistant_closed_audit_triggers(&transaction)?;

    let suspended_pending_output_triggers =
        if staged_tables.contains("case_assistant_pending_outputs") {
            suspend_case_assistant_pending_output_migration_triggers(&transaction)?
        } else {
            Vec::new()
        };
    if !staged_tables.is_empty() {
        migrate_staged_user_tables(&transaction, &staged_tables)?;
    }
    restore_case_assistant_pending_output_migration_triggers(
        &transaction,
        &suspended_pending_output_triggers,
    )?;

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

    const TEST_PRIVACY_DELETION_ID: &str = "pdel_00000000000000000000000000000000";

    fn retirement_authorized(
        connection: &rusqlite::Connection,
        project_id: &str,
        retirement_reason: &str,
        privacy_deletion_id: Option<&str>,
    ) -> i64 {
        connection
            .query_row(
                "SELECT case_retirement_authorized(?1,?2,?3)",
                params![project_id, retirement_reason, privacy_deletion_id],
                |row| row.get(0),
            )
            .expect("retirement authority UDF evaluates")
    }

    #[test]
    fn case_retirement_authority_is_exact_connection_scoped_and_raii_cleared() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let first = open_user_database(&database_path).expect("first database connection opens");
        let second = open_user_database(&database_path).expect("second database connection opens");
        let first_nonce =
            case_retirement_connection_nonce(&first).expect("first connection nonce reads");
        let second_nonce =
            case_retirement_connection_nonce(&second).expect("second connection nonce reads");
        assert!(second_nonce > first_nonce);
        assert_eq!(
            retirement_authorized(
                &first,
                "authority-project",
                "case_project_deleted",
                Some(TEST_PRIVACY_DELETION_ID)
            ),
            0
        );

        with_case_retirement_authority(
            &first,
            "authority-project",
            "case_project_deleted",
            Some(TEST_PRIVACY_DELETION_ID),
            || {
                assert_eq!(
                    retirement_authorized(
                        &first,
                        "authority-project",
                        "case_project_deleted",
                        Some(TEST_PRIVACY_DELETION_ID)
                    ),
                    1
                );
                assert_eq!(
                    retirement_authorized(
                        &first,
                        "other-project",
                        "case_project_deleted",
                        Some(TEST_PRIVACY_DELETION_ID)
                    ),
                    0
                );
                assert_eq!(
                    retirement_authorized(
                        &first,
                        "authority-project",
                        "privacy_journal_recovery",
                        Some(TEST_PRIVACY_DELETION_ID)
                    ),
                    0
                );
                assert_eq!(
                    retirement_authorized(
                        &first,
                        "authority-project",
                        "case_project_deleted",
                        None
                    ),
                    0
                );
                assert_eq!(
                    retirement_authorized(
                        &second,
                        "authority-project",
                        "case_project_deleted",
                        Some(TEST_PRIVACY_DELETION_ID)
                    ),
                    0,
                    "authority from connection A must not authorize connection B"
                );
                Ok(())
            },
        )
        .expect("exact authority scope succeeds");
        assert_eq!(
            retirement_authorized(
                &first,
                "authority-project",
                "case_project_deleted",
                Some(TEST_PRIVACY_DELETION_ID)
            ),
            0
        );

        let forced_error = with_case_retirement_authority(
            &first,
            "authority-project",
            "case_project_deleted",
            Some(TEST_PRIVACY_DELETION_ID),
            || -> rusqlite::Result<()> {
                Err(user_schema_migration_error(
                    "forced retirement authority error".to_owned(),
                ))
            },
        );
        assert!(forced_error.is_err());
        assert_eq!(
            retirement_authorized(
                &first,
                "authority-project",
                "case_project_deleted",
                Some(TEST_PRIVACY_DELETION_ID)
            ),
            0,
            "error return must clear retirement authority"
        );

        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_case_retirement_authority::<()>(
                &first,
                "authority-project",
                "case_project_deleted",
                Some(TEST_PRIVACY_DELETION_ID),
                || panic!("forced retirement authority unwind"),
            )
        }));
        assert!(unwind.is_err());
        assert_eq!(
            retirement_authorized(
                &first,
                "authority-project",
                "case_project_deleted",
                Some(TEST_PRIVACY_DELETION_ID)
            ),
            0,
            "panic unwind must clear retirement authority"
        );
    }

    #[test]
    fn user_database_is_created_under_app_local_data_dir() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");

        assert_eq!(database_path, directory.path().join(USER_DB_FILE_NAME));
        assert!(database_path.is_file());
    }

    #[test]
    fn existing_only_and_read_only_user_database_open_modes_are_enforced() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database is created");
        let read_only =
            open_user_database_read_only(&database_path).expect("read-only database opens");
        assert_eq!(
            read_only
                .query_row("PRAGMA query_only", [], |row| row.get::<_, i64>(0))
                .expect("query-only pragma reads"),
            1
        );
        assert!(read_only
            .execute(
                "INSERT INTO projects (project_id, title, status) VALUES ('forbidden', 'Forbidden', 'active')",
                [],
            )
            .is_err());
        drop(read_only);

        let missing = directory.path().join("must-not-be-created.sqlite");
        assert!(open_existing_user_database(&missing).is_err());
        assert!(!missing.exists());
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

        assert!(
            delete_case_project(&connection, "legacy-project", TEST_PRIVACY_DELETION_ID)
                .expect("canonical project cascade deletes migrated children")
        );
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
    fn user_database_migrates_v6_unowned_answers_into_case_free_conversations() {
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
                "SELECT project_id, conversation_id, provider_id, question, answer_text, case_date,
                        query_json, source_ids_json, verified_citations_json,
                        invalid_citations_json, unsupported_legal_conclusion, created_at
                 FROM legal_answer_records WHERE record_id = 'legacy-answer'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .expect("legacy answer survives");
        assert_eq!(migrated.0, None);
        assert_eq!(migrated.1, "legacy-qa:legacy-answer");
        assert_eq!(migrated.2, "legacy-provider");
        assert_eq!(migrated.3, "Preserve question");
        assert_eq!(migrated.4, "Preserve answer");
        assert_eq!(migrated.5.as_deref(), Some("2024-01-02"));
        assert_eq!(migrated.6, r#"{"keywords":["breach"]}"#);
        assert_eq!(migrated.7, r#"["source-1"]"#);
        assert_eq!(
            migrated.8,
            r#"[{"rawMarker":"[SRC:source-1]","sourceId":"source-1","status":"valid","reason":null,"source":null}]"#
        );
        assert_eq!(migrated.9, "[]");
        assert_eq!(migrated.10, 0);
        assert_eq!(migrated.11, "2026-07-13 10:00:00");

        let project_id_not_null: i64 = connection
            .query_row(
                "SELECT \"notnull\" FROM pragma_table_info('legal_answer_records')
                 WHERE name = 'project_id'",
                [],
                |row| row.get(0),
            )
            .expect("canonical project ownership constraint reads");
        assert_eq!(project_id_not_null, 0);
        let conversation = get_conversation(&connection, "legacy-qa:legacy-answer")
            .expect("conversation reads")
            .expect("conversation exists");
        assert_eq!(conversation.project_id, None);
        assert_eq!(conversation.title, "Preserve question");
        let messages =
            list_messages(&connection, "legacy-qa:legacy-answer").expect("legacy messages read");
        assert_eq!(messages.len(), 2);
        assert_eq!(
            (messages[0].role.as_str(), messages[0].text_summary.as_str()),
            ("user", "Preserve question")
        );
        assert_eq!(
            (messages[1].role.as_str(), messages[1].text_summary.as_str()),
            ("assistant", "Preserve answer")
        );
        assert!(
            case_project_exists(&connection, LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX)
                .expect("colliding user project remains")
        );
        assert_eq!(
            table_row_count(&connection, "legal_answer_records"),
            1,
            "case-free history survives without manufacturing a project"
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

        assert!(
            delete_case_project(&connection, "project-1", TEST_PRIVACY_DELETION_ID)
                .expect("project deletes")
        );
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
        assert!(
            delete_case_project(&connection, "project-answer", TEST_PRIVACY_DELETION_ID)
                .expect("project deletes")
        );
        assert!(
            list_legal_answer_records_for_project(&connection, "project-answer", 10)
                .expect("deleted project records list")
                .is_empty()
        );
        assert_eq!(
            list_legal_answer_records(&connection, 10)
                .expect("conversation history survives project deletion")
                .len(),
            2
        );
        let detached = get_conversation(&connection, "qa:answer-1")
            .expect("conversation reads")
            .expect("conversation survives");
        assert_eq!(detached.project_id, None);
        assert_eq!(
            list_legal_answer_records_for_conversation(&connection, "qa:answer-1", 10)
                .expect("detached answer remains in its conversation")
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
    fn v11_schema_exposes_exact_assistant_case_lineage_and_operation_audit_objects() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let connection = open_user_database(&database_path).expect("database opens");
        for table in [
            "retired_case_project_ids",
            "conversations",
            "artifacts",
            "artifact_versions",
            "messages",
            "attachments",
            "message_attachments",
            "conversation_sources",
            "agent_runs",
            "tool_calls",
            "case_change_proposals",
            "case_assistant_pending_outputs",
            "operation_audit",
        ] {
            assert_eq!(
                sqlite_master_count(&connection, table),
                1,
                "v11 table {table} must exist exactly once"
            );
        }
        for index in [
            "idx_conversations_updated",
            "idx_conversations_project_updated",
            "idx_artifacts_conversation_updated",
            "idx_artifacts_project_updated",
            "idx_artifact_versions_created",
            "idx_attachments_project_created",
            "idx_messages_conversation_created",
            "idx_messages_run",
            "idx_message_attachments_attachment",
            "idx_conversation_sources_source",
            "idx_agent_runs_conversation_created",
            "idx_agent_runs_status",
            "idx_tool_calls_status",
            "idx_case_change_proposals_conversation_created",
            "idx_case_change_proposals_project_status",
            "idx_case_assistant_pending_outputs_conversation_created",
            "idx_case_assistant_pending_outputs_project_status",
            "idx_operation_audit_idempotency",
            "idx_operation_audit_project_created",
            "idx_legal_answer_records_conversation_created",
        ] {
            assert_eq!(
                sqlite_master_count(&connection, index),
                1,
                "v11 index {index} must exist exactly once"
            );
        }
        for trigger in [
            "trg_retired_case_project_ids_authorized_insert",
            "trg_retired_case_project_ids_no_update",
            "trg_retired_case_project_ids_no_delete",
            "trg_projects_reject_retired_id",
            "trg_projects_require_retirement_before_delete",
            "trg_projects_detach_assistant_data_before_delete",
            "trg_artifacts_scope_insert",
            "trg_artifacts_scope_update",
            "trg_messages_artifact_run_scope_insert",
            "trg_messages_artifact_run_scope_update",
            "trg_agent_runs_message_scope_insert",
            "trg_agent_runs_message_scope_update",
            "trg_case_change_proposals_scope_insert",
            "trg_case_change_proposals_scope_update",
            "trg_conversations_scope_immutable",
            "trg_case_assistant_pending_outputs_closed_contract_insert",
            "trg_case_assistant_pending_outputs_scope_insert",
            "trg_case_assistant_pending_outputs_append_preserving",
            "trg_case_assistant_pending_outputs_confirmation_target",
            "trg_case_assistant_pending_outputs_no_delete",
            "trg_case_assistant_run_provider_audit_insert",
            "trg_case_assistant_run_provider_audit_update",
            "trg_case_assistant_tool_audit_insert",
            "trg_case_assistant_tool_audit_update",
            "trg_case_assistant_live_conversation_no_delete",
            "trg_case_assistant_live_run_no_delete",
            "trg_case_assistant_live_run_lineage_immutable",
            "trg_case_assistant_live_message_no_delete",
            "trg_case_assistant_live_message_lineage_immutable",
            "trg_case_assistant_live_message_attachment_no_insert",
            "trg_case_assistant_live_message_attachment_no_update",
            "trg_case_assistant_live_tool_call_no_insert",
            "trg_case_assistant_live_tool_call_no_delete",
            "trg_case_assistant_live_tool_call_immutable",
            "trg_case_assistant_confirmed_artifact_scope_immutable",
            "trg_case_assistant_confirmed_artifact_no_delete",
            "trg_case_assistant_confirmed_artifact_v1_immutable",
            "trg_case_assistant_confirmed_artifact_v1_no_delete",
            "trg_case_assistant_confirmed_proposal_scope_immutable",
            "trg_case_assistant_confirmed_proposal_no_delete",
            "trg_legal_answer_records_scope_insert",
            "trg_legal_answer_records_scope_update",
        ] {
            assert_eq!(
                sqlite_master_count(&connection, trigger),
                1,
                "v11 trigger {trigger} must exist exactly once"
            );
        }

        let nullable_answer_columns = connection
            .prepare(
                "SELECT name, \"notnull\" FROM pragma_table_info('legal_answer_records')
                 WHERE name IN ('project_id', 'conversation_id') ORDER BY name",
            )
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .expect("legal answer nullability reads");
        assert_eq!(
            nullable_answer_columns,
            vec![
                ("conversation_id".to_owned(), 0),
                ("project_id".to_owned(), 0)
            ]
        );

        let conversation_fks = table_foreign_key_contracts(&connection, "conversations")
            .expect("conversation foreign keys read");
        assert!(conversation_fks.iter().any(|contract| {
            contract.target_table == "projects"
                && contract.on_delete == "SET NULL"
                && contract.columns == vec![(0, "project_id".to_owned(), "project_id".to_owned())]
        }));
        let proposal_fks = table_foreign_key_contracts(&connection, "case_change_proposals")
            .expect("proposal foreign keys read");
        assert!(proposal_fks.iter().any(|contract| {
            contract.target_table == "projects" && contract.on_delete == "CASCADE"
        }));
        assert!(proposal_fks.iter().any(|contract| {
            contract.target_table == "conversations" && contract.on_delete == "CASCADE"
        }));
        assert!(
            table_foreign_key_contracts(&connection, "case_assistant_pending_outputs")
                .expect("pending output foreign keys read")
                .is_empty(),
            "pending output audit identifiers must remain opaque after retirement"
        );
        let audit_fks = table_foreign_key_contracts(&connection, "operation_audit")
            .expect("operation audit foreign keys read");
        assert!(audit_fks.iter().any(|contract| {
            contract.target_table == "projects" && contract.on_delete == "SET NULL"
        }));
        validate_user_database_read_only(&database_path).expect("v11 schema is canonical");
    }

    #[test]
    fn operation_audit_is_idempotent_cas_bounded_and_project_scoped() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let connection = open_user_database(&database_path).expect("database opens");
        connection
            .execute(
                "INSERT INTO projects (project_id, title, status)
                 VALUES ('audit-project', 'Audit project', 'active')",
                [],
            )
            .expect("project is seeded");

        let prepared = create_operation_audit(
            &connection,
            &NewOperationAuditRow {
                audit_id: "audit-1".to_owned(),
                origin: "mcp".to_owned(),
                operation: "case_apply_patch".to_owned(),
                project_id: Some("audit-project".to_owned()),
                request_hash: "a".repeat(64),
                idempotency_key_hash: Some("b".repeat(64)),
                details_json: r#"{"proposalHash":"redacted-hash-only"}"#.to_owned(),
            },
        )
        .expect("prepared audit is created");
        assert_eq!(prepared.status, "prepared");
        assert!(prepared.finished_at.is_none());

        let by_key = get_operation_audit_by_idempotency_key_hash(
            &connection,
            "mcp",
            "case_apply_patch",
            &"b".repeat(64),
        )
        .expect("idempotency lookup succeeds")
        .expect("audit exists");
        assert_eq!(by_key.audit_id, prepared.audit_id);

        let finished = compare_and_set_operation_audit_status(
            &connection,
            "audit-1",
            "succeeded",
            r#"{"newRevision":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}"#,
        )
        .expect("audit status update succeeds");
        assert!(matches!(
            finished,
            OperationAuditStatusUpdateResult::Updated(OperationAuditRow {
                ref status,
                finished_at: Some(_),
                ..
            }) if status == "succeeded"
        ));

        assert!(matches!(
            compare_and_set_operation_audit_status(
                &connection,
                "audit-1",
                "failed",
                r#"{"code":"late"}"#,
            )
            .expect("second status update returns conflict"),
            OperationAuditStatusUpdateResult::Conflict(_)
        ));

        let duplicate = create_operation_audit(
            &connection,
            &NewOperationAuditRow {
                audit_id: "audit-2".to_owned(),
                origin: "mcp".to_owned(),
                operation: "case_apply_patch".to_owned(),
                project_id: Some("audit-project".to_owned()),
                request_hash: "d".repeat(64),
                idempotency_key_hash: Some("b".repeat(64)),
                details_json: "{}".to_owned(),
            },
        );
        assert!(
            duplicate.is_err(),
            "idempotency key must be unique per operation"
        );

        assert!(
            delete_case_project(&connection, "audit-project", TEST_PRIVACY_DELETION_ID)
                .expect("project deletion succeeds")
        );
        let detached = get_operation_audit(&connection, "audit-1")
            .expect("audit reload succeeds")
            .expect("audit remains after project deletion");
        assert!(detached.project_id.is_none());
    }

    #[test]
    fn v8_answers_migrate_with_exact_fields_real_binding_and_precise_quarantine_cleanup() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("current database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            seed_project(&connection, "real-v8-project");
            seed_project(&connection, LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX);
            connection
                .execute(
                    "UPDATE projects SET title = 'User-owned reserved-looking project'
                     WHERE project_id = ?1",
                    [LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX],
                )
                .expect("collision fixture updates");
            for project_id in [
                "migration-unassigned-legal-answers-1",
                "migration-unassigned-legal-answers-2",
            ] {
                connection
                    .execute(
                        "INSERT INTO projects (
                             project_id, title, case_type, status, opened_on, summary
                         ) VALUES (?1, ?2, 'migration_quarantine', 'archived', NULL, ?3)",
                        params![
                            project_id,
                            LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE,
                            LEGACY_ANSWER_QUARANTINE_PROJECT_SUMMARY
                        ],
                    )
                    .expect("precise quarantine fixture inserts");
            }
            connection
                .execute(
                    "INSERT INTO case_files (
                         file_id, project_id, title, file_type, storage_reference, summary
                     ) VALUES ('quarantine-child', ?1, 'Preserved child', '', '', '')",
                    ["migration-unassigned-legal-answers-2"],
                )
                .expect("other business child inserts");

            for (record_id, project_id, question, answer, query_json) in [
                (
                    "v8-real-answer",
                    "real-v8-project",
                    "Real project question",
                    "Real project answer",
                    r#"{"keywords":["real"]}"#,
                ),
                (
                    "v8-quarantine-delete",
                    "migration-unassigned-legal-answers-1",
                    "Detached question one",
                    "",
                    r#"{"keywords":["one"]}"#,
                ),
                (
                    "v8-quarantine-keep",
                    "migration-unassigned-legal-answers-2",
                    "Detached question two",
                    "Detached answer two",
                    r#"{"keywords":["two"]}"#,
                ),
            ] {
                connection
                    .execute(
                        "INSERT INTO legal_answer_records (
                             record_id, project_id, conversation_id, provider_id,
                             provider_snapshot_json, question, answer_text, case_date,
                             query_json, source_ids_json, verified_citations_json,
                             invalid_citations_json, unsupported_legal_conclusion, created_at
                         ) VALUES (
                             ?1, ?2, NULL, 'legacy-provider', '{}', ?3, ?4, '2024-02-03',
                             ?5, '[\"source-a\"]', '[{\"sourceId\":\"source-a\"}]',
                             '[]', 0, '2026-07-15 12:34:56'
                         )",
                        params![record_id, project_id, question, answer, query_json],
                    )
                    .expect("legacy answer fixture inserts");
            }
            connection
                .execute_batch(
                    "UPDATE user_database_metadata SET value = '8'
                       WHERE key = 'schema_version';
                     UPDATE user_database_metadata
                       SET value = 'v8-fact-issue-links-20260716'
                       WHERE key = 'canonical_schema_version';",
                )
                .expect("fixture is marked v8");
        }

        ensure_user_database(directory.path()).expect("v8 database migrates to v9");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        assert_eq!(table_row_count(&connection, "legal_answer_records"), 3);

        let real = connection
            .query_row(
                "SELECT project_id, conversation_id, provider_id, question, answer_text,
                        case_date, query_json, source_ids_json, verified_citations_json,
                        invalid_citations_json, unsupported_legal_conclusion, created_at
                 FROM legal_answer_records WHERE record_id = 'v8-real-answer'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .expect("real answer reads");
        assert_eq!(real.0.as_deref(), Some("real-v8-project"));
        assert_eq!(real.1, "legacy-qa:v8-real-answer");
        assert_eq!(real.2, "legacy-provider");
        assert_eq!(real.3, "Real project question");
        assert_eq!(real.4, "Real project answer");
        assert_eq!(real.5.as_deref(), Some("2024-02-03"));
        assert_eq!(real.6, r#"{"keywords":["real"]}"#);
        assert_eq!(real.7, r#"["source-a"]"#);
        assert_eq!(real.8, r#"[{"sourceId":"source-a"}]"#);
        assert_eq!(real.9, "[]");
        assert_eq!(real.10, 0);
        assert_eq!(real.11, "2026-07-15 12:34:56");
        assert_eq!(
            get_conversation(&connection, "legacy-qa:v8-real-answer")
                .expect("real conversation reads")
                .expect("real conversation exists")
                .project_id
                .as_deref(),
            Some("real-v8-project")
        );

        for record_id in ["v8-quarantine-delete", "v8-quarantine-keep"] {
            let (project_id, conversation_id): (Option<String>, String) = connection
                .query_row(
                    "SELECT project_id, conversation_id FROM legal_answer_records
                     WHERE record_id = ?1",
                    [record_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .expect("detached answer reads");
            assert_eq!(project_id, None);
            assert_eq!(conversation_id, format!("legacy-qa:{record_id}"));
            assert_eq!(
                get_conversation(&connection, &conversation_id)
                    .expect("detached conversation reads")
                    .expect("detached conversation exists")
                    .project_id,
                None
            );
            assert_eq!(
                list_messages(&connection, &conversation_id)
                    .expect("deterministic messages read")
                    .len(),
                2
            );
        }
        assert!(
            !case_project_exists(&connection, "migration-unassigned-legal-answers-1")
                .expect("empty precise quarantine is removed")
        );
        assert!(
            case_project_exists(&connection, "migration-unassigned-legal-answers-2")
                .expect("quarantine with another child is retained")
        );
        assert!(
            case_project_exists(&connection, LEGACY_ANSWER_QUARANTINE_PROJECT_ID_PREFIX)
                .expect("user-owned reserved-looking project remains")
        );
        validate_user_database_read_only(&database_path).expect("migrated v9 is canonical");
    }

    #[test]
    fn ambiguous_quarantine_metadata_aborts_v8_rebuild_atomically() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("current database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            connection
                .execute(
                    "INSERT INTO projects (
                         project_id, title, case_type, status, opened_on, summary
                     ) VALUES (?1, ?2, 'migration_quarantine', 'archived', NULL, 'modified')",
                    params![
                        "migration-unassigned-legal-answers-3",
                        LEGACY_ANSWER_QUARANTINE_PROJECT_TITLE
                    ],
                )
                .expect("ambiguous project inserts");
            connection
                .execute_batch(
                    "UPDATE user_database_metadata SET value = '8'
                       WHERE key = 'schema_version';
                     UPDATE user_database_metadata
                       SET value = 'v8-fact-issue-links-20260716'
                       WHERE key = 'canonical_schema_version';",
                )
                .expect("fixture is marked v8");
        }

        let error = validate_and_migrate_user_database(&database_path)
            .expect_err("ambiguous quarantine must fail closed");
        assert!(error.to_string().contains("ambiguous metadata"));
        let connection = open_user_database(&database_path).expect("rolled-back database opens");
        let (version, marker): (String, String) = connection
            .query_row(
                "SELECT
                     (SELECT value FROM user_database_metadata WHERE key = 'schema_version'),
                     (SELECT value FROM user_database_metadata
                      WHERE key = 'canonical_schema_version')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("metadata reads");
        assert_eq!(version, "8");
        assert_eq!(marker, "v8-fact-issue-links-20260716");
        let summary: String = connection
            .query_row(
                "SELECT summary FROM projects
                 WHERE project_id = 'migration-unassigned-legal-answers-3'",
                [],
                |row| row.get(0),
            )
            .expect("ambiguous project survives rollback");
        assert_eq!(summary, "modified");
        assert_eq!(
            sqlite_master_count(&connection, "__lawyer_assistance_v6_legacy_conversations"),
            0
        );
    }

    #[test]
    fn case_free_conversation_message_attachment_and_set_null_lifecycle_work() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        let conversation = create_conversation(
            &connection,
            "conversation-free",
            None,
            "Independent research",
        )
        .expect("case-free conversation creates");
        assert_eq!(conversation.project_id, None);
        let message = create_message(
            &connection,
            &NewMessageRow {
                message_id: "message-free".to_owned(),
                conversation_id: conversation.conversation_id.clone(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "Please inspect the attachment".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("message creates");
        let attachment = NewAttachmentRow {
            attachment_id: "attachment-one".to_owned(),
            project_id: None,
            original_name: "note.txt".to_owned(),
            extension: "txt".to_owned(),
            detected_mime: "text/plain".to_owned(),
            sha256: "1".repeat(64),
            size_bytes: 3,
            content_blob: b"abc".to_vec(),
            extraction_status: "pending".to_owned(),
            extracted_text: None,
            segments_json: "[]".to_owned(),
            error_code: None,
        };
        assert!(matches!(
            insert_attachment(&connection, &attachment).expect("attachment inserts"),
            AttachmentInsertResult::Inserted(_)
        ));
        let mut duplicate = attachment.clone();
        duplicate.attachment_id = "attachment-duplicate".to_owned();
        assert!(matches!(
            insert_attachment(&connection, &duplicate).expect("duplicate resolves"),
            AttachmentInsertResult::Existing(AttachmentRow { attachment_id, .. })
                if attachment_id == "attachment-one"
        ));
        assert!(update_attachment_extraction(
            &connection,
            "attachment-one",
            "pending",
            "succeeded",
            Some("abc"),
            r#"[{"locator":"line:1","text":"abc"}]"#,
            None,
        )
        .expect("extraction CAS updates"));
        attach_to_message(&connection, &message.message_id, "attachment-one", 0)
            .expect("attachment links");
        assert_eq!(
            list_attachments_for_message(&connection, &message.message_id)
                .expect("linked attachments read")
                .len(),
            1
        );
        assert_eq!(
            delete_attachment(&mut connection, "attachment-one").expect("delete checks references"),
            AttachmentDeleteResult::InUse
        );

        seed_project(&connection, "conversation-project");
        assert!(bind_conversation_to_case(
            &connection,
            "conversation-free",
            "conversation-project"
        )
        .expect("conversation binds"));
        assert!(delete_case_project(
            &connection,
            "conversation-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("bound project deletes"));
        assert_eq!(
            get_conversation(&connection, "conversation-free")
                .expect("conversation reads")
                .expect("conversation survives project deletion")
                .project_id,
            None
        );
        assert!(
            archive_conversation(&connection, "conversation-free").expect("conversation archives")
        );
        assert!(
            !bind_conversation_to_case(&connection, "conversation-free", "missing-project")
                .expect("archived conversation cannot bind")
        );
        validate_user_database_read_only(&database_path).expect("database remains canonical");
    }

    #[test]
    fn artifact_creation_joins_an_outer_transaction_and_rolls_back_with_it() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        create_conversation(
            &connection,
            "artifact-transaction-conversation",
            None,
            "Atomic artifact",
        )
        .expect("conversation creates");

        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("outer transaction starts");
        let artifact = create_artifact(
            &transaction,
            &NewArtifactRow {
                artifact_id: "artifact-transactional".to_owned(),
                conversation_id: Some("artifact-transaction-conversation".to_owned()),
                project_id: None,
                kind: "research".to_owned(),
                title: "Transactional artifact".to_owned(),
                status: "draft".to_owned(),
            },
            &NewArtifactVersionRow {
                version_id: "artifact-transactional-v1".to_owned(),
                artifact_id: "artifact-transactional".to_owned(),
                content_json: r#"{"schemaVersion":1}"#.to_owned(),
                rendered_text: "transactional".to_owned(),
                source_refs_json: "[]".to_owned(),
                citation_report_json: "{}".to_owned(),
                provider_snapshot_json: "{}".to_owned(),
            },
        )
        .expect("artifact joins the caller transaction");
        assert_eq!(artifact.current_version, 1);
        assert!(get_artifact(&transaction, "artifact-transactional")
            .expect("artifact reads inside transaction")
            .is_some());
        transaction
            .rollback()
            .expect("outer transaction rolls back");

        assert!(get_artifact(&connection, "artifact-transactional")
            .expect("artifact reads after rollback")
            .is_none());
        assert!(
            list_artifact_versions(&connection, "artifact-transactional")
                .expect("artifact versions read after rollback")
                .is_empty()
        );

        create_artifact(
            &connection,
            &NewArtifactRow {
                artifact_id: "artifact-version-transactional".to_owned(),
                conversation_id: Some("artifact-transaction-conversation".to_owned()),
                project_id: None,
                kind: "research".to_owned(),
                title: "Transactional version".to_owned(),
                status: "draft".to_owned(),
            },
            &NewArtifactVersionRow {
                version_id: "artifact-version-transactional-v1".to_owned(),
                artifact_id: "artifact-version-transactional".to_owned(),
                content_json: r#"{"schemaVersion":1}"#.to_owned(),
                rendered_text: "v1".to_owned(),
                source_refs_json: "[]".to_owned(),
                citation_report_json: "{}".to_owned(),
                provider_snapshot_json: "{}".to_owned(),
            },
        )
        .expect("base artifact creates");
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("outer version transaction starts");
        assert!(matches!(
            create_artifact_version(
                &transaction,
                &NewArtifactVersionRow {
                    version_id: "artifact-version-transactional-v2".to_owned(),
                    artifact_id: "artifact-version-transactional".to_owned(),
                    content_json: r#"{"schemaVersion":1}"#.to_owned(),
                    rendered_text: "v2".to_owned(),
                    source_refs_json: "[]".to_owned(),
                    citation_report_json: "{}".to_owned(),
                    provider_snapshot_json: "{}".to_owned(),
                },
                1,
            )
            .expect("version joins outer transaction"),
            ArtifactVersionCreateResult::Created(_)
        ));
        transaction
            .rollback()
            .expect("outer version transaction rolls back");
        assert_eq!(
            get_artifact(&connection, "artifact-version-transactional")
                .expect("artifact reads")
                .expect("artifact remains")
                .current_version,
            1
        );
        assert_eq!(
            list_artifact_versions(&connection, "artifact-version-transactional")
                .expect("versions read")
                .len(),
            1
        );
    }

    #[test]
    fn artifact_versions_are_append_only_cas_and_survive_canonical_rebuild() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            create_conversation(&connection, "artifact-conversation", None, "Artifact work")
                .expect("conversation creates");
            let artifact = create_artifact(
                &connection,
                &NewArtifactRow {
                    artifact_id: "artifact-one".to_owned(),
                    conversation_id: Some("artifact-conversation".to_owned()),
                    project_id: None,
                    kind: "document".to_owned(),
                    title: "Draft document".to_owned(),
                    status: "draft".to_owned(),
                },
                &NewArtifactVersionRow {
                    version_id: "artifact-version-one".to_owned(),
                    artifact_id: "artifact-one".to_owned(),
                    content_json: r#"{"schemaVersion":1,"body":"one"}"#.to_owned(),
                    rendered_text: "version one".to_owned(),
                    source_refs_json: "[]".to_owned(),
                    citation_report_json: "{}".to_owned(),
                    provider_snapshot_json: "{}".to_owned(),
                },
            )
            .expect("artifact and version one create atomically");
            assert_eq!(artifact.current_version, 1);
            let second = NewArtifactVersionRow {
                version_id: "artifact-version-two".to_owned(),
                artifact_id: "artifact-one".to_owned(),
                content_json: r#"{"schemaVersion":1,"body":"two"}"#.to_owned(),
                rendered_text: "version two".to_owned(),
                source_refs_json: "[]".to_owned(),
                citation_report_json: "{}".to_owned(),
                provider_snapshot_json: "{}".to_owned(),
            };
            assert!(matches!(
                create_artifact_version(&connection, &second, 1).expect("second version appends"),
                ArtifactVersionCreateResult::Created(ArtifactVersionRow {
                    version_number: 2,
                    ..
                })
            ));
            let stale = NewArtifactVersionRow {
                version_id: "artifact-version-stale".to_owned(),
                ..second.clone()
            };
            assert_eq!(
                create_artifact_version(&connection, &stale, 1).expect("stale CAS is reported"),
                ArtifactVersionCreateResult::Conflict
            );
            assert_eq!(
                list_artifact_versions(&connection, "artifact-one")
                    .unwrap()
                    .len(),
                2
            );
            connection
                .execute(
                    "UPDATE user_database_metadata SET value = 'precanonical-v9'
                     WHERE key = 'canonical_schema_version'",
                    [],
                )
                .expect("marker is made stale");
        }

        ensure_user_database(directory.path()).expect("canonical v9 rebuild succeeds");
        let connection = open_user_database(&database_path).expect("rebuilt database opens");
        assert_eq!(
            get_artifact(&connection, "artifact-one")
                .expect("artifact reads")
                .expect("artifact survives")
                .current_version,
            2
        );
        assert_eq!(
            list_artifact_versions(&connection, "artifact-one")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            sqlite_master_count(&connection, "__lawyer_assistance_v6_legacy_artifacts"),
            0
        );
        validate_user_database_read_only(&database_path).expect("rebuilt database is canonical");
    }

    #[test]
    fn run_tool_and_proposal_statuses_use_cas_and_support_transaction_rollback() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "proposal-project");
        seed_project(&connection, "other-project");
        create_conversation(
            &connection,
            "proposal-conversation",
            Some("proposal-project"),
            "Case analysis",
        )
        .expect("conversation creates");
        create_message(
            &connection,
            &NewMessageRow {
                message_id: "proposal-user-message".to_owned(),
                conversation_id: "proposal-conversation".to_owned(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "Analyze this case".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("user message creates");
        create_agent_run(
            &connection,
            &NewAgentRunRow {
                run_id: "agent-run-one".to_owned(),
                conversation_id: "proposal-conversation".to_owned(),
                user_message_id: "proposal-user-message".to_owned(),
                provider_id: None,
                provider_snapshot_json: "{}".to_owned(),
                intent: "case_analysis".to_owned(),
                status: "queued".to_owned(),
                budget_json: r#"{"maxToolCalls":8}"#.to_owned(),
            },
        )
        .expect("agent run creates");
        create_tool_call(
            &connection,
            &NewToolCallRow {
                tool_call_id: "tool-call-one".to_owned(),
                run_id: "agent-run-one".to_owned(),
                ordinal: 0,
                capability_name: "case.read".to_owned(),
                status: "queued".to_owned(),
                access_mode: "read".to_owned(),
                requires_confirmation: false,
                input_audit_json: r#"{"projectId":"proposal-project"}"#.to_owned(),
                output_audit_json: "{}".to_owned(),
                source_audit_json: "[]".to_owned(),
            },
        )
        .expect("tool call creates");
        assert!(matches!(
            compare_and_set_agent_run_status(
                &connection,
                "agent-run-one",
                "queued",
                "running",
                None,
                None,
            )
            .expect("run starts"),
            AgentRunStatusUpdateResult::Updated(AgentRunRow { status, .. }) if status == "running"
        ));
        assert!(matches!(
            compare_and_set_tool_call_status(
                &connection,
                "tool-call-one",
                "queued",
                "running",
                "{}",
                "[]",
                None,
            )
            .expect("tool starts"),
            ToolCallStatusUpdateResult::Updated(ToolCallRow { status, .. }) if status == "running"
        ));
        assert!(matches!(
            compare_and_set_tool_call_status(
                &connection,
                "tool-call-one",
                "running",
                "succeeded",
                r#"{"entityCount":1}"#,
                "[]",
                None,
            )
            .expect("tool succeeds"),
            ToolCallStatusUpdateResult::Updated(ToolCallRow {
                finished_at: Some(_),
                ..
            })
        ));
        create_message(
            &connection,
            &NewMessageRow {
                message_id: "proposal-assistant-message".to_owned(),
                conversation_id: "proposal-conversation".to_owned(),
                role: "assistant".to_owned(),
                kind: "proposal_ref".to_owned(),
                text_summary: "A pending proposal is ready".to_owned(),
                artifact_id: None,
                run_id: Some("agent-run-one".to_owned()),
            },
        )
        .expect("assistant message creates");
        assert!(matches!(
            compare_and_set_agent_run_status(
                &connection,
                "agent-run-one",
                "running",
                "succeeded",
                Some("proposal-assistant-message"),
                None,
            )
            .expect("run succeeds"),
            AgentRunStatusUpdateResult::Updated(AgentRunRow {
                finished_at: Some(_),
                ..
            })
        ));

        let digest = "a".repeat(64);
        create_case_change_proposal(
            &connection,
            &NewCaseChangeProposalRow {
                proposal_id: "proposal-one".to_owned(),
                conversation_id: "proposal-conversation".to_owned(),
                project_id: "proposal-project".to_owned(),
                run_id: Some("agent-run-one".to_owned()),
                base_case_digest: digest.clone(),
                changes_json: r#"{"facts":[]}"#.to_owned(),
                source_refs_json: "[]".to_owned(),
            },
        )
        .expect("pending proposal creates");
        assert_eq!(table_row_count(&connection, "case_facts"), 0);
        let cross_project = create_case_change_proposal(
            &connection,
            &NewCaseChangeProposalRow {
                proposal_id: "proposal-cross-project".to_owned(),
                conversation_id: "proposal-conversation".to_owned(),
                project_id: "other-project".to_owned(),
                run_id: None,
                base_case_digest: digest.clone(),
                changes_json: "{}".to_owned(),
                source_refs_json: "[]".to_owned(),
            },
        )
        .expect_err("cross-project proposal is rejected");
        assert!(cross_project
            .to_string()
            .contains("case proposal must match"));

        {
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("apply transaction starts");
            assert!(matches!(
                compare_and_set_case_change_proposal_status(
                    &transaction,
                    "proposal-one",
                    "proposal-project",
                    &digest,
                    "applied",
                )
                .expect("proposal is claimed inside transaction"),
                CaseChangeProposalStatusUpdateResult::Updated(_)
            ));
            transaction
                .rollback()
                .expect("simulated apply failure rolls back");
        }
        assert_eq!(
            get_case_change_proposal(&connection, "proposal-one")
                .expect("proposal reads")
                .expect("proposal remains")
                .status,
            "pending"
        );
        assert!(matches!(
            compare_and_set_case_change_proposal_status(
                &connection,
                "proposal-one",
                "proposal-project",
                &digest,
                "applied",
            )
            .expect("proposal applies"),
            CaseChangeProposalStatusUpdateResult::Updated(CaseChangeProposalRow {
                status,
                applied_at: Some(_),
                ..
            }) if status == "applied"
        ));
        assert!(matches!(
            compare_and_set_case_change_proposal_status(
                &connection,
                "proposal-one",
                "proposal-project",
                &digest,
                "rejected",
            )
            .expect("repeat decision conflicts"),
            CaseChangeProposalStatusUpdateResult::Conflict(_)
        ));
        assert_eq!(table_row_count(&connection, "case_facts"), 0);
        validate_user_database_read_only(&database_path).expect("lifecycle database is canonical");
    }

    #[test]
    fn answer_and_message_scope_triggers_reject_cross_conversation_ownership() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "scope-project-a");
        seed_project(&connection, "scope-project-b");
        create_conversation(
            &connection,
            "scope-conversation-a",
            Some("scope-project-a"),
            "Scope A",
        )
        .expect("bound conversation creates");
        create_conversation(
            &connection,
            "scope-conversation-b",
            Some("scope-project-b"),
            "Scope B",
        )
        .expect("other bound conversation creates");
        create_conversation(&connection, "scope-conversation-free", None, "Scope free")
            .expect("unbound conversation creates");

        let legal_record = |record_id: &str, project_id: Option<&str>| LegalAnswerRecordRow {
            record_id: record_id.to_owned(),
            project_id: project_id.map(str::to_owned),
            provider_id: "scope-provider".to_owned(),
            provider_snapshot_json: provider_snapshot_json(),
            question: "Scope question".to_owned(),
            answer_text: "Scope answer".to_owned(),
            case_date: None,
            query_json: "{}".to_owned(),
            source_ids_json: "[]".to_owned(),
            verified_citations_json: "[]".to_owned(),
            invalid_citations_json: "[]".to_owned(),
            unsupported_legal_conclusion: false,
            created_at: String::new(),
        };
        insert_legal_answer_record_for_conversation(
            &connection,
            &legal_record("answer-free-valid", None),
            "scope-conversation-free",
        )
        .expect("unbound answer matches unbound conversation");
        insert_legal_answer_record_for_conversation(
            &connection,
            &legal_record("answer-bound-valid", Some("scope-project-a")),
            "scope-conversation-a",
        )
        .expect("bound answer matches bound conversation");
        for (record_id, project_id, conversation_id) in [
            ("answer-bound-null", None, "scope-conversation-a"),
            (
                "answer-free-project",
                Some("scope-project-a"),
                "scope-conversation-free",
            ),
            (
                "answer-cross-project",
                Some("scope-project-b"),
                "scope-conversation-a",
            ),
        ] {
            let error = insert_legal_answer_record_for_conversation(
                &connection,
                &legal_record(record_id, project_id),
                conversation_id,
            )
            .expect_err("answer ownership mismatch is rejected");
            assert!(error
                .to_string()
                .contains("legal answer project must match"));
        }

        for (conversation_id, message_id, run_id) in [
            ("scope-conversation-a", "scope-user-a", "scope-run-a"),
            ("scope-conversation-b", "scope-user-b", "scope-run-b"),
        ] {
            create_message(
                &connection,
                &NewMessageRow {
                    message_id: message_id.to_owned(),
                    conversation_id: conversation_id.to_owned(),
                    role: "user".to_owned(),
                    kind: "text".to_owned(),
                    text_summary: "User message".to_owned(),
                    artifact_id: None,
                    run_id: None,
                },
            )
            .expect("user message creates");
            create_agent_run(
                &connection,
                &NewAgentRunRow {
                    run_id: run_id.to_owned(),
                    conversation_id: conversation_id.to_owned(),
                    user_message_id: message_id.to_owned(),
                    provider_id: None,
                    provider_snapshot_json: "{}".to_owned(),
                    intent: "file_analysis".to_owned(),
                    status: "queued".to_owned(),
                    budget_json: "{}".to_owned(),
                },
            )
            .expect("run creates");
        }
        let insert_error = connection
            .execute(
                "INSERT INTO messages (
                     message_id, conversation_id, role, kind, text_summary, run_id
                 ) VALUES (
                     'scope-cross-run-message', 'scope-conversation-a',
                     'assistant', 'text', '', 'scope-run-b'
                 )",
                [],
            )
            .expect_err("cross-conversation run insert is rejected");
        assert!(insert_error
            .to_string()
            .contains("message artifact and run must remain"));
        let update_error = connection
            .execute(
                "UPDATE messages SET run_id = 'scope-run-b'
                 WHERE message_id = 'scope-user-a'",
                [],
            )
            .expect_err("cross-conversation run update is rejected");
        assert!(update_error
            .to_string()
            .contains("message artifact and run must remain"));

        assert!(
            delete_case_project(&connection, "scope-project-a", TEST_PRIVACY_DELETION_ID)
                .expect("project deletion succeeds with strict scope triggers")
        );
        assert_eq!(
            get_conversation(&connection, "scope-conversation-a")
                .unwrap()
                .unwrap()
                .project_id,
            None
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT project_id FROM legal_answer_records
                     WHERE record_id = 'answer-bound-valid'",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )
                .expect("detached answer reads"),
            None
        );
        validate_user_database_read_only(&database_path).expect("scope database is canonical");
    }

    #[test]
    fn artifact_project_scope_blocks_cross_case_bind_and_message_reference() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "artifact-project-a");
        seed_project(&connection, "artifact-project-b");
        create_conversation(
            &connection,
            "artifact-bound-a",
            Some("artifact-project-a"),
            "Bound A",
        )
        .expect("bound conversation creates");
        create_conversation(&connection, "artifact-free-transfer", None, "Free transfer")
            .expect("free conversation creates");

        let initial_version = |version_id: &str, artifact_id: &str| NewArtifactVersionRow {
            version_id: version_id.to_owned(),
            artifact_id: artifact_id.to_owned(),
            content_json: "{}".to_owned(),
            rendered_text: String::new(),
            source_refs_json: "[]".to_owned(),
            citation_report_json: "{}".to_owned(),
            provider_snapshot_json: "{}".to_owned(),
        };
        create_artifact(
            &connection,
            &NewArtifactRow {
                artifact_id: "artifact-cross-create".to_owned(),
                conversation_id: Some("artifact-bound-a".to_owned()),
                project_id: Some("artifact-project-b".to_owned()),
                kind: "research".to_owned(),
                title: "Cross create".to_owned(),
                status: "draft".to_owned(),
            },
            &initial_version("artifact-cross-create-v1", "artifact-cross-create"),
        )
        .expect_err("cross-project artifact create is rejected");

        create_artifact(
            &connection,
            &NewArtifactRow {
                artifact_id: "artifact-transferred-b".to_owned(),
                conversation_id: Some("artifact-free-transfer".to_owned()),
                project_id: Some("artifact-project-b".to_owned()),
                kind: "research".to_owned(),
                title: "Transferred B".to_owned(),
                status: "draft".to_owned(),
            },
            &initial_version("artifact-transferred-b-v1", "artifact-transferred-b"),
        )
        .expect("unbound conversation may retain transferred artifact");
        assert!(!bind_conversation_to_case(
            &connection,
            "artifact-free-transfer",
            "artifact-project-a"
        )
        .expect("cross-case conversation bind is refused"));
        assert!(bind_conversation_to_case(
            &connection,
            "artifact-free-transfer",
            "artifact-project-b"
        )
        .expect("matching conversation bind succeeds"));

        create_artifact(
            &connection,
            &NewArtifactRow {
                artifact_id: "artifact-bound-unowned".to_owned(),
                conversation_id: Some("artifact-bound-a".to_owned()),
                project_id: None,
                kind: "map".to_owned(),
                title: "Bound unowned".to_owned(),
                status: "draft".to_owned(),
            },
            &initial_version("artifact-bound-unowned-v1", "artifact-bound-unowned"),
        )
        .expect("case-neutral artifact creates in bound conversation");
        assert!(!bind_artifact_to_case(
            &connection,
            "artifact-bound-unowned",
            "artifact-project-b"
        )
        .expect("cross-case artifact bind is refused"));
        assert!(
            bind_artifact_to_case(&connection, "artifact-bound-unowned", "artifact-project-a")
                .expect("matching artifact bind succeeds")
        );

        create_artifact(
            &connection,
            &NewArtifactRow {
                artifact_id: "artifact-independent-b".to_owned(),
                conversation_id: None,
                project_id: Some("artifact-project-b".to_owned()),
                kind: "document".to_owned(),
                title: "Independent B".to_owned(),
                status: "draft".to_owned(),
            },
            &initial_version("artifact-independent-b-v1", "artifact-independent-b"),
        )
        .expect("independent transferred artifact creates");
        let reference_error = create_message(
            &connection,
            &NewMessageRow {
                message_id: "artifact-cross-reference".to_owned(),
                conversation_id: "artifact-bound-a".to_owned(),
                role: "assistant".to_owned(),
                kind: "artifact_ref".to_owned(),
                text_summary: "Cross reference".to_owned(),
                artifact_id: Some("artifact-independent-b".to_owned()),
                run_id: None,
            },
        )
        .expect_err("bound case cannot reference another case artifact");
        assert!(reference_error
            .to_string()
            .contains("message artifact and run must remain"));
        validate_user_database_read_only(&database_path).expect("artifact scope remains canonical");
    }

    #[test]
    fn case_workspace_digest_is_stable_complete_and_transaction_aware() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "digest-project");
        let party = |party_id: &str, name: &str, notes: &str| CasePartyRow {
            party_id: party_id.to_owned(),
            project_id: "digest-project".to_owned(),
            name: name.to_owned(),
            normalized_name: name.to_lowercase(),
            role: "other".to_owned(),
            contact: String::new(),
            notes: notes.to_owned(),
        };
        upsert_case_party(&connection, &party("party-b", "Beta", ""))
            .expect("party B inserts first");
        upsert_case_party(&connection, &party("party-a", "Alpha", ""))
            .expect("party A inserts second");
        let first = case_workspace_digest(&connection, "digest-project")
            .expect("digest computes")
            .expect("project exists");
        assert_eq!(first.len(), 64);

        connection
            .execute(
                "DELETE FROM case_parties WHERE project_id = 'digest-project'",
                [],
            )
            .expect("parties clear");
        upsert_case_party(&connection, &party("party-a", "Alpha", ""))
            .expect("party A reinserts first");
        upsert_case_party(&connection, &party("party-b", "Beta", ""))
            .expect("party B reinserts second");
        let reordered = case_workspace_digest(&connection, "digest-project")
            .expect("reordered digest computes")
            .expect("project exists");
        assert_eq!(
            first, reordered,
            "row insertion order must not affect digest"
        );

        upsert_case_party(&connection, &party("party-a", "Alpha", "changed"))
            .expect("business field changes");
        let changed = case_workspace_digest(&connection, "digest-project")
            .expect("changed digest computes")
            .expect("project exists");
        assert_ne!(
            first, changed,
            "any covered business field must change digest"
        );
        assert_eq!(
            case_workspace_digest(&connection, "missing-project").expect("missing lookup succeeds"),
            None
        );
        assert_eq!(
            get_case_workspace_rows_with_digest(&connection, "missing-project")
                .expect("missing combined lookup succeeds"),
            None
        );

        let before_artifact = case_workspace_digest(&connection, "digest-project")
            .expect("pre-artifact digest computes")
            .expect("project exists");
        create_artifact(
            &connection,
            &NewArtifactRow {
                artifact_id: "digest-artifact".to_owned(),
                conversation_id: None,
                project_id: Some("digest-project".to_owned()),
                kind: "research".to_owned(),
                title: "Digest artifact".to_owned(),
                status: "draft".to_owned(),
            },
            &NewArtifactVersionRow {
                version_id: "digest-artifact-v1".to_owned(),
                artifact_id: "digest-artifact".to_owned(),
                content_json: "{}".to_owned(),
                rendered_text: String::new(),
                source_refs_json: "[]".to_owned(),
                citation_report_json: "{}".to_owned(),
                provider_snapshot_json: "{}".to_owned(),
            },
        )
        .expect("project artifact creates");
        let after_artifact = case_workspace_digest(&connection, "digest-project")
            .expect("artifact digest computes")
            .expect("project exists");
        assert_ne!(before_artifact, after_artifact);
        connection
            .execute(
                "UPDATE artifacts SET title = 'Changed artifact title'
                 WHERE artifact_id = 'digest-artifact'",
                [],
            )
            .expect("artifact title changes");
        let after_artifact_title = case_workspace_digest(&connection, "digest-project")
            .expect("artifact title digest computes")
            .expect("project exists");
        assert_ne!(after_artifact, after_artifact_title);

        let (combined_workspace, combined_digest) =
            get_case_workspace_rows_with_digest(&connection, "digest-project")
                .expect("combined snapshot reads")
                .expect("project exists");
        assert_eq!(combined_workspace.project.project_id, "digest-project");
        assert_eq!(
            combined_digest,
            case_workspace_digest(&connection, "digest-project")
                .expect("standalone digest reads")
                .expect("project exists")
        );

        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("outer proposal transaction starts");
        let before = case_workspace_digest(&transaction, "digest-project")
            .expect("digest works inside transaction")
            .expect("project exists");
        let (_, combined_before) =
            get_case_workspace_rows_with_digest(&transaction, "digest-project")
                .expect("combined snapshot works inside transaction")
                .expect("project exists");
        assert_eq!(before, combined_before);
        upsert_case_fact(
            &transaction,
            &CaseFactRow {
                fact_id: "digest-fact".to_owned(),
                project_id: "digest-project".to_owned(),
                occurred_on: None,
                title: "Digest fact".to_owned(),
                description: "Changed in transaction".to_owned(),
                source: "test".to_owned(),
                confirmation_status: "confirmed".to_owned(),
            },
        )
        .expect("transactional fact inserts");
        let after = case_workspace_digest(&transaction, "digest-project")
            .expect("updated digest works inside transaction")
            .expect("project exists");
        assert_ne!(before, after);
        let (combined_after_workspace, combined_after) =
            get_case_workspace_rows_with_digest(&transaction, "digest-project")
                .expect("updated combined snapshot works inside transaction")
                .expect("project exists");
        assert_eq!(after, combined_after);
        assert!(combined_after_workspace
            .facts
            .iter()
            .any(|fact| fact.fact_id == "digest-fact"));
        transaction
            .rollback()
            .expect("fixture transaction rolls back");
    }

    #[test]
    fn attachment_references_delete_guards_and_atomic_case_claims_are_canonical() {
        assert_eq!(
            attachment_storage_reference("bare-id"),
            "attachment:bare-id"
        );
        assert_eq!(
            attachment_storage_reference("attachment:canonical-id"),
            "attachment:canonical-id"
        );

        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "claim-project-a");
        seed_project(&connection, "claim-project-b");
        create_conversation(
            &connection,
            "claim-conversation-a",
            Some("claim-project-a"),
            "Claim A",
        )
        .expect("conversation A creates");
        create_conversation(
            &connection,
            "claim-conversation-b",
            Some("claim-project-b"),
            "Claim B",
        )
        .expect("conversation B creates");
        create_conversation(&connection, "claim-conversation-free", None, "Claim free")
            .expect("free conversation creates");

        let insert_message =
            |connection: &rusqlite::Connection, message_id: &str, conversation_id: &str| {
                create_message(
                    connection,
                    &NewMessageRow {
                        message_id: message_id.to_owned(),
                        conversation_id: conversation_id.to_owned(),
                        role: "user".to_owned(),
                        kind: "text".to_owned(),
                        text_summary: "claim fixture".to_owned(),
                        artifact_id: None,
                        run_id: None,
                    },
                )
                .expect("message creates");
            };
        insert_message(&connection, "claim-message-a", "claim-conversation-a");
        insert_message(&connection, "claim-message-b", "claim-conversation-b");
        insert_message(&connection, "claim-message-free", "claim-conversation-free");

        let insert_claim_attachment =
            |connection: &rusqlite::Connection, attachment_id: &str, sha256: &str| {
                insert_attachment(
                    connection,
                    &NewAttachmentRow {
                        attachment_id: attachment_id.to_owned(),
                        project_id: None,
                        original_name: format!("{attachment_id}.txt"),
                        extension: "txt".to_owned(),
                        detected_mime: "text/plain".to_owned(),
                        sha256: format!("{sha256:0<64}"),
                        size_bytes: 1,
                        content_blob: vec![1],
                        extraction_status: "succeeded".to_owned(),
                        extracted_text: Some("x".to_owned()),
                        segments_json: "[]".to_owned(),
                        error_code: None,
                    },
                )
                .expect("attachment inserts");
            };
        insert_claim_attachment(&connection, "attachment:claim-a", "claim-sha-a");
        attach_to_message(&connection, "claim-message-a", "attachment:claim-a", 0)
            .expect("attachment links to A");
        assert!(attachment_can_be_claimed_for_case(
            &connection,
            "attachment:claim-a",
            "claim-project-a"
        )
        .expect("claim eligibility reads"));
        assert!(
            claim_attachment_for_case(&connection, "attachment:claim-a", "claim-project-a")
                .expect("claim succeeds")
        );
        assert!(
            !claim_attachment_for_case(&connection, "attachment:claim-a", "claim-project-a")
                .expect("second NULL-to-project claim is refused")
        );

        insert_claim_attachment(&connection, "attachment:claim-cross", "claim-sha-cross");
        attach_to_message(&connection, "claim-message-a", "attachment:claim-cross", 0)
            .expect("cross attachment links to A");
        attach_to_message(&connection, "claim-message-b", "attachment:claim-cross", 0)
            .expect("cross attachment links to B");
        assert!(!attachment_can_be_claimed_for_case(
            &connection,
            "attachment:claim-cross",
            "claim-project-a"
        )
        .expect("cross-project eligibility reads"));
        assert!(!claim_attachment_for_case(
            &connection,
            "attachment:claim-cross",
            "claim-project-a"
        )
        .expect("cross-project claim is refused"));

        insert_claim_attachment(&connection, "attachment:claim-free", "claim-sha-free");
        attach_to_message(
            &connection,
            "claim-message-free",
            "attachment:claim-free",
            0,
        )
        .expect("free attachment links");
        assert!(!attachment_can_be_claimed_for_case(
            &connection,
            "attachment:claim-free",
            "claim-project-a"
        )
        .expect("unbound conversation eligibility reads"));

        for (index, storage_reference) in [
            "delete-reference-raw".to_owned(),
            "attachment:delete-reference-canonical".to_owned(),
            "attachment:attachment:delete-reference-double".to_owned(),
        ]
        .into_iter()
        .enumerate()
        {
            let attachment_id = match index {
                0 => "delete-reference-raw",
                1 => "delete-reference-canonical",
                _ => "delete-reference-double",
            };
            insert_claim_attachment(&connection, attachment_id, &format!("delete-sha-{index}"));
            upsert_case_file(
                &connection,
                &CaseFileRow {
                    file_id: format!("delete-file-{index}"),
                    project_id: "claim-project-a".to_owned(),
                    title: "Delete guard".to_owned(),
                    file_type: "txt".to_owned(),
                    storage_reference,
                    summary: String::new(),
                    created_at: String::new(),
                },
            )
            .expect("case file inserts");
            assert_eq!(
                delete_attachment(&mut connection, attachment_id).expect("delete guard checks"),
                AttachmentDeleteResult::InUse
            );
        }

        insert_claim_attachment(
            &connection,
            "delete-artifact-reference",
            "delete-sha-artifact",
        );
        create_artifact(
            &connection,
            &NewArtifactRow {
                artifact_id: "delete-reference-artifact".to_owned(),
                conversation_id: Some("claim-conversation-a".to_owned()),
                project_id: Some("claim-project-a".to_owned()),
                kind: "research".to_owned(),
                title: "Delete reference artifact".to_owned(),
                status: "draft".to_owned(),
            },
            &NewArtifactVersionRow {
                version_id: "delete-reference-artifact-v1".to_owned(),
                artifact_id: "delete-reference-artifact".to_owned(),
                content_json: "{}".to_owned(),
                rendered_text: String::new(),
                source_refs_json: r#"["delete-artifact-reference"]"#.to_owned(),
                citation_report_json: "{}".to_owned(),
                provider_snapshot_json: "{}".to_owned(),
            },
        )
        .expect("artifact reference inserts");
        assert_eq!(
            delete_attachment(&mut connection, "delete-artifact-reference")
                .expect("artifact delete guard checks"),
            AttachmentDeleteResult::InUse
        );

        for (index, status) in ["pending", "rejected", "applied"].into_iter().enumerate() {
            let attachment_id = format!("delete-proposal-{status}");
            insert_claim_attachment(
                &connection,
                &attachment_id,
                &format!("delete-sha-proposal-{index}"),
            );
            let proposal_id = format!("delete-reference-proposal-{status}");
            let digest = format!("{index:0<64}");
            create_case_change_proposal(
                &connection,
                &NewCaseChangeProposalRow {
                    proposal_id: proposal_id.clone(),
                    conversation_id: "claim-conversation-a".to_owned(),
                    project_id: "claim-project-a".to_owned(),
                    run_id: None,
                    base_case_digest: digest.clone(),
                    changes_json: "{}".to_owned(),
                    source_refs_json: serde_json::to_string(&[&attachment_id])
                        .expect("source reference serializes"),
                },
            )
            .expect("proposal reference inserts");
            if status != "pending" {
                assert!(matches!(
                    compare_and_set_case_change_proposal_status(
                        &connection,
                        &proposal_id,
                        "claim-project-a",
                        &digest,
                        status,
                    )
                    .expect("proposal status changes"),
                    CaseChangeProposalStatusUpdateResult::Updated(_)
                ));
            }
            assert_eq!(
                delete_attachment(&mut connection, &attachment_id)
                    .expect("proposal delete guard checks"),
                AttachmentDeleteResult::InUse,
                "{status} proposals retain their source audit references"
            );
        }
    }

    #[test]
    fn conversation_attachment_delete_serializes_a_concurrent_reference_writer() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        let mut writer = open_user_database(&database_path).expect("writer opens");
        create_conversation(&writer, "delete-race-conversation", None, "Delete race")
            .expect("conversation creates");
        create_message(
            &writer,
            &NewMessageRow {
                message_id: "delete-race-message".to_owned(),
                conversation_id: "delete-race-conversation".to_owned(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "race fixture".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("message creates");
        insert_attachment(
            &writer,
            &NewAttachmentRow {
                attachment_id: "delete-race-attachment".to_owned(),
                project_id: None,
                original_name: "race.txt".to_owned(),
                extension: "txt".to_owned(),
                detected_mime: "text/plain".to_owned(),
                sha256: "9".repeat(64),
                size_bytes: 4,
                content_blob: b"race".to_vec(),
                extraction_status: "succeeded".to_owned(),
                extracted_text: Some("race".to_owned()),
                segments_json: "[]".to_owned(),
                error_code: None,
            },
        )
        .expect("attachment inserts");
        attach_to_message(&writer, "delete-race-message", "delete-race-attachment", 0)
            .expect("attachment links");

        let write_transaction = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("reference writer takes the write lock");
        let delete_path = database_path.clone();
        let (attempt_tx, attempt_rx) = std::sync::mpsc::channel();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let delete_thread = std::thread::spawn(move || {
            let mut connection = open_user_database(&delete_path).expect("deleter opens");
            connection
                .busy_timeout(std::time::Duration::from_secs(5))
                .expect("busy timeout configures");
            attempt_tx.send(()).expect("attempt signal sends");
            let result = delete_attachment_from_conversation(
                &mut connection,
                "delete-race-conversation",
                "delete-race-attachment",
            );
            result_tx.send(result).expect("delete result sends");
        });
        attempt_rx.recv().expect("deleter begins");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(matches!(
            result_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));

        create_artifact(
            &write_transaction,
            &NewArtifactRow {
                artifact_id: "delete-race-artifact".to_owned(),
                conversation_id: Some("delete-race-conversation".to_owned()),
                project_id: None,
                kind: "research".to_owned(),
                title: "Concurrent reference".to_owned(),
                status: "draft".to_owned(),
            },
            &NewArtifactVersionRow {
                version_id: "delete-race-artifact-v1".to_owned(),
                artifact_id: "delete-race-artifact".to_owned(),
                content_json: "{}".to_owned(),
                rendered_text: String::new(),
                source_refs_json: r#"["delete-race-attachment"]"#.to_owned(),
                citation_report_json: "{}".to_owned(),
                provider_snapshot_json: "{}".to_owned(),
            },
        )
        .expect("concurrent reference inserts before the lock is released");
        write_transaction.commit().expect("reference commits");

        assert_eq!(
            result_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("delete returns")
                .expect("delete query succeeds"),
            AttachmentDeleteResult::InUse
        );
        delete_thread.join().expect("deleter joins");
        let connection = open_user_database(&database_path).expect("database reopens");
        assert!(get_attachment(&connection, "delete-race-attachment")
            .expect("attachment reads")
            .is_some());
        assert_eq!(
            list_attachments_for_message(&connection, "delete-race-message")
                .expect("message attachments read")
                .len(),
            1,
            "the in-use result rolls the conversation unlink back"
        );
    }

    #[test]
    fn claimed_v9_with_missing_index_is_rejected_without_silent_repair() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = ensure_user_database(directory.path()).expect("database is created");
        {
            let connection = open_user_database(&database_path).expect("database opens");
            connection
                .execute("DROP INDEX idx_messages_conversation_created", [])
                .expect("canonical index is removed");
        }
        let error = validate_and_migrate_user_database(&database_path)
            .expect_err("claimed-current schema damage is rejected");
        assert!(error
            .to_string()
            .contains("sqlite_master does not match the exact canonical schema"));
        let connection = open_user_database(&database_path).expect("damaged database opens raw");
        assert_eq!(
            sqlite_master_count(&connection, "idx_messages_conversation_created"),
            0,
            "validation must not silently recreate a claimed-current missing index"
        );
    }

    #[test]
    fn v10_conversations_migrate_to_authoritative_assistant_scope_without_inference() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join(USER_DB_FILE_NAME);
        let connection = rusqlite::Connection::open(&database_path).expect("legacy opens");
        connection
            .execute_batch(
                "
                CREATE TABLE user_database_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO user_database_metadata(key, value)
                VALUES('schema_version', '10');
                INSERT INTO user_database_metadata(key, value)
                VALUES('canonical_schema_version', 'v10-operation-audit-20260717');
                CREATE TABLE projects (
                    project_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                INSERT INTO projects(project_id, title, status)
                VALUES('legacy-project', 'Legacy project', 'active');
                CREATE TABLE conversations (
                    conversation_id TEXT PRIMARY KEY,
                    project_id TEXT,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                INSERT INTO conversations(
                    conversation_id, project_id, title, status, created_at, updated_at
                ) VALUES(
                    'legacy-project-conversation', 'legacy-project', 'Legacy project chat',
                    'open', '2026-07-01 01:02:03', '2026-07-02 04:05:06'
                );
                ",
            )
            .expect("v10 rows seed");
        drop(connection);

        validate_and_migrate_user_database(&database_path).expect("v10 migrates");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        let conversation = get_conversation(&connection, "legacy-project-conversation")
            .expect("assistant read succeeds")
            .expect("legacy conversation remains");
        assert_eq!(conversation.scope, ConversationScope::Assistant);
        assert_eq!(conversation.project_id.as_deref(), Some("legacy-project"));
        assert_eq!(conversation.created_at, "2026-07-01 01:02:03");
        assert_eq!(conversation.updated_at, "2026-07-02 04:05:06");
        assert!(get_case_work_conversation(
            &connection,
            "legacy-project-conversation",
            "legacy-project"
        )
        .expect("case-work read stays isolated")
        .is_none());
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM user_database_metadata WHERE key='schema_version'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .expect("schema version reads"),
            "11"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM case_assistant_pending_outputs",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .expect("pending table reads"),
            0
        );
    }

    #[test]
    fn conversation_scope_repository_apis_are_backend_isolated_and_transactional() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "scope-project-a");
        seed_project(&connection, "scope-project-b");

        create_conversation(
            &connection,
            "assistant-scoped",
            Some("scope-project-a"),
            "Assistant",
        )
        .expect("assistant conversation creates");
        create_case_work_conversation(
            &connection,
            "case-work-scoped",
            "scope-project-a",
            "Case work",
        )
        .expect("case-work conversation creates");

        assert_eq!(
            list_conversations(&connection, 100)
                .expect("assistant list succeeds")
                .iter()
                .map(|row| row.conversation_id.as_str())
                .collect::<Vec<_>>(),
            vec!["assistant-scoped"]
        );
        assert_eq!(
            list_case_work_conversations_for_project(&connection, "scope-project-a", 100)
                .expect("case-work list succeeds")
                .iter()
                .map(|row| row.conversation_id.as_str())
                .collect::<Vec<_>>(),
            vec!["case-work-scoped"]
        );
        assert!(get_conversation(&connection, "case-work-scoped")
            .expect("assistant read is isolated")
            .is_none());
        assert!(
            get_case_work_conversation(&connection, "assistant-scoped", "scope-project-a")
                .expect("case-work read is isolated")
                .is_none()
        );
        assert!(
            get_case_work_conversation(&connection, "case-work-scoped", "scope-project-b")
                .expect("cross-project case-work read is isolated")
                .is_none()
        );
        connection
            .execute(
                "UPDATE conversations SET scope='assistant'
                 WHERE conversation_id='case-work-scoped'",
                [],
            )
            .expect_err("scope conversion is forbidden");

        {
            let transaction = connection.transaction().expect("transaction begins");
            create_case_work_conversation(
                &transaction,
                "case-work-rolled-back",
                "scope-project-b",
                "Rollback",
            )
            .expect("repository API joins caller transaction");
            assert!(get_case_work_conversation(
                &transaction,
                "case-work-rolled-back",
                "scope-project-b"
            )
            .expect("transactional read succeeds")
            .is_some());
        }
        assert!(get_case_work_conversation(
            &connection,
            "case-work-rolled-back",
            "scope-project-b"
        )
        .expect("rolled-back read succeeds")
        .is_none());

        connection
            .execute(
                "UPDATE projects SET status='archived' WHERE project_id='scope-project-b'",
                [],
            )
            .expect("project archives");
        create_case_work_conversation(
            &connection,
            "case-work-archived",
            "scope-project-b",
            "Archived",
        )
        .expect_err("archived project cannot create case-work conversation");
    }

    #[test]
    fn case_assistant_canonical_payload_and_source_contracts_fail_closed() {
        let snapshots = case_assistant_source_snapshots_json();
        let snapshots_hash = sha256_hex(snapshots.as_bytes());
        validate_case_assistant_source_snapshots_json(&snapshots, &snapshots_hash)
            .expect("closed canonical snapshots validate");

        let with_private_identity = snapshots.replacen(
            "\"riskRevisionHash\"",
            "\"privacyCaseId\":\"case_forbidden\",\"riskRevisionHash\"",
            1,
        );
        validate_case_assistant_source_snapshots_json(
            &with_private_identity,
            &sha256_hex(with_private_identity.as_bytes()),
        )
        .expect_err("unknown privacy identity field is rejected");
        validate_case_assistant_source_snapshots_json(
            &format!(" {snapshots}"),
            &sha256_hex(format!(" {snapshots}").as_bytes()),
        )
        .expect_err("non-canonical source JSON is rejected");
        validate_case_assistant_source_snapshots_json(&snapshots, &"f".repeat(64))
            .expect_err("source hash drift is rejected");

        let payload = case_assistant_output_payload_json("case_document");
        validate_case_assistant_output_payload_json(
            "case_document",
            &payload,
            &sha256_hex(payload.as_bytes()),
        )
        .expect("typed output validates");
        validate_case_assistant_output_payload_json(
            "case_diagram",
            &payload,
            &sha256_hex(payload.as_bytes()),
        )
        .expect_err("row kind and typed payload kind must match");
    }

    #[test]
    fn pending_output_requires_one_closed_case_work_tool_audit() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "tool-contract-project");
        seed_case_assistant_successful_run(
            &connection,
            "tool-contract-project",
            "tool-contract-conversation",
            "tool-contract-run",
            "tool-contract-user-message",
            "tool-contract-assistant-message",
        );
        let workspace_base_digest = case_workspace_digest(&connection, "tool-contract-project")
            .expect("workspace digest computes")
            .expect("project exists");
        let snapshots = case_assistant_source_snapshots_json();
        let payload = case_assistant_output_payload_json("case_document");
        let output = NewCaseAssistantPendingOutputRow {
            pending_output_id: "tool-contract-output".to_owned(),
            project_id: "tool-contract-project".to_owned(),
            conversation_id: "tool-contract-conversation".to_owned(),
            run_id: "tool-contract-run".to_owned(),
            assistant_message_id: "tool-contract-assistant-message".to_owned(),
            project_binding_sha256: "a".repeat(64),
            source_snapshots_sha256: sha256_hex(snapshots.as_bytes()),
            source_snapshots_json: snapshots,
            expected_proposal_source_refs_json: "[]".to_owned(),
            expected_proposal_source_refs_sha256: sha256_hex(b"[]"),
            output_kind: "case_document".to_owned(),
            output_sha256: sha256_hex(payload.as_bytes()),
            output_payload_json: payload,
            output_preview: "Answer".to_owned(),
            output_version: 1,
            workspace_base_digest,
        };
        set_case_assistant_tool_audit_for_pending_output(&connection, &output);

        let mut secret_provider =
            serde_json::from_str::<serde_json::Value>(&provider_snapshot_json())
                .expect("provider snapshot parses");
        secret_provider
            .as_object_mut()
            .expect("provider snapshot is an object")
            .insert(
                "apiKey".to_owned(),
                serde_json::Value::String("must-not-persist".to_owned()),
            );
        let secret_provider =
            serde_json::to_string(&secret_provider).expect("secret provider serializes");
        create_message(
            &connection,
            &NewMessageRow {
                message_id: "tool-contract-invalid-run-user".to_owned(),
                conversation_id: "tool-contract-conversation".to_owned(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "invalid run".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("invalid run user message creates");
        let invalid_provider_insert = connection
            .execute(
                "INSERT INTO agent_runs(
                     run_id,conversation_id,user_message_id,provider_snapshot_json,
                     intent,status,budget_json
                 ) VALUES(?1,?2,?3,?4,'interactive_case_work','queued','{}')",
                params![
                    "tool-contract-invalid-run",
                    "tool-contract-conversation",
                    "tool-contract-invalid-run-user",
                    secret_provider
                ],
            )
            .expect_err("case-work run insert rejects secret provider fields");
        assert!(!invalid_provider_insert
            .to_string()
            .contains("must-not-persist"));
        connection
            .execute(
                "UPDATE agent_runs SET provider_snapshot_json=?2 WHERE run_id=?1",
                params!["tool-contract-run", secret_provider],
            )
            .expect_err("case-work run update rejects secret provider fields");

        let mut secret_input =
            serde_json::from_str::<serde_json::Value>(&case_assistant_tool_input_audit_json(
                "tool-contract-run",
                "tool-contract-project",
                "tool-contract-conversation",
                &["generation-one".to_owned()],
                &output.workspace_base_digest,
            ))
            .expect("input audit parses");
        secret_input
            .as_object_mut()
            .expect("input audit is an object")
            .insert(
                "apiKey".to_owned(),
                serde_json::Value::String("must-not-persist".to_owned()),
            );
        let secret_input =
            serde_json::to_string(&secret_input).expect("secret input audit serializes");
        connection
            .execute(
                "INSERT INTO tool_calls(
                     tool_call_id,run_id,ordinal,capability_name,status,access_mode,
                     requires_confirmation,input_audit_json,output_audit_json,
                     source_audit_json
                 ) VALUES(
                     'tool-contract-invalid-insert','tool-contract-run',1,
                     'assistant.case_work','running','write',0,?1,'{}','{}'
                 )",
                [secret_input.as_str()],
            )
            .expect_err("case-work tool insert rejects unknown secret fields");
        connection
            .execute(
                "UPDATE tool_calls
                 SET input_audit_json=json_set(input_audit_json,'$.apiKey','secret')
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work input audit update rejects unknown keys");
        connection
            .execute(
                "UPDATE tool_calls
                 SET output_audit_json=json_set(
                     output_audit_json,'$.rawBody','must-not-persist'
                 )
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work output audit update rejects raw provider bodies");
        connection
            .execute(
                "UPDATE tool_calls
                 SET source_audit_json=json_set(
                     source_audit_json,'$.sourceRefs[0]','C:\\secret\\source.txt'
                 )
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work source audit update rejects filesystem paths");
        let oversized_audit = serde_json::to_string(&serde_json::json!({
            "rawBody": "x".repeat(MAX_CASE_ASSISTANT_TOOL_AUDIT_BYTES + 1)
        }))
        .expect("oversized audit serializes");
        connection
            .execute(
                "UPDATE tool_calls SET input_audit_json=?2 WHERE tool_call_id=?1",
                params!["tool-contract-run-case-work-tool", oversized_audit],
            )
            .expect_err("case-work audit update rejects oversized JSON");
        connection
            .execute(
                "UPDATE tool_calls
                 SET input_audit_json=json_remove(
                     input_audit_json,'$.inputHashes.historySha256'
                 )
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work input audit rejects a missing nested required key");
        connection
            .execute(
                "UPDATE tool_calls
                 SET output_audit_json=json_remove(
                     output_audit_json,'$.outputCounts.bytes'
                 )
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work output audit rejects a missing nested required key");
        connection
            .execute(
                "UPDATE tool_calls
                 SET output_audit_json=json_remove(
                     output_audit_json,
                     '$.outputHashes.proposalSourceRefsSha256'
                 )
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work output audit rejects a missing proposal provenance hash");
        connection
            .execute(
                "UPDATE tool_calls
                 SET output_audit_json=json_set(
                     output_audit_json,
                     '$.outputHashes.proposalSourceRefsSha256',
                     1
                 )
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work output audit rejects a non-text proposal provenance hash");
        connection
            .execute(
                "UPDATE tool_calls
                 SET source_audit_json=json_remove(
                     source_audit_json,'$.inputHashes.aggregateSourceSha256'
                 )
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect_err("case-work source audit rejects a missing nested required key");
        assert_eq!(
            connection
                .query_row(
                    "SELECT case_assistant_sha256(?1)",
                    [&output.output_payload_json],
                    |row| row.get::<_, String>(0),
                )
                .expect("registered SHA-256 function evaluates"),
            output.output_sha256
        );

        create_message(
            &connection,
            &NewMessageRow {
                message_id: "tool-contract-second-assistant".to_owned(),
                conversation_id: "tool-contract-conversation".to_owned(),
                role: "assistant".to_owned(),
                kind: "text".to_owned(),
                text_summary: output.output_preview.clone(),
                artifact_id: None,
                run_id: Some("tool-contract-run".to_owned()),
            },
        )
        .expect("same-run second assistant message creates before pending");
        let mut second_message_output = output.clone();
        second_message_output.pending_output_id = "tool-contract-second-output".to_owned();
        second_message_output.assistant_message_id = "tool-contract-second-assistant".to_owned();
        create_case_assistant_pending_output(&connection, &second_message_output)
            .expect_err("pending output cannot select a second assistant message from the run");
        connection
            .execute(
                "DELETE FROM messages WHERE message_id='tool-contract-second-assistant'",
                [],
            )
            .expect("unselected pre-pending assistant message deletes");

        connection
            .execute(
                "UPDATE messages SET run_id='tool-contract-run'
                 WHERE message_id='tool-contract-user-message'",
                [],
            )
            .expect("pre-pending prompt can be made impure");
        create_case_assistant_pending_output(&connection, &output)
            .expect_err("run-linked user message cannot seed pending output");
        connection
            .execute(
                "UPDATE messages SET run_id=NULL
                 WHERE message_id='tool-contract-user-message'",
                [],
            )
            .expect("pure user prompt restores");

        connection
            .execute(
                "UPDATE messages SET text_summary='mismatched preview'
                 WHERE message_id='tool-contract-assistant-message'",
                [],
            )
            .expect("pre-pending assistant preview can drift");
        create_case_assistant_pending_output(&connection, &output)
            .expect_err("assistant summary must equal the pending output preview");
        connection
            .execute(
                "UPDATE messages SET text_summary='Answer'
                 WHERE message_id='tool-contract-assistant-message'",
                [],
            )
            .expect("assistant preview restores");

        let raw_insert = |candidate: &NewCaseAssistantPendingOutputRow| {
            connection.execute(
                "INSERT INTO case_assistant_pending_outputs(
                     pending_output_id,project_id,conversation_id,run_id,
                     assistant_message_id,project_binding_sha256,
                     source_snapshots_json,source_snapshots_sha256,
                     expected_proposal_source_refs_json,
                     expected_proposal_source_refs_sha256,output_kind,
                     output_payload_json,output_preview,output_sha256,
                     output_version,workspace_base_digest,status
                 ) VALUES(
                     ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,
                     'pending'
                 )",
                params![
                    candidate.pending_output_id,
                    candidate.project_id,
                    candidate.conversation_id,
                    candidate.run_id,
                    candidate.assistant_message_id,
                    candidate.project_binding_sha256,
                    candidate.source_snapshots_json,
                    candidate.source_snapshots_sha256,
                    candidate.expected_proposal_source_refs_json,
                    candidate.expected_proposal_source_refs_sha256,
                    candidate.output_kind,
                    candidate.output_payload_json,
                    candidate.output_preview,
                    candidate.output_sha256,
                    candidate.output_version,
                    candidate.workspace_base_digest,
                ],
            )
        };
        let mut forged_source = output.clone();
        forged_source.pending_output_id = "tool-contract-forged-source".to_owned();
        let mut forged_source_json =
            serde_json::from_str::<serde_json::Value>(&forged_source.source_snapshots_json)
                .expect("source snapshots parse");
        forged_source_json[0]["riskRevision"] = serde_json::json!(99);
        forged_source.source_snapshots_json =
            serde_json::to_string(&forged_source_json).expect("forged source serializes");
        raw_insert(&forged_source)
            .expect_err("raw pending insert cannot forge the source snapshot hash");

        let mut forged_output = output.clone();
        forged_output.pending_output_id = "tool-contract-forged-output".to_owned();
        let mut forged_output_json =
            serde_json::from_str::<serde_json::Value>(&forged_output.output_payload_json)
                .expect("output payload parses");
        forged_output_json["content"] = serde_json::json!({"body": "forged"});
        forged_output.output_payload_json =
            serde_json::to_string(&forged_output_json).expect("forged output serializes");
        raw_insert(&forged_output)
            .expect_err("raw pending insert cannot forge the typed output hash");

        let mut noncanonical_proposal_refs = output.clone();
        noncanonical_proposal_refs.pending_output_id =
            "tool-contract-noncanonical-proposal-refs".to_owned();
        noncanonical_proposal_refs.expected_proposal_source_refs_json = "[ ]".to_owned();
        noncanonical_proposal_refs.expected_proposal_source_refs_sha256 = sha256_hex(
            noncanonical_proposal_refs
                .expected_proposal_source_refs_json
                .as_bytes(),
        );
        raw_insert(&noncanonical_proposal_refs)
            .expect_err("raw pending insert rejects non-canonical proposal provenance JSON");

        let mut forged_proposal_refs_hash = output.clone();
        forged_proposal_refs_hash.pending_output_id =
            "tool-contract-forged-proposal-refs-hash".to_owned();
        forged_proposal_refs_hash.expected_proposal_source_refs_sha256 = "e".repeat(64);
        raw_insert(&forged_proposal_refs_hash)
            .expect_err("raw pending insert rejects proposal provenance JSON/SHA drift");

        let mut forged_cross_binding = output.clone();
        forged_cross_binding.pending_output_id = "tool-contract-forged-binding".to_owned();
        forged_cross_binding.project_binding_sha256 = "e".repeat(64);
        raw_insert(&forged_cross_binding)
            .expect_err("raw pending insert must match the exact closed tool audit");

        connection
            .execute(
                "UPDATE tool_calls
                 SET output_audit_json=json_set(
                     output_audit_json,
                     '$.outputHashes.proposalSourceRefsSha256',
                     ?2
                 )
                 WHERE tool_call_id=?1",
                params!["tool-contract-run-case-work-tool", "f".repeat(64)],
            )
            .expect("well-shaped but wrong proposal provenance hash can be staged");
        create_case_assistant_pending_output(&connection, &output)
            .expect_err("pending output rejects a well-shaped mismatched tool provenance hash");
        set_case_assistant_tool_audit_for_pending_output(&connection, &output);

        connection
            .execute(
                "UPDATE tool_calls
                 SET status='running',output_audit_json='{}',source_audit_json='{}',
                     error_type=NULL,finished_at=NULL
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect("pre-pending fixture can reopen tool audit");
        create_case_assistant_pending_output(&connection, &output)
            .expect_err("non-terminal case-work tool audit rejects pending output");
        connection
            .execute(
                "UPDATE tool_calls
                 SET status='succeeded',
                     output_audit_json=?1,source_audit_json=?2,
                     error_type=NULL,finished_at=CURRENT_TIMESTAMP
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                params![
                    case_assistant_tool_output_audit_json(
                        &output.output_kind,
                        &output.output_sha256,
                        &output.expected_proposal_source_refs_sha256,
                    ),
                    case_assistant_tool_source_audit_json(
                        &["generation-one".to_owned()],
                        &output.project_binding_sha256,
                        &output.source_snapshots_sha256
                    )
                ],
            )
            .expect("tool audit closes again");

        create_tool_call(
            &connection,
            &NewToolCallRow {
                tool_call_id: "tool-contract-extra".to_owned(),
                run_id: "tool-contract-run".to_owned(),
                ordinal: 1,
                capability_name: "assistant.case_work".to_owned(),
                status: "running".to_owned(),
                access_mode: "write".to_owned(),
                requires_confirmation: false,
                input_audit_json: case_assistant_tool_input_audit_json(
                    "tool-contract-run",
                    "tool-contract-project",
                    "tool-contract-conversation",
                    &["generation-one".to_owned()],
                    &output.workspace_base_digest,
                ),
                output_audit_json: "{}".to_owned(),
                source_audit_json: "{}".to_owned(),
            },
        )
        .expect("extra tool audit creates");
        assert!(matches!(
            compare_and_set_tool_call_status(
                &connection,
                "tool-contract-extra",
                "running",
                "succeeded",
                &case_assistant_tool_output_audit_json(
                    &output.output_kind,
                    &output.output_sha256,
                    &output.expected_proposal_source_refs_sha256,
                ),
                &case_assistant_tool_source_audit_json(
                    &["generation-one".to_owned()],
                    &output.project_binding_sha256,
                    &output.source_snapshots_sha256,
                ),
                None,
            )
            .expect("extra tool audit closes"),
            ToolCallStatusUpdateResult::Updated(_)
        ));
        create_case_assistant_pending_output(&connection, &output)
            .expect_err("multiple case-work tool audits reject pending output");
        connection
            .execute(
                "DELETE FROM tool_calls WHERE tool_call_id='tool-contract-extra'",
                [],
            )
            .expect("pre-pending extra tool audit deletes");

        connection
            .execute(
                "UPDATE tool_calls
                 SET capability_name='assistant.chat'
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect("pre-pending capability can change");
        create_case_assistant_pending_output(&connection, &output)
            .expect_err("wrong case-work capability rejects pending output");
        connection
            .execute(
                "UPDATE tool_calls
                 SET capability_name='assistant.case_work'
                 WHERE tool_call_id='tool-contract-run-case-work-tool'",
                [],
            )
            .expect("case-work capability restores");
        create_case_assistant_pending_output(&connection, &output)
            .expect("one exact closed tool audit permits pending output");
        validate_user_database_read_only(&database_path)
            .expect("exact tool audit contract remains canonical");
    }

    #[test]
    fn pending_outputs_are_append_preserving_case_scoped_and_confirm_with_cas() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let mut connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "pending-project");
        seed_case_assistant_successful_run(
            &connection,
            "pending-project",
            "pending-conversation",
            "pending-run",
            "pending-user-message",
            "pending-assistant-message",
        );
        let workspace_base_digest = case_workspace_digest(&connection, "pending-project")
            .expect("workspace digest computes")
            .expect("project exists");
        let snapshots = case_assistant_source_snapshots_json();
        let payload = case_assistant_output_payload_json("case_document");
        let new_output = NewCaseAssistantPendingOutputRow {
            pending_output_id: "pending-output".to_owned(),
            project_id: "pending-project".to_owned(),
            conversation_id: "pending-conversation".to_owned(),
            run_id: "pending-run".to_owned(),
            assistant_message_id: "pending-assistant-message".to_owned(),
            project_binding_sha256: "a".repeat(64),
            source_snapshots_sha256: sha256_hex(snapshots.as_bytes()),
            source_snapshots_json: snapshots,
            expected_proposal_source_refs_json: "[]".to_owned(),
            expected_proposal_source_refs_sha256: sha256_hex(b"[]"),
            output_kind: "case_document".to_owned(),
            output_sha256: sha256_hex(payload.as_bytes()),
            output_payload_json: payload,
            output_preview: "Answer".to_owned(),
            output_version: 1,
            workspace_base_digest: workspace_base_digest.clone(),
        };
        set_case_assistant_tool_audit_for_pending_output(&connection, &new_output);
        {
            let transaction = connection.transaction().expect("transaction begins");
            let created = create_case_assistant_pending_output(&transaction, &new_output)
                .expect("pending output creates in caller transaction");
            assert_eq!(created.status, "pending");
            assert_eq!(created.workspace_base_digest, workspace_base_digest);
            assert_eq!(
                list_case_assistant_pending_outputs(
                    &transaction,
                    "pending-project",
                    "pending-conversation",
                    100
                )
                .expect("pending output lists")
                .len(),
                1
            );
            transaction.commit().expect("pending transaction commits");
        }

        create_tool_call(
            &connection,
            &NewToolCallRow {
                tool_call_id: "pending-post-insert-tool".to_owned(),
                run_id: "pending-run".to_owned(),
                ordinal: 1,
                capability_name: "assistant.chat".to_owned(),
                status: "queued".to_owned(),
                access_mode: "read".to_owned(),
                requires_confirmation: false,
                input_audit_json: "{}".to_owned(),
                output_audit_json: "{}".to_owned(),
                source_audit_json: "{}".to_owned(),
            },
        )
        .expect_err("live pending run cannot gain a second tool audit");
        create_message(
            &connection,
            &NewMessageRow {
                message_id: "pending-ordinary-message".to_owned(),
                conversation_id: "pending-conversation".to_owned(),
                role: "system".to_owned(),
                kind: "text".to_owned(),
                text_summary: "ordinary message".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("ordinary message creates");
        insert_attachment(
            &connection,
            &NewAttachmentRow {
                attachment_id: "pending-ordinary-attachment".to_owned(),
                project_id: Some("pending-project".to_owned()),
                original_name: "ordinary.txt".to_owned(),
                extension: "txt".to_owned(),
                detected_mime: "text/plain".to_owned(),
                sha256: "f".repeat(64),
                size_bytes: 0,
                content_blob: Vec::new(),
                extraction_status: "succeeded".to_owned(),
                extracted_text: Some(String::new()),
                segments_json: "[]".to_owned(),
                error_code: None,
            },
        )
        .expect("ordinary attachment creates");
        attach_to_message(
            &connection,
            "pending-ordinary-message",
            "pending-ordinary-attachment",
            0,
        )
        .expect("ordinary attachment links");
        connection
            .execute(
                "UPDATE message_attachments
                 SET message_id='pending-assistant-message'
                 WHERE message_id='pending-ordinary-message'
                   AND attachment_id='pending-ordinary-attachment'",
                [],
            )
            .expect_err("attachment update cannot target protected assistant message");

        assert!(get_case_assistant_pending_output(
            &connection,
            "pending-output",
            "different-project"
        )
        .expect("cross-project read stays opaque")
        .is_none());
        connection
            .execute(
                "UPDATE case_assistant_pending_outputs
                 SET output_preview='mutated'
                 WHERE pending_output_id='pending-output'",
                [],
            )
            .expect_err("pending output content is immutable");
        connection
            .execute(
                "UPDATE case_assistant_pending_outputs
                 SET expected_proposal_source_refs_json='[\"extra-valid-ref\"]'
                 WHERE pending_output_id='pending-output'",
                [],
            )
            .expect_err("pending proposal provenance JSON is immutable");
        connection
            .execute(
                "UPDATE case_assistant_pending_outputs
                 SET expected_proposal_source_refs_sha256=?1
                 WHERE pending_output_id='pending-output'",
                ["e".repeat(64)],
            )
            .expect_err("pending proposal provenance hash is immutable");
        connection
            .execute(
                "DELETE FROM case_assistant_pending_outputs
                 WHERE pending_output_id='pending-output'",
                [],
            )
            .expect_err("pending output history cannot be deleted");

        let confirmed = {
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("confirmation transaction begins");
            create_artifact(
                &transaction,
                &NewArtifactRow {
                    artifact_id: "pending-document-artifact".to_owned(),
                    conversation_id: Some("pending-conversation".to_owned()),
                    project_id: None,
                    kind: "document".to_owned(),
                    title: "Confirmed document".to_owned(),
                    status: "draft".to_owned(),
                },
                &NewArtifactVersionRow {
                    version_id: "pending-document-artifact-v1".to_owned(),
                    artifact_id: "pending-document-artifact".to_owned(),
                    content_json: r#"{"body":"Confirmed provider result"}"#.to_owned(),
                    rendered_text: new_output.output_preview.clone(),
                    source_refs_json: "[]".to_owned(),
                    citation_report_json: "{}".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                },
            )
            .expect("unbound artifact creates");
            assert!(bind_artifact_to_case(
                &transaction,
                "pending-document-artifact",
                "pending-project"
            )
            .expect("artifact bind checks"));
            assert!(matches!(
                compare_and_set_case_assistant_pending_output_confirmed(
                    &transaction,
                    &ConfirmCaseAssistantPendingOutput {
                        pending_output_id: "pending-output",
                        project_id: "pending-project",
                        expected_output_version: 1,
                        expected_output_sha256: &new_output.output_sha256,
                        expected_workspace_base_digest: &workspace_base_digest,
                        expected_proposal_source_refs_json: r#"["extra-valid-ref"]"#,
                        expected_proposal_source_refs_sha256: &sha256_hex(
                            br#"["extra-valid-ref"]"#
                        ),
                        confirmation_request_sha256: &"a".repeat(64),
                        target: &CaseAssistantConfirmationTarget::Artifact(
                            "pending-document-artifact".to_owned(),
                        ),
                    },
                )
                .expect("proposal provenance CAS mismatch returns a conflict"),
                CaseAssistantPendingOutputConfirmResult::Conflict(_)
            ));
            transaction
                .execute(
                    "UPDATE case_assistant_pending_outputs
                     SET status='confirmed',
                         confirmed_artifact_id='pending-document-artifact',
                         confirmation_request_sha256=?2,
                         row_version=row_version+1,
                         confirmed_at=CURRENT_TIMESTAMP,
                         created_at='forged'
                     WHERE pending_output_id=?1 AND status='pending'",
                    params!["pending-output", "d".repeat(64)],
                )
                .expect_err("confirmation cannot rewrite pending creation time");
            let result = compare_and_set_case_assistant_pending_output_confirmed(
                &transaction,
                &ConfirmCaseAssistantPendingOutput {
                    pending_output_id: "pending-output",
                    project_id: "pending-project",
                    expected_output_version: 1,
                    expected_output_sha256: &new_output.output_sha256,
                    expected_workspace_base_digest: &workspace_base_digest,
                    expected_proposal_source_refs_json: &new_output
                        .expected_proposal_source_refs_json,
                    expected_proposal_source_refs_sha256: &new_output
                        .expected_proposal_source_refs_sha256,
                    confirmation_request_sha256: &"b".repeat(64),
                    target: &CaseAssistantConfirmationTarget::Artifact(
                        "pending-document-artifact".to_owned(),
                    ),
                },
            )
            .expect("confirmation CAS succeeds");
            let CaseAssistantPendingOutputConfirmResult::Confirmed(row) = result else {
                panic!("pending output must become confirmed");
            };
            transaction.commit().expect("confirmation commits");
            row
        };
        assert_eq!(confirmed.status, "confirmed");
        assert_eq!(confirmed.row_version, 2);
        assert_eq!(
            confirmed.confirmed_artifact_id.as_deref(),
            Some("pending-document-artifact")
        );
        assert!(matches!(
            compare_and_set_case_assistant_pending_output_confirmed(
                &connection,
                &ConfirmCaseAssistantPendingOutput {
                    pending_output_id: "pending-output",
                    project_id: "pending-project",
                    expected_output_version: 1,
                    expected_output_sha256: &new_output.output_sha256,
                    expected_workspace_base_digest: &workspace_base_digest,
                    expected_proposal_source_refs_json: &new_output
                        .expected_proposal_source_refs_json,
                    expected_proposal_source_refs_sha256: &new_output
                        .expected_proposal_source_refs_sha256,
                    confirmation_request_sha256: &"c".repeat(64),
                    target: &CaseAssistantConfirmationTarget::Artifact(
                        "pending-document-artifact".to_owned(),
                    ),
                },
            )
            .expect("double confirmation returns a CAS result"),
            CaseAssistantPendingOutputConfirmResult::Conflict(_)
        ));
        connection
            .execute(
                "UPDATE artifacts SET project_id=NULL
                 WHERE artifact_id='pending-document-artifact'",
                [],
            )
            .expect_err("confirmed artifact scope is immutable");
        connection
            .execute(
                "INSERT OR REPLACE INTO case_assistant_pending_outputs
                 SELECT * FROM case_assistant_pending_outputs
                 WHERE pending_output_id='pending-output'",
                [],
            )
            .expect_err("replace cannot bypass append-preserving triggers");

        let before_rebuild =
            get_case_assistant_pending_output(&connection, "pending-output", "pending-project")
                .expect("confirmed output reads")
                .expect("confirmed output exists");
        connection
            .execute(
                "UPDATE user_database_metadata
                 SET value='v11-rebuild-test'
                 WHERE key='canonical_schema_version'",
                [],
            )
            .expect("marker makes a controlled rebuild necessary");
        drop(connection);
        validate_and_migrate_user_database(&database_path)
            .expect("confirmed lineage survives canonical rebuild");
        let connection = open_user_database(&database_path).expect("rebuilt database opens");
        assert_eq!(
            get_case_assistant_pending_output(&connection, "pending-output", "pending-project")
                .expect("rebuilt output reads")
                .expect("rebuilt output remains"),
            before_rebuild
        );
        validate_user_database_read_only(&database_path)
            .expect("rebuilt case assistant lineage remains canonical");
    }

    #[test]
    fn v11_proposal_provenance_migration_is_exact_for_every_output_state() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let mut connection = open_user_database(&database_path).expect("database opens");
        let document = seed_case_assistant_pending_output_fixture(
            &connection,
            "migration-document",
            "case_document",
        );
        let diagram = seed_case_assistant_pending_output_fixture(
            &connection,
            "migration-diagram",
            "case_diagram",
        );
        let unconfirmed_analysis = seed_case_assistant_pending_output_fixture(
            &connection,
            "migration-unconfirmed-analysis",
            "case_analysis",
        );
        let confirmed_refs = r#"["legal-dataset-snapshot","proposal-legal-snapshot"]"#;
        let confirmed_analysis = seed_case_assistant_pending_output_fixture_with_refs(
            &connection,
            "migration-confirmed-analysis",
            "case_analysis",
            confirmed_refs,
        );
        confirm_case_assistant_analysis_fixture(
            &mut connection,
            &confirmed_analysis,
            "migration-confirmed-analysis-proposal",
        );
        downgrade_case_assistant_proposal_provenance_fixture(&connection);
        drop(connection);

        validate_and_migrate_user_database(&database_path)
            .expect("legacy proposal provenance migrates deterministically");
        let connection = open_user_database(&database_path).expect("migrated database opens");
        for output in [&document, &diagram, &unconfirmed_analysis] {
            let migrated = get_case_assistant_pending_output(
                &connection,
                &output.pending_output_id,
                &output.project_id,
            )
            .expect("migrated pending output reads")
            .expect("migrated pending output exists");
            assert_eq!(migrated.expected_proposal_source_refs_json, "[]");
            assert_eq!(
                migrated.expected_proposal_source_refs_sha256,
                sha256_hex(b"[]")
            );
            assert_eq!(
                connection
                    .query_row(
                        "SELECT json_extract(
                             output_audit_json,
                             '$.outputHashes.proposalSourceRefsSha256'
                         )
                         FROM tool_calls WHERE run_id=?1",
                        [&output.run_id],
                        |row| row.get::<_, String>(0),
                    )
                    .expect("migrated tool proposal provenance hash reads"),
                sha256_hex(b"[]")
            );
        }
        let migrated_confirmed = get_case_assistant_pending_output(
            &connection,
            &confirmed_analysis.pending_output_id,
            &confirmed_analysis.project_id,
        )
        .expect("migrated confirmed analysis reads")
        .expect("migrated confirmed analysis exists");
        assert_eq!(
            migrated_confirmed.expected_proposal_source_refs_json,
            confirmed_refs
        );
        assert_eq!(
            migrated_confirmed.expected_proposal_source_refs_sha256,
            sha256_hex(confirmed_refs.as_bytes())
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT json_extract(
                         output_audit_json,
                         '$.outputHashes.proposalSourceRefsSha256'
                     )
                     FROM tool_calls WHERE run_id=?1",
                    [&confirmed_analysis.run_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("migrated confirmed tool provenance hash reads"),
            sha256_hex(confirmed_refs.as_bytes())
        );
        validate_user_database_read_only(&database_path)
            .expect("migrated proposal provenance remains canonical");
    }

    #[test]
    fn v11_confirmed_analysis_missing_proposal_rolls_back_without_inference() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let mut connection = open_user_database(&database_path).expect("database opens");
        let refs = r#"["legal-dataset-snapshot","proposal-legal-snapshot"]"#;
        let output = seed_case_assistant_pending_output_fixture_with_refs(
            &connection,
            "migration-missing-proposal",
            "case_analysis",
            refs,
        );
        confirm_case_assistant_analysis_fixture(
            &mut connection,
            &output,
            "migration-proposal-that-will-be-missing",
        );
        downgrade_case_assistant_proposal_provenance_fixture(&connection);
        connection
            .execute(
                "DELETE FROM case_change_proposals
                 WHERE proposal_id='migration-proposal-that-will-be-missing'",
                [],
            )
            .expect("legacy fixture removes the confirmed proposal");
        drop(connection);

        validate_and_migrate_user_database(&database_path)
            .expect_err("missing confirmed proposal must abort the entire migration");
        let connection =
            rusqlite::Connection::open(&database_path).expect("rolled-back legacy database opens");
        assert!(
            !table_columns(&connection, "case_assistant_pending_outputs")
                .expect("rolled-back pending columns read")
                .contains("expected_proposal_source_refs_json")
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM case_assistant_pending_outputs
                     WHERE pending_output_id=?1",
                    [&output.pending_output_id],
                    |row| row.get::<_, String>(0),
                )
                .expect("legacy confirmed output survives the failed migration"),
            "confirmed"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT json_type(
                         output_audit_json,
                         '$.outputHashes.proposalSourceRefsSha256'
                     )
                     FROM tool_calls WHERE run_id=?1",
                    [&output.run_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .expect("legacy tool audit survives the failed migration"),
            None
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT value FROM user_database_metadata WHERE key=?1",
                    [USER_CANONICAL_SCHEMA_MARKER_KEY],
                    |row| row.get::<_, String>(0),
                )
                .expect("legacy schema marker survives the failed migration"),
            "v11-before-exact-proposal-provenance"
        );
    }

    #[test]
    fn retirement_tombstones_and_cleanup_require_live_exact_connection_authority() {
        const FORGED_PRIVACY_DELETION_ID: &str = "pdel_22222222222222222222222222222222";
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "raw-retirement-project");

        let raw_tombstone_error = connection
            .execute(
                "INSERT INTO retired_case_project_ids(
                     project_id,retirement_reason,privacy_deletion_id
                 )
                 VALUES (?1,'case_project_deleted',?2)",
                params!["raw-retirement-project", TEST_PRIVACY_DELETION_ID],
            )
            .expect_err("raw SQL cannot create a retirement tombstone");
        assert!(raw_tombstone_error
            .to_string()
            .contains("case project retirement is not authorized"));
        connection
            .execute(
                "DELETE FROM projects WHERE project_id='raw-retirement-project'",
                [],
            )
            .expect_err("raw SQL cannot physically delete a project");

        seed_case_assistant_pending_output_fixture(
            &connection,
            "forged-retirement",
            "case_document",
        );
        with_case_retirement_authority(
            &connection,
            "forged-retirement-project",
            CASE_PROJECT_DELETED_RETIREMENT_REASON,
            Some(FORGED_PRIVACY_DELETION_ID),
            || {
                connection.execute(
                    "INSERT INTO retired_case_project_ids(
                         project_id,retirement_reason,privacy_deletion_id
                     )
                     VALUES (?1,'case_project_deleted',?2)",
                    params!["forged-retirement-project", FORGED_PRIVACY_DELETION_ID],
                )
            },
        )
        .expect("test fixture installs a tombstone under exact internal authority");

        connection
            .execute(
                "DELETE FROM conversations
                 WHERE conversation_id='forged-retirement-conversation'",
                [],
            )
            .expect_err("a tombstone without live authority cannot disable child guards");
        connection
            .execute(
                "DELETE FROM projects
                 WHERE project_id='forged-retirement-project'",
                [],
            )
            .expect_err("a tombstone without live authority cannot authorize project deletion");

        let second = open_user_database(&database_path).expect("second database connection opens");
        with_case_retirement_authority(
            &connection,
            "forged-retirement-project",
            CASE_PROJECT_DELETED_RETIREMENT_REASON,
            Some(FORGED_PRIVACY_DELETION_ID),
            || {
                second
                    .execute(
                        "DELETE FROM agent_runs
                         WHERE run_id='forged-retirement-run'",
                        [],
                    )
                    .expect_err("connection A authority cannot disable connection B child guards");
                second
                    .execute(
                        "DELETE FROM projects
                         WHERE project_id='forged-retirement-project'",
                        [],
                    )
                    .expect_err("connection A authority cannot authorize connection B deletion");
                Ok(())
            },
        )
        .expect("cross-connection denial leaves the authority scope healthy");
    }

    #[test]
    fn project_delete_preflight_retires_empty_case_work_and_preserves_assistant_history() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let connection = open_user_database(&database_path).expect("database opens");
        seed_project(&connection, "retire-empty-project");
        create_case_work_conversation(
            &connection,
            "retire-empty-case-work",
            "retire-empty-project",
            "Case work",
        )
        .expect("empty case-work conversation creates");
        create_conversation(
            &connection,
            "retire-preserved-assistant",
            Some("retire-empty-project"),
            "Assistant history",
        )
        .expect("assistant conversation creates");
        create_message(
            &connection,
            &NewMessageRow {
                message_id: "retire-preserved-message".to_owned(),
                conversation_id: "retire-preserved-assistant".to_owned(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "Preserve me".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("assistant history message creates");

        assert!(preflight_delete_case_project(
            &connection,
            "retire-empty-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("exact project delete preflight succeeds"));
        assert!(
            !case_project_id_is_retired(&connection, "retire-empty-project")
                .expect("preflight tombstone rollback reads")
        );
        assert_eq!(
            retirement_authorized(
                &connection,
                "retire-empty-project",
                CASE_PROJECT_DELETED_RETIREMENT_REASON,
                Some(TEST_PRIVACY_DELETION_ID)
            ),
            0,
            "preflight rollback must also leave no live retirement authority"
        );
        connection
            .execute(
                "DELETE FROM projects WHERE project_id='retire-empty-project'",
                [],
            )
            .expect_err("preflight cannot leak authority to a later raw delete");
        assert!(get_case_work_conversation(
            &connection,
            "retire-empty-case-work",
            "retire-empty-project"
        )
        .expect("case-work conversation reads after preflight")
        .is_some());
        assert!(delete_case_project(
            &connection,
            "retire-empty-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("project deletion succeeds"));

        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM projects
                     WHERE project_id='retire-empty-project'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .expect("project lookup succeeds"),
            0
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM conversations
                     WHERE conversation_id='retire-empty-case-work'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .expect("case-work lookup succeeds"),
            0
        );
        let assistant = get_conversation(&connection, "retire-preserved-assistant")
            .expect("assistant conversation reads")
            .expect("assistant conversation is preserved");
        assert_eq!(assistant.scope, ConversationScope::Assistant);
        assert!(assistant.project_id.is_none());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM messages
                     WHERE message_id='retire-preserved-message'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .expect("preserved message count reads"),
            1
        );
        assert!(
            case_project_id_is_retired(&connection, "retire-empty-project")
                .expect("retirement tombstone reads")
        );
        assert!(case_project_retirement_matches_privacy_deletion(
            &connection,
            "retire-empty-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("retirement journal binding reads"));
        assert_eq!(
            connection
                .query_row(
                    "SELECT privacy_deletion_id
                     FROM retired_case_project_ids
                     WHERE project_id='retire-empty-project'",
                    [],
                    |row| row.get::<_, String>(0)
                )
                .expect("retirement journal id reads"),
            TEST_PRIVACY_DELETION_ID
        );
        connection
            .execute(
                "INSERT OR REPLACE INTO retired_case_project_ids
                 SELECT * FROM retired_case_project_ids
                 WHERE project_id='retire-empty-project'",
                [],
            )
            .expect_err("replace cannot mutate an append-only retirement tombstone");

        let retired_project = CaseProjectRow {
            project_id: "retire-empty-project".to_owned(),
            title: "Cannot recreate".to_owned(),
            case_type: "civil".to_owned(),
            status: "active".to_owned(),
            opened_on: None,
            summary: String::new(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        upsert_case_project(&connection, &retired_project)
            .expect_err("upsert cannot resurrect a retired project id");
        insert_case_project_if_absent(&connection, &retired_project)
            .expect_err("insert-if-absent cannot resurrect a retired project id");
        validate_user_database_read_only(&database_path)
            .expect("retired empty case-work deletion remains canonical");
    }

    #[test]
    fn retirement_recovery_is_concurrently_idempotent_and_journal_scoped() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let worker_count = 4;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(worker_count));
        let mut workers = Vec::new();
        for _ in 0..worker_count {
            let worker_path = database_path.clone();
            let worker_barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                let connection = open_user_database(&worker_path).expect("worker database opens");
                worker_barrier.wait();
                retire_absent_case_project_id_after_privacy_revocation(
                    &connection,
                    "retire-recovery-project",
                    TEST_PRIVACY_DELETION_ID,
                )
                .expect("concurrent retirement recovery succeeds")
            }));
        }
        for worker in workers {
            assert!(worker.join().expect("retirement worker joins"));
        }

        let connection = open_user_database(&database_path).expect("database reopens");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM retired_case_project_ids
                     WHERE project_id='retire-recovery-project'
                       AND privacy_deletion_id=?1",
                    [TEST_PRIVACY_DELETION_ID],
                    |row| row.get::<_, i64>(0)
                )
                .expect("retirement row count reads"),
            1
        );
        assert!(!retire_absent_case_project_id_after_privacy_revocation(
            &connection,
            "retire-recovery-project",
            "pdel_11111111111111111111111111111111",
        )
        .expect("mismatched journal recovery is rejected"));
        validate_user_database_read_only(&database_path)
            .expect("concurrent retirement recovery remains canonical");
        connection
            .execute(
                "UPDATE user_database_metadata
                 SET value='v11-retirement-recovery-rebuild-test'
                 WHERE key='canonical_schema_version'",
                [],
            )
            .expect("marker makes a controlled recovery tombstone rebuild necessary");
        drop(connection);
        validate_and_migrate_user_database(&database_path)
            .expect("recovery retirement tombstone rebuilds under row authority");
        let rebuilt = open_user_database(&database_path).expect("rebuilt database reopens");
        assert!(case_project_retirement_matches_privacy_deletion(
            &rebuilt,
            "retire-recovery-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("rebuilt recovery retirement binding reads"));
        validate_user_database_read_only(&database_path)
            .expect("rebuilt recovery retirement remains canonical");
    }

    #[test]
    fn project_delete_retains_pending_output_as_opaque_audit_across_rebuild() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let connection = open_user_database(&database_path).expect("database opens");
        seed_case_assistant_pending_output_fixture(&connection, "retire-pending", "case_document");
        connection
            .execute(
                "DELETE FROM conversations
                 WHERE conversation_id='retire-pending-conversation'",
                [],
            )
            .expect_err("live pending lineage blocks conversation deletion");
        connection
            .execute(
                "UPDATE agent_runs SET status='failed'
                 WHERE run_id='retire-pending-run'",
                [],
            )
            .expect_err("live pending lineage blocks run mutation");
        let run_snapshot_before = connection
            .query_row(
                "SELECT provider_snapshot_json,budget_json,error_type,created_at,finished_at
                 FROM agent_runs WHERE run_id='retire-pending-run'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .expect("live run audit reads");
        connection
            .execute(
                "UPDATE agent_runs SET provider_snapshot_json='{\"forged\":true}'
                 WHERE run_id='retire-pending-run'",
                [],
            )
            .expect_err("live pending lineage blocks provider snapshot mutation");
        let run_snapshot_after = connection
            .query_row(
                "SELECT provider_snapshot_json,budget_json,error_type,created_at,finished_at
                 FROM agent_runs WHERE run_id='retire-pending-run'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .expect("guarded live run audit reads");
        assert_eq!(run_snapshot_after, run_snapshot_before);
        connection
            .execute(
                "UPDATE messages SET role='system'
                 WHERE message_id='retire-pending-assistant-message'",
                [],
            )
            .expect_err("live pending lineage blocks assistant message mutation");
        let history_before = connection
            .query_row(
                "SELECT
                     (SELECT text_summary FROM messages
                      WHERE message_id='retire-pending-user-message'),
                     (SELECT text_summary FROM messages
                      WHERE message_id='retire-pending-assistant-message')",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .expect("live message history reads");
        connection
            .execute(
                "UPDATE messages SET text_summary='forged user history'
                 WHERE message_id='retire-pending-user-message'",
                [],
            )
            .expect_err("live pending lineage blocks user text mutation");
        connection
            .execute(
                "UPDATE messages SET text_summary='forged assistant history'
                 WHERE message_id='retire-pending-assistant-message'",
                [],
            )
            .expect_err("live pending lineage blocks assistant text mutation");
        let history_after = connection
            .query_row(
                "SELECT
                     (SELECT text_summary FROM messages
                      WHERE message_id='retire-pending-user-message'),
                     (SELECT text_summary FROM messages
                      WHERE message_id='retire-pending-assistant-message')",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .expect("guarded live message history reads");
        assert_eq!(history_after, history_before);
        connection
            .execute(
                "DELETE FROM agent_runs WHERE run_id='retire-pending-run'",
                [],
            )
            .expect_err("live pending lineage blocks run deletion");
        let tool_audit_before = get_tool_call(&connection, "retire-pending-run-case-work-tool")
            .expect("live tool audit reads")
            .expect("live tool audit exists");
        connection
            .execute(
                "UPDATE tool_calls SET output_audit_json='{\"forged\":true}'
                 WHERE tool_call_id='retire-pending-run-case-work-tool'",
                [],
            )
            .expect_err("live pending lineage blocks tool audit mutation");
        connection
            .execute(
                "DELETE FROM tool_calls
                 WHERE tool_call_id='retire-pending-run-case-work-tool'",
                [],
            )
            .expect_err("live pending lineage blocks tool audit deletion");
        assert_eq!(
            get_tool_call(&connection, "retire-pending-run-case-work-tool")
                .expect("guarded live tool audit reads")
                .expect("guarded live tool audit exists"),
            tool_audit_before
        );
        connection
            .execute(
                "DELETE FROM messages
                 WHERE message_id='retire-pending-assistant-message'",
                [],
            )
            .expect_err("live pending lineage blocks assistant message deletion");

        assert!(delete_case_project(
            &connection,
            "retire-pending-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("project with pending output deletes"));
        let audit_before_rebuild = connection
            .query_row(
                "SELECT project_id,conversation_id,run_id,assistant_message_id,status,row_version
                 FROM case_assistant_pending_outputs
                 WHERE pending_output_id='retire-pending-output'",
                [],
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
            .expect("pending audit remains");
        assert_eq!(audit_before_rebuild.4, "pending");
        assert_eq!(audit_before_rebuild.5, 1);
        assert!(get_case_assistant_pending_output(
            &connection,
            "retire-pending-output",
            "retire-pending-project"
        )
        .expect("retired pending output repository read succeeds")
        .is_some());
        assert_eq!(
            list_case_assistant_pending_outputs(
                &connection,
                "retire-pending-project",
                "retire-pending-conversation",
                100
            )
            .expect("retired pending output repository list succeeds")
            .len(),
            1
        );
        for (table, column, id) in [
            ("projects", "project_id", "retire-pending-project"),
            (
                "conversations",
                "conversation_id",
                "retire-pending-conversation",
            ),
            ("agent_runs", "run_id", "retire-pending-run"),
            ("messages", "message_id", "retire-pending-assistant-message"),
        ] {
            assert_eq!(
                connection
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1"),
                        [id],
                        |row| row.get::<_, i64>(0)
                    )
                    .expect("retired live lineage count reads"),
                0,
                "{table} live lineage must be physically deleted"
            );
        }
        connection
            .execute(
                "UPDATE case_assistant_pending_outputs
                 SET output_preview='forged'
                 WHERE pending_output_id='retire-pending-output'",
                [],
            )
            .expect_err("retired pending audit remains immutable");
        connection
            .execute(
                "DELETE FROM case_assistant_pending_outputs
                 WHERE pending_output_id='retire-pending-output'",
                [],
            )
            .expect_err("retired pending audit remains append only");
        connection
            .execute(
                "UPDATE user_database_metadata
                 SET value='retired-pending-rebuild-test'
                 WHERE key='canonical_schema_version'",
                [],
            )
            .expect("marker requests canonical rebuild");
        drop(connection);

        validate_and_migrate_user_database(&database_path)
            .expect("retired orphan audit survives canonical rebuild");
        let connection = open_user_database(&database_path).expect("rebuilt database opens");
        let audit_after_rebuild = connection
            .query_row(
                "SELECT project_id,conversation_id,run_id,assistant_message_id,status,row_version
                 FROM case_assistant_pending_outputs
                 WHERE pending_output_id='retire-pending-output'",
                [],
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
            .expect("rebuilt pending audit remains");
        assert_eq!(audit_after_rebuild, audit_before_rebuild);
        validate_user_database_read_only(&database_path)
            .expect("retired pending audit remains canonical");
    }

    #[test]
    fn project_delete_removes_confirmed_proposal_but_retains_confirmation_audit() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let mut connection = open_user_database(&database_path).expect("database opens");
        let output = seed_case_assistant_pending_output_fixture(
            &connection,
            "retire-proposal",
            "case_analysis",
        );
        {
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("proposal confirmation transaction begins");
            create_case_change_proposal(
                &transaction,
                &NewCaseChangeProposalRow {
                    proposal_id: "retire-wrong-proposal".to_owned(),
                    conversation_id: "retire-proposal-conversation".to_owned(),
                    project_id: "retire-proposal-project".to_owned(),
                    run_id: Some("retire-proposal-run".to_owned()),
                    base_case_digest: output.workspace_base_digest.clone(),
                    changes_json: r#"{"changes":[{"op":"wrong"}]}"#.to_owned(),
                    source_refs_json: "[]".to_owned(),
                },
            )
            .expect("wrong same-scope proposal creates");
            assert!(matches!(
                compare_and_set_case_change_proposal_status(
                    &transaction,
                    "retire-wrong-proposal",
                    "retire-proposal-project",
                    &output.workspace_base_digest,
                    "applied",
                )
                .expect("wrong same-scope proposal applies"),
                CaseChangeProposalStatusUpdateResult::Updated(_)
            ));
            compare_and_set_case_assistant_pending_output_confirmed(
                &transaction,
                &ConfirmCaseAssistantPendingOutput {
                    pending_output_id: "retire-proposal-output",
                    project_id: "retire-proposal-project",
                    expected_output_version: 1,
                    expected_output_sha256: &output.output_sha256,
                    expected_workspace_base_digest: &output.workspace_base_digest,
                    expected_proposal_source_refs_json: &output.expected_proposal_source_refs_json,
                    expected_proposal_source_refs_sha256: &output
                        .expected_proposal_source_refs_sha256,
                    confirmation_request_sha256: &"1".repeat(64),
                    target: &CaseAssistantConfirmationTarget::Proposal(
                        "retire-wrong-proposal".to_owned(),
                    ),
                },
            )
            .expect_err("wrong same-scope proposal cannot satisfy confirmation");
            create_case_change_proposal(
                &transaction,
                &NewCaseChangeProposalRow {
                    proposal_id: "retire-extra-source-proposal".to_owned(),
                    conversation_id: "retire-proposal-conversation".to_owned(),
                    project_id: "retire-proposal-project".to_owned(),
                    run_id: Some("retire-proposal-run".to_owned()),
                    base_case_digest: output.workspace_base_digest.clone(),
                    changes_json: r#"{"changes":[]}"#.to_owned(),
                    source_refs_json: r#"["extra-but-valid-source-ref"]"#.to_owned(),
                },
            )
            .expect("extra-source same-scope proposal creates");
            assert!(matches!(
                compare_and_set_case_change_proposal_status(
                    &transaction,
                    "retire-extra-source-proposal",
                    "retire-proposal-project",
                    &output.workspace_base_digest,
                    "applied",
                )
                .expect("extra-source same-scope proposal applies"),
                CaseChangeProposalStatusUpdateResult::Updated(_)
            ));
            compare_and_set_case_assistant_pending_output_confirmed(
                &transaction,
                &ConfirmCaseAssistantPendingOutput {
                    pending_output_id: "retire-proposal-output",
                    project_id: "retire-proposal-project",
                    expected_output_version: 1,
                    expected_output_sha256: &output.output_sha256,
                    expected_workspace_base_digest: &output.workspace_base_digest,
                    expected_proposal_source_refs_json: &output.expected_proposal_source_refs_json,
                    expected_proposal_source_refs_sha256: &output
                        .expected_proposal_source_refs_sha256,
                    confirmation_request_sha256: &"2".repeat(64),
                    target: &CaseAssistantConfirmationTarget::Proposal(
                        "retire-extra-source-proposal".to_owned(),
                    ),
                },
            )
            .expect_err("an extra but valid proposal source ref cannot satisfy confirmation");
            create_case_change_proposal(
                &transaction,
                &NewCaseChangeProposalRow {
                    proposal_id: "retire-confirmed-proposal".to_owned(),
                    conversation_id: "retire-proposal-conversation".to_owned(),
                    project_id: "retire-proposal-project".to_owned(),
                    run_id: Some("retire-proposal-run".to_owned()),
                    base_case_digest: output.workspace_base_digest.clone(),
                    changes_json: r#"{"changes":[]}"#.to_owned(),
                    source_refs_json: "[]".to_owned(),
                },
            )
            .expect("proposal creates");
            assert!(matches!(
                compare_and_set_case_change_proposal_status(
                    &transaction,
                    "retire-confirmed-proposal",
                    "retire-proposal-project",
                    &output.workspace_base_digest,
                    "applied",
                )
                .expect("proposal applies"),
                CaseChangeProposalStatusUpdateResult::Updated(_)
            ));
            let target =
                CaseAssistantConfirmationTarget::Proposal("retire-confirmed-proposal".to_owned());
            assert!(matches!(
                compare_and_set_case_assistant_pending_output_confirmed(
                    &transaction,
                    &ConfirmCaseAssistantPendingOutput {
                        pending_output_id: "retire-proposal-output",
                        project_id: "retire-proposal-project",
                        expected_output_version: 1,
                        expected_output_sha256: &output.output_sha256,
                        expected_workspace_base_digest: &output.workspace_base_digest,
                        expected_proposal_source_refs_json: &output
                            .expected_proposal_source_refs_json,
                        expected_proposal_source_refs_sha256: &output
                            .expected_proposal_source_refs_sha256,
                        confirmation_request_sha256: &"b".repeat(64),
                        target: &target,
                    },
                )
                .expect("proposal confirmation succeeds"),
                CaseAssistantPendingOutputConfirmResult::Confirmed(_)
            ));
            transaction.commit().expect("proposal confirmation commits");
        }
        let proposal_before = get_case_change_proposal(&connection, "retire-confirmed-proposal")
            .expect("confirmed proposal reads")
            .expect("confirmed proposal exists");
        connection
            .execute(
                "UPDATE case_change_proposals SET changes_json='{\"forged\":true}'
                 WHERE proposal_id='retire-confirmed-proposal'",
                [],
            )
            .expect_err("live confirmed proposal audit cannot be changed");
        assert_eq!(
            get_case_change_proposal(&connection, "retire-confirmed-proposal")
                .expect("guarded confirmed proposal reads")
                .expect("guarded confirmed proposal exists"),
            proposal_before
        );
        connection
            .execute(
                "DELETE FROM case_change_proposals
                 WHERE proposal_id='retire-confirmed-proposal'",
                [],
            )
            .expect_err("live confirmed proposal cannot be deleted outside retirement");

        assert!(delete_case_project(
            &connection,
            "retire-proposal-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("confirmed proposal project deletes"));
        assert!(
            get_case_change_proposal(&connection, "retire-confirmed-proposal")
                .expect("proposal lookup succeeds")
                .is_none()
        );
        let (status, proposal_id, row_version) = connection
            .query_row(
                "SELECT status,confirmed_proposal_id,row_version
                 FROM case_assistant_pending_outputs
                 WHERE pending_output_id='retire-proposal-output'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("confirmed proposal audit remains");
        assert_eq!(status, "confirmed");
        assert_eq!(proposal_id, "retire-confirmed-proposal");
        assert_eq!(row_version, 2);
        validate_user_database_read_only(&database_path)
            .expect("confirmed proposal retirement remains canonical");
    }

    #[test]
    fn project_delete_removes_confirmed_artifact_but_retains_confirmation_audit() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("user database initializes");
        let mut connection = open_user_database(&database_path).expect("database opens");
        let output = seed_case_assistant_pending_output_fixture(
            &connection,
            "retire-artifact",
            "case_document",
        );
        {
            let transaction = connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .expect("artifact confirmation transaction begins");
            create_artifact(
                &transaction,
                &NewArtifactRow {
                    artifact_id: "retire-wrong-artifact".to_owned(),
                    conversation_id: Some("retire-artifact-conversation".to_owned()),
                    project_id: None,
                    kind: "document".to_owned(),
                    title: "Wrong same-scope artifact".to_owned(),
                    status: "draft".to_owned(),
                },
                &NewArtifactVersionRow {
                    version_id: "retire-wrong-artifact-v1".to_owned(),
                    artifact_id: "retire-wrong-artifact".to_owned(),
                    content_json: r#"{"body":"wrong provider result"}"#.to_owned(),
                    rendered_text: output.output_preview.clone(),
                    source_refs_json: "[]".to_owned(),
                    citation_report_json: "{}".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                },
            )
            .expect("wrong same-scope artifact creates");
            assert!(bind_artifact_to_case(
                &transaction,
                "retire-wrong-artifact",
                "retire-artifact-project"
            )
            .expect("wrong same-scope artifact binds"));
            compare_and_set_case_assistant_pending_output_confirmed(
                &transaction,
                &ConfirmCaseAssistantPendingOutput {
                    pending_output_id: "retire-artifact-output",
                    project_id: "retire-artifact-project",
                    expected_output_version: 1,
                    expected_output_sha256: &output.output_sha256,
                    expected_workspace_base_digest: &output.workspace_base_digest,
                    expected_proposal_source_refs_json: &output.expected_proposal_source_refs_json,
                    expected_proposal_source_refs_sha256: &output
                        .expected_proposal_source_refs_sha256,
                    confirmation_request_sha256: &"2".repeat(64),
                    target: &CaseAssistantConfirmationTarget::Artifact(
                        "retire-wrong-artifact".to_owned(),
                    ),
                },
            )
            .expect_err("wrong same-scope artifact cannot satisfy confirmation");
            create_artifact(
                &transaction,
                &NewArtifactRow {
                    artifact_id: "retire-confirmed-artifact".to_owned(),
                    conversation_id: Some("retire-artifact-conversation".to_owned()),
                    project_id: None,
                    kind: "document".to_owned(),
                    title: "Confirmed artifact".to_owned(),
                    status: "draft".to_owned(),
                },
                &NewArtifactVersionRow {
                    version_id: "retire-confirmed-artifact-v1".to_owned(),
                    artifact_id: "retire-confirmed-artifact".to_owned(),
                    content_json: r#"{"body":"Confirmed provider result"}"#.to_owned(),
                    rendered_text: output.output_preview.clone(),
                    source_refs_json: "[]".to_owned(),
                    citation_report_json: "{}".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                },
            )
            .expect("artifact creates");
            assert!(bind_artifact_to_case(
                &transaction,
                "retire-confirmed-artifact",
                "retire-artifact-project"
            )
            .expect("artifact binds"));
            let target =
                CaseAssistantConfirmationTarget::Artifact("retire-confirmed-artifact".to_owned());
            assert!(matches!(
                compare_and_set_case_assistant_pending_output_confirmed(
                    &transaction,
                    &ConfirmCaseAssistantPendingOutput {
                        pending_output_id: "retire-artifact-output",
                        project_id: "retire-artifact-project",
                        expected_output_version: 1,
                        expected_output_sha256: &output.output_sha256,
                        expected_workspace_base_digest: &output.workspace_base_digest,
                        expected_proposal_source_refs_json: &output
                            .expected_proposal_source_refs_json,
                        expected_proposal_source_refs_sha256: &output
                            .expected_proposal_source_refs_sha256,
                        confirmation_request_sha256: &"c".repeat(64),
                        target: &target,
                    },
                )
                .expect("artifact confirmation succeeds"),
                CaseAssistantPendingOutputConfirmResult::Confirmed(_)
            ));
            transaction.commit().expect("artifact confirmation commits");
        }
        let version_one = get_artifact_version(&connection, "retire-confirmed-artifact", 1)
            .expect("confirmed artifact version reads")
            .expect("confirmed artifact version exists");
        connection
            .execute(
                "UPDATE artifact_versions SET rendered_text='forged'
                 WHERE version_id='retire-confirmed-artifact-v1'",
                [],
            )
            .expect_err("confirmed artifact version one cannot be mutated");
        connection
            .execute(
                "DELETE FROM artifact_versions
                 WHERE version_id='retire-confirmed-artifact-v1'",
                [],
            )
            .expect_err("confirmed artifact version one cannot be deleted");
        assert_eq!(
            get_artifact_version(&connection, "retire-confirmed-artifact", 1)
                .expect("guarded artifact version reads")
                .expect("guarded artifact version exists"),
            version_one
        );
        assert!(matches!(
            create_artifact_version(
                &connection,
                &NewArtifactVersionRow {
                    version_id: "retire-confirmed-artifact-v2".to_owned(),
                    artifact_id: "retire-confirmed-artifact".to_owned(),
                    content_json: r#"{"body":"later user revision"}"#.to_owned(),
                    rendered_text: "Later user revision".to_owned(),
                    source_refs_json: "[]".to_owned(),
                    citation_report_json: "{}".to_owned(),
                    provider_snapshot_json: provider_snapshot_json(),
                },
                1,
            )
            .expect("later artifact version appends"),
            ArtifactVersionCreateResult::Created(ArtifactVersionRow {
                version_number: 2,
                ..
            })
        ));
        validate_user_database_read_only(&database_path)
            .expect("confirmed artifact remains canonical after a later version");
        connection
            .execute(
                "UPDATE artifacts SET status='archived'
                 WHERE artifact_id='retire-confirmed-artifact'",
                [],
            )
            .expect_err("live confirmed artifact cannot be archived");
        connection
            .execute(
                "DELETE FROM artifacts
                 WHERE artifact_id='retire-confirmed-artifact'",
                [],
            )
            .expect_err("live confirmed artifact cannot be deleted outside retirement");

        assert!(delete_case_project(
            &connection,
            "retire-artifact-project",
            TEST_PRIVACY_DELETION_ID
        )
        .expect("confirmed artifact project deletes"));
        assert!(get_artifact(&connection, "retire-confirmed-artifact")
            .expect("artifact lookup succeeds")
            .is_none());
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM artifact_versions
                     WHERE artifact_id='retire-confirmed-artifact'",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .expect("artifact version count reads"),
            0
        );
        let (status, artifact_id, row_version) = connection
            .query_row(
                "SELECT status,confirmed_artifact_id,row_version
                 FROM case_assistant_pending_outputs
                 WHERE pending_output_id='retire-artifact-output'",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("confirmed artifact audit remains");
        assert_eq!(status, "confirmed");
        assert_eq!(artifact_id, "retire-confirmed-artifact");
        assert_eq!(row_version, 2);
        validate_user_database_read_only(&database_path)
            .expect("confirmed artifact retirement remains canonical");
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

    fn case_assistant_source_snapshots_json() -> String {
        serde_json::to_string(&serde_json::json!([
            {
                "approvedPayloadSha256": "1".repeat(64),
                "extractionSha256": "2".repeat(64),
                "generationId": "generation-one",
                "generationNumber": 3,
                "generationRowVersion": 7,
                "materialId": "material-one",
                "ordinal": 0,
                "redactedContentSha256": "3".repeat(64),
                "riskRevision": 2,
                "riskRevisionHash": "4".repeat(64),
                "selectionId": "selection-one",
                "selectionRowVersion": 1
            }
        ]))
        .expect("source snapshots serialize")
    }

    fn case_assistant_output_payload_json(output_kind: &str) -> String {
        let content = if output_kind == "case_analysis" {
            serde_json::json!({"changes": []})
        } else {
            serde_json::json!({"body": "Confirmed provider result"})
        };
        serde_json::to_string(&serde_json::json!({
            "content": content,
            "outputKind": output_kind,
            "schemaVersion": 1
        }))
        .expect("typed output serializes")
    }

    fn case_assistant_tool_input_audit_json(
        run_id: &str,
        project_id: &str,
        conversation_id: &str,
        generation_ids: &[String],
        workspace_digest: &str,
    ) -> String {
        let provider_snapshot =
            serde_json::from_str::<serde_json::Value>(&provider_snapshot_json())
                .expect("provider snapshot parses");
        serde_json::to_string(&serde_json::json!({
            "requestId": run_id,
            "runId": run_id,
            "capability": "assistant.case_work",
            "classification": "case_redacted_approved",
            "inputIds": {
                "projectId": project_id,
                "conversationId": conversation_id,
                "redactionGenerationIds": generation_ids,
            },
            "inputHashes": {
                "promptSha256": "1".repeat(64),
                "historySha256": "2".repeat(64),
                "minimalContextSha256": "3".repeat(64),
                "generationSetSha256": "4".repeat(64),
                "workspaceDigest": workspace_digest,
            },
            "inputCounts": {
                "promptBytes": 1,
                "historyMessages": 0,
                "historyBytes": 0,
                "generationCount": generation_ids.len(),
                "knownBodyBytes": 1,
            },
            "providerSnapshot": provider_snapshot,
            "confirmation": {
                "writebackRequired": true,
                "received": false,
            },
            "status": "running",
        }))
        .expect("case assistant input audit serializes")
    }

    fn case_assistant_tool_output_audit_json(
        output_kind: &str,
        output_sha256: &str,
        proposal_source_refs_sha256: &str,
    ) -> String {
        serde_json::to_string(&serde_json::json!({
            "outputIds": {"pendingOutputKind": output_kind},
            "outputHashes": {
                "providerOutputSha256": "5".repeat(64),
                "typedOutputSha256": output_sha256,
                "approvedEnvelopeSha256": "6".repeat(64),
                "proposalSourceRefsSha256": proposal_source_refs_sha256,
            },
            "outputCounts": {
                "approvedEnvelopeBytes": 1,
                "bytes": 1,
                "items": 1,
            },
            "status": "succeeded",
            "confirmation": {
                "writebackRequired": true,
                "received": false,
            },
        }))
        .expect("case assistant output audit serializes")
    }

    fn case_assistant_tool_source_audit_json(
        generation_ids: &[String],
        project_binding_sha256: &str,
        source_snapshots_sha256: &str,
    ) -> String {
        let provider_snapshot =
            serde_json::from_str::<serde_json::Value>(&provider_snapshot_json())
                .expect("provider snapshot parses");
        serde_json::to_string(&serde_json::json!({
            "classification": "case_redacted_approved",
            "sourceRefs": generation_ids,
            "inputHashes": {
                "projectBindingSha256": project_binding_sha256,
                "sourceSnapshotsSha256": source_snapshots_sha256,
                "aggregateSourceSha256": "7".repeat(64),
                "aggregateExtractionSha256": "8".repeat(64),
                "aggregateRedactedContentSha256": "9".repeat(64),
            },
            "providerSnapshot": provider_snapshot,
            "confirmation": {
                "writebackRequired": true,
                "received": false,
            },
        }))
        .expect("case assistant source audit serializes")
    }

    fn set_case_assistant_tool_audit_for_pending_output(
        connection: &rusqlite::Connection,
        output: &NewCaseAssistantPendingOutputRow,
    ) {
        let generation_ids =
            serde_json::from_str::<Vec<serde_json::Value>>(&output.source_snapshots_json)
                .expect("source snapshots parse")
                .into_iter()
                .map(|snapshot| {
                    snapshot
                        .get("generationId")
                        .and_then(serde_json::Value::as_str)
                        .expect("generation id exists")
                        .to_owned()
                })
                .collect::<Vec<_>>();
        let input = case_assistant_tool_input_audit_json(
            &output.run_id,
            &output.project_id,
            &output.conversation_id,
            &generation_ids,
            &output.workspace_base_digest,
        );
        let result = case_assistant_tool_output_audit_json(
            &output.output_kind,
            &output.output_sha256,
            &output.expected_proposal_source_refs_sha256,
        );
        let source = case_assistant_tool_source_audit_json(
            &generation_ids,
            &output.project_binding_sha256,
            &output.source_snapshots_sha256,
        );
        connection
            .execute(
                "UPDATE tool_calls
                 SET input_audit_json=?2,output_audit_json=?3,source_audit_json=?4
                 WHERE tool_call_id=?1",
                params![
                    format!("{}-case-work-tool", output.run_id),
                    input,
                    result,
                    source
                ],
            )
            .expect("case assistant tool audit binds to pending output");
    }

    fn seed_case_assistant_successful_run(
        connection: &rusqlite::Connection,
        project_id: &str,
        conversation_id: &str,
        run_id: &str,
        user_message_id: &str,
        assistant_message_id: &str,
    ) {
        create_case_work_conversation(connection, conversation_id, project_id, "Case assistant")
            .expect("case-work conversation creates");
        create_message(
            connection,
            &NewMessageRow {
                message_id: user_message_id.to_owned(),
                conversation_id: conversation_id.to_owned(),
                role: "user".to_owned(),
                kind: "text".to_owned(),
                text_summary: "Question".to_owned(),
                artifact_id: None,
                run_id: None,
            },
        )
        .expect("case assistant user message creates");
        create_agent_run(
            connection,
            &NewAgentRunRow {
                run_id: run_id.to_owned(),
                conversation_id: conversation_id.to_owned(),
                user_message_id: user_message_id.to_owned(),
                provider_id: None,
                provider_snapshot_json: provider_snapshot_json(),
                intent: "interactive_case_work".to_owned(),
                status: "queued".to_owned(),
                budget_json: "{}".to_owned(),
            },
        )
        .expect("case assistant run creates");
        create_message(
            connection,
            &NewMessageRow {
                message_id: assistant_message_id.to_owned(),
                conversation_id: conversation_id.to_owned(),
                role: "assistant".to_owned(),
                kind: "text".to_owned(),
                text_summary: "Answer".to_owned(),
                artifact_id: None,
                run_id: Some(run_id.to_owned()),
            },
        )
        .expect("case assistant response message creates");
        let tool_call_id = format!("{run_id}-case-work-tool");
        let generation_ids = vec!["generation-one".to_owned()];
        let placeholder_output_sha256 = "a".repeat(64);
        let initial_input_audit = case_assistant_tool_input_audit_json(
            run_id,
            project_id,
            conversation_id,
            &generation_ids,
            &"b".repeat(64),
        );
        create_tool_call(
            connection,
            &NewToolCallRow {
                tool_call_id: tool_call_id.clone(),
                run_id: run_id.to_owned(),
                ordinal: 0,
                capability_name: "assistant.case_work".to_owned(),
                status: "running".to_owned(),
                access_mode: "write".to_owned(),
                requires_confirmation: false,
                input_audit_json: initial_input_audit,
                output_audit_json: "{}".to_owned(),
                source_audit_json: "{}".to_owned(),
            },
        )
        .expect("case assistant tool audit creates");
        assert!(matches!(
            compare_and_set_tool_call_status(
                connection,
                &tool_call_id,
                "running",
                "succeeded",
                &case_assistant_tool_output_audit_json(
                    "case_document",
                    &placeholder_output_sha256,
                    &sha256_hex(b"[]"),
                ),
                &case_assistant_tool_source_audit_json(
                    &generation_ids,
                    &"c".repeat(64),
                    &"d".repeat(64),
                ),
                None,
            )
            .expect("case assistant tool audit succeeds"),
            ToolCallStatusUpdateResult::Updated(_)
        ));
        assert!(matches!(
            compare_and_set_agent_run_status(
                connection,
                run_id,
                "queued",
                "succeeded",
                Some(assistant_message_id),
                None,
            )
            .expect("case assistant run succeeds"),
            AgentRunStatusUpdateResult::Updated(_)
        ));
    }

    fn seed_case_assistant_pending_output_fixture(
        connection: &rusqlite::Connection,
        fixture_prefix: &str,
        output_kind: &str,
    ) -> NewCaseAssistantPendingOutputRow {
        seed_case_assistant_pending_output_fixture_with_refs(
            connection,
            fixture_prefix,
            output_kind,
            "[]",
        )
    }

    fn seed_case_assistant_pending_output_fixture_with_refs(
        connection: &rusqlite::Connection,
        fixture_prefix: &str,
        output_kind: &str,
        expected_proposal_source_refs_json: &str,
    ) -> NewCaseAssistantPendingOutputRow {
        let project_id = format!("{fixture_prefix}-project");
        let conversation_id = format!("{fixture_prefix}-conversation");
        let run_id = format!("{fixture_prefix}-run");
        let user_message_id = format!("{fixture_prefix}-user-message");
        let assistant_message_id = format!("{fixture_prefix}-assistant-message");
        let pending_output_id = format!("{fixture_prefix}-output");
        seed_project(connection, &project_id);
        seed_case_assistant_successful_run(
            connection,
            &project_id,
            &conversation_id,
            &run_id,
            &user_message_id,
            &assistant_message_id,
        );
        let workspace_base_digest = case_workspace_digest(connection, &project_id)
            .expect("workspace digest computes")
            .expect("project exists");
        let snapshots = case_assistant_source_snapshots_json();
        let payload = case_assistant_output_payload_json(output_kind);
        let output = NewCaseAssistantPendingOutputRow {
            pending_output_id,
            project_id,
            conversation_id,
            run_id,
            assistant_message_id,
            project_binding_sha256: "a".repeat(64),
            source_snapshots_sha256: sha256_hex(snapshots.as_bytes()),
            source_snapshots_json: snapshots,
            expected_proposal_source_refs_json: expected_proposal_source_refs_json.to_owned(),
            expected_proposal_source_refs_sha256: sha256_hex(
                expected_proposal_source_refs_json.as_bytes(),
            ),
            output_kind: output_kind.to_owned(),
            output_sha256: sha256_hex(payload.as_bytes()),
            output_payload_json: payload,
            output_preview: "Answer".to_owned(),
            output_version: 1,
            workspace_base_digest,
        };
        set_case_assistant_tool_audit_for_pending_output(connection, &output);
        create_case_assistant_pending_output(connection, &output)
            .expect("case assistant pending output creates");
        output
    }

    fn confirm_case_assistant_analysis_fixture(
        connection: &mut rusqlite::Connection,
        output: &NewCaseAssistantPendingOutputRow,
        proposal_id: &str,
    ) {
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("analysis fixture confirmation transaction begins");
        create_case_change_proposal(
            &transaction,
            &NewCaseChangeProposalRow {
                proposal_id: proposal_id.to_owned(),
                conversation_id: output.conversation_id.clone(),
                project_id: output.project_id.clone(),
                run_id: Some(output.run_id.clone()),
                base_case_digest: output.workspace_base_digest.clone(),
                changes_json: r#"{"changes":[]}"#.to_owned(),
                source_refs_json: output.expected_proposal_source_refs_json.clone(),
            },
        )
        .expect("analysis fixture proposal creates");
        assert!(matches!(
            compare_and_set_case_change_proposal_status(
                &transaction,
                proposal_id,
                &output.project_id,
                &output.workspace_base_digest,
                "applied",
            )
            .expect("analysis fixture proposal applies"),
            CaseChangeProposalStatusUpdateResult::Updated(_)
        ));
        assert!(matches!(
            compare_and_set_case_assistant_pending_output_confirmed(
                &transaction,
                &ConfirmCaseAssistantPendingOutput {
                    pending_output_id: &output.pending_output_id,
                    project_id: &output.project_id,
                    expected_output_version: output.output_version,
                    expected_output_sha256: &output.output_sha256,
                    expected_workspace_base_digest: &output.workspace_base_digest,
                    expected_proposal_source_refs_json: &output.expected_proposal_source_refs_json,
                    expected_proposal_source_refs_sha256: &output
                        .expected_proposal_source_refs_sha256,
                    confirmation_request_sha256: &"a".repeat(64),
                    target: &CaseAssistantConfirmationTarget::Proposal(proposal_id.to_owned()),
                },
            )
            .expect("analysis fixture confirmation succeeds"),
            CaseAssistantPendingOutputConfirmResult::Confirmed(_)
        ));
        transaction
            .commit()
            .expect("analysis fixture confirmation commits");
    }

    fn downgrade_case_assistant_proposal_provenance_fixture(connection: &rusqlite::Connection) {
        for trigger in USER_SCHEMA_TRIGGER_NAMES {
            connection
                .execute(&format!("DROP TRIGGER IF EXISTS \"{trigger}\""), [])
                .expect("canonical trigger drops for legacy provenance fixture");
        }
        connection
            .execute(
                "UPDATE tool_calls
                 SET output_audit_json=json_remove(
                     output_audit_json,
                     '$.outputHashes.proposalSourceRefsSha256'
                 )
                 WHERE capability_name='assistant.case_work'
                   AND status='succeeded'",
                [],
            )
            .expect("legacy tool audits omit exact proposal provenance hash");
        connection
            .execute_batch(
                "CREATE TABLE case_assistant_pending_outputs_legacy_fixture AS
                 SELECT
                     pending_output_id, project_id, conversation_id, run_id,
                     assistant_message_id, project_binding_sha256,
                     source_snapshots_json, source_snapshots_sha256,
                     output_kind, output_payload_json, output_preview,
                     output_sha256, output_version, workspace_base_digest,
                     status, confirmed_artifact_id, confirmed_proposal_id,
                     confirmation_request_sha256, row_version, created_at,
                     confirmed_at
                 FROM case_assistant_pending_outputs;
                 DROP TABLE case_assistant_pending_outputs;
                 ALTER TABLE case_assistant_pending_outputs_legacy_fixture
                 RENAME TO case_assistant_pending_outputs;",
            )
            .expect("legacy pending-output table omits exact proposal provenance columns");
        connection
            .execute(
                "UPDATE user_database_metadata
                 SET value='v11-before-exact-proposal-provenance'
                 WHERE key=?1",
                [USER_CANONICAL_SCHEMA_MARKER_KEY],
            )
            .expect("legacy provenance fixture requests canonical rebuild");
    }

    fn provider_snapshot_json() -> String {
        serde_json::to_string(&serde_json::json!({
            "kind": "deep_seek",
            "modelId": "test-model",
            "baseUrl": "https://api.example.invalid/v1",
            "capabilities": {
                "chat": true,
                "streaming": true,
                "customModelId": true,
                "customBaseUrl": true,
                "reasoning": true,
            },
            "options": {
                "thinking": false,
                "enableThinking": null,
                "thinkingBudget": null,
                "reasoningEffort": null,
                "endpointId": null,
                "workspaceId": null,
                "allowPrivateNetwork": false,
            },
        }))
        .expect("provider snapshot serializes")
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
