use super::{
    configure_user_database_connection, existing_user_schema_version, sha256_hex,
    user_database_metadata_value, user_schema_migration_error, user_schema_objects,
    validate_open_user_database, DatabaseInitError, UserSchemaObject,
    USER_CANONICAL_SCHEMA_MARKER_KEY, USER_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

pub const V031_USER_SCHEMA_VERSION: i64 = 10;
pub const V031_USER_CANONICAL_SCHEMA_MARKER: &str = "v10-operation-audit-20260717";
const V031_USER_SCHEMA_MANIFEST: &str = include_str!("../schema/v031-user-sqlite-master.jsonl");
pub const V031_USER_SCHEMA_MANIFEST_SHA256: &str =
    "947a2823d2bbfce22bf687dc0a302c62fbbed4d68066e4167de9e0c15b534cf9";
pub const V031_USER_SCHEMA_OBJECT_COUNT: usize = 74;
pub const V031_USER_INTERNAL_SCHEMA_OBJECT_COUNT: usize = 37;
pub const V031_USER_INTERNAL_SCHEMA_MANIFEST_SHA256: &str =
    "d943817279c2b2a48573e33dad8c3e36671df21346f8895464c5d2758f98c28c";
pub const V031_USER_CANONICAL_EMPTY_FIXTURE_SHA256: &str =
    "ff287cdef2b76914256fdbdd33847bcd07daf6a48fe22e8f6c845b1fcd224910";
pub const V031_USER_GENERATOR_SHA256: &str =
    "bf04c5165584e8de64adcc17fc549cd06dfdc7928dee9a41c6ed0b7e68c696cc";
pub const V031_USER_GENERATION_CARGO_LOCK_SHA256: &str =
    "586ba74064e84a274d003ce78b6fc331c1f4b09cd94219c3a0d4aa0df2fbd74e";
pub const V031_USER_GENERATION_DATABASE_SOURCE_SHA256: &str =
    "48a532e6a097e9ada8f151d44bc59fb977431146b9178417a34babab10991cb7";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V031UserSchemaProvenance {
    pub tag_name: &'static str,
    pub annotated_tag_object_id: &'static str,
    pub peeled_commit_id: &'static str,
    pub tagger_utc: &'static str,
    pub schema_version: i64,
    pub canonical_marker: &'static str,
    pub application_schema_object_count: usize,
    pub application_schema_manifest_sha256: &'static str,
    pub internal_schema_object_count: usize,
    pub internal_schema_manifest_sha256: &'static str,
    pub canonical_empty_fixture_sha256: &'static str,
    pub generator_sha256: &'static str,
    pub generation_cargo_lock_sha256: &'static str,
    pub generation_database_source_sha256: &'static str,
}

pub const V031_USER_SCHEMA_PROVENANCE: V031UserSchemaProvenance = V031UserSchemaProvenance {
    tag_name: "v0.3.1",
    annotated_tag_object_id: "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc",
    peeled_commit_id: "0970f1c614b1bec1856869c68065162339849468",
    tagger_utc: "2026-07-19T15:41:29Z",
    schema_version: V031_USER_SCHEMA_VERSION,
    canonical_marker: V031_USER_CANONICAL_SCHEMA_MARKER,
    application_schema_object_count: V031_USER_SCHEMA_OBJECT_COUNT,
    application_schema_manifest_sha256: V031_USER_SCHEMA_MANIFEST_SHA256,
    internal_schema_object_count: V031_USER_INTERNAL_SCHEMA_OBJECT_COUNT,
    internal_schema_manifest_sha256: V031_USER_INTERNAL_SCHEMA_MANIFEST_SHA256,
    canonical_empty_fixture_sha256: V031_USER_CANONICAL_EMPTY_FIXTURE_SHA256,
    generator_sha256: V031_USER_GENERATOR_SHA256,
    generation_cargo_lock_sha256: V031_USER_GENERATION_CARGO_LOCK_SHA256,
    generation_database_source_sha256: V031_USER_GENERATION_DATABASE_SOURCE_SHA256,
};

const V031_USER_INTERNAL_AUTO_INDEX_ALLOWLIST: &[(&str, &str)] = &[
    ("sqlite_autoindex_agent_runs_1", "agent_runs"),
    ("sqlite_autoindex_artifact_versions_1", "artifact_versions"),
    ("sqlite_autoindex_artifact_versions_2", "artifact_versions"),
    ("sqlite_autoindex_artifacts_1", "artifacts"),
    ("sqlite_autoindex_attachments_1", "attachments"),
    ("sqlite_autoindex_attachments_2", "attachments"),
    (
        "sqlite_autoindex_case_change_proposals_1",
        "case_change_proposals",
    ),
    (
        "sqlite_autoindex_case_extraction_confirmations_1",
        "case_extraction_confirmations",
    ),
    ("sqlite_autoindex_case_facts_1", "case_facts"),
    ("sqlite_autoindex_case_facts_2", "case_facts"),
    ("sqlite_autoindex_case_files_1", "case_files"),
    ("sqlite_autoindex_case_parties_1", "case_parties"),
    (
        "sqlite_autoindex_case_uncertainties_1",
        "case_uncertainties",
    ),
    (
        "sqlite_autoindex_conversation_sources_1",
        "conversation_sources",
    ),
    ("sqlite_autoindex_conversations_1", "conversations"),
    (
        "sqlite_autoindex_document_generation_records_1",
        "document_generation_records",
    ),
    ("sqlite_autoindex_evidence_items_1", "evidence_items"),
    ("sqlite_autoindex_evidence_items_2", "evidence_items"),
    ("sqlite_autoindex_evidence_items_3", "evidence_items"),
    ("sqlite_autoindex_evidence_links_1", "evidence_links"),
    ("sqlite_autoindex_evidence_links_2", "evidence_links"),
    ("sqlite_autoindex_fact_issue_links_1", "fact_issue_links"),
    ("sqlite_autoindex_fact_issue_links_2", "fact_issue_links"),
    (
        "sqlite_autoindex_legal_answer_records_1",
        "legal_answer_records",
    ),
    ("sqlite_autoindex_legal_basis_1", "legal_basis"),
    ("sqlite_autoindex_legal_issues_1", "legal_issues"),
    ("sqlite_autoindex_legal_issues_2", "legal_issues"),
    (
        "sqlite_autoindex_message_attachments_1",
        "message_attachments",
    ),
    ("sqlite_autoindex_messages_1", "messages"),
    ("sqlite_autoindex_operation_audit_1", "operation_audit"),
    (
        "sqlite_autoindex_pending_extraction_reviews_1",
        "pending_extraction_reviews",
    ),
    (
        "sqlite_autoindex_pending_extraction_reviews_2",
        "pending_extraction_reviews",
    ),
    ("sqlite_autoindex_projects_1", "projects"),
    ("sqlite_autoindex_provider_profiles_1", "provider_profiles"),
    ("sqlite_autoindex_tool_calls_1", "tool_calls"),
    ("sqlite_autoindex_tool_calls_2", "tool_calls"),
    (
        "sqlite_autoindex_user_database_metadata_1",
        "user_database_metadata",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatedUserSourceSchema {
    V031V10,
    CurrentV11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMigrationSourceFileProof {
    pub identity_sha256: String,
    pub length: u64,
    pub modified_unix_nanos: Option<u128>,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMigrationTableProof {
    pub table: String,
    pub rows: u64,
    pub logical_manifest_sha256: String,
    pub business_manifest_sha256: Option<String>,
    pub business_primary_key_manifest_sha256: Option<String>,
    pub business_row_manifest_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMigrationSourceProof {
    pub schema: ValidatedUserSourceSchema,
    pub database_file: UserMigrationSourceFileProof,
    pub wal: Option<UserMigrationSourceFileProof>,
    pub shm: Option<UserMigrationSourceFileProof>,
    pub journal: Option<UserMigrationSourceFileProof>,
    pub schema_manifest_sha256: String,
    pub logical_database_manifest_sha256: String,
    pub business_manifest_sha256: String,
    pub business_primary_key_manifest_sha256: String,
    pub business_row_manifest_sha256: String,
    pub tables: Vec<UserMigrationTableProof>,
    pub total_rows: u64,
    pub data_version: i64,
}

/// Narrow view of the already validated, still-pinned source transaction.
///
/// The source connection is deliberately private. The only operation exposed
/// to migration orchestration is SQLite's Backup API, so transaction-control,
/// PRAGMA, ATTACH, and arbitrary source queries are not expressible here.
pub struct ValidatedUserMigrationSourceSession<'transaction> {
    source: &'transaction rusqlite::Connection,
    proof: &'transaction UserMigrationSourceProof,
}

impl ValidatedUserMigrationSourceSession<'_> {
    pub const fn proof(&self) -> &UserMigrationSourceProof {
        self.proof
    }

    pub fn backup_to(
        &self,
        destination: &mut rusqlite::Connection,
    ) -> Result<(), DatabaseInitError> {
        let backup = rusqlite::backup::Backup::new(self.source, destination)?;
        backup.run_to_completion(64, Duration::from_millis(1), None)?;
        Ok(())
    }
}

/// Validates a database that may be the immutable v0.3.1 migration source or
/// the current v11 schema without granting SQLite write access.
///
/// This deliberately does not call the writable migration path. The source
/// file and its SQLite sidecars are fingerprinted before and after a deferred
/// read transaction so a caller never receives a successful classification
/// for a path that drifted during validation.
pub fn validate_user_database_migration_source_read_only(
    user_database_path: impl AsRef<Path>,
) -> Result<ValidatedUserSourceSchema, DatabaseInitError> {
    let (proof, ()) =
        with_validated_user_database_migration_source_read_only(user_database_path, |_| ())?;
    Ok(proof.schema)
}

/// Runs an operation against the same pinned deferred read transaction used to
/// validate and fingerprint a migration source.
///
/// The callback result is intentionally opaque to this crate, so callers can
/// return their own result type. After the callback returns, every logical
/// manifest and the on-disk database/sidecar proof is recomputed before this
/// function can succeed. The proof exposes hashes and counts only: paths,
/// platform file identifiers, primary keys, and row values remain private.
pub fn with_validated_user_database_migration_source_read_only<T>(
    user_database_path: impl AsRef<Path>,
    operation: impl FnOnce(&ValidatedUserMigrationSourceSession<'_>) -> T,
) -> Result<(UserMigrationSourceProof, T), DatabaseInitError> {
    with_validated_user_database_migration_source_read_only_inner(
        user_database_path.as_ref(),
        operation,
        |_| Ok(()),
        |_| Ok(()),
    )
}

fn with_validated_user_database_migration_source_read_only_inner<T, F, G, H>(
    user_database_path: &Path,
    operation: F,
    during_operation_fault: G,
    after_primary_transaction: H,
) -> Result<(UserMigrationSourceProof, T), DatabaseInitError>
where
    F: FnOnce(&ValidatedUserMigrationSourceSession<'_>) -> T,
    G: FnOnce(&rusqlite::Connection) -> Result<(), DatabaseInitError>,
    H: FnOnce(&rusqlite::Connection) -> Result<(), DatabaseInitError>,
{
    let before = migration_source_path_snapshot(user_database_path)?;
    validate_migration_source_sidecar_preflight(&before)?;
    let mut connection =
        open_migration_source_database_read_only_no_create(user_database_path, &before)?;

    let (proof, operation_result, logical_before) = (|| {
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let logical_before = migration_source_logical_proof(&transaction)?;
        let proof = migration_source_public_proof(&before, &logical_before);
        install_migration_source_operation_authorizer(&transaction)?;
        let operation_result = operation(&ValidatedUserMigrationSourceSession {
            source: &transaction,
            proof: &proof,
        });
        during_operation_fault(&transaction)?;
        remove_migration_source_operation_authorizer(&transaction)?;

        let query_only_after: i64 =
            transaction.query_row("PRAGMA query_only", [], |row| row.get(0))?;
        if transaction.is_autocommit() || query_only_after != 1 {
            return Err(user_schema_migration_error(
                "user migration source operation changed its pinned query-only transaction"
                    .to_owned(),
            )
            .into());
        }
        let logical_after = migration_source_logical_proof(&transaction)?;
        if logical_before != logical_after {
            return Err(user_schema_migration_error(
                "user migration source logical proof changed during its deferred read transaction"
                    .to_owned(),
            )
            .into());
        }
        transaction.commit()?;
        Ok::<_, DatabaseInitError>((proof, operation_result, logical_before))
    })()?;

    after_primary_transaction(&connection)?;
    let data_version_after_primary: i64 =
        connection.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    if data_version_after_primary != logical_before.data_version {
        return Err(user_schema_migration_error(
            "user migration source data_version changed after its primary transaction".to_owned(),
        )
        .into());
    }

    let logical_after_transaction = (|| {
        let transaction =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)?;
        let logical = migration_source_logical_proof(&transaction)?;
        transaction.commit()?;
        Ok::<_, DatabaseInitError>(logical)
    })()?;

    let data_version_after_second: i64 =
        connection.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    if data_version_after_second != logical_before.data_version {
        return Err(user_schema_migration_error(
            "user migration source data_version changed after its verification transaction"
                .to_owned(),
        )
        .into());
    }

    drop(connection);
    let after = migration_source_path_snapshot(user_database_path)?;
    if !before.same_evidence(&after) {
        return Err(user_schema_migration_error(
            "user migration source file or SQLite sidecar changed during read-only validation"
                .to_owned(),
        )
        .into());
    }
    if logical_before != logical_after_transaction {
        return Err(user_schema_migration_error(
            "user migration source logical proof changed after its deferred read transaction"
                .to_owned(),
        )
        .into());
    }
    Ok((proof, operation_result))
}

/// Classifies an already-open, query-only migration-source connection.
///
/// Callers that need one pinned snapshot can begin their own deferred read
/// transaction and pass it here. Exact v0.3.1 validation uses the frozen tag
/// manifest; current v11 validation continues to use the ordinary current
/// validator unchanged.
pub fn validate_open_user_database_migration_source_read_only(
    connection: &rusqlite::Connection,
) -> Result<ValidatedUserSourceSchema, DatabaseInitError> {
    let query_only: i64 = connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
    if query_only != 1 || !connection.is_readonly(rusqlite::MAIN_DB)? {
        return Err(user_schema_migration_error(
            "user migration source connection must be main-read-only and query-only".to_owned(),
        )
        .into());
    }

    match existing_user_schema_version(connection)? {
        Some(V031_USER_SCHEMA_VERSION) => {
            validate_v031_canonical_user_database(connection)?;
            Ok(ValidatedUserSourceSchema::V031V10)
        }
        Some(USER_SCHEMA_VERSION) => {
            validate_open_user_database(connection)?;
            Ok(ValidatedUserSourceSchema::CurrentV11)
        }
        Some(found) if found > USER_SCHEMA_VERSION => {
            Err(DatabaseInitError::UnsupportedUserSchemaVersion {
                found,
                supported: USER_SCHEMA_VERSION,
            })
        }
        Some(found) => Err(DatabaseInitError::InvalidUserSchemaVersion(format!(
            "unsupported migration-source schema version {found}"
        ))),
        None => Err(DatabaseInitError::InvalidUserSchemaVersion(
            "missing migration-source schema version".to_owned(),
        )),
    }
}

struct MigrationSourcePathSnapshot {
    database: MigrationSourceFileSnapshot,
    wal: Option<MigrationSourceFileSnapshot>,
    shm: Option<MigrationSourceFileSnapshot>,
    journal: Option<MigrationSourceFileSnapshot>,
    _directory_guards: MigrationSourceDirectoryGuards,
}

struct MigrationSourceFileSnapshot {
    canonical_path: PathBuf,
    platform_identity: Vec<u8>,
    length: u64,
    modified: SystemTime,
    sha256: String,
    prefix: [u8; 32],
    sqlite_journal_mode: Option<SqliteJournalMode>,
    _guard: File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqliteJournalMode {
    Rollback,
    Wal,
}

impl MigrationSourceFileSnapshot {
    fn same_evidence(&self, other: &Self) -> bool {
        self.canonical_path == other.canonical_path
            && self.platform_identity == other.platform_identity
            && self.length == other.length
            && self.modified == other.modified
            && self.sha256 == other.sha256
            && self.sqlite_journal_mode == other.sqlite_journal_mode
    }
}

impl MigrationSourcePathSnapshot {
    fn same_evidence(&self, other: &Self) -> bool {
        self.database.same_evidence(&other.database)
            && optional_file_evidence_eq(self.wal.as_ref(), other.wal.as_ref())
            && optional_file_evidence_eq(self.shm.as_ref(), other.shm.as_ref())
            && optional_file_evidence_eq(self.journal.as_ref(), other.journal.as_ref())
    }
}

fn optional_file_evidence_eq(
    left: Option<&MigrationSourceFileSnapshot>,
    right: Option<&MigrationSourceFileSnapshot>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.same_evidence(right),
        (None, None) => true,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationSourceLogicalProof {
    schema: ValidatedUserSourceSchema,
    schema_manifest_sha256: String,
    logical_database_manifest_sha256: String,
    business_manifest_sha256: String,
    business_primary_key_manifest_sha256: String,
    business_row_manifest_sha256: String,
    tables: Vec<UserMigrationTableProof>,
    total_rows: u64,
    data_version: i64,
}

struct CanonicalManifestHashes {
    logical_database_manifest_sha256: String,
    business_manifest_sha256: String,
    business_primary_key_manifest_sha256: String,
    business_row_manifest_sha256: String,
    tables: Vec<UserMigrationTableProof>,
    total_rows: u64,
}

struct CanonicalLogicalTable {
    name: String,
    create_table_sql: String,
    columns: Vec<CanonicalLogicalColumn>,
    primary_key_columns: Vec<usize>,
    rows: Vec<CanonicalLogicalRow>,
}

struct CanonicalLogicalColumn {
    cid: u64,
    name: String,
    declared_type: String,
    not_null: bool,
    default_sql: Option<String>,
    primary_key_ordinal: u64,
    hidden_flag: u64,
}

struct CanonicalLogicalRow {
    sort_key: Zeroizing<Vec<u8>>,
    encoded_values: Zeroizing<Vec<u8>>,
}

const LOGICAL_MANIFEST_DOMAIN: &[u8] = b"lawyer-assistance\0sqlite-canonical-logical-manifest-v1\0";
const BUSINESS_MANIFEST_DOMAIN: &[u8] =
    b"lawyer-assistance\0sqlite-canonical-business-manifest-v1\0";
const BUSINESS_PRIMARY_KEY_MANIFEST_DOMAIN: &[u8] =
    b"lawyer-assistance\0sqlite-canonical-business-primary-key-manifest-v1\0";
const BUSINESS_ROW_MANIFEST_DOMAIN: &[u8] =
    b"lawyer-assistance\0sqlite-canonical-business-row-manifest-v1\0";

fn migration_source_public_proof(
    path: &MigrationSourcePathSnapshot,
    logical: &MigrationSourceLogicalProof,
) -> UserMigrationSourceProof {
    UserMigrationSourceProof {
        schema: logical.schema,
        database_file: migration_source_public_file_proof(&path.database),
        wal: path.wal.as_ref().map(migration_source_public_file_proof),
        shm: path.shm.as_ref().map(migration_source_public_file_proof),
        journal: path
            .journal
            .as_ref()
            .map(migration_source_public_file_proof),
        schema_manifest_sha256: logical.schema_manifest_sha256.clone(),
        logical_database_manifest_sha256: logical.logical_database_manifest_sha256.clone(),
        business_manifest_sha256: logical.business_manifest_sha256.clone(),
        business_primary_key_manifest_sha256: logical.business_primary_key_manifest_sha256.clone(),
        business_row_manifest_sha256: logical.business_row_manifest_sha256.clone(),
        tables: logical.tables.clone(),
        total_rows: logical.total_rows,
        data_version: logical.data_version,
    }
}

fn migration_source_public_file_proof(
    snapshot: &MigrationSourceFileSnapshot,
) -> UserMigrationSourceFileProof {
    let mut identity = Sha256::new();
    identity.update(b"lawyer-assistance-user-migration-file-identity-v1\0");
    update_digest_bytes(&mut identity, &snapshot.platform_identity);
    UserMigrationSourceFileProof {
        identity_sha256: sha256_digest_hex(identity.finalize()),
        length: snapshot.length,
        modified_unix_nanos: snapshot
            .modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|value| value.as_nanos()),
        sha256: snapshot.sha256.clone(),
    }
}

fn migration_source_path_snapshot(
    user_database_path: &Path,
) -> Result<MigrationSourcePathSnapshot, DatabaseInitError> {
    validate_migration_source_path_components(user_database_path)?;
    let directory_guards = MigrationSourceDirectoryGuards::capture(user_database_path)?;
    let database =
        migration_source_file_snapshot(user_database_path, true, true)?.ok_or_else(|| {
            DatabaseInitError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "user migration source does not exist: {}",
                    user_database_path.display()
                ),
            ))
        })?;
    Ok(MigrationSourcePathSnapshot {
        database,
        wal: migration_source_file_snapshot(
            &sqlite_sidecar_path(user_database_path, "-wal"),
            false,
            false,
        )?,
        shm: migration_source_file_snapshot(
            &sqlite_sidecar_path(user_database_path, "-shm"),
            false,
            false,
        )?,
        journal: migration_source_file_snapshot(
            &sqlite_sidecar_path(user_database_path, "-journal"),
            false,
            false,
        )?,
        _directory_guards: directory_guards,
    })
}

fn sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut path = OsString::from(database_path.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

fn migration_source_file_snapshot(
    path: &Path,
    required: bool,
    inspect_sqlite_header: bool,
) -> Result<Option<MigrationSourceFileSnapshot>, DatabaseInitError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || migration_source_metadata_is_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "user migration source component is not a plain file: {}",
                path.display()
            ),
        )));
    }
    let canonical_before = fs::canonicalize(path)?;
    let mut file = open_migration_source_guarded_file(path)?;
    let platform_before = migration_source_platform_file_info(&file)?;
    let metadata_before = file.metadata()?;
    if platform_before.link_count != 1 {
        return Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "user migration source component must have exactly one link: {}",
                path.display()
            ),
        )));
    }

    let mut hasher = Sha256::new();
    let mut buffer = Zeroizing::new([0u8; 64 * 1024]);
    let mut prefix = [0u8; 32];
    let mut total_read = 0usize;
    loop {
        let read = file.read(&mut *buffer)?;
        if read == 0 {
            break;
        }
        if total_read < prefix.len() {
            let copy = (prefix.len() - total_read).min(read);
            prefix[total_read..total_read + copy].copy_from_slice(&buffer[..copy]);
        }
        total_read = total_read.saturating_add(read);
        hasher.update(&buffer[..read]);
    }
    let metadata_after = file.metadata()?;
    let platform_after = migration_source_platform_file_info(&file)?;
    validate_migration_source_path_components(path)?;
    let path_file = open_migration_source_guarded_file(path)?;
    let path_platform = migration_source_platform_file_info(&path_file)?;
    let path_metadata = path_file.metadata()?;
    let canonical_after = fs::canonicalize(path)?;
    let modified_before = metadata_before.modified()?;
    let modified_after = metadata_after.modified()?;
    let path_modified = path_metadata.modified()?;
    if canonical_before != canonical_after
        || platform_before != platform_after
        || platform_before != path_platform
        || metadata_before.len() != metadata_after.len()
        || metadata_before.len() != path_metadata.len()
        || modified_before != modified_after
        || modified_before != path_modified
    {
        return Err(user_schema_migration_error(format!(
            "user migration source component path or handle changed while hashing: {}",
            path.display()
        ))
        .into());
    }
    let sqlite_journal_mode = if inspect_sqlite_header {
        Some(sqlite_header_journal_mode(&prefix, metadata_after.len())?)
    } else {
        None
    };
    let sha256 = sha256_digest_hex(hasher.finalize());

    Ok(Some(MigrationSourceFileSnapshot {
        canonical_path: canonical_after,
        platform_identity: platform_after.identity,
        length: metadata_after.len(),
        modified: modified_after,
        sha256,
        prefix,
        sqlite_journal_mode,
        _guard: file,
    }))
}

fn validate_migration_source_path_components(path: &Path) -> Result<(), DatabaseInitError> {
    if !path.is_absolute() {
        return Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "user migration source path must be absolute",
        )));
    }
    #[cfg(not(windows))]
    {
        return Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "user migration source fixed-local identity proof is unavailable on this platform",
        )));
    }
    #[cfg(windows)]
    {
        validate_windows_migration_source_path_components(path)
    }
}

#[cfg(windows)]
fn validate_windows_migration_source_path_components(path: &Path) -> Result<(), DatabaseInitError> {
    for component_path in path
        .ancestors()
        .filter(|value| !value.as_os_str().is_empty())
    {
        let metadata = fs::symlink_metadata(component_path)?;
        if metadata.file_type().is_symlink()
            || migration_source_metadata_is_reparse_point(&metadata)
        {
            return Err(DatabaseInitError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "user migration source path contains a link or reparse point: {}",
                    component_path.display()
                ),
            )));
        }
    }
    let canonical = fs::canonicalize(path)?;
    validate_windows_fixed_local_path(&canonical)?;
    Ok(())
}

#[cfg(windows)]
fn migration_source_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MigrationSourcePlatformFileInfo {
    identity: Vec<u8>,
    link_count: u64,
}

#[cfg(windows)]
fn migration_source_platform_file_info(
    file: &File,
) -> Result<MigrationSourcePlatformFileInfo, DatabaseInitError> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let information = unsafe { information.assume_init() };
    if information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
    {
        return Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "user migration source handle is not an ordinary non-reparse file",
        )));
    }
    let file_index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    let mut identity = Vec::with_capacity(12);
    identity.extend_from_slice(&information.dwVolumeSerialNumber.to_le_bytes());
    identity.extend_from_slice(&file_index.to_le_bytes());
    Ok(MigrationSourcePlatformFileInfo {
        identity,
        link_count: u64::from(information.nNumberOfLinks),
    })
}

#[cfg(not(windows))]
fn migration_source_platform_file_info(
    _file: &File,
) -> Result<MigrationSourcePlatformFileInfo, DatabaseInitError> {
    Err(DatabaseInitError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "user migration source file identity is unavailable on this platform",
    )))
}

#[cfg(windows)]
fn open_migration_source_guarded_file(path: &Path) -> Result<File, DatabaseInitError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

#[cfg(not(windows))]
fn open_migration_source_guarded_file(_path: &Path) -> Result<File, DatabaseInitError> {
    Err(DatabaseInitError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "user migration source guarded open is unavailable on this platform",
    )))
}

struct MigrationSourceDirectoryGuards {
    _handles: Vec<File>,
}

impl MigrationSourceDirectoryGuards {
    #[cfg(windows)]
    fn capture(path: &Path) -> Result<Self, DatabaseInitError> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        };

        let mut handles = Vec::new();
        for directory in path
            .parent()
            .into_iter()
            .flat_map(Path::ancestors)
            .filter(|value| !value.as_os_str().is_empty())
        {
            let handle = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(directory)?;
            handles.push(handle);
        }
        Ok(Self { _handles: handles })
    }

    #[cfg(not(windows))]
    fn capture(_path: &Path) -> Result<Self, DatabaseInitError> {
        Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "user migration source directory guards are unavailable on this platform",
        )))
    }
}

#[cfg(windows)]
fn validate_windows_fixed_local_path(path: &Path) -> Result<(), DatabaseInitError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;

    const DRIVE_FIXED_TYPE: u32 = 3;
    let drive_root = path.ancestors().last().ok_or_else(|| {
        DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "user migration source has no fixed-volume root",
        ))
    })?;
    let wide = drive_root
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe { GetDriveTypeW(wide.as_ptr()) } != DRIVE_FIXED_TYPE {
        return Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "user migration source must be on a fixed local volume",
        )));
    }
    Ok(())
}

fn sqlite_header_journal_mode(
    prefix: &[u8; 32],
    length: u64,
) -> Result<SqliteJournalMode, DatabaseInitError> {
    if length < 100 || &prefix[..16] != b"SQLite format 3\0" {
        return Err(user_schema_migration_error(
            "user migration source has an invalid SQLite database header".to_owned(),
        )
        .into());
    }
    sqlite_header_page_size(prefix)?;
    match (prefix[18], prefix[19]) {
        (1, 1) => Ok(SqliteJournalMode::Rollback),
        (2, 2) => Ok(SqliteJournalMode::Wal),
        _ => Err(user_schema_migration_error(
            "user migration source has an unsafe SQLite journal-mode header".to_owned(),
        )
        .into()),
    }
}

fn sqlite_header_page_size(prefix: &[u8; 32]) -> Result<u64, DatabaseInitError> {
    let encoded = u16::from_be_bytes(prefix[16..18].try_into().expect("fixed prefix"));
    let page_size = if encoded == 1 {
        65_536
    } else {
        u64::from(encoded)
    };
    if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(user_schema_migration_error(
            "user migration source has an invalid SQLite page size".to_owned(),
        )
        .into());
    }
    Ok(page_size)
}

fn validate_migration_source_sidecar_preflight(
    snapshot: &MigrationSourcePathSnapshot,
) -> Result<(), DatabaseInitError> {
    const ROLLBACK_JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    match snapshot.database.sqlite_journal_mode {
        Some(SqliteJournalMode::Rollback) => {
            if snapshot.wal.is_some() || snapshot.shm.is_some() {
                return Err(user_schema_migration_error(
                    "rollback-mode user migration source has WAL sidecars".to_owned(),
                )
                .into());
            }
            if snapshot.journal.as_ref().is_some_and(|journal| {
                journal.length >= 8 && journal.prefix[..8] == ROLLBACK_JOURNAL_MAGIC
            }) {
                return Err(user_schema_migration_error(
                    "user migration source has a hot rollback journal that cannot be recovered read-only"
                        .to_owned(),
                )
                .into());
            }
        }
        Some(SqliteJournalMode::Wal) => {
            let (wal, shm) = snapshot
                .wal
                .as_ref()
                .zip(snapshot.shm.as_ref())
                .ok_or_else(|| {
                    user_schema_migration_error(
                        "WAL-mode user migration source requires existing WAL and SHM sidecars"
                            .to_owned(),
                    )
                })?;
            if snapshot.journal.is_some() {
                return Err(user_schema_migration_error(
                    "WAL-mode user migration source has an incompatible rollback journal"
                        .to_owned(),
                )
                .into());
            }
            let wal_magic = u32::from_be_bytes(wal.prefix[..4].try_into().expect("fixed prefix"));
            if wal.length != 0 {
                let wal_version =
                    u32::from_be_bytes(wal.prefix[4..8].try_into().expect("fixed prefix"));
                let wal_page_size =
                    u32::from_be_bytes(wal.prefix[8..12].try_into().expect("fixed prefix"));
                let database_page_size = sqlite_header_page_size(&snapshot.database.prefix)?;
                let wal_page_size = u64::from(wal_page_size);
                let frame_size = 24u64.checked_add(wal_page_size).ok_or_else(|| {
                    user_schema_migration_error(
                        "user migration source WAL frame size overflowed".to_owned(),
                    )
                })?;
                if wal.length < 32
                    || !matches!(wal_magic, 0x377f_0682 | 0x377f_0683)
                    || wal_version != 3_007_000
                    || wal_page_size != database_page_size
                    || !(512..=65_536).contains(&wal_page_size)
                    || !wal_page_size.is_power_of_two()
                    || (wal.length - 32) % frame_size != 0
                {
                    return Err(user_schema_migration_error(
                        "user migration source WAL sidecar has an invalid header or frame layout"
                            .to_owned(),
                    )
                    .into());
                }
            }
            if shm.length < 32 * 1024 || shm.length % (32 * 1024) != 0 {
                return Err(user_schema_migration_error(
                    "user migration source SHM sidecar is incomplete".to_owned(),
                )
                .into());
            }
        }
        None => {
            return Err(user_schema_migration_error(
                "user migration source SQLite journal mode was not proven".to_owned(),
            )
            .into())
        }
    }
    Ok(())
}

fn open_migration_source_database_read_only_no_create(
    path: &Path,
    expected: &MigrationSourcePathSnapshot,
) -> Result<rusqlite::Connection, DatabaseInitError> {
    let immutable = match expected.database.sqlite_journal_mode {
        Some(SqliteJournalMode::Rollback) => true,
        Some(SqliteJournalMode::Wal) => false,
        None => {
            return Err(user_schema_migration_error(
                "user migration source SQLite journal mode was not proven before open".to_owned(),
            )
            .into())
        }
    };
    let uri = migration_source_uri(path, immutable)?;
    let connection = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    configure_user_database_connection(&connection)?;
    connection.pragma_update(None, "query_only", "ON")?;
    if !connection.is_readonly(rusqlite::MAIN_DB)? {
        return Err(user_schema_migration_error(
            "user migration source open is not main-read-only".to_owned(),
        )
        .into());
    }
    let current = migration_source_path_snapshot(path)?;
    if !expected.same_evidence(&current) {
        return Err(user_schema_migration_error(
            "SQLite opened a user migration source with different path or sidecar evidence"
                .to_owned(),
        )
        .into());
    }
    Ok(connection)
}

#[cfg(windows)]
fn migration_source_uri(path: &Path, immutable: bool) -> Result<String, DatabaseInitError> {
    let canonical = fs::canonicalize(path)?;
    let raw = canonical.to_str().ok_or_else(|| {
        DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "user migration source path is not valid Unicode",
        ))
    })?;
    let raw = raw.strip_prefix(r"\\?\").unwrap_or(raw).replace('\\', "/");
    let bytes = raw.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'/'
        || bytes[3..].contains(&b':')
    {
        return Err(DatabaseInitError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "user migration source path is not a fixed-drive absolute path",
        )));
    }
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'.' | b'-' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    Ok(if immutable {
        format!("file:///{encoded}?mode=ro&immutable=1")
    } else {
        format!("file:///{encoded}?mode=ro&readonly_shm=1")
    })
}

#[cfg(not(windows))]
fn migration_source_uri(_path: &Path, _immutable: bool) -> Result<String, DatabaseInitError> {
    Err(DatabaseInitError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "user migration source immutable fixed-local URI is unavailable on this platform",
    )))
}

fn install_migration_source_operation_authorizer(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    use rusqlite::hooks::{AuthAction, Authorization};

    connection.authorizer(Some(
        |context: rusqlite::hooks::AuthContext<'_>| match context.action {
            AuthAction::Read { .. } | AuthAction::Select | AuthAction::Function { .. } => {
                Authorization::Allow
            }
            _ => Authorization::Deny,
        },
    ))?;
    Ok(())
}

fn remove_migration_source_operation_authorizer(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    use rusqlite::hooks::{AuthContext, Authorization};

    connection.authorizer(None::<fn(AuthContext<'_>) -> Authorization>)?;
    Ok(())
}

fn migration_source_logical_proof(
    connection: &rusqlite::Connection,
) -> Result<MigrationSourceLogicalProof, DatabaseInitError> {
    let data_version_before: i64 =
        connection.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    let schema = validate_open_user_database_migration_source_read_only(connection)?;
    let schema_objects = user_schema_objects(connection)?;
    let schema_manifest_sha256 = canonical_schema_manifest_sha256(&schema_objects)?;
    let tables = canonical_logical_tables(connection, &schema_objects)?;
    let manifests = canonical_logical_manifest_hashes(&tables)?;
    let data_version_after: i64 =
        connection.query_row("PRAGMA data_version", [], |row| row.get(0))?;
    if data_version_before != data_version_after {
        return Err(user_schema_migration_error(
            "user migration source data_version changed while computing its logical proof"
                .to_owned(),
        )
        .into());
    }
    Ok(MigrationSourceLogicalProof {
        schema,
        schema_manifest_sha256,
        logical_database_manifest_sha256: manifests.logical_database_manifest_sha256,
        business_manifest_sha256: manifests.business_manifest_sha256,
        business_primary_key_manifest_sha256: manifests.business_primary_key_manifest_sha256,
        business_row_manifest_sha256: manifests.business_row_manifest_sha256,
        tables: manifests.tables,
        total_rows: manifests.total_rows,
        data_version: data_version_before,
    })
}

fn canonical_schema_manifest_sha256(
    objects: &[UserSchemaObject],
) -> Result<String, DatabaseInitError> {
    let mut encoded = String::new();
    for (object_type, name, table_name, sql) in objects {
        let json_string = |value: &str| {
            serde_json::to_string(value).map_err(|_| {
                user_schema_migration_error(
                    "user migration source schema manifest could not be encoded".to_owned(),
                )
            })
        };
        encoded.push_str("{\"object_type\":");
        encoded.push_str(&json_string(object_type)?);
        encoded.push_str(",\"name\":");
        encoded.push_str(&json_string(name)?);
        encoded.push_str(",\"table_name\":");
        encoded.push_str(&json_string(table_name)?);
        encoded.push_str(",\"sql\":");
        encoded.push_str(&json_string(sql)?);
        encoded.push_str("}\n");
    }
    Ok(sha256_hex(encoded.as_bytes()))
}

fn canonical_logical_tables(
    connection: &rusqlite::Connection,
    schema_objects: &[UserSchemaObject],
) -> Result<Vec<CanonicalLogicalTable>, DatabaseInitError> {
    let mut table_definitions = schema_objects
        .iter()
        .filter(|(object_type, _, _, _)| object_type == "table")
        .map(|(_, name, table_name, sql)| {
            if name != table_name || name.starts_with("sqlite_") {
                return Err(user_schema_migration_error(
                    "user migration source contains an invalid application table definition"
                        .to_owned(),
                )
                .into());
            }
            Ok((name.clone(), normalized_create_table_sql(sql)))
        })
        .collect::<Result<Vec<_>, DatabaseInitError>>()?;
    table_definitions.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    if table_definitions
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() == pair[1].0.as_bytes())
    {
        return Err(user_schema_migration_error(
            "user migration source schema contains duplicate table names".to_owned(),
        )
        .into());
    }

    table_definitions
        .into_iter()
        .map(|(table_name, create_table_sql)| {
            canonical_logical_table(connection, table_name, create_table_sql)
        })
        .collect()
}

fn normalized_create_table_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn canonical_logical_table(
    connection: &rusqlite::Connection,
    table_name: String,
    create_table_sql: String,
) -> Result<CanonicalLogicalTable, DatabaseInitError> {
    if create_table_sql.is_empty() {
        return Err(user_schema_migration_error(format!(
            "user migration source table has no canonical CREATE TABLE SQL: {table_name}"
        ))
        .into());
    }

    let mut column_statement = connection.prepare(&format!(
        "PRAGMA table_xinfo({})",
        quote_sql_identifier(&table_name)
    ))?;
    let raw_columns = column_statement
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut columns = raw_columns
        .into_iter()
        .map(
            |(cid, name, declared_type, not_null, default_sql, primary_key_ordinal, hidden_flag)| {
                let cid = u64::try_from(cid).map_err(|_| {
                    user_schema_migration_error(format!(
                        "user migration source table has a negative column id: {table_name}"
                    ))
                })?;
                let primary_key_ordinal = u64::try_from(primary_key_ordinal).map_err(|_| {
                    user_schema_migration_error(format!(
                        "user migration source table has a negative primary-key ordinal: {table_name}"
                    ))
                })?;
                let hidden_flag = u64::try_from(hidden_flag).map_err(|_| {
                    user_schema_migration_error(format!(
                        "user migration source table has a negative hidden flag: {table_name}"
                    ))
                })?;
                let not_null = match not_null {
                    0 => false,
                    1 => true,
                    _ => {
                        return Err(user_schema_migration_error(format!(
                            "user migration source table has an invalid not-null flag: {table_name}"
                        )))
                    }
                };
                Ok(CanonicalLogicalColumn {
                    cid,
                    name,
                    declared_type,
                    not_null,
                    default_sql,
                    primary_key_ordinal,
                    hidden_flag,
                })
            },
        )
        .collect::<rusqlite::Result<Vec<_>>>()?;
    columns.sort_by_key(|column| column.cid);
    if columns.is_empty() || columns.windows(2).any(|pair| pair[0].cid >= pair[1].cid) {
        return Err(user_schema_migration_error(format!(
            "user migration source table has invalid table_xinfo metadata: {table_name}"
        ))
        .into());
    }

    let mut primary_key_columns = columns
        .iter()
        .enumerate()
        .filter(|(_, column)| column.primary_key_ordinal > 0)
        .map(|(column_index, column)| (column.primary_key_ordinal, column_index))
        .collect::<Vec<_>>();
    primary_key_columns.sort_by_key(|(ordinal, _)| *ordinal);
    if primary_key_columns
        .iter()
        .enumerate()
        .any(|(position, (ordinal, _))| *ordinal != position as u64 + 1)
    {
        return Err(user_schema_migration_error(format!(
            "user migration source table has invalid primary-key ordinals: {table_name}"
        ))
        .into());
    }
    let primary_key_columns = primary_key_columns
        .into_iter()
        .map(|(_, column_index)| column_index)
        .collect::<Vec<_>>();

    let select_columns = columns
        .iter()
        .map(|column| quote_sql_identifier(&column.name))
        .collect::<Vec<_>>()
        .join(",");
    let mut row_statement = connection.prepare(&format!(
        "SELECT {select_columns} FROM {}",
        quote_sql_identifier(&table_name)
    ))?;
    let mut query = row_statement.query([])?;
    let mut canonical_rows = Vec::new();
    while let Some(row) = query.next()? {
        let mut encoded_columns = Vec::with_capacity(columns.len());
        for column_index in 0..columns.len() {
            let mut encoded_value = Zeroizing::new(Vec::new());
            append_canonical_value(&mut encoded_value, row.get_ref(column_index)?);
            encoded_columns.push(encoded_value);
        }

        let encoded_value_length = encoded_columns.iter().map(|value| value.len()).sum();
        let mut encoded_values = Zeroizing::new(Vec::with_capacity(encoded_value_length));
        for encoded_value in &encoded_columns {
            encoded_values.extend_from_slice(encoded_value);
        }

        let sort_key = if primary_key_columns.is_empty() {
            Zeroizing::new(encoded_values.to_vec())
        } else {
            let key_length = primary_key_columns
                .iter()
                .map(|column_index| encoded_columns[*column_index].len())
                .sum();
            let mut primary_key = Zeroizing::new(Vec::with_capacity(key_length));
            for column_index in &primary_key_columns {
                primary_key.extend_from_slice(&encoded_columns[*column_index]);
            }
            primary_key
        };
        canonical_rows.push(CanonicalLogicalRow {
            sort_key,
            encoded_values,
        });
    }
    canonical_rows.sort_by(|left, right| {
        left.sort_key
            .as_slice()
            .cmp(right.sort_key.as_slice())
            .then_with(|| {
                left.encoded_values
                    .as_slice()
                    .cmp(right.encoded_values.as_slice())
            })
    });

    Ok(CanonicalLogicalTable {
        name: table_name,
        create_table_sql,
        columns,
        primary_key_columns,
        rows: canonical_rows,
    })
}

fn canonical_logical_manifest_hashes(
    tables: &[CanonicalLogicalTable],
) -> Result<CanonicalManifestHashes, DatabaseInitError> {
    let logical_tables = tables.iter().collect::<Vec<_>>();
    let business_tables = tables
        .iter()
        .filter(|table| table.name != "user_database_metadata")
        .collect::<Vec<_>>();

    let logical_database_manifest_sha256 =
        canonical_manifest_sha256(LOGICAL_MANIFEST_DOMAIN, &logical_tables)?;
    let business_manifest_sha256 =
        canonical_manifest_sha256(BUSINESS_MANIFEST_DOMAIN, &business_tables)?;
    let business_primary_key_manifest_sha256 = canonical_primary_key_manifest_sha256(
        BUSINESS_PRIMARY_KEY_MANIFEST_DOMAIN,
        &business_tables,
    )?;
    let business_row_manifest_sha256 =
        canonical_manifest_sha256(BUSINESS_ROW_MANIFEST_DOMAIN, &business_tables)?;

    let mut table_proofs = Vec::with_capacity(tables.len());
    let mut total_rows = 0u64;
    for table in tables {
        let rows = u64::try_from(table.rows.len()).map_err(|_| {
            user_schema_migration_error("user migration source row count is too large".to_owned())
        })?;
        total_rows = total_rows.checked_add(rows).ok_or_else(|| {
            user_schema_migration_error(
                "user migration source total row count is too large".to_owned(),
            )
        })?;
        let business = table.name != "user_database_metadata";
        table_proofs.push(UserMigrationTableProof {
            table: table.name.clone(),
            rows,
            logical_manifest_sha256: canonical_manifest_sha256(LOGICAL_MANIFEST_DOMAIN, &[table])?,
            business_manifest_sha256: business
                .then(|| canonical_manifest_sha256(BUSINESS_MANIFEST_DOMAIN, &[table]))
                .transpose()?,
            business_primary_key_manifest_sha256: business
                .then(|| {
                    canonical_primary_key_manifest_sha256(
                        BUSINESS_PRIMARY_KEY_MANIFEST_DOMAIN,
                        &[table],
                    )
                })
                .transpose()?,
            business_row_manifest_sha256: business
                .then(|| canonical_manifest_sha256(BUSINESS_ROW_MANIFEST_DOMAIN, &[table]))
                .transpose()?,
        });
    }

    Ok(CanonicalManifestHashes {
        logical_database_manifest_sha256,
        business_manifest_sha256,
        business_primary_key_manifest_sha256,
        business_row_manifest_sha256,
        tables: table_proofs,
        total_rows,
    })
}

fn canonical_manifest_sha256(
    domain: &[u8],
    tables: &[&CanonicalLogicalTable],
) -> Result<String, DatabaseInitError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_digest_u64(
        &mut hasher,
        u64::try_from(tables.len()).map_err(|_| {
            user_schema_migration_error("user migration source table count is too large".to_owned())
        })?,
    );

    for table in tables {
        hasher.update([0x10]);
        update_manifest_field(&mut hasher, 0x11, table.name.as_bytes());
        update_manifest_field(&mut hasher, 0x12, table.create_table_sql.as_bytes());
        update_digest_u64(
            &mut hasher,
            u64::try_from(table.columns.len()).map_err(|_| {
                user_schema_migration_error(
                    "user migration source column count is too large".to_owned(),
                )
            })?,
        );
        for column in &table.columns {
            hasher.update([0x13]);
            update_digest_u64(&mut hasher, column.cid);
            update_manifest_field(&mut hasher, 0x14, column.name.as_bytes());
            update_manifest_field(&mut hasher, 0x15, column.declared_type.as_bytes());
            hasher.update([u8::from(column.not_null)]);
            hasher.update([u8::from(column.default_sql.is_some())]);
            if let Some(default_sql) = &column.default_sql {
                update_manifest_field(&mut hasher, 0x16, default_sql.as_bytes());
            }
            update_digest_u64(&mut hasher, column.primary_key_ordinal);
            update_digest_u64(&mut hasher, column.hidden_flag);
        }
        update_digest_u64(
            &mut hasher,
            u64::try_from(table.rows.len()).map_err(|_| {
                user_schema_migration_error(
                    "user migration source row count is too large".to_owned(),
                )
            })?,
        );
        for row in &table.rows {
            hasher.update([0x20]);
            update_digest_u64(
                &mut hasher,
                u64::try_from(table.columns.len()).map_err(|_| {
                    user_schema_migration_error(
                        "user migration source column count is too large".to_owned(),
                    )
                })?,
            );
            hasher.update(&row.encoded_values);
        }
    }
    Ok(sha256_digest_hex(hasher.finalize()))
}

fn canonical_primary_key_manifest_sha256(
    domain: &[u8],
    tables: &[&CanonicalLogicalTable],
) -> Result<String, DatabaseInitError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    update_digest_u64(
        &mut hasher,
        u64::try_from(tables.len()).map_err(|_| {
            user_schema_migration_error(
                "user migration source business table count is too large".to_owned(),
            )
        })?,
    );
    for table in tables {
        hasher.update([0x10]);
        update_manifest_field(&mut hasher, 0x11, table.name.as_bytes());
        update_digest_u64(
            &mut hasher,
            u64::try_from(table.primary_key_columns.len()).map_err(|_| {
                user_schema_migration_error(
                    "user migration source primary-key width is too large".to_owned(),
                )
            })?,
        );
        for column_index in &table.primary_key_columns {
            let column = &table.columns[*column_index];
            hasher.update([0x13]);
            update_digest_u64(&mut hasher, column.primary_key_ordinal);
            update_manifest_field(&mut hasher, 0x14, column.name.as_bytes());
        }
        update_digest_u64(
            &mut hasher,
            u64::try_from(table.rows.len()).map_err(|_| {
                user_schema_migration_error(
                    "user migration source row count is too large".to_owned(),
                )
            })?,
        );
        for row in &table.rows {
            hasher.update([0x20]);
            update_digest_u64(
                &mut hasher,
                u64::try_from(row.sort_key.len()).map_err(|_| {
                    user_schema_migration_error(
                        "user migration source primary-key encoding is too large".to_owned(),
                    )
                })?,
            );
            hasher.update(&row.sort_key);
        }
    }
    Ok(sha256_digest_hex(hasher.finalize()))
}

fn quote_sql_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn update_digest_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_be_bytes());
}

fn update_digest_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    update_digest_u64(hasher, bytes.len() as u64);
    hasher.update(bytes);
}

fn update_manifest_field(hasher: &mut Sha256, tag: u8, bytes: &[u8]) {
    hasher.update([tag]);
    update_digest_bytes(hasher, bytes);
}

fn append_canonical_value(output: &mut Vec<u8>, value: rusqlite::types::ValueRef<'_>) {
    match value {
        rusqlite::types::ValueRef::Null => output.push(0x00),
        rusqlite::types::ValueRef::Integer(value) => {
            output.push(0x01);
            output.extend_from_slice(&value.to_be_bytes());
        }
        rusqlite::types::ValueRef::Real(value) => {
            output.push(0x02);
            output.extend_from_slice(&value.to_bits().to_be_bytes());
        }
        rusqlite::types::ValueRef::Text(value) => {
            output.push(0x03);
            output.extend_from_slice(&(value.len() as u64).to_be_bytes());
            output.extend_from_slice(value);
        }
        rusqlite::types::ValueRef::Blob(value) => {
            output.push(0x04);
            output.extend_from_slice(&(value.len() as u64).to_be_bytes());
            output.extend_from_slice(value);
        }
    }
}

fn sha256_digest_hex(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_v031_project_scoped_relations(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<()> {
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

fn validate_v031_assistant_scoped_relations(
    connection: &rusqlite::Connection,
) -> rusqlite::Result<()> {
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

    Ok(())
}

fn validate_v031_canonical_user_database(
    connection: &rusqlite::Connection,
) -> Result<(), DatabaseInitError> {
    if existing_user_schema_version(connection)? != Some(V031_USER_SCHEMA_VERSION) {
        return Err(user_schema_migration_error(
            "v0.3.1 user database schema version is missing or invalid".to_owned(),
        )
        .into());
    }
    let marker = user_database_metadata_value(connection, USER_CANONICAL_SCHEMA_MARKER_KEY)?;
    if marker.as_deref() != Some(V031_USER_CANONICAL_SCHEMA_MARKER) {
        return Err(user_schema_migration_error(
            "v0.3.1 canonical user schema marker is missing or invalid".to_owned(),
        )
        .into());
    }

    if user_schema_objects(connection)? != v031_user_schema_objects()? {
        return Err(user_schema_migration_error(
            "user database sqlite_master does not match the exact v0.3.1 canonical schema"
                .to_owned(),
        )
        .into());
    }
    if user_internal_schema_objects(connection)? != v031_user_internal_schema_objects()? {
        return Err(user_schema_migration_error(
            "user database internal sqlite_master objects do not match the frozen v0.3.1 allowlist"
                .to_owned(),
        )
        .into());
    }
    validate_v031_project_scoped_relations(connection)?;
    validate_v031_assistant_scoped_relations(connection)?;

    let mut foreign_keys = connection.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(user_schema_migration_error(
            "foreign key violations remain in v0.3.1 user database".to_owned(),
        )
        .into());
    }
    let quick_check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(user_schema_migration_error(
            "v0.3.1 user database quick_check failed".to_owned(),
        )
        .into());
    }
    Ok(())
}

fn user_internal_schema_objects(
    connection: &rusqlite::Connection,
) -> Result<Vec<UserSchemaObject>, DatabaseInitError> {
    let mut statement = connection.prepare(
        "SELECT type,name,tbl_name,COALESCE(sql,'')
         FROM sqlite_master
         WHERE type IN ('table','index','trigger','view')
           AND name LIKE 'sqlite_%'
         ORDER BY type,name",
    )?;
    let objects = statement
        .query_map([], |row| {
            let sql = row.get::<_, String>(3)?;
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                normalized_create_table_sql(&sql),
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(objects)
}

fn v031_user_internal_schema_objects() -> Result<Vec<UserSchemaObject>, DatabaseInitError> {
    let objects = V031_USER_INTERNAL_AUTO_INDEX_ALLOWLIST
        .iter()
        .map(|(name, table_name)| {
            (
                "index".to_owned(),
                (*name).to_owned(),
                (*table_name).to_owned(),
                String::new(),
            )
        })
        .collect::<Vec<_>>();
    if objects.len() != V031_USER_INTERNAL_SCHEMA_OBJECT_COUNT
        || canonical_schema_manifest_sha256(&objects)? != V031_USER_INTERNAL_SCHEMA_MANIFEST_SHA256
    {
        return Err(user_schema_migration_error(
            "embedded v0.3.1 internal schema allowlist failed provenance verification".to_owned(),
        )
        .into());
    }
    Ok(objects)
}

fn v031_user_schema_objects() -> Result<Vec<UserSchemaObject>, DatabaseInitError> {
    if sha256_hex(V031_USER_SCHEMA_MANIFEST.as_bytes()) != V031_USER_SCHEMA_MANIFEST_SHA256 {
        return Err(user_schema_migration_error(
            "embedded v0.3.1 user schema manifest failed provenance verification".to_owned(),
        )
        .into());
    }

    let mut objects = Vec::with_capacity(V031_USER_SCHEMA_OBJECT_COUNT);
    for line in V031_USER_SCHEMA_MANIFEST.lines() {
        let value = serde_json::from_str::<serde_json::Value>(line).map_err(|_| {
            user_schema_migration_error(
                "embedded v0.3.1 user schema manifest is invalid JSON Lines".to_owned(),
            )
        })?;
        let object = value.as_object().ok_or_else(|| {
            user_schema_migration_error(
                "embedded v0.3.1 user schema manifest entry is not an object".to_owned(),
            )
        })?;
        if object.len() != 4 {
            return Err(user_schema_migration_error(
                "embedded v0.3.1 user schema manifest entry has unexpected fields".to_owned(),
            )
            .into());
        }
        let field = |name: &str| -> rusqlite::Result<String> {
            object
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    user_schema_migration_error(format!(
                        "embedded v0.3.1 user schema manifest field is invalid: {name}"
                    ))
                })
        };
        objects.push((
            field("object_type")?,
            field("name")?,
            field("table_name")?,
            field("sql")?,
        ));
    }

    if objects.len() != V031_USER_SCHEMA_OBJECT_COUNT {
        return Err(user_schema_migration_error(
            "embedded v0.3.1 user schema manifest object count is invalid".to_owned(),
        )
        .into());
    }
    let counts = objects.iter().fold(
        BTreeMap::<&str, usize>::new(),
        |mut counts, (object_type, _, _, _)| {
            *counts.entry(object_type.as_str()).or_default() += 1;
            counts
        },
    );
    if counts.get("table") != Some(&27)
        || counts.get("index") != Some(&34)
        || counts.get("trigger") != Some(&13)
        || counts.get("view").copied().unwrap_or_default() != 0
        || counts.len() != 3
    {
        return Err(user_schema_migration_error(
            "embedded v0.3.1 user schema manifest object classes are invalid".to_owned(),
        )
        .into());
    }
    if objects
        .windows(2)
        .any(|pair| (&pair[0].0, &pair[0].1) >= (&pair[1].0, &pair[1].1))
    {
        return Err(user_schema_migration_error(
            "embedded v0.3.1 user schema manifest is not strictly ordered".to_owned(),
        )
        .into());
    }
    Ok(objects)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ensure_user_database, is_lower_hex_sha256, open_user_database,
        open_user_database_read_only, validate_user_database_read_only,
    };
    use std::{fs, path::Path};

    fn create_v031_user_database_from_manifest(
        database_path: &Path,
        mutate: impl FnOnce(&mut Vec<UserSchemaObject>),
    ) {
        let mut objects =
            v031_user_schema_objects().expect("frozen v0.3.1 manifest parses and verifies");
        mutate(&mut objects);
        let connection = open_user_database(database_path).expect("v0.3.1 fixture database opens");
        for object_type in ["table", "index", "trigger", "view"] {
            for (_, name, _, sql) in objects
                .iter()
                .filter(|(found_type, _, _, _)| found_type == object_type)
            {
                connection.execute_batch(sql).unwrap_or_else(|error| {
                    panic!("v0.3.1 manifest DDL failed for {name}: {error}")
                });
            }
        }
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('schema_version',?1,'2026-07-19 15:41:29')",
                [V031_USER_SCHEMA_VERSION.to_string()],
            )
            .expect("v0.3.1 schema version is inserted");
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES(?1,?2,'2026-07-19 15:41:29')",
                (
                    USER_CANONICAL_SCHEMA_MARKER_KEY,
                    V031_USER_CANONICAL_SCHEMA_MARKER,
                ),
            )
            .expect("v0.3.1 canonical marker is inserted");
    }

    fn create_exact_v031_user_database(database_path: &Path) {
        create_v031_user_database_from_manifest(database_path, |_| {});
    }

    fn migration_source_proof(database_path: &Path) -> UserMigrationSourceProof {
        with_validated_user_database_migration_source_read_only(database_path, |_| ())
            .expect("migration source proof validates")
            .0
    }

    fn migration_source_table_rows(proof: &UserMigrationSourceProof) -> Vec<(String, u64)> {
        proof
            .tables
            .iter()
            .map(|table| (table.table.clone(), table.rows))
            .collect()
    }

    const WAL_FIXTURE_CHILD_DATABASE_ENV: &str = "LAWYER_ASSISTANCE_WAL_SOURCE_CHILD_DATABASE";

    fn exit_after_creating_crash_wal_fixture_if_requested() {
        let Some(database_path) = std::env::var_os(WAL_FIXTURE_CHILD_DATABASE_ENV) else {
            return;
        };
        let database_path = PathBuf::from(database_path);
        create_exact_v031_user_database(&database_path);
        let wal_connection =
            open_user_database(&database_path).expect("WAL setup connection opens");
        let journal_mode: String = wal_connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("WAL mode enables");
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        wal_connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("automatic checkpoints disable");
        let main_before_row = fs::read(&database_path).expect("WAL main bytes read");
        wal_connection
            .execute(
                "INSERT INTO projects(
                     project_id,title,case_type,status,opened_on,summary,created_at,updated_at
                 ) VALUES('wal-only-project','WAL','civil','active','2026-07-19',
                          'Committed frame','2026-07-19 15:41:29','2026-07-19 15:41:29')",
                [],
            )
            .expect("WAL-only project commits");
        assert_eq!(
            fs::read(&database_path).expect("WAL main bytes re-read"),
            main_before_row,
            "the committed project must remain outside the main database file"
        );
        assert!(sqlite_sidecar_path(&database_path, "-wal").is_file());
        assert!(sqlite_sidecar_path(&database_path, "-shm").is_file());
        // Exit without running Connection::drop: a graceful final close is
        // allowed to checkpoint/delete WAL, which would stop exercising the
        // recovery snapshot that migration validation must safely consume.
        std::process::exit(0);
    }

    fn create_crash_wal_fixture(database_path: &Path) {
        let child_status = std::process::Command::new(
            std::env::current_exe().expect("current test executable resolves"),
        )
        .arg("--exact")
        .arg(
            "migration_source::tests::migration_source_wal_snapshot_includes_uncheckpointed_commits_without_mutation",
        )
        .env(WAL_FIXTURE_CHILD_DATABASE_ENV, database_path)
        .status()
        .expect("WAL fixture child process launches");
        assert!(child_status.success(), "WAL fixture child must succeed");
    }

    fn insert_v031_project(database_path: &Path, project_id: &str, title: &str, summary: &str) {
        let connection =
            open_user_database(database_path).expect("v0.3.1 project connection opens");
        connection
            .execute(
                "INSERT INTO projects(
                     project_id,title,case_type,status,opened_on,summary,created_at,updated_at
                 ) VALUES(?1,?2,'civil','active','2026-07-19',?3,
                          '2026-07-19 15:41:29','2026-07-19 15:41:29')",
                (project_id, title, summary),
            )
            .expect("v0.3.1 project inserts");
    }

    fn mutate_v031_manifest_sql(
        objects: &mut [UserSchemaObject],
        object_type: &str,
        name: &str,
        before: &str,
        after: &str,
    ) {
        let object = objects
            .iter_mut()
            .find(|(found_type, found_name, _, _)| found_type == object_type && found_name == name)
            .unwrap_or_else(|| panic!("manifest object exists: {object_type}/{name}"));
        let changed = object.3.replace(before, after);
        assert_ne!(changed, object.3, "manifest mutation must change DDL");
        object.3 = changed;
    }

    #[test]
    fn migration_source_validator_accepts_exact_manifest_v10_and_current_v11_read_only() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let v10_path = directory.path().join("v031-user.sqlite");
        create_exact_v031_user_database(&v10_path);
        let bytes_before = fs::read(&v10_path).expect("v0.3.1 fixture bytes read");
        let modified_before = fs::metadata(&v10_path)
            .expect("v0.3.1 fixture metadata reads")
            .modified()
            .expect("v0.3.1 fixture mtime reads");

        assert_eq!(
            validate_user_database_migration_source_read_only(&v10_path)
                .expect("exact v0.3.1 source validates"),
            ValidatedUserSourceSchema::V031V10
        );
        assert_eq!(
            fs::read(&v10_path).expect("validated v0.3.1 bytes read"),
            bytes_before
        );
        assert_eq!(
            fs::metadata(&v10_path)
                .expect("validated v0.3.1 metadata reads")
                .modified()
                .expect("validated v0.3.1 mtime reads"),
            modified_before
        );

        let read_only = open_user_database_read_only(&v10_path).expect("v0.3.1 opens read-only");
        assert_eq!(
            validate_open_user_database_migration_source_read_only(&read_only)
                .expect("open exact v0.3.1 source validates"),
            ValidatedUserSourceSchema::V031V10
        );
        assert!(read_only
            .execute(
                "INSERT INTO projects(project_id,title,status)
                 VALUES('must-not-write','Must not write','active')",
                [],
            )
            .is_err());
        drop(read_only);
        assert!(
            validate_user_database_read_only(&v10_path).is_err(),
            "ordinary current validator must remain v11-only"
        );

        let writable = open_user_database(&v10_path).expect("test writable connection opens");
        writable
            .pragma_update(None, "query_only", "ON")
            .expect("writable connection enters query-only mode");
        assert!(
            validate_open_user_database_migration_source_read_only(&writable).is_err(),
            "query_only must not substitute for a main-read-only SQLite open"
        );
        drop(writable);

        let current_directory = tempfile::tempdir().expect("current tempdir exists");
        let current_path =
            ensure_user_database(current_directory.path()).expect("current database initializes");
        assert_eq!(
            validate_user_database_migration_source_read_only(&current_path)
                .expect("current migration source validates"),
            ValidatedUserSourceSchema::CurrentV11
        );
        validate_user_database_read_only(&current_path)
            .expect("ordinary current validator still accepts v11");
    }

    #[test]
    fn migration_source_manifest_provenance_is_exact_and_fully_ordered() {
        assert_eq!(
            V031_USER_SCHEMA_PROVENANCE,
            V031UserSchemaProvenance {
                tag_name: "v0.3.1",
                annotated_tag_object_id: "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc",
                peeled_commit_id: "0970f1c614b1bec1856869c68065162339849468",
                tagger_utc: "2026-07-19T15:41:29Z",
                schema_version: 10,
                canonical_marker: "v10-operation-audit-20260717",
                application_schema_object_count: 74,
                application_schema_manifest_sha256:
                    "947a2823d2bbfce22bf687dc0a302c62fbbed4d68066e4167de9e0c15b534cf9",
                internal_schema_object_count: 37,
                internal_schema_manifest_sha256:
                    "d943817279c2b2a48573e33dad8c3e36671df21346f8895464c5d2758f98c28c",
                canonical_empty_fixture_sha256:
                    "ff287cdef2b76914256fdbdd33847bcd07daf6a48fe22e8f6c845b1fcd224910",
                generator_sha256:
                    "bf04c5165584e8de64adcc17fc549cd06dfdc7928dee9a41c6ed0b7e68c696cc",
                generation_cargo_lock_sha256:
                    "586ba74064e84a274d003ce78b6fc331c1f4b09cd94219c3a0d4aa0df2fbd74e",
                generation_database_source_sha256:
                    "48a532e6a097e9ada8f151d44bc59fb977431146b9178417a34babab10991cb7",
            }
        );
        assert_eq!(
            sha256_hex(V031_USER_SCHEMA_MANIFEST.as_bytes()),
            V031_USER_SCHEMA_MANIFEST_SHA256
        );
        let objects = v031_user_schema_objects().expect("v0.3.1 manifest verifies");
        assert_eq!(objects.len(), 74);
        assert_eq!(
            objects
                .iter()
                .filter(|(object_type, _, _, _)| object_type == "table")
                .count(),
            27
        );
        assert_eq!(
            objects
                .iter()
                .filter(|(object_type, _, _, _)| object_type == "index")
                .count(),
            34
        );
        assert_eq!(
            objects
                .iter()
                .filter(|(object_type, _, _, _)| object_type == "trigger")
                .count(),
            13
        );

        let provenance = serde_json::from_str::<serde_json::Value>(include_str!(
            "../schema/v031-user-schema-provenance.json"
        ))
        .expect("v0.3.1 provenance is valid JSON");
        assert_eq!(provenance["tagName"], V031_USER_SCHEMA_PROVENANCE.tag_name);
        assert_eq!(
            provenance["annotatedTagObject"],
            V031_USER_SCHEMA_PROVENANCE.annotated_tag_object_id
        );
        assert_eq!(
            provenance["peeledCommit"],
            V031_USER_SCHEMA_PROVENANCE.peeled_commit_id
        );
        assert_eq!(
            provenance["taggerUtc"],
            V031_USER_SCHEMA_PROVENANCE.tagger_utc
        );
        assert_eq!(
            provenance["schemaVersion"],
            V031_USER_SCHEMA_PROVENANCE.schema_version
        );
        assert_eq!(
            provenance["canonicalMarker"],
            V031_USER_SCHEMA_PROVENANCE.canonical_marker
        );
        assert_eq!(
            provenance["manifest"]["objectCount"],
            V031_USER_SCHEMA_PROVENANCE.application_schema_object_count
        );
        assert_eq!(
            provenance["manifest"]["sha256"].as_str(),
            Some(V031_USER_SCHEMA_MANIFEST_SHA256),
            "logical-manifest documentation must not alter the frozen schema manifest hash"
        );
        assert_eq!(
            provenance["internalManifest"]["objectCount"],
            V031_USER_SCHEMA_PROVENANCE.internal_schema_object_count
        );
        assert_eq!(
            provenance["internalManifest"]["sha256"],
            V031_USER_SCHEMA_PROVENANCE.internal_schema_manifest_sha256
        );
        assert_eq!(
            provenance["fixture"]["sha256"],
            V031_USER_SCHEMA_PROVENANCE.canonical_empty_fixture_sha256
        );
        assert_eq!(
            provenance["generation"]["generatorSha256"],
            V031_USER_SCHEMA_PROVENANCE.generator_sha256
        );
        assert_eq!(
            provenance["generation"]["cargoLockSha256"],
            V031_USER_SCHEMA_PROVENANCE.generation_cargo_lock_sha256
        );
        assert_eq!(
            provenance["generation"]["databaseSourceSha256"],
            V031_USER_SCHEMA_PROVENANCE.generation_database_source_sha256
        );
        assert_eq!(
            provenance["migrationSourceOpen"],
            serde_json::json!({
                "rollbackUriParameters": "mode=ro&immutable=1",
                "walUriParameters": "mode=ro&readonly_shm=1",
                "walPreflight": "The main header must be WAL mode and both existing WAL and SHM sidecars must pass frozen preflight before SQLite opens; immutable is forbidden because it would ignore WAL frames.",
                "lifetimeGuard": "Fixed-local non-reparse single-link handles for main/WAL/SHM and non-reparse directory handles remain pinned through proof, Backup API callback, commit, second-transaction closure, and final evidence comparison."
            })
        );
        assert_eq!(
            provenance["logicalManifest"],
            serde_json::json!({
                "decision": "ADR-0002",
                "logicalDomain": "lawyer-assistance\0sqlite-canonical-logical-manifest-v1\0",
                "businessDomain": "lawyer-assistance\0sqlite-canonical-business-manifest-v1\0",
                "businessPrimaryKeyDomain": "lawyer-assistance\0sqlite-canonical-business-primary-key-manifest-v1\0",
                "businessRowDomain": "lawyer-assistance\0sqlite-canonical-business-row-manifest-v1\0",
                "fieldEncoding": "one-byte tag || u64be(byte_length(value)) || value",
                "tableAllowlist": "All application tables in the exact canonical schema; an unlisted application table fails closed.",
                "userBusinessExcludedTables": ["user_database_metadata"],
                "tableOrdering": "Ascending unsigned lexicographic order of raw UTF-8 table-name bytes.",
                "createTableSql": "Manifest-normalized sqlite_schema CREATE TABLE SQL: replace every maximal SQL whitespace sequence with one ASCII space and trim leading and trailing whitespace.",
                "columnMetadata": "PRAGMA table_xinfo ordered by ascending cid: cid, name, exact declared type, not-null flag, default presence and exact SQL text, primary-key ordinal, and hidden flag.",
                "rowOrdering": "Sort by concatenated full encoded PRIMARY KEY values in primary-key ordinal order; only a table without a declared PRIMARY KEY uses the full encoded row as its fallback key; ties sort by the full encoded row.",
                "valueEncoding": {
                    "null": "0x00",
                    "integer": "0x01 || i64be(value)",
                    "real": "0x02 || u64be(IEEE-754 f64 bits)",
                    "text": "0x03 || u64be(length) || raw UTF-8 bytes",
                    "blob": "0x04 || u64be(length) || raw bytes"
                },
                "persistentOutput": "Hashes and counts only: overall logical/business/primary-key/row SHA-256, per-table logical/business/primary-key/row SHA-256 where applicable, per-table row count, and total row count; never schema SQL, row or column values, primary keys, raw TEXT, or BLOB."
            })
        );
    }

    #[test]
    fn migration_source_proof_is_independent_of_business_row_insertion_order() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let first_path = directory.path().join("order-first.sqlite");
        let second_path = directory.path().join("order-second.sqlite");
        create_exact_v031_user_database(&first_path);
        create_exact_v031_user_database(&second_path);
        insert_v031_project(&first_path, "project-a", "Alpha", "First");
        insert_v031_project(&first_path, "project-b", "Beta", "Second");
        insert_v031_project(&second_path, "project-b", "Beta", "Second");
        insert_v031_project(&second_path, "project-a", "Alpha", "First");

        let first = migration_source_proof(&first_path);
        let second = migration_source_proof(&second_path);
        assert_eq!(first.schema, ValidatedUserSourceSchema::V031V10);
        assert_eq!(
            first.schema_manifest_sha256,
            V031_USER_SCHEMA_MANIFEST_SHA256
        );
        assert_eq!(first.schema_manifest_sha256, second.schema_manifest_sha256);
        assert_eq!(
            first.logical_database_manifest_sha256,
            second.logical_database_manifest_sha256
        );
        assert_eq!(
            first.business_manifest_sha256,
            second.business_manifest_sha256
        );
        assert_eq!(
            first.business_primary_key_manifest_sha256,
            second.business_primary_key_manifest_sha256
        );
        assert_eq!(
            first.business_row_manifest_sha256,
            second.business_row_manifest_sha256
        );
        assert_eq!(first.tables, second.tables);
        assert_eq!(first.total_rows, second.total_rows);
        assert_eq!(
            first
                .tables
                .iter()
                .find(|count| count.table == "projects")
                .map(|count| count.rows),
            Some(2)
        );
    }

    #[test]
    fn migration_source_proof_distinguishes_non_primary_business_row_changes() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("non-primary-change.sqlite");
        create_exact_v031_user_database(&database_path);
        insert_v031_project(&database_path, "stable-project", "Before", "Stable summary");
        let before = migration_source_proof(&database_path);

        let connection =
            open_user_database(&database_path).expect("fixture mutation connection opens");
        connection
            .execute(
                "UPDATE projects SET title='After' WHERE project_id='stable-project'",
                [],
            )
            .expect("non-primary business value updates");
        drop(connection);
        let after = migration_source_proof(&database_path);

        assert_eq!(
            before.business_primary_key_manifest_sha256,
            after.business_primary_key_manifest_sha256
        );
        assert_ne!(
            before.business_manifest_sha256,
            after.business_manifest_sha256
        );
        assert_ne!(
            before.business_row_manifest_sha256,
            after.business_row_manifest_sha256
        );
        assert_ne!(
            before.logical_database_manifest_sha256,
            after.logical_database_manifest_sha256
        );
        assert_ne!(before.database_file.sha256, after.database_file.sha256);
        assert_eq!(
            migration_source_table_rows(&before),
            migration_source_table_rows(&after)
        );
        let before_project = before
            .tables
            .iter()
            .find(|table| table.table == "projects")
            .expect("project proof exists");
        let after_project = after
            .tables
            .iter()
            .find(|table| table.table == "projects")
            .expect("project proof exists");
        assert_ne!(
            before_project.logical_manifest_sha256,
            after_project.logical_manifest_sha256
        );
        assert_eq!(
            before_project.business_primary_key_manifest_sha256,
            after_project.business_primary_key_manifest_sha256
        );
        assert_ne!(
            before_project.business_manifest_sha256,
            after_project.business_manifest_sha256
        );
        assert_ne!(
            before_project.business_row_manifest_sha256,
            after_project.business_row_manifest_sha256
        );
    }

    #[test]
    fn migration_source_proof_distinguishes_primary_key_changes() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("primary-key-change.sqlite");
        create_exact_v031_user_database(&database_path);
        insert_v031_project(&database_path, "project-before", "Project", "Summary");
        let before = migration_source_proof(&database_path);

        let connection =
            open_user_database(&database_path).expect("fixture mutation connection opens");
        connection
            .execute(
                "UPDATE projects
                 SET project_id='project-after'
                 WHERE project_id='project-before'",
                [],
            )
            .expect("primary key updates");
        drop(connection);
        let after = migration_source_proof(&database_path);

        assert_ne!(
            before.business_primary_key_manifest_sha256,
            after.business_primary_key_manifest_sha256
        );
        assert_ne!(
            before.business_manifest_sha256,
            after.business_manifest_sha256
        );
        assert_ne!(
            before.business_row_manifest_sha256,
            after.business_row_manifest_sha256
        );
        assert_ne!(
            before.logical_database_manifest_sha256,
            after.logical_database_manifest_sha256
        );
        assert_eq!(
            migration_source_table_rows(&before),
            migration_source_table_rows(&after)
        );
    }

    #[test]
    fn migration_source_proof_separates_metadata_from_business_manifests() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("metadata-change.sqlite");
        create_exact_v031_user_database(&database_path);
        insert_v031_project(&database_path, "metadata-project", "Project", "Summary");
        let before = migration_source_proof(&database_path);

        let connection =
            open_user_database(&database_path).expect("metadata mutation connection opens");
        connection
            .execute(
                "UPDATE user_database_metadata
                 SET updated_at='2031-01-01 00:00:00'
                 WHERE key='schema_version'",
                [],
            )
            .expect("non-contract metadata timestamp updates");
        drop(connection);
        let after = migration_source_proof(&database_path);

        assert_ne!(
            before.logical_database_manifest_sha256,
            after.logical_database_manifest_sha256
        );
        assert_eq!(
            before.business_primary_key_manifest_sha256,
            after.business_primary_key_manifest_sha256
        );
        assert_eq!(
            before.business_manifest_sha256,
            after.business_manifest_sha256
        );
        assert_eq!(
            before.business_row_manifest_sha256,
            after.business_row_manifest_sha256
        );
        assert_eq!(
            migration_source_table_rows(&before),
            migration_source_table_rows(&after)
        );
        let metadata_before = before
            .tables
            .iter()
            .find(|table| table.table == "user_database_metadata")
            .expect("metadata proof exists");
        let metadata_after = after
            .tables
            .iter()
            .find(|table| table.table == "user_database_metadata")
            .expect("metadata proof exists");
        assert_ne!(
            metadata_before.logical_manifest_sha256,
            metadata_after.logical_manifest_sha256
        );
        assert!(metadata_before.business_manifest_sha256.is_none());
        assert!(metadata_before
            .business_primary_key_manifest_sha256
            .is_none());
        assert!(metadata_before.business_row_manifest_sha256.is_none());
    }

    #[test]
    fn migration_source_callback_builds_snapshot_from_the_validated_connection() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("callback-source.sqlite");
        let snapshot_path = directory.path().join("callback-snapshot.sqlite");
        create_exact_v031_user_database(&database_path);
        insert_v031_project(
            &database_path,
            "snapshot-project",
            "Snapshot",
            "Same transaction",
        );

        let (source_proof, backup_result) =
            with_validated_user_database_migration_source_read_only(
                &database_path,
                |session| -> Result<(), DatabaseInitError> {
                    assert_eq!(session.proof().schema, ValidatedUserSourceSchema::V031V10);
                    let mut destination = rusqlite::Connection::open(&snapshot_path)?;
                    session.backup_to(&mut destination)?;
                    destination
                        .close()
                        .map_err(|(_, error)| DatabaseInitError::from(error))
                },
            )
            .expect("source remains stable around callback");
        backup_result.expect("SQLite snapshot is created from pinned connection");

        let snapshot_proof = migration_source_proof(&snapshot_path);
        assert_eq!(
            source_proof.schema_manifest_sha256,
            snapshot_proof.schema_manifest_sha256
        );
        assert_eq!(
            source_proof.logical_database_manifest_sha256,
            snapshot_proof.logical_database_manifest_sha256
        );
        assert_eq!(
            source_proof.business_primary_key_manifest_sha256,
            snapshot_proof.business_primary_key_manifest_sha256
        );
        assert_eq!(
            source_proof.business_manifest_sha256,
            snapshot_proof.business_manifest_sha256
        );
        assert_eq!(
            source_proof.business_row_manifest_sha256,
            snapshot_proof.business_row_manifest_sha256
        );
        assert_eq!(source_proof.tables, snapshot_proof.tables);
        assert_eq!(source_proof.total_rows, snapshot_proof.total_rows);
    }

    #[test]
    fn migration_source_wal_snapshot_includes_uncheckpointed_commits_without_mutation() {
        exit_after_creating_crash_wal_fixture_if_requested();

        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("wal-source.sqlite");
        let snapshot_path = directory.path().join("wal-snapshot.sqlite");
        create_crash_wal_fixture(&database_path);

        let wal_path = sqlite_sidecar_path(&database_path, "-wal");
        let shm_path = sqlite_sidecar_path(&database_path, "-shm");
        assert!(wal_path.is_file() && shm_path.is_file());
        let capture = |path: &Path| {
            let snapshot = migration_source_file_snapshot(path, true, false)
                .expect("file evidence captures")
                .expect("file exists");
            (
                fs::read(path).expect("file bytes read"),
                snapshot.platform_identity,
                snapshot.length,
                snapshot.modified,
            )
        };
        let main_before = capture(&database_path);
        let wal_before = capture(&wal_path);
        let shm_before = capture(&shm_path);

        let immutable = rusqlite::Connection::open_with_flags(
            migration_source_uri(&database_path, true).expect("immutable URI builds"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_URI
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .expect("main-only immutable view opens");
        let immutable_count: i64 = immutable
            .query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id='wal-only-project'",
                [],
                |row| row.get(0),
            )
            .expect("main-only immutable view reads");
        assert_eq!(immutable_count, 0, "the committed row exists only in WAL");
        drop(immutable);

        let (proof, backup_result) = with_validated_user_database_migration_source_read_only(
            &database_path,
            |session| -> Result<(), DatabaseInitError> {
                assert_eq!(
                    session
                        .proof()
                        .tables
                        .iter()
                        .find(|table| table.table == "projects")
                        .map(|table| table.rows),
                    Some(1)
                );
                let mut destination = rusqlite::Connection::open(&snapshot_path)?;
                session.backup_to(&mut destination)
            },
        )
        .expect("WAL source validates without mutation");
        backup_result.expect("WAL snapshot completes");
        assert!(proof.wal.is_some() && proof.shm.is_some());
        let snapshot = open_user_database_read_only(&snapshot_path)
            .expect("WAL-backed snapshot opens read-only");
        let snapshot_count: i64 = snapshot
            .query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id='wal-only-project'",
                [],
                |row| row.get(0),
            )
            .expect("WAL-backed row reads from backup");
        assert_eq!(snapshot_count, 1);
        drop(snapshot);

        assert_eq!(capture(&database_path), main_before);
        assert_eq!(capture(&wal_path), wal_before);
        assert_eq!(capture(&shm_path), shm_before);
    }

    #[test]
    fn migration_source_rollback_open_creates_no_sidecars_and_preserves_cold_journal() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("rollback-source.sqlite");
        create_exact_v031_user_database(&database_path);
        let wal_path = sqlite_sidecar_path(&database_path, "-wal");
        let shm_path = sqlite_sidecar_path(&database_path, "-shm");
        let journal_path = sqlite_sidecar_path(&database_path, "-journal");
        assert!(!wal_path.exists() && !shm_path.exists() && !journal_path.exists());

        let proof = migration_source_proof(&database_path);
        assert!(proof.wal.is_none() && proof.shm.is_none() && proof.journal.is_none());
        assert!(
            !wal_path.exists() && !shm_path.exists() && !journal_path.exists(),
            "an immutable rollback-mode read must not create missing sidecars"
        );

        File::create(&journal_path).expect("cold rollback journal creates");
        let journal_before = migration_source_file_snapshot(&journal_path, true, false)
            .expect("cold journal evidence captures")
            .expect("cold journal exists");
        let proof = migration_source_proof(&database_path);
        let journal_after = migration_source_file_snapshot(&journal_path, true, false)
            .expect("cold journal evidence recaptures")
            .expect("cold journal remains");
        assert!(proof.journal.is_some());
        assert!(journal_before.same_evidence(&journal_after));
        assert_eq!(fs::read(&journal_path).expect("cold journal reads"), b"");
        assert!(!wal_path.exists() && !shm_path.exists());
    }

    #[test]
    fn migration_source_wal_preflight_rejects_missing_shm_without_creating_it() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("wal-missing-shm.sqlite");
        create_crash_wal_fixture(&database_path);
        let wal_path = sqlite_sidecar_path(&database_path, "-wal");
        let shm_path = sqlite_sidecar_path(&database_path, "-shm");
        fs::remove_file(&shm_path).expect("negative-test SHM removes");
        let main_before = fs::read(&database_path).expect("main bytes read");
        let wal_before = fs::read(&wal_path).expect("WAL bytes read");

        assert!(
            validate_user_database_migration_source_read_only(&database_path).is_err(),
            "WAL header without both existing sidecars must fail before SQLite opens"
        );
        assert!(
            !shm_path.exists(),
            "validation must not recreate missing SHM"
        );
        assert_eq!(
            fs::read(&database_path).expect("main bytes re-read"),
            main_before
        );
        assert_eq!(fs::read(&wal_path).expect("WAL bytes re-read"), wal_before);
    }

    #[test]
    fn migration_source_guarded_path_blocks_replacement_and_overwrite() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("guarded-source.sqlite");
        let moved_path = directory.path().join("guarded-source-moved.sqlite");
        create_exact_v031_user_database(&database_path);
        let before = fs::read(&database_path).expect("guarded source reads");

        let (proof, (rename_result, overwrite_result)) =
            with_validated_user_database_migration_source_read_only(&database_path, |_| {
                let rename_result = fs::rename(&database_path, &moved_path);
                let overwrite_result = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&database_path);
                (rename_result, overwrite_result)
            })
            .expect("failed path attacks preserve a stable source");
        assert_eq!(proof.schema, ValidatedUserSourceSchema::V031V10);
        assert!(rename_result.is_err(), "the pinned path cannot be renamed");
        assert!(
            overwrite_result.is_err(),
            "the pinned file cannot be overwritten"
        );
        assert!(!moved_path.exists());
        assert_eq!(
            fs::read(&database_path).expect("guarded source re-reads"),
            before
        );
    }

    #[test]
    fn migration_source_internal_authorizer_rejects_commit_escape() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("callback-commit.sqlite");
        create_exact_v031_user_database(&database_path);
        let before = fs::read(&database_path).expect("source bytes read");

        let result = with_validated_user_database_migration_source_read_only_inner(
            &database_path,
            |_| (),
            |connection| {
                connection.execute_batch("COMMIT; BEGIN DEFERRED")?;
                Ok(())
            },
            |_| Ok(()),
        );
        assert!(matches!(
            result,
            Err(DatabaseInitError::Sqlite(rusqlite::Error::SqliteFailure(
                ref failure,
                _
            ))) if failure.code == rusqlite::ErrorCode::AuthorizationForStatementDenied
        ));
        assert_eq!(
            fs::read(&database_path).expect("validated source bytes read"),
            before
        );
    }

    #[test]
    fn migration_source_proof_exposes_no_plaintext_primary_key_or_path() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let secret_directory = directory.path().join("path-canary-not-for-proof");
        fs::create_dir(&secret_directory).expect("secret test directory creates");
        let database_path = secret_directory.join("user-secret-location.sqlite");
        create_exact_v031_user_database(&database_path);
        insert_v031_project(
            &database_path,
            "primary-key-canary-not-for-proof",
            "plaintext-title-canary-not-for-proof",
            "plaintext-summary-canary-not-for-proof",
        );

        let proof = migration_source_proof(&database_path);
        let diagnostic = format!("{proof:?}");
        for forbidden in [
            "path-canary-not-for-proof",
            "user-secret-location.sqlite",
            "primary-key-canary-not-for-proof",
            "plaintext-title-canary-not-for-proof",
            "plaintext-summary-canary-not-for-proof",
        ] {
            assert!(
                !diagnostic.contains(forbidden),
                "public proof leaked forbidden plaintext: {forbidden}"
            );
        }
        for hash in [
            &proof.database_file.identity_sha256,
            &proof.database_file.sha256,
            &proof.schema_manifest_sha256,
            &proof.logical_database_manifest_sha256,
            &proof.business_manifest_sha256,
            &proof.business_primary_key_manifest_sha256,
            &proof.business_row_manifest_sha256,
        ] {
            assert!(is_lower_hex_sha256(hash));
        }
    }

    #[test]
    fn migration_source_current_v11_proof_is_stable_without_relaxing_current_validation() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            ensure_user_database(directory.path()).expect("current database initializes");
        let connection =
            open_user_database(&database_path).expect("current project connection opens");
        connection
            .execute(
                "INSERT INTO projects(
                     project_id,title,case_type,status,opened_on,summary,created_at,updated_at
                 ) VALUES('current-proof-project','Current','civil','active',
                          '2026-08-01','Stable',
                          '2026-08-01 00:00:00','2026-08-01 00:00:00')",
                [],
            )
            .expect("current project inserts");
        drop(connection);

        let first = migration_source_proof(&database_path);
        let second = migration_source_proof(&database_path);
        assert_eq!(first, second);
        assert_eq!(first.schema, ValidatedUserSourceSchema::CurrentV11);
        assert_ne!(
            first.schema_manifest_sha256,
            V031_USER_SCHEMA_MANIFEST_SHA256
        );
        validate_user_database_read_only(&database_path)
            .expect("ordinary current validator remains exact v11");

        let v10_path = directory.path().join("still-not-current.sqlite");
        create_exact_v031_user_database(&v10_path);
        assert!(
            validate_user_database_read_only(&v10_path).is_err(),
            "ordinary current validator must still reject exact v10"
        );
    }

    #[test]
    fn migration_source_canonical_value_encoding_is_type_and_length_separated() {
        let encodings = [
            rusqlite::types::ValueRef::Null,
            rusqlite::types::ValueRef::Integer(1),
            rusqlite::types::ValueRef::Real(1.0),
            rusqlite::types::ValueRef::Text(b"1"),
            rusqlite::types::ValueRef::Blob(b"1"),
            rusqlite::types::ValueRef::Text(b""),
            rusqlite::types::ValueRef::Blob(b""),
        ]
        .into_iter()
        .map(|value| {
            let mut encoded = Vec::new();
            append_canonical_value(&mut encoded, value);
            encoded
        })
        .collect::<Vec<_>>();
        assert_eq!(encodings[0], vec![0x00]);
        assert_eq!(
            encodings[1],
            [vec![0x01], 1i64.to_be_bytes().to_vec()].concat()
        );
        assert_eq!(
            encodings[2],
            [vec![0x02], 1.0f64.to_bits().to_be_bytes().to_vec()].concat()
        );
        assert_eq!(
            encodings[3],
            [vec![0x03], 1u64.to_be_bytes().to_vec(), b"1".to_vec()].concat()
        );
        assert_eq!(
            encodings[4],
            [vec![0x04], 1u64.to_be_bytes().to_vec(), b"1".to_vec()].concat()
        );
        assert_eq!(
            encodings[5],
            [vec![0x03], 0u64.to_be_bytes().to_vec()].concat()
        );
        assert_eq!(
            encodings[6],
            [vec![0x04], 0u64.to_be_bytes().to_vec()].concat()
        );
        for left in 0..encodings.len() {
            for right in left + 1..encodings.len() {
                assert_ne!(encodings[left], encodings[right]);
            }
        }
    }

    #[test]
    fn migration_source_manifest_wire_matches_the_frozen_adr() {
        let table = CanonicalLogicalTable {
            name: "z_table".to_owned(),
            create_table_sql:
                "CREATE TABLE z_table (id INTEGER PRIMARY KEY, note TEXT DEFAULT NULL)".to_owned(),
            columns: vec![
                CanonicalLogicalColumn {
                    cid: 0,
                    name: "id".to_owned(),
                    declared_type: "INTEGER".to_owned(),
                    not_null: false,
                    default_sql: None,
                    primary_key_ordinal: 1,
                    hidden_flag: 0,
                },
                CanonicalLogicalColumn {
                    cid: 1,
                    name: "note".to_owned(),
                    declared_type: "TEXT".to_owned(),
                    not_null: true,
                    default_sql: Some("NULL".to_owned()),
                    primary_key_ordinal: 0,
                    hidden_flag: 0,
                },
            ],
            primary_key_columns: vec![0],
            rows: vec![CanonicalLogicalRow {
                sort_key: [vec![0x01], 7i64.to_be_bytes().to_vec()].concat().into(),
                encoded_values: [
                    vec![0x01],
                    7i64.to_be_bytes().to_vec(),
                    vec![0x03],
                    1u64.to_be_bytes().to_vec(),
                    b"x".to_vec(),
                ]
                .concat()
                .into(),
            }],
        };

        let mut expected = b"lawyer-assistance\0sqlite-canonical-logical-manifest-v1\0".to_vec();
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.push(0x10);
        for (tag, value) in [
            (0x11, table.name.as_bytes()),
            (0x12, table.create_table_sql.as_bytes()),
        ] {
            expected.push(tag);
            expected.extend_from_slice(&(value.len() as u64).to_be_bytes());
            expected.extend_from_slice(value);
        }
        expected.extend_from_slice(&2u64.to_be_bytes());
        for column in &table.columns {
            expected.push(0x13);
            expected.extend_from_slice(&column.cid.to_be_bytes());
            for (tag, value) in [
                (0x14, column.name.as_bytes()),
                (0x15, column.declared_type.as_bytes()),
            ] {
                expected.push(tag);
                expected.extend_from_slice(&(value.len() as u64).to_be_bytes());
                expected.extend_from_slice(value);
            }
            expected.push(u8::from(column.not_null));
            expected.push(u8::from(column.default_sql.is_some()));
            if let Some(default_sql) = &column.default_sql {
                expected.push(0x16);
                expected.extend_from_slice(&(default_sql.len() as u64).to_be_bytes());
                expected.extend_from_slice(default_sql.as_bytes());
            }
            expected.extend_from_slice(&column.primary_key_ordinal.to_be_bytes());
            expected.extend_from_slice(&column.hidden_flag.to_be_bytes());
        }
        expected.extend_from_slice(&1u64.to_be_bytes());
        expected.push(0x20);
        expected.extend_from_slice(&2u64.to_be_bytes());
        expected.extend_from_slice(&table.rows[0].encoded_values);

        assert_eq!(
            canonical_manifest_sha256(
                b"lawyer-assistance\0sqlite-canonical-logical-manifest-v1\0",
                &[&table],
            )
            .expect("ADR manifest vector hashes"),
            sha256_hex(&expected)
        );
        assert_eq!(
            normalized_create_table_sql("  CREATE\n TABLE\tz_table ( id INTEGER )  "),
            "CREATE TABLE z_table ( id INTEGER )"
        );
    }

    #[test]
    fn migration_source_rows_use_full_row_fallback_only_without_a_declared_primary_key() {
        let connection = rusqlite::Connection::open_in_memory().expect("fixture opens");
        connection
            .execute_batch(
                "CREATE TABLE bag (left_value, right_value);
                 INSERT INTO bag VALUES(2,'b'),(1,'z'),(1,'a'),(1,'a');",
            )
            .expect("keyless fixture creates");

        let table = canonical_logical_table(
            &connection,
            "bag".to_owned(),
            "CREATE TABLE bag (left_value, right_value)".to_owned(),
        )
        .expect("keyless table canonicalizes");
        assert!(table.primary_key_columns.is_empty());
        assert_eq!(table.rows.len(), 4);
        assert!(table
            .rows
            .iter()
            .all(|row| row.sort_key == row.encoded_values));
        assert!(table.rows.windows(2).all(|rows| {
            (
                rows[0].sort_key.as_slice(),
                rows[0].encoded_values.as_slice(),
            ) <= (
                rows[1].sort_key.as_slice(),
                rows[1].encoded_values.as_slice(),
            )
        }));
        assert_eq!(
            table
                .rows
                .windows(2)
                .filter(|rows| rows[0].encoded_values == rows[1].encoded_values)
                .count(),
            1,
            "identical keyless rows remain valid and order-independent"
        );
    }

    #[test]
    fn migration_source_validator_rejects_each_missing_v031_schema_object() {
        let objects = v031_user_schema_objects().expect("v0.3.1 manifest verifies");
        let directory = tempfile::tempdir().expect("tempdir exists");
        for (index, (object_type, name, _, _)) in objects.iter().enumerate() {
            let database_path = directory.path().join(format!("missing-{index}.sqlite"));
            create_exact_v031_user_database(&database_path);
            let connection =
                open_user_database(&database_path).expect("fixture mutation connection opens");
            connection
                .pragma_update(None, "foreign_keys", "OFF")
                .expect("fixture foreign keys disable");
            connection
                .execute_batch(&format!(
                    "DROP {} \"{}\"",
                    object_type.to_ascii_uppercase(),
                    name.replace('"', "\"\"")
                ))
                .unwrap_or_else(|error| {
                    panic!("schema object drops for negative test {object_type}/{name}: {error}")
                });
            drop(connection);
            assert!(
                validate_user_database_migration_source_read_only(&database_path).is_err(),
                "missing schema object must be rejected: {object_type}/{name}"
            );
        }
    }

    #[test]
    fn migration_source_validator_rejects_modified_table_index_and_trigger_ddl() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let mutations = [
            (
                "table",
                "projects",
                "CHECK (length(project_id) > 0)",
                "CHECK (length(project_id) >= 0)",
            ),
            (
                "index",
                "idx_agent_runs_conversation_created",
                "agent_runs(conversation_id, created_at)",
                "agent_runs(created_at, conversation_id)",
            ),
            (
                "trigger",
                "trg_legal_basis_issue_project_insert",
                "WHEN NEW.issue_id IS NOT NULL AND NOT EXISTS",
                "WHEN 0 AND NEW.issue_id IS NOT NULL AND NOT EXISTS",
            ),
        ];
        for (index, (object_type, name, before, after)) in mutations.into_iter().enumerate() {
            let database_path = directory.path().join(format!("modified-{index}.sqlite"));
            create_v031_user_database_from_manifest(&database_path, |objects| {
                mutate_v031_manifest_sql(objects, object_type, name, before, after);
            });
            assert!(
                validate_user_database_migration_source_read_only(&database_path).is_err(),
                "modified schema object must be rejected: {object_type}/{name}"
            );
        }
    }

    #[test]
    fn migration_source_validator_rejects_marker_version_extra_object_and_hardlink() {
        let relative_error = validate_user_database_migration_source_read_only(Path::new(
            "relative-v031-user.sqlite",
        ))
        .expect_err("relative migration source path must be rejected");
        assert!(matches!(
            relative_error,
            DatabaseInitError::Io(ref error)
                if error.kind() == std::io::ErrorKind::InvalidInput
        ));

        let directory = tempfile::tempdir().expect("tempdir exists");
        for (name, sql) in [
            (
                "marker",
                "UPDATE user_database_metadata
                 SET value='forged-marker'
                 WHERE key='canonical_schema_version'",
            ),
            (
                "old-version",
                "UPDATE user_database_metadata SET value='9' WHERE key='schema_version'",
            ),
            (
                "future-version",
                "UPDATE user_database_metadata SET value='12' WHERE key='schema_version'",
            ),
            (
                "extra-object",
                "CREATE TABLE forged_extra_object(value TEXT)",
            ),
        ] {
            let database_path = directory.path().join(format!("{name}.sqlite"));
            create_exact_v031_user_database(&database_path);
            let connection =
                open_user_database(&database_path).expect("fixture mutation connection opens");
            connection
                .execute_batch(sql)
                .unwrap_or_else(|error| panic!("{name} mutation succeeds: {error}"));
            drop(connection);
            assert!(
                validate_user_database_migration_source_read_only(&database_path).is_err(),
                "{name} mutation must be rejected"
            );
        }

        let hardlink_path = directory.path().join("hardlink-source.sqlite");
        let hardlink_alias = directory.path().join("hardlink-alias.sqlite");
        create_exact_v031_user_database(&hardlink_path);
        fs::hard_link(&hardlink_path, &hardlink_alias).expect("hardlink fixture is created");
        assert!(
            validate_user_database_migration_source_read_only(&hardlink_path).is_err(),
            "multi-link source must be rejected before SQLite validation"
        );
    }

    #[test]
    fn migration_source_validator_rejects_v031_foreign_key_and_semantic_corruption() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let foreign_key_path = directory.path().join("foreign-key.sqlite");
        create_exact_v031_user_database(&foreign_key_path);
        let foreign_key_connection =
            rusqlite::Connection::open(&foreign_key_path).expect("raw fixture connection opens");
        foreign_key_connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("foreign key enforcement disables for corruption injection");
        foreign_key_connection
            .execute(
                "INSERT INTO message_attachments(message_id,attachment_id,ordinal)
                 VALUES('missing-message','missing-attachment',0)",
                [],
            )
            .expect("foreign key corruption is injected with enforcement disabled");
        drop(foreign_key_connection);
        assert!(
            validate_user_database_migration_source_read_only(&foreign_key_path).is_err(),
            "foreign_key_check violation must be rejected"
        );

        let semantic_path = directory.path().join("semantic.sqlite");
        create_exact_v031_user_database(&semantic_path);
        let semantic_connection =
            open_user_database(&semantic_path).expect("semantic fixture connection opens");
        semantic_connection
            .execute(
                "INSERT INTO artifacts(
                     artifact_id,kind,title,status,current_version
                 ) VALUES('artifact','research','Artifact','draft',1)",
                [],
            )
            .expect("artifact inserts");
        for version in [1, 2] {
            semantic_connection
                .execute(
                    "INSERT INTO artifact_versions(
                         version_id,artifact_id,version_number,content_json
                     ) VALUES(?1,'artifact',?2,'{}')",
                    (format!("version-{version}"), version),
                )
                .expect("artifact version inserts");
        }
        drop(semantic_connection);
        assert!(
            validate_user_database_migration_source_read_only(&semantic_path).is_err(),
            "v0.3.1 artifact lineage corruption must be rejected"
        );
    }

    #[test]
    fn migration_source_frozen_internal_schema_allowlist_is_exact() {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path = directory.path().join("internal-schema.sqlite");
        create_exact_v031_user_database(&database_path);
        let connection = open_user_database_read_only(&database_path).expect("fixture opens");
        let objects =
            user_internal_schema_objects(&connection).expect("frozen internal schema objects read");
        let expected =
            v031_user_internal_schema_objects().expect("frozen internal schema allowlist verifies");
        assert_eq!(objects, expected);
        assert_eq!(objects.len(), V031_USER_INTERNAL_SCHEMA_OBJECT_COUNT);
        assert_eq!(
            canonical_schema_manifest_sha256(&objects).expect("internal schema hashes"),
            V031_USER_INTERNAL_SCHEMA_MANIFEST_SHA256
        );
    }

    #[test]
    fn migration_source_validator_rejects_analyze_sqlite_stat_objects() {
        let directory = tempfile::tempdir().expect("tempdir exists");

        let v10_path = directory.path().join("analyzed-v10.sqlite");
        create_exact_v031_user_database(&v10_path);
        let v10 = open_user_database(&v10_path).expect("v10 fixture opens");
        v10.execute_batch("ANALYZE").expect("v10 ANALYZE succeeds");
        assert!(v10
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE name='sqlite_stat1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .is_ok());
        drop(v10);
        assert!(
            validate_user_database_migration_source_read_only(&v10_path).is_err(),
            "v0.3.1 sqlite_stat1 must fail the frozen internal allowlist"
        );

        let v11_directory = tempfile::tempdir().expect("v11 tempdir exists");
        let v11_path = ensure_user_database(v11_directory.path()).expect("v11 fixture creates");
        let v11 = open_user_database(&v11_path).expect("v11 fixture opens");
        v11.execute_batch("ANALYZE").expect("v11 ANALYZE succeeds");
        drop(v11);
        assert!(
            validate_user_database_migration_source_read_only(&v11_path).is_err(),
            "current validation must reject unexpected sqlite_stat1 too"
        );
    }
}
