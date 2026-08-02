//! Exact, read-only validation for the frozen Privacy v1 migration source.
//!
//! This module is deliberately separate from [`crate::store::PrivacyStore`].
//! Normal startup continues to accept only the current schema (or a truly
//! empty store); coordinated v0.3.1 upgrades opt into this validator before
//! any target component is created or migrated.

use crate::{
    egress::{DataClassification, PrivacyEgressAuditRecord},
    receipt::DestinationKind,
    sha256_hex, unprotect_local,
    v5_manifest::{
        compute_privacy_v5_manifests_read_only, PrivacyV5ManifestError, PrivacyV5ManifestProof,
    },
    LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{
    params_from_iter, types::Value, Connection, OpenFlags, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use zeroize::{Zeroize, Zeroizing};

pub const PRIVACY_V1_SCHEMA_VERSION: i64 = 1;
pub const PRIVACY_V1_SCHEMA_OBJECT_COUNT: usize = 11;
const PRIVACY_V1_INTERNAL_SCHEMA_OBJECT_COUNT: usize = 6;
const PRIVACY_V1_INTERNAL_SCHEMA_MANIFEST_SHA256: &str =
    "cf855879f3274b7439a3707dfd1e0c2df8ab58715f179cdeb03b0760f42540f2";
/// Exact ADR-0002 domain prefix for every SQLite canonical logical manifest.
/// The two `\0` escapes are literal NUL bytes in the hashed stream.
pub const SQLITE_CANONICAL_LOGICAL_MANIFEST_V1_DOMAIN: &[u8] =
    b"lawyer-assistance\0sqlite-canonical-logical-manifest-v1\0";
const SQLITE_CANONICAL_BUSINESS_MANIFEST_V1_DOMAIN: &[u8] =
    b"lawyer-assistance\0sqlite-canonical-business-manifest-v1\0";
const SQLITE_CANONICAL_BUSINESS_PRIMARY_KEY_MANIFEST_V1_DOMAIN: &[u8] =
    b"lawyer-assistance\0sqlite-canonical-business-primary-key-manifest-v1\0";
const SQLITE_CANONICAL_BUSINESS_ROW_MANIFEST_V1_DOMAIN: &[u8] =
    b"lawyer-assistance\0sqlite-canonical-business-row-manifest-v1\0";
const PRIVACY_V1_MAX_ACTIVE_RECEIPT_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;
const PRIVACY_V1_SOURCE_FILE_IDENTITY_DOMAIN: &[u8] =
    b"lawyer-assistance-privacy-migration-file-identity-v1\0";
const PRIVACY_V1_MEMORY_IMAGE_IDENTITY_DOMAIN: &[u8] =
    b"lawyer-assistance-privacy-migration-memory-image-identity-v1\0";
pub const MAX_PRIVACY_V1_SQLITE_IMAGE_BYTES: usize =
    crate::lifecycle::MAX_PRE_MIGRATION_BACKUP_DATABASE_BYTES;
const PRIVACY_V1_INTERNAL_AUTO_INDEX_ALLOWLIST: &[(&str, &str)] = &[
    (
        "sqlite_autoindex_privacy_egress_audit_1",
        "privacy_egress_audit",
    ),
    (
        "sqlite_autoindex_privacy_egress_audit_2",
        "privacy_egress_audit",
    ),
    ("sqlite_autoindex_privacy_materials_1", "privacy_materials"),
    ("sqlite_autoindex_privacy_receipts_1", "privacy_receipts"),
    (
        "sqlite_autoindex_privacy_redactions_1",
        "privacy_redactions",
    ),
    (
        "sqlite_autoindex_privacy_schema_metadata_1",
        "privacy_schema_metadata",
    ),
];
pub const PRIVACY_V1_SCHEMA_MANIFEST_JSONL: &str =
    include_str!("../schema/v031-privacy-sqlite-master.jsonl");
#[cfg(all(test, windows))]
pub const PRIVACY_V1_SCHEMA_PROVENANCE_JSON: &str =
    include_str!("../schema/v031-privacy-schema-provenance.json");

/// Canonical fixture DDL copied from the immutable v0.3.1 tag's
/// `PrivacyStore::initialize` implementation. Tests execute this text instead
/// of copying a binary SQLite fixture, then compare every normalized object to
/// [`PRIVACY_V1_SCHEMA_MANIFEST_JSONL`].
pub const PRIVACY_V1_SCHEMA_MANIFEST_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS privacy_schema_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS privacy_materials (
    material_id TEXT PRIMARY KEY CHECK(length(material_id) BETWEEN 1 AND 128),
    project_id TEXT CHECK(project_id IS NULL OR length(project_id) BETWEEN 1 AND 128),
    attachment_id TEXT CHECK(attachment_id IS NULL OR length(attachment_id) BETWEEN 1 AND 128),
    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64),
    source_name_sha256 TEXT NOT NULL CHECK(length(source_name_sha256) = 64),
    media_type TEXT NOT NULL CHECK(length(media_type) BETWEEN 1 AND 128),
    page_count INTEGER CHECK(page_count IS NULL OR page_count BETWEEN 0 AND 10000),
    state TEXT NOT NULL CHECK(state IN (
        'registered','assessing','extracting_native','ocr_required','ocr_running',
        'extracted','redacting','review_required','approved','outbound_ready',
        'failed','blocked','stale','revoked'
    )),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS privacy_redactions (
    redaction_id TEXT PRIMARY KEY CHECK(length(redaction_id) BETWEEN 1 AND 128),
    material_id TEXT NOT NULL,
    extraction_sha256 TEXT NOT NULL CHECK(length(extraction_sha256) = 64),
    redacted_content_sha256 TEXT NOT NULL CHECK(length(redacted_content_sha256) = 64),
    approved_payload_sha256 TEXT CHECK(
        approved_payload_sha256 IS NULL OR length(approved_payload_sha256) = 64
    ),
    policy_id TEXT NOT NULL CHECK(length(policy_id) BETWEEN 1 AND 128),
    policy_version INTEGER NOT NULL CHECK(policy_version > 0),
    detector_version TEXT NOT NULL CHECK(length(detector_version) BETWEEN 1 AND 128),
    unresolved_high_risk_count INTEGER NOT NULL CHECK(unresolved_high_risk_count >= 0),
    review_state TEXT NOT NULL CHECK(
        review_state IN ('review_required','approved','revoked','stale')
    ),
    protected_review_blob BLOB NOT NULL CHECK(length(protected_review_blob) > 0),
    protection_scheme TEXT NOT NULL CHECK(
        protection_scheme = 'windows_dpapi_current_user_v1'
    ),
    reviewed_by_sha256 TEXT CHECK(
        reviewed_by_sha256 IS NULL OR length(reviewed_by_sha256) = 64
    ),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    FOREIGN KEY(material_id)
        REFERENCES privacy_materials(material_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS privacy_receipts (
    receipt_id TEXT PRIMARY KEY CHECK(length(receipt_id) BETWEEN 1 AND 128),
    redaction_id TEXT NOT NULL,
    signed_token TEXT NOT NULL CHECK(length(signed_token) BETWEEN 1 AND 65536),
    destination_kind TEXT NOT NULL CHECK(destination_kind IN (
        'external_provider','external_mcp_host','verified_local_provider'
    )),
    destination_identifier_sha256 TEXT NOT NULL CHECK(
        length(destination_identifier_sha256) = 64
    ),
    purpose TEXT NOT NULL CHECK(length(purpose) BETWEEN 1 AND 128),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    policy_id TEXT NOT NULL CHECK(length(policy_id) BETWEEN 1 AND 128),
    policy_version INTEGER NOT NULL CHECK(policy_version > 0),
    issued_at_unix INTEGER NOT NULL CHECK(issued_at_unix > 0),
    expires_at_unix INTEGER CHECK(
        expires_at_unix IS NULL OR expires_at_unix > issued_at_unix
    ),
    revoked_at_unix INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(redaction_id)
        REFERENCES privacy_redactions(redaction_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS privacy_egress_audit (
    event_id TEXT PRIMARY KEY CHECK(length(event_id) BETWEEN 1 AND 128),
    occurred_at_unix INTEGER NOT NULL CHECK(occurred_at_unix > 0),
    classification TEXT NOT NULL CHECK(classification IN (
        'legal_public','product_public','case_raw','case_redacted_pending',
        'case_redacted_approved','secret'
    )),
    destination_kind TEXT NOT NULL CHECK(destination_kind IN (
        'external_provider','external_mcp_host','verified_local_provider'
    )),
    destination_identifier_sha256 TEXT NOT NULL CHECK(
        length(destination_identifier_sha256) = 64
    ),
    purpose TEXT NOT NULL CHECK(length(purpose) BETWEEN 1 AND 128),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256) = 64),
    payload_bytes INTEGER NOT NULL CHECK(payload_bytes >= 0),
    policy_id TEXT NOT NULL CHECK(length(policy_id) BETWEEN 1 AND 128),
    policy_version INTEGER NOT NULL CHECK(policy_version > 0),
    detector_version TEXT NOT NULL CHECK(length(detector_version) BETWEEN 1 AND 128),
    receipt_id TEXT,
    residual_counts_json TEXT NOT NULL CHECK(
        json_valid(residual_counts_json)
        AND json_type(residual_counts_json) = 'object'
        AND length(residual_counts_json) <= 65536
    ),
    allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
    reason_code TEXT NOT NULL CHECK(length(reason_code) BETWEEN 1 AND 128),
    previous_event_hash TEXT NOT NULL CHECK(length(previous_event_hash) IN (0,64)),
    event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash) = 64),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_privacy_materials_project
    ON privacy_materials(project_id, updated_at);
CREATE INDEX IF NOT EXISTS idx_privacy_redactions_material
    ON privacy_redactions(material_id, created_at);
CREATE INDEX IF NOT EXISTS idx_privacy_receipts_redaction
    ON privacy_receipts(redaction_id, created_at);
CREATE INDEX IF NOT EXISTS idx_privacy_audit_occurred
    ON privacy_egress_audit(occurred_at_unix);
CREATE TRIGGER IF NOT EXISTS trg_privacy_egress_audit_no_update
BEFORE UPDATE ON privacy_egress_audit BEGIN
    SELECT RAISE(ABORT, 'privacy egress audit is append only');
END;
CREATE TRIGGER IF NOT EXISTS trg_privacy_egress_audit_no_delete
BEFORE DELETE ON privacy_egress_audit BEGIN
    SELECT RAISE(ABORT, 'privacy egress audit is append only');
END;
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyV1SchemaProvenance {
    pub annotated_tag_object_id: &'static str,
    pub peeled_commit_id: &'static str,
    pub tagger_utc: &'static str,
    pub schema_version: i64,
    pub schema_object_count: usize,
    pub internal_schema_object_count: usize,
    pub normalized_sqlite_master_sha256: &'static str,
    pub internal_schema_manifest_sha256: &'static str,
    pub canonical_empty_fixture_sha256: &'static str,
}

/// Provenance of the immutable source used to freeze
/// [`PRIVACY_V1_SCHEMA_MANIFEST_DDL`]. These values describe the schema
/// contract's origin; a matching database alone does not assert an application
/// product version.
pub const PRIVACY_V1_SCHEMA_PROVENANCE: PrivacyV1SchemaProvenance = PrivacyV1SchemaProvenance {
    annotated_tag_object_id: "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc",
    peeled_commit_id: "0970f1c614b1bec1856869c68065162339849468",
    tagger_utc: "2026-07-19T15:41:29Z",
    schema_version: PRIVACY_V1_SCHEMA_VERSION,
    schema_object_count: PRIVACY_V1_SCHEMA_OBJECT_COUNT,
    internal_schema_object_count: PRIVACY_V1_INTERNAL_SCHEMA_OBJECT_COUNT,
    normalized_sqlite_master_sha256:
        "c41507b6441799decf2b2c506e884439b0ede732fa4ef2382ce5e22aaf9534b5",
    internal_schema_manifest_sha256: PRIVACY_V1_INTERNAL_SCHEMA_MANIFEST_SHA256,
    canonical_empty_fixture_sha256:
        "b86b1f7c35e7592ec3311535885b329670db6c946bde65496c98fd27eed29625",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyV1SourceValidationError {
    Database,
    UnsafeFilesystem,
    SchemaMismatch,
    SchemaVersionMismatch,
    IntegrityCheckFailed,
    ForeignKeyViolation,
    DataBoundary,
    ProtectedReviewPayload,
    SourceDrift,
}

impl PrivacyV1SourceValidationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Database => "privacy_v1_source_database_error",
            Self::UnsafeFilesystem => "privacy_v1_source_unsafe_filesystem",
            Self::SchemaMismatch => "privacy_v1_source_schema_mismatch",
            Self::SchemaVersionMismatch => "privacy_v1_source_schema_version_mismatch",
            Self::IntegrityCheckFailed => "privacy_v1_source_integrity_check_failed",
            Self::ForeignKeyViolation => "privacy_v1_source_foreign_key_violation",
            Self::DataBoundary => "privacy_v1_source_data_boundary_invalid",
            Self::ProtectedReviewPayload => "privacy_v1_source_protected_review_payload_invalid",
            Self::SourceDrift => "privacy_v1_source_drift",
        }
    }
}

impl std::fmt::Display for PrivacyV1SourceValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivacyV1SourceValidationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyV5SourceValidationError {
    Database,
    UnsafeFilesystem,
    Manifest(PrivacyV5ManifestError),
    SourceDrift,
}

impl PrivacyV5SourceValidationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Database => "privacy_v5_source_database_error",
            Self::UnsafeFilesystem => "privacy_v5_source_unsafe_filesystem",
            Self::Manifest(_) => "privacy_v5_source_manifest_invalid",
            Self::SourceDrift => "privacy_v5_source_drift",
        }
    }
}

impl std::fmt::Display for PrivacyV5SourceValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivacyV5SourceValidationError {}

impl From<PrivacyV5ManifestError> for PrivacyV5SourceValidationError {
    fn from(error: PrivacyV5ManifestError) -> Self {
        Self::Manifest(error)
    }
}

fn map_v5_source_guard_error(
    error: PrivacyV1SourceValidationError,
) -> PrivacyV5SourceValidationError {
    match error {
        PrivacyV1SourceValidationError::UnsafeFilesystem => {
            PrivacyV5SourceValidationError::UnsafeFilesystem
        }
        PrivacyV1SourceValidationError::SourceDrift => PrivacyV5SourceValidationError::SourceDrift,
        _ => PrivacyV5SourceValidationError::Database,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV1SourceFileProof {
    pub identity_sha256: String,
    pub length: u64,
    pub modified_unix_nanos: Option<u128>,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPrivacyV1Source {
    pub schema_version: i64,
    pub schema_object_count: usize,
    pub protected_review_payload_count: u64,
    pub normalized_sqlite_master_sha256: &'static str,
    pub database_file: PrivacyV1SourceFileProof,
    pub wal: Option<PrivacyV1SourceFileProof>,
    pub shm: Option<PrivacyV1SourceFileProof>,
    pub journal: Option<PrivacyV1SourceFileProof>,
    pub logical_manifest: PrivacyV1LogicalManifest,
    pub business_manifest: PrivacyV1BusinessManifest,
    pub data_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV1LogicalManifest {
    pub sha256: String,
    pub total_row_count: u64,
    pub tables: Vec<PrivacyV1LogicalTableManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV1LogicalTableManifest {
    pub table_name: String,
    pub row_count: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV1BusinessManifest {
    pub sha256: String,
    pub primary_key_sha256: String,
    pub row_sha256: String,
    pub total_row_count: u64,
    pub tables: Vec<PrivacyV1BusinessTableManifest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyV1BusinessTableManifest {
    pub table_name: String,
    pub row_count: u64,
    pub sha256: String,
    pub primary_key_sha256: String,
    pub row_sha256: String,
}

/// A callback-scoped view of the exact validated deferred transaction. The
/// underlying connection has both SQLite read-only flags and `query_only=ON`;
/// callers may use it as a source for SQLite's backup API but cannot write.
pub struct ValidatedPrivacyV1ReadOnlySession<'connection> {
    connection: &'connection Connection,
    proof: &'connection ValidatedPrivacyV1Source,
}

impl<'connection> ValidatedPrivacyV1ReadOnlySession<'connection> {
    /// Returns the complete, path-free proof captured for this still-pinned
    /// source snapshot. The outer validator repeats every proof after the
    /// callback before it can return success.
    pub const fn proof(&self) -> &'connection ValidatedPrivacyV1Source {
        self.proof
    }

    pub const fn logical_manifest(&self) -> &'connection PrivacyV1LogicalManifest {
        &self.proof.logical_manifest
    }

    pub const fn business_manifest(&self) -> &'connection PrivacyV1BusinessManifest {
        &self.proof.business_manifest
    }

    /// Copies the exact pinned source snapshot into a caller-owned destination
    /// using SQLite's online Backup API. No general SQL or transaction-control
    /// handle is exposed to the callback.
    pub fn backup_to(&self, destination: &mut Connection) -> rusqlite::Result<()> {
        let backup = rusqlite::backup::Backup::new(self.connection, destination)?;
        backup.run_to_completion(64, Duration::from_millis(1), None)
    }

    #[cfg(test)]
    fn execute_batch_for_transaction_guard_test(&self, sql: &str) -> rusqlite::Result<()> {
        self.connection.execute_batch(sql)
    }
}

/// Narrow Backup-API-only view of one exact Privacy-v5 snapshot.  The source
/// transaction remains pinned for the callback and is re-proven, together
/// with every database sidecar and ancestor binding, before success returns.
pub struct ValidatedPrivacyV5ReadOnlySession<'connection> {
    connection: &'connection Connection,
    proof: &'connection PrivacyV5ManifestProof,
}

impl ValidatedPrivacyV5ReadOnlySession<'_> {
    pub const fn proof(&self) -> &PrivacyV5ManifestProof {
        self.proof
    }

    pub fn backup_to(&self, destination: &mut Connection) -> rusqlite::Result<()> {
        let backup = rusqlite::backup::Backup::new(self.connection, destination)?;
        backup.run_to_completion(64, Duration::from_millis(1), None)
    }
}

/// Runs a Backup API operation while both the exact schema-5 semantic proof
/// and all source file identities are stable.  This is migration-only; normal
/// Privacy startup continues to reject schema 5.
pub fn with_validated_privacy_v5_migration_source_read_only<T>(
    path: impl AsRef<Path>,
    callback: impl FnOnce(&ValidatedPrivacyV5ReadOnlySession<'_>) -> T,
) -> Result<(PrivacyV5ManifestProof, T), PrivacyV5SourceValidationError> {
    let path = path.as_ref();
    let mut source_guard = SourcePathGuard::capture(path).map_err(map_v5_source_guard_error)?;
    let before = source_guard.initial_snapshot();
    let connection = open_privacy_v1_source_read_only(path).map_err(map_v5_source_guard_error)?;
    source_guard
        .verify_sqlite_binding(&connection)
        .map_err(map_v5_source_guard_error)?;
    let proof_before = compute_privacy_v5_manifests_read_only(&connection)?;

    let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)
        .map_err(|_| PrivacyV5SourceValidationError::Database)?;
    // The first read pins the snapshot before the Backup API is exposed.
    let _: i64 = transaction
        .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
        .map_err(|_| PrivacyV5SourceValidationError::Database)?;
    let data_version_before = transaction
        .pragma_query_value(None, "data_version", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV5SourceValidationError::Database)?;
    let callback_result = callback(&ValidatedPrivacyV5ReadOnlySession {
        connection: &transaction,
        proof: &proof_before,
    });
    let data_version_after = transaction
        .pragma_query_value(None, "data_version", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV5SourceValidationError::Database)?;
    let query_only = transaction
        .pragma_query_value(None, "query_only", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV5SourceValidationError::Database)?;
    if transaction.is_autocommit() || query_only != 1 || data_version_before != data_version_after {
        return Err(PrivacyV5SourceValidationError::SourceDrift);
    }
    transaction
        .commit()
        .map_err(|_| PrivacyV5SourceValidationError::Database)?;

    let proof_after = compute_privacy_v5_manifests_read_only(&connection)?;
    drop(connection);
    let after = source_guard
        .recapture()
        .map_err(map_v5_source_guard_error)?;
    if proof_before != proof_after || before != after {
        return Err(PrivacyV5SourceValidationError::SourceDrift);
    }
    Ok((proof_before, callback_result))
}

/// Opens an existing Privacy database with SQLite read-only flags and validates
/// the exact v1 migration-source contract. It never calls current initialization
/// or any writable migration/repair path.
pub fn validate_privacy_v1_migration_source_read_only(
    path: impl AsRef<Path>,
) -> Result<ValidatedPrivacyV1Source, PrivacyV1SourceValidationError> {
    with_validated_privacy_v1_migration_source_read_only(path, |_| ()).map(|(proof, ())| proof)
}

/// Reconstructs the complete exact-Privacy-v1 proof from one canonical SQLite
/// database image without creating a file or touching the original source.
///
/// SQLite copies the bytes into an owned in-memory buffer and attaches that
/// buffer with `SQLITE_DESERIALIZE_READONLY`. The connection is additionally
/// held in `query_only` mode, and only the frozen Privacy-v1 schema and data
/// boundaries are accepted.
pub fn validate_privacy_v1_sqlite_image_read_only(
    sqlite_image: &[u8],
) -> Result<ValidatedPrivacyV1Source, PrivacyV1SourceValidationError> {
    validate_privacy_v1_sqlite_image_input(sqlite_image)?;
    let image_length = u64::try_from(sqlite_image.len())
        .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
    let image_sha256 = sha256_hex(sqlite_image);

    let mut connection =
        Connection::open_in_memory().map_err(|_| PrivacyV1SourceValidationError::Database)?;
    connection
        .deserialize_read_exact(
            rusqlite::MAIN_DB,
            Cursor::new(sqlite_image),
            sqlite_image.len(),
            true,
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    validate_privacy_v1_deserialized_image_geometry(&connection, image_length)?;

    let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let initial_validation = validate_privacy_v1_transaction(&transaction)?;
    let query_only = transaction
        .pragma_query_value(None, "query_only", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    if query_only != 1 {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }
    let final_validation = validate_privacy_v1_transaction(&transaction)?;
    if initial_validation != final_validation {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }
    transaction
        .commit()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;

    Ok(ValidatedPrivacyV1Source {
        schema_version: PRIVACY_V1_SCHEMA_VERSION,
        schema_object_count: PRIVACY_V1_SCHEMA_OBJECT_COUNT,
        protected_review_payload_count: initial_validation.protected_review_payload_count,
        normalized_sqlite_master_sha256: PRIVACY_V1_SCHEMA_PROVENANCE
            .normalized_sqlite_master_sha256,
        database_file: privacy_v1_memory_image_file_proof(image_length, image_sha256),
        wal: None,
        shm: None,
        journal: None,
        logical_manifest: initial_validation.logical_manifest,
        business_manifest: initial_validation.business_manifest,
        data_version: initial_validation.data_version,
    })
}

fn validate_privacy_v1_sqlite_image_input(
    sqlite_image: &[u8],
) -> Result<(), PrivacyV1SourceValidationError> {
    if sqlite_image.len() < 100
        || sqlite_image.len() > MAX_PRIVACY_V1_SQLITE_IMAGE_BYTES
        || !sqlite_image.starts_with(b"SQLite format 3\0")
    {
        return Err(PrivacyV1SourceValidationError::DataBoundary);
    }
    Ok(())
}

fn validate_privacy_v1_deserialized_image_geometry(
    connection: &Connection,
    image_length: u64,
) -> Result<(), PrivacyV1SourceValidationError> {
    let page_size = connection
        .pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let page_count = connection
        .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let expected_length = u64::try_from(page_size)
        .ok()
        .and_then(|size| {
            u64::try_from(page_count)
                .ok()
                .and_then(|count| size.checked_mul(count))
        })
        .filter(|length| *length > 0)
        .ok_or(PrivacyV1SourceValidationError::DataBoundary)?;
    if expected_length != image_length {
        return Err(PrivacyV1SourceValidationError::DataBoundary);
    }
    Ok(())
}

fn privacy_v1_memory_image_file_proof(
    image_length: u64,
    image_sha256: String,
) -> PrivacyV1SourceFileProof {
    let mut identity = Sha256::new();
    Digest::update(&mut identity, PRIVACY_V1_MEMORY_IMAGE_IDENTITY_DOMAIN);
    Digest::update(&mut identity, image_length.to_be_bytes());
    Digest::update(&mut identity, image_sha256.as_bytes());
    PrivacyV1SourceFileProof {
        identity_sha256: format!("{:x}", identity.finalize()),
        length: image_length,
        modified_unix_nanos: None,
        sha256: image_sha256,
    }
}

/// Validates the source, invokes `callback` against that same pinned read-only
/// transaction, then repeats the logical/schema/data-version and filesystem
/// proofs before returning either result. The callback output is deliberately
/// opaque: callers that need fallible snapshot work return a `Result` as `T`,
/// so even an inner error value cannot bypass the mandatory postvalidation.
pub fn with_validated_privacy_v1_migration_source_read_only<T, F>(
    path: impl AsRef<Path>,
    callback: F,
) -> Result<(ValidatedPrivacyV1Source, T), PrivacyV1SourceValidationError>
where
    F: FnOnce(&ValidatedPrivacyV1ReadOnlySession<'_>) -> T,
{
    with_validated_privacy_v1_migration_source_read_only_inner(path.as_ref(), callback, || {})
}

fn with_validated_privacy_v1_migration_source_read_only_inner<T, F, H>(
    path: &Path,
    callback: F,
    after_primary_transaction: H,
) -> Result<(ValidatedPrivacyV1Source, T), PrivacyV1SourceValidationError>
where
    F: FnOnce(&ValidatedPrivacyV1ReadOnlySession<'_>) -> T,
    H: FnOnce(),
{
    let mut source_guard = SourcePathGuard::capture(path)?;
    let before = source_guard.initial_snapshot();
    let connection = open_privacy_v1_source_read_only(path)?;
    source_guard.verify_sqlite_binding(&connection)?;
    let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let initial_validation = validate_privacy_v1_transaction(&transaction)?;
    let source_proof = ValidatedPrivacyV1Source {
        schema_version: PRIVACY_V1_SCHEMA_VERSION,
        schema_object_count: PRIVACY_V1_SCHEMA_OBJECT_COUNT,
        protected_review_payload_count: initial_validation.protected_review_payload_count,
        normalized_sqlite_master_sha256: PRIVACY_V1_SCHEMA_PROVENANCE
            .normalized_sqlite_master_sha256,
        database_file: privacy_v1_source_file_proof(&before.database),
        wal: before.wal.as_ref().map(privacy_v1_source_file_proof),
        shm: before.shm.as_ref().map(privacy_v1_source_file_proof),
        journal: before.journal.as_ref().map(privacy_v1_source_file_proof),
        logical_manifest: initial_validation.logical_manifest.clone(),
        business_manifest: initial_validation.business_manifest.clone(),
        data_version: initial_validation.data_version,
    };
    let transaction_guard = format!("privacy_migration_guard_{}", uuid::Uuid::new_v4().simple());
    transaction
        .execute_batch(&format!(
            "SAVEPOINT {}",
            quote_identifier(&transaction_guard)
        ))
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;

    let callback_result = callback(&ValidatedPrivacyV1ReadOnlySession {
        connection: &transaction,
        proof: &source_proof,
    });
    transaction
        .execute_batch(&format!(
            "RELEASE SAVEPOINT {}",
            quote_identifier(&transaction_guard)
        ))
        .map_err(|_| PrivacyV1SourceValidationError::SourceDrift)?;
    let query_only_after = transaction
        .pragma_query_value(None, "query_only", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    if transaction.is_autocommit() || query_only_after != 1 {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }

    let validation_after_callback = validate_privacy_v1_transaction(&transaction)?;
    if initial_validation != validation_after_callback {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }
    transaction
        .commit()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    after_primary_transaction();

    let post_transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Deferred)
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let final_validation = validate_privacy_v1_transaction(&post_transaction)
        .map_err(|_| PrivacyV1SourceValidationError::SourceDrift)?;
    post_transaction
        .commit()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    if initial_validation != final_validation {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }
    if sqlite_data_version(&connection)? != initial_validation.data_version {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }
    drop(connection);

    let after = source_guard.recapture()?;
    if before != after {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }

    Ok((source_proof, callback_result))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourcePathSnapshot {
    database: FileSnapshot,
    wal: Option<FileSnapshot>,
    shm: Option<FileSnapshot>,
    journal: Option<FileSnapshot>,
}

struct GuardedSourceFile {
    path: PathBuf,
    file: File,
    initial_snapshot: FileSnapshot,
}

impl GuardedSourceFile {
    fn capture(path: &Path) -> Result<Self, PrivacyV1SourceValidationError> {
        validate_ordinary_single_link_file(path)?;
        let mut file = open_restrictive_read_guard(path)?;
        let initial_snapshot = FileSnapshot::capture_opened(path, &mut file)?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            initial_snapshot,
        })
    }

    fn recapture(&mut self) -> Result<FileSnapshot, PrivacyV1SourceValidationError> {
        FileSnapshot::capture_opened(&self.path, &mut self.file)
    }

    fn verify_path_identity(&self, path: &Path) -> Result<(), PrivacyV1SourceValidationError> {
        validate_ordinary_single_link_file(path)?;
        let file = open_restrictive_read_guard(path)?;
        let identity = crate::vault_store::fixed_local_file_identity(&file)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        if identity != self.initial_snapshot.identity {
            return Err(PrivacyV1SourceValidationError::SourceDrift);
        }
        Ok(())
    }

    fn sqlite_header_uses_wal(&mut self) -> Result<bool, PrivacyV1SourceValidationError> {
        if self.initial_snapshot.length < 20 {
            return Ok(false);
        }
        self.file
            .seek(SeekFrom::Start(18))
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        let mut versions = [0_u8; 2];
        self.file
            .read_exact(&mut versions)
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        Ok(versions.contains(&2))
    }
}

struct SourcePathGuard {
    ancestor_directories: Vec<GuardedSourceDirectory>,
    database: GuardedSourceFile,
    wal: Option<GuardedSourceFile>,
    shm: Option<GuardedSourceFile>,
    journal: Option<GuardedSourceFile>,
}

impl SourcePathGuard {
    fn capture(database_path: &Path) -> Result<Self, PrivacyV1SourceValidationError> {
        if !database_path.is_absolute() {
            return Err(PrivacyV1SourceValidationError::UnsafeFilesystem);
        }
        let ancestor_directories = capture_ancestor_directory_guards(database_path)?;
        let mut database = GuardedSourceFile::capture(database_path)?;
        let wal = capture_optional_guarded_file(&sqlite_sidecar_path(database_path, "-wal")?)?;
        let shm = capture_optional_guarded_file(&sqlite_sidecar_path(database_path, "-shm")?)?;
        let journal =
            capture_optional_guarded_file(&sqlite_sidecar_path(database_path, "-journal")?)?;
        if database.sqlite_header_uses_wal()? && (wal.is_none() || shm.is_none()) {
            // A WAL-mode database cannot be opened observationally when its
            // read-only WAL index is absent: SQLite would otherwise need to
            // create or initialize a sidecar in the source directory.
            return Err(PrivacyV1SourceValidationError::UnsafeFilesystem);
        }
        Ok(Self {
            ancestor_directories,
            database,
            wal,
            shm,
            journal,
        })
    }

    fn initial_snapshot(&self) -> SourcePathSnapshot {
        SourcePathSnapshot {
            database: self.database.initial_snapshot.clone(),
            wal: self.wal.as_ref().map(|file| file.initial_snapshot.clone()),
            shm: self.shm.as_ref().map(|file| file.initial_snapshot.clone()),
            journal: self
                .journal
                .as_ref()
                .map(|file| file.initial_snapshot.clone()),
        }
    }

    fn recapture(&mut self) -> Result<SourcePathSnapshot, PrivacyV1SourceValidationError> {
        let wal_path = sqlite_sidecar_path(&self.database.path, "-wal")?;
        let shm_path = sqlite_sidecar_path(&self.database.path, "-shm")?;
        let journal_path = sqlite_sidecar_path(&self.database.path, "-journal")?;
        let snapshot = SourcePathSnapshot {
            database: self.database.recapture()?,
            wal: recapture_optional_guarded_file(&mut self.wal, &wal_path)?,
            shm: recapture_optional_guarded_file(&mut self.shm, &shm_path)?,
            journal: recapture_optional_guarded_file(&mut self.journal, &journal_path)?,
        };
        for directory in &self.ancestor_directories {
            directory.verify_binding()?;
        }
        Ok(snapshot)
    }

    fn verify_sqlite_binding(
        &self,
        connection: &Connection,
    ) -> Result<(), PrivacyV1SourceValidationError> {
        if !connection
            .is_readonly(rusqlite::MAIN_DB)
            .map_err(|_| PrivacyV1SourceValidationError::Database)?
        {
            return Err(PrivacyV1SourceValidationError::UnsafeFilesystem);
        }
        let sqlite_path = connection
            .path()
            .filter(|path| !path.is_empty())
            .ok_or(PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        let sqlite_path = Path::new(sqlite_path);
        let guarded_canonical = fs::canonicalize(&self.database.path)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        let sqlite_canonical = fs::canonicalize(sqlite_path)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        if guarded_canonical != sqlite_canonical {
            return Err(PrivacyV1SourceValidationError::UnsafeFilesystem);
        }
        self.database.verify_path_identity(sqlite_path)
    }
}

struct GuardedSourceDirectory {
    path: PathBuf,
    file: File,
    identity: Vec<u8>,
}

impl GuardedSourceDirectory {
    fn capture(path: &Path) -> Result<Self, PrivacyV1SourceValidationError> {
        crate::vault_store::validate_fixed_local_directory(path)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        let file = open_restrictive_directory_guard(path)?;
        if !file
            .metadata()
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?
            .is_dir()
        {
            return Err(PrivacyV1SourceValidationError::UnsafeFilesystem);
        }
        let identity = crate::vault_store::fixed_local_file_identity(&file)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        let guard = Self {
            path: path.to_path_buf(),
            file,
            identity,
        };
        guard.verify_binding()?;
        Ok(guard)
    }

    fn verify_binding(&self) -> Result<(), PrivacyV1SourceValidationError> {
        crate::vault_store::validate_fixed_local_directory(&self.path)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        if !self
            .file
            .metadata()
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?
            .is_dir()
            || crate::vault_store::fixed_local_file_identity(&self.file)
                .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?
                != self.identity
        {
            return Err(PrivacyV1SourceValidationError::UnsafeFilesystem);
        }
        let fresh = open_restrictive_directory_guard(&self.path)?;
        let fresh_identity = crate::vault_store::fixed_local_file_identity(&fresh)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        if fresh_identity != self.identity {
            return Err(PrivacyV1SourceValidationError::SourceDrift);
        }
        Ok(())
    }
}

impl SourcePathSnapshot {
    #[cfg(all(test, windows))]
    fn capture(database_path: &Path) -> Result<Self, PrivacyV1SourceValidationError> {
        if !database_path.is_absolute() {
            return Err(PrivacyV1SourceValidationError::UnsafeFilesystem);
        }
        Ok(Self {
            database: FileSnapshot::capture(database_path)?,
            wal: capture_optional_file(&sqlite_sidecar_path(database_path, "-wal")?)?,
            shm: capture_optional_file(&sqlite_sidecar_path(database_path, "-shm")?)?,
            journal: capture_optional_file(&sqlite_sidecar_path(database_path, "-journal")?)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSnapshot {
    identity: Vec<u8>,
    length: u64,
    modified: SystemTime,
    sha256: String,
}

impl FileSnapshot {
    #[cfg(all(test, windows))]
    fn capture(path: &Path) -> Result<Self, PrivacyV1SourceValidationError> {
        validate_ordinary_single_link_file(path)?;
        let mut file = File::open(path).map_err(|_| PrivacyV1SourceValidationError::Database)?;
        Self::capture_opened(path, &mut file)
    }

    fn capture_opened(
        path: &Path,
        file: &mut File,
    ) -> Result<Self, PrivacyV1SourceValidationError> {
        file.seek(SeekFrom::Start(0))
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        let identity = crate::vault_store::fixed_local_file_identity(file)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        let metadata_before = file
            .metadata()
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        let modified = metadata_before
            .modified()
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        let mut digest = Sha256::new();
        let mut buffer = Zeroizing::new([0_u8; 64 * 1024]);
        loop {
            let read = file
                .read(&mut buffer[..])
                .map_err(|_| PrivacyV1SourceValidationError::Database)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        let metadata_after = file
            .metadata()
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        let identity_after = crate::vault_store::fixed_local_file_identity(file)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        validate_ordinary_single_link_file(path)?;
        let path_file = File::open(path).map_err(|_| PrivacyV1SourceValidationError::Database)?;
        let path_identity = crate::vault_store::fixed_local_file_identity(&path_file)
            .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)?;
        if metadata_before.len() != metadata_after.len()
            || modified
                != metadata_after
                    .modified()
                    .map_err(|_| PrivacyV1SourceValidationError::Database)?
            || identity != identity_after
            || identity != path_identity
        {
            return Err(PrivacyV1SourceValidationError::SourceDrift);
        }
        Ok(Self {
            identity,
            length: metadata_after.len(),
            modified,
            sha256: format!("{:x}", digest.finalize()),
        })
    }
}

fn capture_optional_guarded_file(
    path: &Path,
) -> Result<Option<GuardedSourceFile>, PrivacyV1SourceValidationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => GuardedSourceFile::capture(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(PrivacyV1SourceValidationError::UnsafeFilesystem),
    }
}

fn recapture_optional_guarded_file(
    guarded: &mut Option<GuardedSourceFile>,
    path: &Path,
) -> Result<Option<FileSnapshot>, PrivacyV1SourceValidationError> {
    match guarded {
        Some(file) => file.recapture().map(Some),
        None => match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            _ => Err(PrivacyV1SourceValidationError::SourceDrift),
        },
    }
}

fn capture_ancestor_directory_guards(
    database_path: &Path,
) -> Result<Vec<GuardedSourceDirectory>, PrivacyV1SourceValidationError> {
    let parent = database_path
        .parent()
        .ok_or(PrivacyV1SourceValidationError::UnsafeFilesystem)?;
    let mut paths = parent
        .ancestors()
        .filter(|path| !path.as_os_str().is_empty())
        .collect::<Vec<_>>();
    paths.reverse();
    paths
        .into_iter()
        .map(GuardedSourceDirectory::capture)
        .collect()
}

#[cfg(windows)]
fn open_restrictive_read_guard(path: &Path) -> Result<File, PrivacyV1SourceValidationError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)
}

#[cfg(windows)]
fn open_restrictive_directory_guard(path: &Path) -> Result<File, PrivacyV1SourceValidationError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)
}

#[cfg(not(windows))]
fn open_restrictive_read_guard(_path: &Path) -> Result<File, PrivacyV1SourceValidationError> {
    Err(PrivacyV1SourceValidationError::UnsafeFilesystem)
}

#[cfg(not(windows))]
fn open_restrictive_directory_guard(_path: &Path) -> Result<File, PrivacyV1SourceValidationError> {
    Err(PrivacyV1SourceValidationError::UnsafeFilesystem)
}

fn privacy_v1_source_file_proof(snapshot: &FileSnapshot) -> PrivacyV1SourceFileProof {
    let mut identity = Sha256::new();
    Digest::update(&mut identity, PRIVACY_V1_SOURCE_FILE_IDENTITY_DOMAIN);
    Digest::update(
        &mut identity,
        (snapshot.identity.len() as u64).to_be_bytes(),
    );
    Digest::update(&mut identity, &snapshot.identity);
    PrivacyV1SourceFileProof {
        identity_sha256: format!("{:x}", identity.finalize()),
        length: snapshot.length,
        modified_unix_nanos: snapshot
            .modified
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_nanos()),
        sha256: snapshot.sha256.clone(),
    }
}

#[cfg(all(test, windows))]
fn capture_optional_file(
    path: &Path,
) -> Result<Option<FileSnapshot>, PrivacyV1SourceValidationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => FileSnapshot::capture(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(PrivacyV1SourceValidationError::Database),
    }
}

fn sqlite_sidecar_path(
    database_path: &Path,
    suffix: &str,
) -> Result<PathBuf, PrivacyV1SourceValidationError> {
    let file_name = database_path
        .file_name()
        .ok_or(PrivacyV1SourceValidationError::UnsafeFilesystem)?;
    let mut sidecar_name = file_name.to_os_string();
    sidecar_name.push(suffix);
    Ok(database_path.with_file_name(sidecar_name))
}

#[cfg(windows)]
fn validate_ordinary_single_link_file(path: &Path) -> Result<(), PrivacyV1SourceValidationError> {
    crate::vault_store::validate_fixed_local_regular_file(path)
        .map_err(|_| PrivacyV1SourceValidationError::UnsafeFilesystem)
}

#[cfg(not(windows))]
fn validate_ordinary_single_link_file(_path: &Path) -> Result<(), PrivacyV1SourceValidationError> {
    // The frozen v0.3.1 payload contract is Windows CurrentUser DPAPI and the
    // standard library has no portable, race-free fixed-local-volume check.
    // Fail closed instead of treating a Unix dev/inode pair as proof that a
    // network, FUSE, removable, or virtual filesystem is local and fixed.
    Err(PrivacyV1SourceValidationError::UnsafeFilesystem)
}

fn open_privacy_v1_source_read_only(
    path: &Path,
) -> Result<Connection, PrivacyV1SourceValidationError> {
    let uri = sqlite_read_only_uri(path)?;
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    connection
        .pragma_update(None, "query_only", "ON")
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let query_only = connection
        .pragma_query_value(None, "query_only", |row| row.get::<_, i64>(0))
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    if query_only != 1 {
        return Err(PrivacyV1SourceValidationError::Database);
    }
    Ok(connection)
}

fn sqlite_read_only_uri(path: &Path) -> Result<String, PrivacyV1SourceValidationError> {
    let path = path
        .to_str()
        .ok_or(PrivacyV1SourceValidationError::UnsafeFilesystem)?;
    let normalized = path.replace('\\', "/");
    let mut uri = String::with_capacity(normalized.len().saturating_mul(3).saturating_add(40));
    if normalized.as_bytes().get(1) == Some(&b':') {
        uri.push_str("file:///");
    } else {
        uri.push_str("file:");
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in normalized.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b':') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    uri.push_str("?mode=ro&readonly_shm=1");
    Ok(uri)
}

fn sqlite_data_version(connection: &Connection) -> Result<i64, PrivacyV1SourceValidationError> {
    connection
        .pragma_query_value(None, "data_version", |row| row.get(0))
        .map_err(|_| PrivacyV1SourceValidationError::Database)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrivacyV1TransactionValidation {
    protected_review_payload_count: u64,
    logical_manifest: PrivacyV1LogicalManifest,
    business_manifest: PrivacyV1BusinessManifest,
    data_version: i64,
}

/// Reconstructed v0.3.1 business identity from the legacy columns retained by
/// the deterministic schema-1 to schema-5 rebuild.  This proof is intentionally
/// crate-private: it is only one input to the stricter partial-v5 recovery
/// classifier and cannot authorize an ordinary schema migration by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivacyV1EvolvedProjectionProof {
    pub(crate) business_manifest_sha256: String,
    pub(crate) total_row_count: u64,
    pub(crate) protected_review_payload_count: u64,
}

/// Reconstructs the exact schema-1 business view from a pinned evolved store
/// without modifying the source connection.  The schema-5 rebuild moves the
/// legacy `privacy_materials.project_id` value to `legacy_case_id`; every other
/// schema-1 column is retained verbatim.  Rows are copied only into an isolated
/// in-memory canonical-v1 fixture, where the existing v1 boundary, DPAPI, FK,
/// and canonical-manifest validators are reused.
pub(crate) fn reconstruct_privacy_v1_projection_from_evolved_store_read_only(
    source: &Connection,
) -> Result<PrivacyV1EvolvedProjectionProof, PrivacyV1SourceValidationError> {
    let fixture =
        Connection::open_in_memory().map_err(|_| PrivacyV1SourceValidationError::Database)?;
    fixture
        .execute_batch(PRIVACY_V1_SCHEMA_MANIFEST_DDL)
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;

    for table_name in [
        "privacy_schema_metadata",
        "privacy_materials",
        "privacy_redactions",
        "privacy_receipts",
        "privacy_egress_audit",
    ] {
        copy_evolved_rows_into_v1_fixture(source, &fixture, table_name)?;
    }

    let validation = validate_privacy_v1_transaction(&fixture)?;
    Ok(PrivacyV1EvolvedProjectionProof {
        business_manifest_sha256: validation.business_manifest.sha256,
        total_row_count: validation.logical_manifest.total_row_count,
        protected_review_payload_count: validation.protected_review_payload_count,
    })
}

fn copy_evolved_rows_into_v1_fixture(
    source: &Connection,
    fixture: &Connection,
    table_name: &str,
) -> Result<(), PrivacyV1SourceValidationError> {
    let columns = logical_table_columns(fixture, table_name)?;
    let quoted_table = quote_projection_identifier(table_name)?;
    let quoted_columns = columns
        .iter()
        .map(|column| quote_projection_identifier(&column.name))
        .collect::<Result<Vec<_>, _>>()?;
    let select_columns = columns
        .iter()
        .map(|column| {
            let quoted = quote_projection_identifier(&column.name)?;
            match (table_name, column.name.as_str()) {
                ("privacy_materials", "project_id") => {
                    Ok("\"legacy_case_id\" AS \"project_id\"".to_owned())
                }
                ("privacy_schema_metadata", "value") => Ok(
                    "CASE WHEN \"key\"='schema_version' THEN '1' ELSE \"value\" END AS \"value\""
                        .to_owned(),
                ),
                _ => Ok(quoted),
            }
        })
        .collect::<Result<Vec<_>, PrivacyV1SourceValidationError>>()?;
    let select_sql = format!(
        "SELECT {} FROM {} ORDER BY rowid",
        select_columns.join(","),
        quoted_table
    );
    let insert_sql = format!(
        "INSERT INTO {}({}) VALUES({})",
        quoted_table,
        quoted_columns.join(","),
        std::iter::repeat_n("?", columns.len())
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut source_statement = source
        .prepare(&select_sql)
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let mut source_rows = source_statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let mut insert = fixture
        .prepare(&insert_sql)
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    while let Some(row) = source_rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
    {
        let values = (0..columns.len())
            .map(|index| row.get::<_, Value>(index))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        insert
            .execute(params_from_iter(values.iter()))
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
    }
    Ok(())
}

fn quote_projection_identifier(value: &str) -> Result<String, PrivacyV1SourceValidationError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    Ok(format!("\"{value}\""))
}

fn validate_privacy_v1_transaction(
    connection: &Connection,
) -> Result<PrivacyV1TransactionValidation, PrivacyV1SourceValidationError> {
    let data_version_before = sqlite_data_version(connection)?;
    let expected = expected_schema_objects()?;
    let actual = schema_objects(connection)?;
    if actual != expected || actual.len() != PRIVACY_V1_SCHEMA_OBJECT_COUNT {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    if internal_schema_objects(connection)? != expected_internal_schema_objects()? {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }

    validate_schema_version(connection)?;
    validate_quick_check(connection)?;
    validate_foreign_keys(connection)?;
    validate_privacy_v1_data_boundaries(connection)?;
    let protected_review_payload_count = validate_protected_review_payloads(connection)?;
    validate_protected_receipt_tokens(connection)?;
    let (logical_manifest, business_manifest) = privacy_v1_manifests(connection)?;
    let data_version_after = sqlite_data_version(connection)?;
    if data_version_before != data_version_after {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }
    Ok(PrivacyV1TransactionValidation {
        protected_review_payload_count,
        logical_manifest,
        business_manifest,
        data_version: data_version_before,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogicalTableDefinition {
    name: String,
    create_table_sql: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LogicalColumnMetadata {
    cid: u64,
    name: String,
    declared_type: String,
    not_null: bool,
    default_sql: Option<String>,
    primary_key_ordinal: u64,
    hidden: u64,
}

struct CanonicalRow {
    sort_key: Vec<u8>,
    encoded: Vec<u8>,
}

struct CanonicalTable {
    definition: LogicalTableDefinition,
    columns: Vec<LogicalColumnMetadata>,
    primary_key_columns: Vec<usize>,
    rows: Vec<CanonicalRow>,
}

impl Drop for CanonicalRow {
    fn drop(&mut self) {
        self.sort_key.zeroize();
        self.encoded.zeroize();
    }
}

trait CanonicalSink {
    fn put(&mut self, bytes: &[u8]);
}

impl CanonicalSink for Sha256 {
    fn put(&mut self, bytes: &[u8]) {
        Digest::update(self, bytes);
    }
}

impl CanonicalSink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

fn privacy_v1_manifests(
    connection: &Connection,
) -> Result<(PrivacyV1LogicalManifest, PrivacyV1BusinessManifest), PrivacyV1SourceValidationError> {
    let definitions = privacy_v1_logical_table_definitions()?
        .into_iter()
        .map(|definition| (definition.name, definition.create_table_sql))
        .collect();
    canonical_sqlite_manifests(connection, definitions, &["privacy_schema_metadata"])
}

/// Shared ADR-0002 SQLite logical/business manifest encoder. Callers must
/// first establish an exact schema allowlist and pass its normalized table
/// definitions in raw UTF-8 name order. This is the only encoder used by both
/// the frozen Privacy v1 source proof and current Privacy schema-6 proofs.
pub(crate) fn canonical_sqlite_manifests(
    connection: &Connection,
    definitions: Vec<(String, String)>,
    business_excluded_tables: &[&str],
) -> Result<(PrivacyV1LogicalManifest, PrivacyV1BusinessManifest), PrivacyV1SourceValidationError> {
    canonical_sqlite_manifests_inner(connection, definitions, business_excluded_tables, None)
}

/// Computes the same canonical manifests while removing exactly one validated
/// application-upgrade lineage row from the logical view. The whole lineage
/// table remains excluded from the business manifest under the frozen v6
/// rules, so historical business evidence is unaffected.
pub(crate) fn canonical_sqlite_manifests_excluding_application_upgrade_lineage(
    connection: &Connection,
    definitions: Vec<(String, String)>,
    business_excluded_tables: &[&str],
    excluded_lineage_id: &str,
) -> Result<(PrivacyV1LogicalManifest, PrivacyV1BusinessManifest), PrivacyV1SourceValidationError> {
    canonical_sqlite_manifests_inner(
        connection,
        definitions,
        business_excluded_tables,
        Some(CanonicalTextRowExclusion {
            table_name: "application_upgrade_lineage",
            column_name: "lineage_id",
            value: excluded_lineage_id,
        }),
    )
}

#[derive(Clone, Copy)]
struct CanonicalTextRowExclusion<'a> {
    table_name: &'a str,
    column_name: &'a str,
    value: &'a str,
}

fn canonical_sqlite_manifests_inner(
    connection: &Connection,
    definitions: Vec<(String, String)>,
    business_excluded_tables: &[&str],
    row_exclusion: Option<CanonicalTextRowExclusion<'_>>,
) -> Result<(PrivacyV1LogicalManifest, PrivacyV1BusinessManifest), PrivacyV1SourceValidationError> {
    if definitions.is_empty()
        || definitions
            .windows(2)
            .any(|pair| pair[0].0.as_bytes() >= pair[1].0.as_bytes())
        || definitions
            .iter()
            .any(|(name, sql)| name.is_empty() || sql != &normalize_sql(sql))
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    let business_excluded = business_excluded_tables
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if business_excluded.len() != business_excluded_tables.len()
        || business_excluded.iter().any(|excluded| {
            !definitions
                .iter()
                .any(|(table_name, _)| table_name == excluded)
        })
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }

    let mut canonical_tables = Vec::with_capacity(definitions.len());
    for (name, create_table_sql) in definitions {
        let definition = LogicalTableDefinition {
            name,
            create_table_sql,
        };
        let columns = logical_table_columns(connection, &definition.name)?;
        let mut primary_key_columns = columns
            .iter()
            .enumerate()
            .filter(|(_, column)| column.primary_key_ordinal > 0)
            .map(|(index, column)| (column.primary_key_ordinal, index))
            .collect::<Vec<_>>();
        primary_key_columns.sort_by_key(|(ordinal, _)| *ordinal);
        let primary_key_columns = primary_key_columns
            .into_iter()
            .map(|(_, index)| index)
            .collect::<Vec<_>>();
        let exclusion =
            row_exclusion.filter(|exclusion| exclusion.table_name == definition.name.as_str());
        if let Some(exclusion) = exclusion {
            if columns
                .iter()
                .filter(|column| column.name == exclusion.column_name)
                .count()
                != 1
            {
                return Err(PrivacyV1SourceValidationError::SchemaMismatch);
            }
        }
        let mut rows = logical_table_rows(connection, &definition.name, &columns, exclusion)?;
        rows.sort_by(|left, right| {
            left.sort_key
                .cmp(&right.sort_key)
                .then_with(|| left.encoded.cmp(&right.encoded))
        });
        canonical_tables.push(CanonicalTable {
            definition,
            columns,
            primary_key_columns,
            rows,
        });
    }
    if row_exclusion.is_some_and(|exclusion| {
        !canonical_tables
            .iter()
            .any(|table| table.definition.name == exclusion.table_name)
    }) {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }

    let logical_tables = canonical_tables.iter().collect::<Vec<_>>();
    let logical_sha256 =
        canonical_manifest_sha256(SQLITE_CANONICAL_LOGICAL_MANIFEST_V1_DOMAIN, &logical_tables)?;
    let mut logical_table_proofs = Vec::with_capacity(logical_tables.len());
    let mut total_row_count = 0_u64;
    for table in &logical_tables {
        let row_count = usize_to_u64(table.rows.len())?;
        total_row_count = total_row_count
            .checked_add(row_count)
            .ok_or(PrivacyV1SourceValidationError::Database)?;
        let mut table_hasher = Sha256::new();
        put_logical_table_section(
            &mut table_hasher,
            &table.definition,
            &table.columns,
            &table.rows,
        )?;
        logical_table_proofs.push(PrivacyV1LogicalTableManifest {
            table_name: table.definition.name.clone(),
            row_count,
            sha256: format!("{:x}", table_hasher.finalize()),
        });
    }

    let business_tables = canonical_tables
        .iter()
        .filter(|table| !business_excluded.contains(table.definition.name.as_str()))
        .collect::<Vec<_>>();
    if business_tables.len() + business_excluded.len() != canonical_tables.len() {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    let business_sha256 = canonical_manifest_sha256(
        SQLITE_CANONICAL_BUSINESS_MANIFEST_V1_DOMAIN,
        &business_tables,
    )?;
    let business_primary_key_sha256 = canonical_primary_key_manifest_sha256(
        SQLITE_CANONICAL_BUSINESS_PRIMARY_KEY_MANIFEST_V1_DOMAIN,
        &business_tables,
    )?;
    let business_row_sha256 = canonical_manifest_sha256(
        SQLITE_CANONICAL_BUSINESS_ROW_MANIFEST_V1_DOMAIN,
        &business_tables,
    )?;
    let mut business_total_row_count = 0_u64;
    let mut business_table_proofs = Vec::with_capacity(business_tables.len());
    for table in business_tables {
        let row_count = usize_to_u64(table.rows.len())?;
        business_total_row_count = business_total_row_count
            .checked_add(row_count)
            .ok_or(PrivacyV1SourceValidationError::Database)?;
        business_table_proofs.push(PrivacyV1BusinessTableManifest {
            table_name: table.definition.name.clone(),
            row_count,
            sha256: canonical_manifest_sha256(
                SQLITE_CANONICAL_BUSINESS_MANIFEST_V1_DOMAIN,
                &[table],
            )?,
            primary_key_sha256: canonical_primary_key_manifest_sha256(
                SQLITE_CANONICAL_BUSINESS_PRIMARY_KEY_MANIFEST_V1_DOMAIN,
                &[table],
            )?,
            row_sha256: canonical_manifest_sha256(
                SQLITE_CANONICAL_BUSINESS_ROW_MANIFEST_V1_DOMAIN,
                &[table],
            )?,
        });
    }

    Ok((
        PrivacyV1LogicalManifest {
            sha256: logical_sha256,
            total_row_count,
            tables: logical_table_proofs,
        },
        PrivacyV1BusinessManifest {
            sha256: business_sha256,
            primary_key_sha256: business_primary_key_sha256,
            row_sha256: business_row_sha256,
            total_row_count: business_total_row_count,
            tables: business_table_proofs,
        },
    ))
}

fn canonical_manifest_sha256(
    domain: &[u8],
    tables: &[&CanonicalTable],
) -> Result<String, PrivacyV1SourceValidationError> {
    let mut hasher = Sha256::new();
    hasher.put(domain);
    put_u64(&mut hasher, usize_to_u64(tables.len())?);
    for table in tables {
        put_logical_table_section(&mut hasher, &table.definition, &table.columns, &table.rows)?;
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn canonical_primary_key_manifest_sha256(
    domain: &[u8],
    tables: &[&CanonicalTable],
) -> Result<String, PrivacyV1SourceValidationError> {
    let mut hasher = Sha256::new();
    hasher.put(domain);
    put_u64(&mut hasher, usize_to_u64(tables.len())?);
    for table in tables {
        hasher.put(&[0x10]);
        put_field(&mut hasher, 0x11, table.definition.name.as_bytes())?;
        put_u64(&mut hasher, usize_to_u64(table.primary_key_columns.len())?);
        for column_index in &table.primary_key_columns {
            let column = &table.columns[*column_index];
            hasher.put(&[0x13]);
            put_u64(&mut hasher, column.primary_key_ordinal);
            put_field(&mut hasher, 0x14, column.name.as_bytes())?;
        }
        put_u64(&mut hasher, usize_to_u64(table.rows.len())?);
        for row in &table.rows {
            hasher.put(&[0x20]);
            put_u64(&mut hasher, usize_to_u64(row.sort_key.len())?);
            hasher.put(&row.sort_key);
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn put_logical_table_section(
    sink: &mut impl CanonicalSink,
    definition: &LogicalTableDefinition,
    columns: &[LogicalColumnMetadata],
    rows: &[CanonicalRow],
) -> Result<(), PrivacyV1SourceValidationError> {
    sink.put(&[0x10]);
    put_field(sink, 0x11, definition.name.as_bytes())?;
    put_field(sink, 0x12, definition.create_table_sql.as_bytes())?;
    put_u64(sink, usize_to_u64(columns.len())?);
    for column in columns {
        put_logical_column_metadata(sink, column)?;
    }
    put_u64(sink, usize_to_u64(rows.len())?);
    for row in rows {
        sink.put(&row.encoded);
    }
    Ok(())
}

fn privacy_v1_logical_table_definitions(
) -> Result<Vec<LogicalTableDefinition>, PrivacyV1SourceValidationError> {
    let mut definitions = expected_schema_objects()?
        .into_iter()
        .filter(|object| object.object_type == "table")
        .map(|object| LogicalTableDefinition {
            name: object.name,
            create_table_sql: object.sql,
        })
        .collect::<Vec<_>>();
    definitions.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
    if definitions.len() != 5
        || definitions
            .windows(2)
            .any(|pair| pair[0].name.as_bytes() >= pair[1].name.as_bytes())
        || definitions.iter().any(|definition| {
            definition.create_table_sql != normalize_sql(&definition.create_table_sql)
        })
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    Ok(definitions)
}

fn logical_table_columns(
    connection: &Connection,
    table_name: &str,
) -> Result<Vec<LogicalColumnMetadata>, PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT cid,name,type,\"notnull\",dflt_value,pk,hidden
             FROM pragma_table_xinfo(?1)
             ORDER BY cid",
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let columns = statement
        .query_map([table_name], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    if columns.is_empty() {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    let mut output = Vec::with_capacity(columns.len());
    for (expected_cid, (cid, name, declared_type, not_null, default_sql, pk, hidden)) in
        columns.into_iter().enumerate()
    {
        if cid < 0
            || usize_to_u64(expected_cid)? != cid as u64
            || name.is_empty()
            || !matches!(not_null, 0 | 1)
            || pk < 0
            || hidden < 0
        {
            return Err(PrivacyV1SourceValidationError::SchemaMismatch);
        }
        output.push(LogicalColumnMetadata {
            cid: cid as u64,
            name,
            declared_type,
            not_null: not_null == 1,
            default_sql,
            primary_key_ordinal: pk as u64,
            hidden: hidden as u64,
        });
    }
    let mut primary_key_ordinals = output
        .iter()
        .filter_map(|column| (column.primary_key_ordinal > 0).then_some(column.primary_key_ordinal))
        .collect::<Vec<_>>();
    primary_key_ordinals.sort_unstable();
    if primary_key_ordinals
        .iter()
        .enumerate()
        .any(|(index, ordinal)| *ordinal != (index as u64) + 1)
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    Ok(output)
}

fn logical_table_rows(
    connection: &Connection,
    table_name: &str,
    columns: &[LogicalColumnMetadata],
    exclusion: Option<CanonicalTextRowExclusion<'_>>,
) -> Result<Vec<CanonicalRow>, PrivacyV1SourceValidationError> {
    let quoted_columns = columns
        .iter()
        .map(|column| quote_identifier(&column.name))
        .collect::<Vec<_>>()
        .join(",");
    let (sql, expected_row_count) = if let Some(exclusion) = exclusion {
        if exclusion.table_name != table_name {
            return Err(PrivacyV1SourceValidationError::SchemaMismatch);
        }
        let total_rows = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {}", quote_identifier(table_name)),
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        let matching_rows = connection
            .query_row(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE {}=?1",
                    quote_identifier(table_name),
                    quote_identifier(exclusion.column_name)
                ),
                [exclusion.value],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| PrivacyV1SourceValidationError::Database)?;
        if matching_rows != 1 || total_rows < 1 {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        }
        (
            format!(
                "SELECT {quoted_columns} FROM {} WHERE {}<>?1",
                quote_identifier(table_name),
                quote_identifier(exclusion.column_name)
            ),
            usize::try_from(total_rows - 1)
                .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?,
        )
    } else {
        (
            format!(
                "SELECT {quoted_columns} FROM {}",
                quote_identifier(table_name)
            ),
            usize::MAX,
        )
    };
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    if statement.column_count() != columns.len() {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    let mut query = if let Some(exclusion) = exclusion {
        statement
            .query([exclusion.value])
            .map_err(|_| PrivacyV1SourceValidationError::Database)?
    } else {
        statement
            .query([])
            .map_err(|_| PrivacyV1SourceValidationError::Database)?
    };
    let mut rows = Vec::new();
    while let Some(row) = query
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
    {
        let mut values = Vec::with_capacity(columns.len());
        for index in 0..columns.len() {
            let value = row
                .get_ref(index)
                .map_err(|_| PrivacyV1SourceValidationError::Database)?;
            values.push(encode_sqlite_value(value)?);
        }

        let mut encoded = Vec::new();
        encoded.put(&[0x20]);
        put_u64(&mut encoded, usize_to_u64(columns.len())?);
        for value in &values {
            encoded.put(value);
        }

        let mut primary_key_columns = columns
            .iter()
            .enumerate()
            .filter(|(_, column)| column.primary_key_ordinal > 0)
            .collect::<Vec<_>>();
        primary_key_columns.sort_by_key(|(_, column)| column.primary_key_ordinal);
        let mut sort_key = Vec::new();
        if primary_key_columns.is_empty() {
            for value in &values {
                sort_key.put(value);
            }
        } else {
            for (index, _) in primary_key_columns {
                sort_key.put(&values[index]);
            }
        }
        for value in &mut values {
            value.zeroize();
        }
        rows.push(CanonicalRow { sort_key, encoded });
    }
    if exclusion.is_some() && rows.len() != expected_row_count {
        return Err(PrivacyV1SourceValidationError::SourceDrift);
    }
    Ok(rows)
}

fn put_logical_column_metadata(
    sink: &mut impl CanonicalSink,
    column: &LogicalColumnMetadata,
) -> Result<(), PrivacyV1SourceValidationError> {
    sink.put(&[0x13]);
    put_u64(sink, column.cid);
    put_field(sink, 0x14, column.name.as_bytes())?;
    put_field(sink, 0x15, column.declared_type.as_bytes())?;
    sink.put(&[u8::from(column.not_null)]);
    sink.put(&[u8::from(column.default_sql.is_some())]);
    if let Some(default_sql) = &column.default_sql {
        put_field(sink, 0x16, default_sql.as_bytes())?;
    }
    put_u64(sink, column.primary_key_ordinal);
    put_u64(sink, column.hidden);
    Ok(())
}

fn encode_sqlite_value(
    value: rusqlite::types::ValueRef<'_>,
) -> Result<Vec<u8>, PrivacyV1SourceValidationError> {
    let mut encoded = Vec::new();
    match value {
        rusqlite::types::ValueRef::Null => encoded.put(&[0x00]),
        rusqlite::types::ValueRef::Integer(value) => {
            encoded.put(&[0x01]);
            encoded.put(&value.to_be_bytes());
        }
        rusqlite::types::ValueRef::Real(value) => {
            encoded.put(&[0x02]);
            encoded.put(&value.to_bits().to_be_bytes());
        }
        rusqlite::types::ValueRef::Text(value) => {
            encoded.put(&[0x03]);
            put_u64(&mut encoded, usize_to_u64(value.len())?);
            encoded.put(value);
        }
        rusqlite::types::ValueRef::Blob(value) => {
            encoded.put(&[0x04]);
            put_u64(&mut encoded, usize_to_u64(value.len())?);
            encoded.put(value);
        }
    }
    Ok(encoded)
}

fn put_field(
    sink: &mut impl CanonicalSink,
    tag: u8,
    value: &[u8],
) -> Result<(), PrivacyV1SourceValidationError> {
    sink.put(&[tag]);
    put_u64(sink, usize_to_u64(value.len())?);
    sink.put(value);
    Ok(())
}

fn put_u64(sink: &mut impl CanonicalSink, value: u64) {
    sink.put(&value.to_be_bytes());
}

fn usize_to_u64(value: usize) -> Result<u64, PrivacyV1SourceValidationError> {
    u64::try_from(value).map_err(|_| PrivacyV1SourceValidationError::Database)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchemaObject {
    pub(crate) object_type: String,
    pub(crate) name: String,
    pub(crate) table_name: String,
    pub(crate) sql: String,
}

fn expected_schema_objects() -> Result<Vec<SchemaObject>, PrivacyV1SourceValidationError> {
    if sha256_hex(PRIVACY_V1_SCHEMA_MANIFEST_JSONL.as_bytes())
        != PRIVACY_V1_SCHEMA_PROVENANCE.normalized_sqlite_master_sha256
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    let objects = PRIVACY_V1_SCHEMA_MANIFEST_JSONL
        .lines()
        .map(|line| {
            serde_json::from_str::<SchemaObject>(line)
                .map_err(|_| PrivacyV1SourceValidationError::SchemaMismatch)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let table_count = objects
        .iter()
        .filter(|object| object.object_type == "table")
        .count();
    let index_count = objects
        .iter()
        .filter(|object| object.object_type == "index")
        .count();
    let trigger_count = objects
        .iter()
        .filter(|object| object.object_type == "trigger")
        .count();
    if objects.len() != PRIVACY_V1_SCHEMA_OBJECT_COUNT
        || table_count != 5
        || index_count != 4
        || trigger_count != 2
        || table_count + index_count + trigger_count != objects.len()
        || objects.windows(2).any(|pair| {
            (&pair[0].object_type, &pair[0].name) >= (&pair[1].object_type, &pair[1].name)
        })
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    Ok(objects)
}

fn expected_internal_schema_objects() -> Result<Vec<SchemaObject>, PrivacyV1SourceValidationError> {
    let objects = PRIVACY_V1_INTERNAL_AUTO_INDEX_ALLOWLIST
        .iter()
        .map(|(name, table_name)| SchemaObject {
            object_type: "index".to_owned(),
            name: (*name).to_owned(),
            table_name: (*table_name).to_owned(),
            sql: String::new(),
        })
        .collect::<Vec<_>>();
    if objects.len() != PRIVACY_V1_INTERNAL_SCHEMA_OBJECT_COUNT
        || objects.windows(2).any(|pair| {
            (&pair[0].object_type, &pair[0].name) >= (&pair[1].object_type, &pair[1].name)
        })
        || canonical_schema_manifest_sha256(&objects)? != PRIVACY_V1_INTERNAL_SCHEMA_MANIFEST_SHA256
    {
        return Err(PrivacyV1SourceValidationError::SchemaMismatch);
    }
    Ok(objects)
}

fn canonical_schema_manifest_sha256(
    objects: &[SchemaObject],
) -> Result<String, PrivacyV1SourceValidationError> {
    let mut encoded = Vec::new();
    for object in objects {
        serde_json::to_writer(&mut encoded, object)
            .map_err(|_| PrivacyV1SourceValidationError::SchemaMismatch)?;
        encoded.push(b'\n');
    }
    Ok(sha256_hex(&encoded))
}

pub(crate) fn schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObject>, PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,tbl_name,COALESCE(sql,'')
             FROM sqlite_master
             WHERE type IN ('table','index','trigger','view')
               AND name NOT LIKE 'sqlite_%'
             ORDER BY type,name",
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let objects = statement
        .query_map([], |row| {
            let sql = row.get::<_, String>(3)?;
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: normalize_sql(&sql),
            })
        })
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    Ok(objects)
}

pub(crate) fn internal_schema_objects(
    connection: &Connection,
) -> Result<Vec<SchemaObject>, PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT type,name,tbl_name,COALESCE(sql,'')
             FROM sqlite_master
             WHERE type IN ('table','index','trigger','view')
               AND name LIKE 'sqlite_%'
             ORDER BY type,name",
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let objects = statement
        .query_map([], |row| {
            let sql = row.get::<_, String>(3)?;
            Ok(SchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: normalize_sql(&sql),
            })
        })
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    Ok(objects)
}

fn normalize_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn validate_schema_version(connection: &Connection) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare("SELECT key,value FROM privacy_schema_metadata ORDER BY key")
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    if rows != [("schema_version".to_owned(), "1".to_owned())] {
        return Err(PrivacyV1SourceValidationError::SchemaVersionMismatch);
    }
    Ok(())
}

pub(crate) fn validate_quick_check(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare("PRAGMA quick_check")
        .map_err(|_| PrivacyV1SourceValidationError::IntegrityCheckFailed)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::IntegrityCheckFailed)?;
    let first = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::IntegrityCheckFailed)?
        .ok_or(PrivacyV1SourceValidationError::IntegrityCheckFailed)?
        .get::<_, String>(0)
        .map_err(|_| PrivacyV1SourceValidationError::IntegrityCheckFailed)?;
    let has_more = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::IntegrityCheckFailed)?
        .is_some();
    if first != "ok" || has_more {
        return Err(PrivacyV1SourceValidationError::IntegrityCheckFailed);
    }
    Ok(())
}

pub(crate) fn validate_foreign_keys(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| PrivacyV1SourceValidationError::ForeignKeyViolation)?;
    if statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::ForeignKeyViolation)?
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::ForeignKeyViolation)?
        .is_some()
    {
        return Err(PrivacyV1SourceValidationError::ForeignKeyViolation);
    }
    Ok(())
}

fn validate_privacy_v1_data_boundaries(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    validate_material_boundaries(connection)?;
    validate_redaction_boundaries(connection)?;
    validate_receipt_boundaries(connection)?;
    validate_egress_audit_boundaries(connection)
}

fn validate_material_boundaries(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT material_id,project_id,attachment_id,source_sha256,
                    source_name_sha256,media_type,page_count,state,created_at,updated_at
             FROM privacy_materials",
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    while let Some(row) = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
    {
        let material_id = row
            .get::<_, String>(0)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let project_id = row
            .get::<_, Option<String>>(1)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let attachment_id = row
            .get::<_, Option<String>>(2)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let source_sha256 = row
            .get::<_, String>(3)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let source_name_sha256 = row
            .get::<_, String>(4)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let media_type = row
            .get::<_, String>(5)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let page_count = row
            .get::<_, Option<i64>>(6)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let state = row
            .get::<_, String>(7)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let created_at = row
            .get::<_, String>(8)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let updated_at = row
            .get::<_, String>(9)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        if !valid_legacy_id(&material_id)
            || !valid_optional_legacy_id(project_id.as_deref())
            || !valid_optional_legacy_id(attachment_id.as_deref())
            || !valid_legacy_sha256(&source_sha256)
            || !valid_legacy_sha256(&source_name_sha256)
            || !valid_legacy_id(&media_type)
            || !page_count
                .map(|value| (0..=10_000).contains(&value))
                .unwrap_or(true)
            || !matches!(
                state.as_str(),
                "registered"
                    | "assessing"
                    | "extracting_native"
                    | "ocr_required"
                    | "ocr_running"
                    | "extracted"
                    | "redacting"
                    | "review_required"
                    | "approved"
                    | "outbound_ready"
                    | "failed"
                    | "blocked"
                    | "stale"
                    | "revoked"
            )
            || !valid_legacy_timestamp(&created_at)
            || !valid_legacy_timestamp(&updated_at)
        {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        }
    }
    Ok(())
}

fn validate_redaction_boundaries(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT redaction_id,material_id,extraction_sha256,redacted_content_sha256,
                    approved_payload_sha256,policy_id,policy_version,detector_version,
                    unresolved_high_risk_count,review_state,protection_scheme,
                    reviewed_by_sha256,created_at,reviewed_at
             FROM privacy_redactions",
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    while let Some(row) = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
    {
        let redaction_id = row
            .get::<_, String>(0)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let material_id = row
            .get::<_, String>(1)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let extraction_sha256 = row
            .get::<_, String>(2)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let redacted_content_sha256 = row
            .get::<_, String>(3)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let approved_payload_sha256 = row
            .get::<_, Option<String>>(4)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let policy_id = row
            .get::<_, String>(5)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let policy_version = row
            .get::<_, i64>(6)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let detector_version = row
            .get::<_, String>(7)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let unresolved_high_risk_count = row
            .get::<_, i64>(8)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let review_state = row
            .get::<_, String>(9)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let protection_scheme = row
            .get::<_, String>(10)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let reviewed_by_sha256 = row
            .get::<_, Option<String>>(11)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let created_at = row
            .get::<_, String>(12)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let reviewed_at = row
            .get::<_, Option<String>>(13)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        if !valid_legacy_id(&redaction_id)
            || !valid_legacy_id(&material_id)
            || !valid_legacy_sha256(&extraction_sha256)
            || !valid_legacy_sha256(&redacted_content_sha256)
            || !valid_optional_legacy_sha256(approved_payload_sha256.as_deref())
            || !valid_legacy_id(&policy_id)
            || !valid_positive_legacy_u32(policy_version)
            || !valid_legacy_id(&detector_version)
            || !valid_nonnegative_legacy_u32(unresolved_high_risk_count)
            || !matches!(
                review_state.as_str(),
                "review_required" | "approved" | "revoked" | "stale"
            )
            || protection_scheme != LOCAL_PROTECTION_SCHEME
            || !valid_optional_legacy_sha256(reviewed_by_sha256.as_deref())
            || !valid_legacy_timestamp(&created_at)
            || !reviewed_at
                .as_deref()
                .map(valid_legacy_timestamp)
                .unwrap_or(true)
        {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        }
    }
    Ok(())
}

fn validate_receipt_boundaries(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT receipt_id,redaction_id,destination_kind,destination_identifier_sha256,
                    purpose,payload_sha256,policy_id,policy_version,issued_at_unix,
                    expires_at_unix,revoked_at_unix,created_at
             FROM privacy_receipts",
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    while let Some(row) = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
    {
        let receipt_id = row
            .get::<_, String>(0)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let redaction_id = row
            .get::<_, String>(1)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let destination_kind = row
            .get::<_, String>(2)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let destination_identifier_sha256 = row
            .get::<_, String>(3)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let purpose = row
            .get::<_, String>(4)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let payload_sha256 = row
            .get::<_, String>(5)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let policy_id = row
            .get::<_, String>(6)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let policy_version = row
            .get::<_, i64>(7)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let issued_at = row
            .get::<_, i64>(8)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let expires_at = row
            .get::<_, Option<i64>>(9)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let revoked_at = row
            .get::<_, Option<i64>>(10)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let created_at = row
            .get::<_, String>(11)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        if !valid_legacy_id(&receipt_id)
            || !valid_legacy_id(&redaction_id)
            || !matches!(
                destination_kind.as_str(),
                "external_provider" | "external_mcp_host" | "verified_local_provider"
            )
            || !valid_legacy_sha256(&destination_identifier_sha256)
            || !valid_legacy_id(&purpose)
            || !valid_legacy_sha256(&payload_sha256)
            || !valid_legacy_id(&policy_id)
            || !valid_positive_legacy_u32(policy_version)
            || issued_at <= 0
            || !expires_at
                .and_then(|value| value.checked_sub(issued_at))
                .map(|ttl| (1..=PRIVACY_V1_MAX_ACTIVE_RECEIPT_TTL_SECONDS).contains(&ttl))
                .unwrap_or(false)
            || !revoked_at.map(|value| value > 0).unwrap_or(true)
            || !valid_legacy_timestamp(&created_at)
        {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        }
    }
    Ok(())
}

fn validate_egress_audit_boundaries(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT event_id,occurred_at_unix,classification,destination_kind,
                    destination_identifier_sha256,purpose,payload_sha256,payload_bytes,
                    policy_id,policy_version,detector_version,receipt_id,
                    residual_counts_json,allowed,reason_code,previous_event_hash,event_hash,
                    created_at
             FROM privacy_egress_audit ORDER BY rowid",
        )
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::Database)?;
    let mut expected_previous = String::new();
    while let Some(row) = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::Database)?
    {
        let event_id = row
            .get::<_, String>(0)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let occurred_at = row
            .get::<_, i64>(1)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let classification = row
            .get::<_, String>(2)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let destination_kind = row
            .get::<_, String>(3)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let destination_identifier_sha256 = row
            .get::<_, String>(4)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let purpose = row
            .get::<_, String>(5)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let payload_sha256 = row
            .get::<_, String>(6)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let payload_bytes = row
            .get::<_, i64>(7)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let policy_id = row
            .get::<_, String>(8)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let policy_version = row
            .get::<_, i64>(9)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let detector_version = row
            .get::<_, String>(10)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let receipt_id = row
            .get::<_, Option<String>>(11)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let residual_counts_json = row
            .get::<_, String>(12)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let allowed = row
            .get::<_, i64>(13)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let reason_code = row
            .get::<_, String>(14)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let previous_event_hash = row
            .get::<_, String>(15)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let event_hash = row
            .get::<_, String>(16)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let created_at = row
            .get::<_, String>(17)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;

        let Some(classification) = legacy_classification(&classification) else {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        };
        let Some(destination_kind) = legacy_destination_kind(&destination_kind) else {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        };
        let residual_counts =
            serde_json::from_str::<BTreeMap<String, usize>>(&residual_counts_json)
                .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let canonical_residual_counts = serde_json::to_string(&residual_counts)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let occurred_at =
            u64::try_from(occurred_at).map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let payload_bytes = usize::try_from(payload_bytes)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let policy_version = u32::try_from(policy_version)
            .map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        if !valid_legacy_id(&event_id)
            || occurred_at == 0
            || !valid_legacy_sha256(&destination_identifier_sha256)
            || !valid_legacy_id(&purpose)
            || !valid_legacy_sha256(&payload_sha256)
            || !valid_legacy_id(&policy_id)
            || policy_version == 0
            || !valid_legacy_id(&detector_version)
            || !valid_optional_legacy_id(receipt_id.as_deref())
            || residual_counts_json != canonical_residual_counts
            || residual_counts_json.len() > 65_536
            || residual_counts.keys().any(|key| !valid_legacy_id(key))
            || !matches!(allowed, 0 | 1)
            || !valid_legacy_id(&reason_code)
            || previous_event_hash != expected_previous
            || (!previous_event_hash.is_empty() && !valid_legacy_sha256(&previous_event_hash))
            || !valid_legacy_sha256(&event_hash)
            || !valid_legacy_timestamp(&created_at)
        {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        }

        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: occurred_at,
            classification,
            destination_kind,
            destination_identifier_sha256,
            purpose,
            payload_sha256,
            payload_bytes,
            policy_id,
            policy_version,
            detector_version,
            receipt_id,
            residual_counts,
            allowed: allowed == 1,
            reason_code,
        };
        let canonical =
            serde_json::to_vec(&audit).map_err(|_| PrivacyV1SourceValidationError::DataBoundary)?;
        let mut chain =
            Vec::with_capacity(event_id.len() + expected_previous.len() + canonical.len() + 2);
        chain.extend_from_slice(event_id.as_bytes());
        chain.push(0);
        chain.extend_from_slice(expected_previous.as_bytes());
        chain.push(0);
        chain.extend_from_slice(&canonical);
        let expected_event_hash = sha256_hex(&chain);
        chain.zeroize();
        if event_hash != expected_event_hash {
            return Err(PrivacyV1SourceValidationError::DataBoundary);
        }
        expected_previous = event_hash;
    }
    Ok(())
}

fn valid_legacy_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn valid_optional_legacy_id(value: Option<&str>) -> bool {
    value.map(valid_legacy_id).unwrap_or(true)
}

fn valid_legacy_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_optional_legacy_sha256(value: Option<&str>) -> bool {
    value.map(valid_legacy_sha256).unwrap_or(true)
}

fn valid_positive_legacy_u32(value: i64) -> bool {
    u32::try_from(value).is_ok_and(|value| value > 0)
}

fn valid_nonnegative_legacy_u32(value: i64) -> bool {
    u32::try_from(value).is_ok()
}

fn valid_legacy_timestamp(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn legacy_classification(value: &str) -> Option<DataClassification> {
    match value {
        "legal_public" => Some(DataClassification::LegalPublic),
        "product_public" => Some(DataClassification::ProductPublic),
        "case_raw" => Some(DataClassification::CaseRaw),
        "case_redacted_pending" => Some(DataClassification::CaseRedactedPending),
        "case_redacted_approved" => Some(DataClassification::CaseRedactedApproved),
        "secret" => Some(DataClassification::Secret),
        _ => None,
    }
}

fn legacy_destination_kind(value: &str) -> Option<DestinationKind> {
    match value {
        "external_provider" => Some(DestinationKind::ExternalProvider),
        "external_mcp_host" => Some(DestinationKind::ExternalMcpHost),
        "verified_local_provider" => Some(DestinationKind::VerifiedLocalProvider),
        _ => None,
    }
}

fn validate_protected_review_payloads(
    connection: &Connection,
) -> Result<u64, PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare(
            "SELECT protection_scheme,protected_review_blob
             FROM privacy_redactions
             ORDER BY redaction_id",
        )
        .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
    let mut count = 0_u64;
    while let Some(row) = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?
    {
        let scheme = row
            .get::<_, String>(0)
            .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
        let protected = row
            .get::<_, Vec<u8>>(1)
            .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
        let protected = Zeroizing::new(protected);
        if scheme != LOCAL_PROTECTION_SCHEME {
            return Err(PrivacyV1SourceValidationError::ProtectedReviewPayload);
        }
        let plaintext = unprotect_local(&protected)
            .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
        let _plaintext = Zeroizing::new(plaintext);
        count = count
            .checked_add(1)
            .ok_or(PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
    }
    Ok(count)
}

fn validate_protected_receipt_tokens(
    connection: &Connection,
) -> Result<(), PrivacyV1SourceValidationError> {
    let mut statement = connection
        .prepare("SELECT signed_token FROM privacy_receipts ORDER BY receipt_id")
        .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
    let mut rows = statement
        .query([])
        .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
    while let Some(row) = rows
        .next()
        .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?
    {
        let protected = row
            .get::<_, Vec<u8>>(0)
            .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
        let protected = Zeroizing::new(protected);
        if protected.is_empty() || protected.len() > 65_536 {
            return Err(PrivacyV1SourceValidationError::ProtectedReviewPayload);
        }
        let plaintext = unprotect_local(&protected)
            .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
        let plaintext = Zeroizing::new(plaintext);
        let token = std::str::from_utf8(&plaintext)
            .map_err(|_| PrivacyV1SourceValidationError::ProtectedReviewPayload)?;
        if token.len() > 32_768 || !token.starts_with("rct_v1.") {
            return Err(PrivacyV1SourceValidationError::ProtectedReviewPayload);
        }
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        protect_local, sha256_hex, PrivacyStore, PrivacyStoreError, PrivacyStoreSchemaStatus,
    };
    use rusqlite::{params, ErrorCode};
    use std::{cell::Cell, fs, fs::OpenOptions, path::PathBuf};
    use tempfile::TempDir;

    struct Fixture {
        _directory: TempDir,
        path: PathBuf,
    }

    fn fixture_with_ddl(ddl: &str) -> Fixture {
        let directory = tempfile::tempdir().expect("fixture directory");
        let path = directory.path().join("privacy-workflow.sqlite");
        let connection = Connection::open(&path).expect("fixture database");
        connection.execute_batch(ddl).expect("manifest DDL");
        connection
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value)
                 VALUES('schema_version','1')",
                [],
            )
            .expect("schema version");
        connection
            .execute(
                "UPDATE privacy_schema_metadata
                 SET updated_at='2026-07-19 15:41:29'
                 WHERE key='schema_version'",
                [],
            )
            .expect("fixed metadata timestamp");
        drop(connection);
        Fixture {
            _directory: directory,
            path,
        }
    }

    fn exact_fixture() -> Fixture {
        fixture_with_ddl(PRIVACY_V1_SCHEMA_MANIFEST_DDL)
    }

    fn exact_v1_memory_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("in-memory v1 fixture opens");
        connection
            .execute_batch(PRIVACY_V1_SCHEMA_MANIFEST_DDL)
            .expect("exact v1 schema initializes");
        connection
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value,updated_at)
                 VALUES('schema_version','1','2026-07-19 15:41:29')",
                [],
            )
            .expect("v1 schema version inserts");
        connection
    }

    fn serialized_exact_v1_image() -> Vec<u8> {
        let connection = exact_v1_memory_connection();
        connection
            .serialize(rusqlite::MAIN_DB)
            .expect("exact v1 fixture serializes")
            .to_vec()
    }

    fn insert_material(connection: &Connection, material_id: &str) {
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,attachment_id,source_sha256,
                    source_name_sha256,media_type,page_count,state
                 ) VALUES(?1,NULL,NULL,?2,?3,'application/pdf',1,'review_required')",
                params![
                    material_id,
                    sha256_hex(b"synthetic-source"),
                    sha256_hex(b"synthetic-name"),
                ],
            )
            .expect("material");
    }

    fn insert_stable_material(
        connection: &Connection,
        material_id: &str,
        project_id: &str,
        source_label: &str,
        media_type: &str,
    ) {
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,attachment_id,source_sha256,
                    source_name_sha256,media_type,page_count,state,
                    created_at,updated_at
                 ) VALUES(
                    ?1,?2,NULL,?3,?4,?5,2,'review_required',
                    '2026-07-19 15:41:29','2026-07-19 15:41:29'
                 )",
                params![
                    material_id,
                    project_id,
                    sha256_hex(format!("source:{source_label}").as_bytes()),
                    sha256_hex(format!("name:{source_label}").as_bytes()),
                    media_type,
                ],
            )
            .expect("stable material");
    }

    fn insert_review_blob(connection: &Connection, material_id: &str, protected: &[u8]) {
        connection
            .execute(
                "INSERT INTO privacy_redactions(
                    redaction_id,material_id,extraction_sha256,
                    redacted_content_sha256,approved_payload_sha256,policy_id,
                    policy_version,detector_version,unresolved_high_risk_count,
                    review_state,protected_review_blob,protection_scheme,
                    reviewed_by_sha256
                 ) VALUES(
                    'synthetic-redaction',?1,?2,?3,NULL,'synthetic-policy',1,
                    'synthetic-detector',0,'review_required',?4,?5,NULL
                 )",
                params![
                    material_id,
                    sha256_hex(b"synthetic-extraction"),
                    sha256_hex(b"synthetic-redacted"),
                    protected,
                    LOCAL_PROTECTION_SCHEME,
                ],
            )
            .expect("redaction");
    }

    fn open_wal_writer_with_uncheckpointed_metadata(fixture: &Fixture) -> Connection {
        let connection = Connection::open(&fixture.path).expect("WAL source connection");
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("enable WAL");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        connection
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("disable automatic checkpoint");
        connection
            .execute(
                "UPDATE privacy_schema_metadata
                 SET updated_at='2026-07-19 15:41:30'
                 WHERE key='schema_version'",
                [],
            )
            .expect("leave a committed WAL frame");
        assert!(sqlite_sidecar_path(&fixture.path, "-wal")
            .expect("WAL path")
            .exists());
        assert!(sqlite_sidecar_path(&fixture.path, "-shm")
            .expect("SHM path")
            .exists());
        connection
    }

    #[allow(unsafe_code)]
    fn enable_persistent_wal_and_shm(fixture: &Fixture) {
        let connection = Connection::open(&fixture.path).expect("persistent WAL connection");
        let mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("enable persistent WAL");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        let mut persist = 1_i32;
        let status = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&mut persist as *mut i32).cast(),
            )
        };
        assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        connection
            .execute(
                "UPDATE privacy_schema_metadata
                 SET updated_at='2026-07-19 15:41:30'
                 WHERE key='schema_version'",
                [],
            )
            .expect("write persistent WAL frame");
        drop(connection);
        assert!(sqlite_sidecar_path(&fixture.path, "-wal")
            .expect("persistent WAL path")
            .exists());
        assert!(sqlite_sidecar_path(&fixture.path, "-shm")
            .expect("persistent SHM path")
            .exists());
    }

    fn insert_egress_event(connection: &Connection, valid_event_hash: bool) {
        let event_id = "synthetic-egress-event";
        let residual_counts = BTreeMap::from([("person_name".to_owned(), 0_usize)]);
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: 1_784_475_689,
            classification: DataClassification::LegalPublic,
            destination_kind: DestinationKind::ExternalProvider,
            destination_identifier_sha256: sha256_hex(b"synthetic-destination"),
            purpose: "synthetic-purpose".to_owned(),
            payload_sha256: sha256_hex(b"synthetic-payload"),
            payload_bytes: 17,
            policy_id: "synthetic-policy".to_owned(),
            policy_version: 1,
            detector_version: "synthetic-detector".to_owned(),
            receipt_id: None,
            residual_counts,
            allowed: true,
            reason_code: "allowed".to_owned(),
        };
        let canonical = serde_json::to_vec(&audit).expect("canonical audit JSON");
        let mut chain = Vec::new();
        chain.extend_from_slice(event_id.as_bytes());
        chain.push(0);
        chain.push(0);
        chain.extend_from_slice(&canonical);
        let event_hash = if valid_event_hash {
            sha256_hex(&chain)
        } else {
            "0".repeat(64)
        };
        let residual_counts_json =
            serde_json::to_string(&audit.residual_counts).expect("residual JSON");
        let occurred_at_unix = i64::try_from(audit.occurred_at_unix).expect("occurred timestamp");
        let payload_bytes = i64::try_from(audit.payload_bytes).expect("payload bytes");
        let policy_version = i64::from(audit.policy_version);
        connection
            .execute(
                "INSERT INTO privacy_egress_audit(
                    event_id,occurred_at_unix,classification,destination_kind,
                    destination_identifier_sha256,purpose,payload_sha256,payload_bytes,
                    policy_id,policy_version,detector_version,receipt_id,
                    residual_counts_json,allowed,reason_code,previous_event_hash,event_hash,
                    created_at
                 ) VALUES(
                    ?1,?2,'legal_public','external_provider',?3,?4,?5,?6,
                    ?7,?8,?9,NULL,?10,1,?11,'',?12,'2026-07-19 15:41:29'
                 )",
                params![
                    event_id,
                    occurred_at_unix,
                    audit.destination_identifier_sha256,
                    audit.purpose,
                    audit.payload_sha256,
                    payload_bytes,
                    audit.policy_id,
                    policy_version,
                    audit.detector_version,
                    residual_counts_json,
                    audit.reason_code,
                    event_hash,
                ],
            )
            .expect("egress audit row");
    }

    #[test]
    fn privacy_v1_sqlite_image_validator_reconstructs_complete_read_only_proof() {
        let image = serialized_exact_v1_image();
        let image_before = image.clone();

        let proof = validate_privacy_v1_sqlite_image_read_only(&image)
            .expect("exact Privacy v1 image validates");

        assert_eq!(proof.schema_version, PRIVACY_V1_SCHEMA_VERSION);
        assert_eq!(proof.schema_object_count, PRIVACY_V1_SCHEMA_OBJECT_COUNT);
        assert_eq!(proof.protected_review_payload_count, 0);
        assert_eq!(proof.database_file.length, image.len() as u64);
        assert_eq!(proof.database_file.sha256, sha256_hex(&image));
        assert_eq!(proof.database_file.identity_sha256.len(), 64);
        assert_eq!(proof.database_file.modified_unix_nanos, None);
        assert_eq!((proof.wal, proof.shm, proof.journal), (None, None, None));
        assert_eq!(
            proof.normalized_sqlite_master_sha256,
            PRIVACY_V1_SCHEMA_PROVENANCE.normalized_sqlite_master_sha256
        );
        assert!(!proof.logical_manifest.tables.is_empty());
        assert_eq!(
            image, image_before,
            "validation must not mutate image bytes"
        );
    }

    #[test]
    fn privacy_v1_sqlite_image_validator_rejects_schema_tamper_and_current_schema() {
        let tampered_connection = exact_v1_memory_connection();
        tampered_connection
            .execute_batch("DROP TRIGGER trg_privacy_egress_audit_no_update")
            .expect("v1 trigger drops");
        let tampered = tampered_connection
            .serialize(rusqlite::MAIN_DB)
            .expect("tampered v1 fixture serializes")
            .to_vec();
        assert_eq!(
            validate_privacy_v1_sqlite_image_read_only(&tampered),
            Err(PrivacyV1SourceValidationError::SchemaMismatch)
        );

        let current_connection =
            Connection::open_in_memory().expect("current Privacy fixture opens");
        PrivacyStore::initialize(&current_connection).expect("current Privacy schema initializes");
        let current = current_connection
            .serialize(rusqlite::MAIN_DB)
            .expect("current Privacy fixture serializes")
            .to_vec();
        assert!(validate_privacy_v1_sqlite_image_read_only(&current).is_err());
    }

    #[test]
    fn privacy_v1_sqlite_image_validator_rejects_corruption_and_non_page_bytes() {
        let valid = serialized_exact_v1_image();

        let mut corrupted_header = valid.clone();
        corrupted_header[0] ^= 0xff;
        assert_eq!(
            validate_privacy_v1_sqlite_image_read_only(&corrupted_header),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );

        let mut trailing_byte = valid;
        trailing_byte.push(0);
        assert_eq!(
            validate_privacy_v1_sqlite_image_read_only(&trailing_byte),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );
        assert_eq!(
            validate_privacy_v1_sqlite_image_read_only(&[]),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );
    }

    #[test]
    fn exact_empty_v1_manifest_is_accepted_without_workspace_or_lifecycle() {
        let fixture = exact_fixture();
        let before = fs::read(&fixture.path).expect("source bytes before validation");
        let before_metadata =
            fs::metadata(&fixture.path).expect("source metadata before validation");

        let validation = validate_privacy_v1_migration_source_read_only(&fixture.path)
            .expect("exact v1 validates");

        assert_eq!(validation.schema_version, 1);
        assert_eq!(validation.schema_object_count, 11);
        assert_eq!(validation.protected_review_payload_count, 0);
        assert_eq!(
            validation.normalized_sqlite_master_sha256,
            PRIVACY_V1_SCHEMA_PROVENANCE.normalized_sqlite_master_sha256
        );
        assert_eq!(validation.database_file.sha256, sha256_hex(&before));
        assert_eq!(validation.database_file.length, before.len() as u64);
        assert_eq!(validation.database_file.identity_sha256.len(), 64);
        assert!(validation.database_file.modified_unix_nanos.is_some());
        let internal_file_snapshot = FileSnapshot::capture(&fixture.path).expect("file snapshot");
        assert_eq!(
            validation.database_file,
            privacy_v1_source_file_proof(&internal_file_snapshot)
        );
        assert_ne!(
            validation.database_file.identity_sha256,
            sha256_hex(&internal_file_snapshot.identity),
            "the public identity proof must be domain separated"
        );
        assert_eq!(validation.wal, None);
        assert_eq!(validation.shm, None);
        assert_eq!(validation.journal, None);
        assert_eq!(
            validation.logical_manifest.sha256,
            "eff9ae270672e61677945a9adc268025294800fab1a250944394170d113f452e"
        );
        assert_eq!(validation.logical_manifest.total_row_count, 1);
        let expected_tables = [
            (
                "privacy_egress_audit",
                0,
                "cc4b6595b3bc59ef8e4991c57bc68237c014f557fbb10076c58dcf6a54c19e69",
            ),
            (
                "privacy_materials",
                0,
                "fe27868bf7c211a7683676615b1f0d5b7ff6bfcd46cbeff0f8c283dd81efd6e4",
            ),
            (
                "privacy_receipts",
                0,
                "387578999f7192f711ed64e33e92c62c1fd788c5aba7c4e77c6a36cb5462f1ef",
            ),
            (
                "privacy_redactions",
                0,
                "0b9648e74e81b01f8261127d0d58bdb46ced878eb95cd06afb7b8daf4a57ccfe",
            ),
            (
                "privacy_schema_metadata",
                1,
                "1aaf4625d4fe55b2a1e94bcb03a16ea42b81b6764050cd1bbe9a88384bf3dcd9",
            ),
        ];
        assert_eq!(
            validation.logical_manifest.tables.len(),
            expected_tables.len()
        );
        for (actual, (name, row_count, sha256)) in validation
            .logical_manifest
            .tables
            .iter()
            .zip(expected_tables)
        {
            assert_eq!(actual.table_name, name);
            assert_eq!(actual.row_count, row_count);
            assert_eq!(actual.sha256, sha256);
        }
        assert!(validation
            .logical_manifest
            .tables
            .windows(2)
            .all(|pair| pair[0].table_name.as_bytes() < pair[1].table_name.as_bytes()));
        assert_eq!(validation.business_manifest.total_row_count, 0);
        assert_eq!(
            validation.business_manifest.sha256,
            "f14cad9f63dcac12219ff9466552bd09a78ed11ba381b969455ae2cc6e6c2072"
        );
        assert_eq!(
            validation.business_manifest.primary_key_sha256,
            "42180ea05b9ae00e093adc0e9fd4e25121108a94dac132e2305f1fac1c903c51"
        );
        assert_eq!(
            validation.business_manifest.row_sha256,
            "116e6b91e26daf6a7f4882dd9d6b325948907c91f18fb1a7c5ae582b58b81fba"
        );
        let expected_business_tables = [
            (
                "privacy_egress_audit",
                "8b1aad48658ceaca4c64759c13282ef886919917b22b806f2951b93e6a637221",
                "f73f3184e901027ec85a038871139a0f36fd154b28608104db2ba91974009b53",
                "fe2291c0b88b83a153a0e4360678db92b19ca52191fbdd84c1ab0c5633c17dcb",
            ),
            (
                "privacy_materials",
                "71154e02409f0656460e336fd5004ae8cf9c279e9db6850e7cdfab891479c02b",
                "6d3a280f84851da9a523eea5604d22dc426489fdadc72f057f5c845624d351a3",
                "607193fdc9fab3c3f2de83efdf95ed022c68044090b1743bcbaa54b33aacd084",
            ),
            (
                "privacy_receipts",
                "d4ad6b00ab9d770520339a71f78f4aaa1c43f1d514801a477450040b9d086ac0",
                "d8e3d97bf0cd19a0a67c172ebf686b5a7b2c18a7b55ca12ac96be7dc39561dea",
                "7dbccec1fb773c0cfc3e23ac94149391184c17be0741b8c60e0f72333d897858",
            ),
            (
                "privacy_redactions",
                "1ae0f01738941aa877a0bbd5ef9f5d8d7a81c2085434c0252132528f5a8f0bae",
                "48eb8296d9fbcce5f05c515e303d876eba6b0bb41e8ba8986188ed3a47df3b7f",
                "1118ba78ca22271ac66272a5b480155cfab689c67624ae11ffe896c8550a5206",
            ),
        ];
        assert_eq!(
            validation.business_manifest.tables.len(),
            expected_business_tables.len()
        );
        for (actual, (name, sha256, primary_key_sha256, row_sha256)) in validation
            .business_manifest
            .tables
            .iter()
            .zip(expected_business_tables)
        {
            assert_eq!(actual.table_name, name);
            assert_eq!(actual.row_count, 0);
            assert_eq!(actual.sha256, sha256);
            assert_eq!(actual.primary_key_sha256, primary_key_sha256);
            assert_eq!(actual.row_sha256, row_sha256);
        }
        for digest in [
            &validation.business_manifest.sha256,
            &validation.business_manifest.primary_key_sha256,
            &validation.business_manifest.row_sha256,
        ] {
            assert_eq!(digest.len(), 64);
            assert!(digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        }
        for table in &validation.business_manifest.tables {
            for digest in [&table.sha256, &table.primary_key_sha256, &table.row_sha256] {
                assert_eq!(digest.len(), 64);
                assert!(digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
            }
        }
        assert!(validation.data_version > 0);
        assert_eq!(
            fs::read(&fixture.path).expect("source bytes after validation"),
            before
        );
        let after_metadata = fs::metadata(&fixture.path).expect("source metadata after validation");
        assert_eq!(after_metadata.len(), before_metadata.len());
        assert_eq!(
            after_metadata.modified().expect("after mtime"),
            before_metadata.modified().expect("before mtime")
        );
        assert!(!fixture.path.with_extension("sqlite-wal").exists());
        assert!(!fixture.path.with_extension("sqlite-shm").exists());

        let connection = Connection::open(&fixture.path).expect("inspect exact fixture");
        let forbidden: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE name LIKE '%workspace%' OR name LIKE '%lifecycle%'",
                [],
                |row| row.get(0),
            )
            .expect("forbidden target objects");
        assert_eq!(forbidden, 0);
    }

    #[test]
    fn frozen_manifest_and_provenance_are_exact_text_artifacts() {
        assert_eq!(
            sha256_hex(PRIVACY_V1_SCHEMA_MANIFEST_JSONL.as_bytes()),
            PRIVACY_V1_SCHEMA_PROVENANCE.normalized_sqlite_master_sha256
        );
        let objects = expected_schema_objects().expect("frozen manifest verifies");
        assert_eq!(objects.len(), 11);
        let expected_internal =
            expected_internal_schema_objects().expect("internal allowlist verifies");
        assert_eq!(expected_internal.len(), 6);
        assert_eq!(
            canonical_schema_manifest_sha256(&expected_internal)
                .expect("internal allowlist hashes"),
            PRIVACY_V1_INTERNAL_SCHEMA_MANIFEST_SHA256
        );
        let fixture = exact_fixture();
        let connection = Connection::open(&fixture.path).expect("internal schema fixture");
        assert_eq!(
            internal_schema_objects(&connection).expect("internal schema objects"),
            expected_internal
        );
        drop(connection);
        let provenance =
            serde_json::from_str::<serde_json::Value>(PRIVACY_V1_SCHEMA_PROVENANCE_JSON)
                .expect("provenance JSON");
        assert_eq!(provenance["tagName"], "v0.3.1");
        assert_eq!(provenance["schemaVersion"], 1);
        assert_eq!(provenance["fixture"]["bytes"], 77_824);
        assert_eq!(provenance["fixture"]["pageSize"], 4_096);
        assert_eq!(provenance["fixture"]["pageCount"], 19);
        assert_eq!(provenance["internalManifest"]["objectCount"], 6);
        assert_eq!(
            provenance["internalManifest"]["sha256"],
            PRIVACY_V1_INTERNAL_SCHEMA_MANIFEST_SHA256
        );
        assert_eq!(
            PRIVACY_V1_SCHEMA_PROVENANCE.internal_schema_object_count,
            PRIVACY_V1_INTERNAL_SCHEMA_OBJECT_COUNT
        );
        assert_eq!(
            PRIVACY_V1_SCHEMA_PROVENANCE.internal_schema_manifest_sha256,
            PRIVACY_V1_INTERNAL_SCHEMA_MANIFEST_SHA256
        );
        assert_eq!(
            provenance["logicalManifest"]["logicalDomain"],
            std::str::from_utf8(SQLITE_CANONICAL_LOGICAL_MANIFEST_V1_DOMAIN)
                .expect("logical domain is UTF-8")
        );
        assert_eq!(
            provenance["logicalManifest"]["businessDomain"],
            std::str::from_utf8(SQLITE_CANONICAL_BUSINESS_MANIFEST_V1_DOMAIN)
                .expect("business domain is UTF-8")
        );
        assert_eq!(
            provenance["logicalManifest"]["businessPrimaryKeyDomain"],
            std::str::from_utf8(SQLITE_CANONICAL_BUSINESS_PRIMARY_KEY_MANIFEST_V1_DOMAIN)
                .expect("business primary-key domain is UTF-8")
        );
        assert_eq!(
            provenance["logicalManifest"]["businessRowDomain"],
            std::str::from_utf8(SQLITE_CANONICAL_BUSINESS_ROW_MANIFEST_V1_DOMAIN)
                .expect("business row domain is UTF-8")
        );
        assert_eq!(
            provenance["logicalManifest"]["businessExcludedTables"],
            serde_json::json!(["privacy_schema_metadata"])
        );
        assert_eq!(provenance["sourceShape"]["workspaceIdentityPresent"], false);
        assert_eq!(provenance["sourceShape"]["lifecycleTablesPresent"], false);
    }

    #[test]
    fn analyze_sqlite_stat_objects_are_rejected_by_the_internal_allowlist() {
        let fixture = exact_fixture();
        let connection = Connection::open(&fixture.path).expect("ANALYZE fixture");
        connection
            .execute_batch("ANALYZE")
            .expect("ANALYZE succeeds");
        assert!(connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE name='sqlite_stat1'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .is_ok());
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&fixture.path),
            Err(PrivacyV1SourceValidationError::SchemaMismatch)
        );
    }

    #[test]
    fn adr_sqlite_value_encoding_matches_fixed_vectors() {
        assert_eq!(
            encode_sqlite_value(rusqlite::types::ValueRef::Null).expect("null encoding"),
            [0x00]
        );
        assert_eq!(
            encode_sqlite_value(rusqlite::types::ValueRef::Integer(-2)).expect("integer encoding"),
            [0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe]
        );
        assert_eq!(
            encode_sqlite_value(rusqlite::types::ValueRef::Real(-0.0)).expect("real encoding"),
            [0x02, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_sqlite_value(rusqlite::types::ValueRef::Text("é".as_bytes()))
                .expect("text encoding"),
            [0x03, 0, 0, 0, 0, 0, 0, 0, 2, 0xc3, 0xa9]
        );
        assert_eq!(
            encode_sqlite_value(rusqlite::types::ValueRef::Blob(&[0x00, 0xff, 0x7f]))
                .expect("blob encoding"),
            [0x04, 0, 0, 0, 0, 0, 0, 0, 3, 0x00, 0xff, 0x7f]
        );
    }

    #[test]
    fn table_section_has_fixed_vector_and_every_metadata_field_is_sensitive() {
        let definition = LogicalTableDefinition {
            name: "t".to_owned(),
            create_table_sql: "CREATE TABLE t(a TEXT)".to_owned(),
        };
        let column = LogicalColumnMetadata {
            cid: 0,
            name: "a".to_owned(),
            declared_type: "TEXT".to_owned(),
            not_null: false,
            default_sql: Some("NULL".to_owned()),
            primary_key_ordinal: 1,
            hidden: 0,
        };
        let encode = |definition: &LogicalTableDefinition, column: &LogicalColumnMetadata| {
            let mut bytes = Vec::new();
            put_logical_table_section(&mut bytes, definition, std::slice::from_ref(column), &[])
                .expect("table section encoding");
            bytes
        };
        let baseline = encode(&definition, &column);
        assert_eq!(baseline.len(), 121);
        assert_eq!(
            sha256_hex(&baseline),
            "a19e96d2dd53bf07b1fcf350d493a6042300e79bd270520e51d0c34d7040d980"
        );

        let mut variants = Vec::new();
        let mut changed = column.clone();
        changed.cid = 1;
        variants.push(changed);
        let mut changed = column.clone();
        changed.name = "b".to_owned();
        variants.push(changed);
        let mut changed = column.clone();
        changed.declared_type = "BLOB".to_owned();
        variants.push(changed);
        let mut changed = column.clone();
        changed.not_null = true;
        variants.push(changed);
        let mut changed = column.clone();
        changed.default_sql = None;
        variants.push(changed);
        let mut changed = column.clone();
        changed.default_sql = Some("(NULL)".to_owned());
        variants.push(changed);
        let mut changed = column.clone();
        changed.primary_key_ordinal = 0;
        variants.push(changed);
        let mut changed = column.clone();
        changed.hidden = 2;
        variants.push(changed);
        for changed in variants {
            assert_ne!(
                sha256_hex(&encode(&definition, &changed)),
                sha256_hex(&baseline)
            );
        }

        let changed_sql = LogicalTableDefinition {
            name: definition.name.clone(),
            create_table_sql: "CREATE TABLE t(a TEXT) STRICT".to_owned(),
        };
        assert_ne!(
            sha256_hex(&encode(&changed_sql, &column)),
            sha256_hex(&baseline)
        );
    }

    #[test]
    fn encoded_primary_key_and_full_row_fallback_define_sort_order() {
        let connection = Connection::open_in_memory().expect("sort vector database");
        connection
            .execute_batch(
                "CREATE TABLE with_pk(k INTEGER PRIMARY KEY,v TEXT);
                 INSERT INTO with_pk(k,v) VALUES(-1,'negative'),(0,'zero');
                 CREATE TABLE without_pk(k INTEGER,v TEXT);
                 INSERT INTO without_pk(k,v) VALUES(-1,'a'),(0,'z'),(0,'a');",
            )
            .expect("sort vector schema and rows");

        let pk_columns = logical_table_columns(&connection, "with_pk").expect("PK metadata");
        let mut pk_rows =
            logical_table_rows(&connection, "with_pk", &pk_columns, None).expect("PK rows");
        pk_rows.sort_by(|left, right| {
            left.sort_key
                .cmp(&right.sort_key)
                .then_with(|| left.encoded.cmp(&right.encoded))
        });
        assert_eq!(
            pk_rows
                .iter()
                .map(|row| row.sort_key.clone())
                .collect::<Vec<_>>(),
            [0_i64, -1]
                .into_iter()
                .map(|value| {
                    encode_sqlite_value(rusqlite::types::ValueRef::Integer(value))
                        .expect("expected PK encoding")
                })
                .collect::<Vec<_>>()
        );

        let no_pk_columns =
            logical_table_columns(&connection, "without_pk").expect("fallback metadata");
        let mut no_pk_rows = logical_table_rows(&connection, "without_pk", &no_pk_columns, None)
            .expect("fallback rows");
        no_pk_rows.sort_by(|left, right| {
            left.sort_key
                .cmp(&right.sort_key)
                .then_with(|| left.encoded.cmp(&right.encoded))
        });
        let fallback_key = |integer, text: &'static [u8]| {
            let mut key = encode_sqlite_value(rusqlite::types::ValueRef::Integer(integer))
                .expect("fallback integer encoding");
            key.extend_from_slice(
                &encode_sqlite_value(rusqlite::types::ValueRef::Text(text))
                    .expect("fallback text encoding"),
            );
            key
        };
        assert_eq!(
            no_pk_rows
                .iter()
                .map(|row| row.sort_key.clone())
                .collect::<Vec<_>>(),
            [
                fallback_key(0, b"a"),
                fallback_key(0, b"z"),
                fallback_key(-1, b"a"),
            ]
        );
    }

    #[test]
    fn source_connection_enforces_sqlite_read_only() {
        let fixture = exact_fixture();
        let connection = open_privacy_v1_source_read_only(&fixture.path).expect("read-only open");
        let error = connection
            .execute_batch("CREATE TABLE forbidden_write(id INTEGER);")
            .expect_err("write must fail");
        assert!(matches!(
            error,
            rusqlite::Error::SqliteFailure(ref failure, _)
                if failure.code == ErrorCode::ReadOnly
        ));
    }

    #[test]
    fn callback_uses_the_validated_transaction_and_writes_return_read_only() {
        let fixture = exact_fixture();
        let (validation, write_was_read_only) =
            with_validated_privacy_v1_migration_source_read_only(&fixture.path, |session| {
                assert!(!session.logical_manifest().sha256.is_empty());
                let error = session
                    .execute_batch_for_transaction_guard_test(
                        "INSERT INTO privacy_schema_metadata(key,value)
                         VALUES('forbidden-write','1')",
                    )
                    .expect_err("callback write must fail");
                matches!(
                    error,
                    rusqlite::Error::SqliteFailure(ref failure, _)
                        if failure.code == ErrorCode::ReadOnly
                )
            })
            .expect("read-only callback succeeds");
        assert!(write_was_read_only);
        assert_eq!(validation.logical_manifest.total_row_count, 1);
    }

    #[test]
    fn logical_manifest_is_stable_across_insertion_order() {
        let first = exact_fixture();
        let first_connection = Connection::open(&first.path).expect("first fixture");
        insert_stable_material(
            &first_connection,
            "material-alpha",
            "project-stable",
            "alpha",
            "application/pdf",
        );
        insert_stable_material(
            &first_connection,
            "material-beta",
            "project-stable",
            "beta",
            "text/plain",
        );
        drop(first_connection);

        let second = exact_fixture();
        let second_connection = Connection::open(&second.path).expect("second fixture");
        insert_stable_material(
            &second_connection,
            "material-beta",
            "project-stable",
            "beta",
            "text/plain",
        );
        insert_stable_material(
            &second_connection,
            "material-alpha",
            "project-stable",
            "alpha",
            "application/pdf",
        );
        drop(second_connection);

        let first_proof = validate_privacy_v1_migration_source_read_only(&first.path)
            .expect("first logical manifest");
        let second_proof = validate_privacy_v1_migration_source_read_only(&second.path)
            .expect("second logical manifest");
        assert_eq!(first_proof.logical_manifest, second_proof.logical_manifest);
        assert_eq!(
            first_proof.business_manifest,
            second_proof.business_manifest
        );
        assert_eq!(first_proof.logical_manifest.total_row_count, 3);
        assert_eq!(
            first_proof
                .logical_manifest
                .tables
                .iter()
                .find(|table| table.table_name == "privacy_materials")
                .expect("materials table")
                .row_count,
            2
        );
    }

    #[test]
    fn logical_manifest_detects_primary_key_and_non_primary_value_changes() {
        let fixture = |material_id: &str, source_label: &str| {
            let fixture = exact_fixture();
            let connection = Connection::open(&fixture.path).expect("logical fixture");
            insert_stable_material(
                &connection,
                material_id,
                "project-logical-proof",
                source_label,
                "application/pdf",
            );
            drop(connection);
            fixture
        };
        let baseline = fixture("material-logical-a", "same-source");
        let changed_non_primary = fixture("material-logical-a", "changed-source");
        let changed_primary = fixture("material-logical-b", "same-source");

        let baseline_proof = validate_privacy_v1_migration_source_read_only(&baseline.path)
            .expect("baseline manifest");
        let non_primary_proof =
            validate_privacy_v1_migration_source_read_only(&changed_non_primary.path)
                .expect("non-primary manifest");
        let primary_proof = validate_privacy_v1_migration_source_read_only(&changed_primary.path)
            .expect("primary manifest");
        assert_ne!(
            baseline_proof.logical_manifest.sha256,
            non_primary_proof.logical_manifest.sha256
        );
        assert_ne!(
            baseline_proof.logical_manifest.sha256,
            primary_proof.logical_manifest.sha256
        );
        assert_ne!(
            baseline_proof.business_manifest.sha256,
            non_primary_proof.business_manifest.sha256
        );
        assert_eq!(
            baseline_proof.business_manifest.primary_key_sha256,
            non_primary_proof.business_manifest.primary_key_sha256
        );
        assert_ne!(
            baseline_proof.business_manifest.row_sha256,
            non_primary_proof.business_manifest.row_sha256
        );
        assert_ne!(
            baseline_proof.business_manifest.sha256,
            primary_proof.business_manifest.sha256
        );
        assert_ne!(
            baseline_proof.business_manifest.primary_key_sha256,
            primary_proof.business_manifest.primary_key_sha256
        );
        assert_ne!(
            baseline_proof.business_manifest.row_sha256,
            primary_proof.business_manifest.row_sha256
        );
        assert_eq!(
            baseline_proof.logical_manifest.total_row_count,
            non_primary_proof.logical_manifest.total_row_count
        );
        assert_eq!(
            baseline_proof.logical_manifest.total_row_count,
            primary_proof.logical_manifest.total_row_count
        );
    }

    #[test]
    fn metadata_only_change_is_excluded_from_every_business_manifest() {
        let fixture = exact_fixture();
        let before =
            validate_privacy_v1_migration_source_read_only(&fixture.path).expect("baseline proof");
        let connection = Connection::open(&fixture.path).expect("metadata fixture");
        connection
            .execute(
                "UPDATE privacy_schema_metadata
                 SET updated_at='2026-08-01 00:00:00'
                 WHERE key='schema_version'",
                [],
            )
            .expect("metadata-only change");
        drop(connection);
        let after =
            validate_privacy_v1_migration_source_read_only(&fixture.path).expect("changed proof");
        assert_ne!(
            before.logical_manifest.sha256,
            after.logical_manifest.sha256
        );
        assert_eq!(before.business_manifest, after.business_manifest);
    }

    #[test]
    fn callback_backup_api_uses_the_pinned_validated_snapshot() {
        let fixture = exact_fixture();
        let connection = Connection::open(&fixture.path).expect("backup source data");
        insert_stable_material(
            &connection,
            "backup-material",
            "backup-project",
            "backup-source",
            "application/pdf",
        );
        drop(connection);

        let destination_directory = tempfile::tempdir().expect("backup destination directory");
        let destination_path = destination_directory.path().join("snapshot.sqlite");
        let mut destination = Connection::open(&destination_path).expect("backup destination");
        let (source_proof, backup_result) =
            with_validated_privacy_v1_migration_source_read_only(&fixture.path, |session| {
                session.backup_to(&mut destination)
            })
            .expect("source proof and postvalidation");
        backup_result.expect("SQLite Backup API snapshot");
        drop(destination);

        let snapshot_proof = validate_privacy_v1_migration_source_read_only(&destination_path)
            .expect("self-contained snapshot validates");
        assert_eq!(
            source_proof.logical_manifest,
            snapshot_proof.logical_manifest
        );
        assert_eq!(
            source_proof.business_manifest,
            snapshot_proof.business_manifest
        );
    }

    #[test]
    fn callback_cannot_replace_the_guarded_transaction_with_commit_and_begin() {
        let fixture = exact_fixture();
        let result =
            with_validated_privacy_v1_migration_source_read_only(&fixture.path, |session| {
                session.execute_batch_for_transaction_guard_test("COMMIT; BEGIN DEFERRED")
            });
        assert!(matches!(
            result,
            Err(PrivacyV1SourceValidationError::SourceDrift)
        ));
    }

    #[test]
    fn existing_wal_and_shm_are_accepted_without_byte_or_metadata_changes() {
        let fixture = exact_fixture();
        enable_persistent_wal_and_shm(&fixture);
        let before = SourcePathSnapshot::capture(&fixture.path).expect("WAL source before");
        assert!(before.wal.is_some());
        assert!(before.shm.is_some());

        let proof = validate_privacy_v1_migration_source_read_only(&fixture.path)
            .expect("valid persistent WAL source");
        let after = SourcePathSnapshot::capture(&fixture.path).expect("WAL source after");
        assert_eq!(before, after);
        assert!(proof.wal.is_some());
        assert!(proof.shm.is_some());
    }

    #[test]
    fn wal_writer_commit_during_primary_snapshot_is_rejected() {
        let fixture = exact_fixture();
        enable_persistent_wal_and_shm(&fixture);
        let writer_path = fixture.path.clone();
        let (proof, write_result) =
            with_validated_privacy_v1_migration_source_read_only(&fixture.path, |_| {
                Connection::open(&writer_path).and_then(|writer| {
                    writer.execute(
                        "UPDATE privacy_schema_metadata
                         SET updated_at='2026-08-01 00:00:01'
                         WHERE key='schema_version'",
                        [],
                    )
                })
            })
            .expect("guarded source remains valid");
        assert!(
            write_result.is_err(),
            "the guarded WAL writer must be denied"
        );
        assert!(proof.wal.is_some());
        assert!(proof.shm.is_some());
    }

    #[test]
    fn already_open_wal_writer_prevents_snapshot_guard_acquisition() {
        let fixture = exact_fixture();
        let writer = open_wal_writer_with_uncheckpointed_metadata(&fixture);
        let result = validate_privacy_v1_migration_source_read_only(&fixture.path);
        assert_eq!(
            result,
            Err(PrivacyV1SourceValidationError::UnsafeFilesystem)
        );
        drop(writer);
    }

    #[test]
    fn guarded_source_parent_and_file_cannot_be_renamed_or_replaced() {
        let fixture = exact_fixture();
        let before = fs::read(&fixture.path).expect("guarded source bytes");
        let parent = fixture.path.parent().expect("guarded source parent");
        let parent_name = parent
            .file_name()
            .expect("guarded source parent name")
            .to_string_lossy();
        let renamed_parent = parent.with_file_name(format!("{parent_name}-rename-attempt"));
        let renamed_source = fixture.path.with_file_name("privacy-renamed.sqlite");

        let (_, (parent_rename, source_rename, source_replace)) =
            with_validated_privacy_v1_migration_source_read_only(&fixture.path, |_| {
                // Replacing an ancestor with a junction/reparse point first
                // requires vacating this guarded name; the directory handle
                // denies that rename for the full snapshot lifetime.
                let parent_rename = fs::rename(parent, &renamed_parent);
                let source_rename = fs::rename(&fixture.path, &renamed_source);
                let source_replace = fs::OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&fixture.path);
                (parent_rename, source_rename, source_replace)
            })
            .expect("guarded validation remains stable");

        assert!(parent_rename.is_err());
        assert!(source_rename.is_err());
        assert!(source_replace.is_err());
        assert_eq!(
            fs::read(&fixture.path).expect("source bytes after denied replacement"),
            before
        );
        assert!(!renamed_parent.exists());
        assert!(!renamed_source.exists());
    }

    #[test]
    fn logical_proof_output_contains_no_plaintext_id_or_path() {
        let fixture = exact_fixture();
        let material_id = "never-leak-material-id";
        let project_id = "never-leak-project-id";
        let plaintext = "never-leak-plaintext-or-path-C:\\secret\\matter.pdf";
        let connection = Connection::open(&fixture.path).expect("private logical fixture");
        insert_stable_material(
            &connection,
            material_id,
            project_id,
            "private-source",
            plaintext,
        );
        drop(connection);
        let validation = validate_privacy_v1_migration_source_read_only(&fixture.path)
            .expect("private logical proof");
        let rendered = format!("{validation:?}");
        for forbidden in [
            material_id,
            project_id,
            plaintext,
            fixture.path.to_string_lossy().as_ref(),
        ] {
            assert!(!rendered.contains(forbidden), "proof leaked {forbidden}");
        }
    }

    #[test]
    fn hardlink_and_reparse_source_paths_are_rejected() {
        let fixture = exact_fixture();
        let hardlink = fixture.path.with_file_name("privacy-hardlink.sqlite");
        fs::hard_link(&fixture.path, &hardlink).expect("hardlink fixture");
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&fixture.path),
            Err(PrivacyV1SourceValidationError::UnsafeFilesystem)
        );
        fs::remove_file(&hardlink).expect("remove hardlink fixture");

        let reparse = fixture.path.with_file_name("privacy-reparse.sqlite");
        #[cfg(windows)]
        let reparse_created = std::os::windows::fs::symlink_file(&fixture.path, &reparse).is_ok();
        #[cfg(unix)]
        let reparse_created = std::os::unix::fs::symlink(&fixture.path, &reparse).is_ok();
        #[cfg(not(any(windows, unix)))]
        let reparse_created = false;
        if reparse_created {
            assert_eq!(
                validate_privacy_v1_migration_source_read_only(&reparse),
                Err(PrivacyV1SourceValidationError::UnsafeFilesystem)
            );
            fs::remove_file(&reparse).expect("remove reparse fixture");
        }
    }

    #[test]
    fn source_sidecar_drift_during_validation_is_rejected() {
        let fixture = exact_fixture();
        let journal = sqlite_sidecar_path(&fixture.path, "-journal").expect("journal path");
        let result = with_validated_privacy_v1_migration_source_read_only(&fixture.path, |_| {
            fs::write(&journal, b"synthetic-concurrent-sidecar-drift")
                .expect("inject sidecar drift");
        });
        assert_eq!(result, Err(PrivacyV1SourceValidationError::SourceDrift));
    }

    #[test]
    fn callback_error_value_cannot_bypass_postvalidation_drift_proof() {
        let fixture = exact_fixture();
        let journal = sqlite_sidecar_path(&fixture.path, "-journal").expect("journal path");
        let result = with_validated_privacy_v1_migration_source_read_only(&fixture.path, |_| {
            fs::write(&journal, b"drift-after-callback-sentinel")
                .expect("inject post-callback drift");
            Err::<(), _>("snapshot-sentinel-error")
        });
        assert_eq!(result, Err(PrivacyV1SourceValidationError::SourceDrift));
    }

    #[test]
    fn source_guard_remains_held_between_primary_and_second_snapshot() {
        let fixture = exact_fixture();
        let writer_path = fixture.path.clone();
        let write_was_denied = Cell::new(false);
        let result = with_validated_privacy_v1_migration_source_read_only_inner(
            &fixture.path,
            |_| (),
            || {
                let write_result = Connection::open(&writer_path).and_then(|writer| {
                    writer.execute(
                        "UPDATE privacy_schema_metadata
                         SET updated_at='2026-08-01 00:00:00'
                         WHERE key='schema_version'",
                        [],
                    )
                });
                write_was_denied.set(write_result.is_err());
            },
        );
        result.expect("the guarded source remains valid");
        assert!(
            write_was_denied.get(),
            "the source guard must cover the second-snapshot gap"
        );
    }

    #[test]
    fn every_missing_manifest_object_is_rejected() {
        let expected = expected_schema_objects().expect("expected objects");
        assert_eq!(expected.len(), PRIVACY_V1_SCHEMA_OBJECT_COUNT);
        assert_eq!(
            expected
                .iter()
                .filter(|object| object.object_type == "table")
                .count(),
            5
        );
        assert_eq!(
            expected
                .iter()
                .filter(|object| object.object_type == "index")
                .count(),
            4
        );
        assert_eq!(
            expected
                .iter()
                .filter(|object| object.object_type == "trigger")
                .count(),
            2
        );

        for object in expected {
            let fixture = exact_fixture();
            let connection = Connection::open(&fixture.path).expect("tamper fixture");
            let object_kind = match object.object_type.as_str() {
                "table" => "TABLE",
                "index" => "INDEX",
                "trigger" => "TRIGGER",
                other => panic!("unexpected manifest object type: {other}"),
            };
            connection
                .execute_batch(&format!("DROP {object_kind} \"{}\";", object.name))
                .expect("drop manifest object");
            drop(connection);
            assert_eq!(
                validate_privacy_v1_migration_source_read_only(&fixture.path),
                Err(PrivacyV1SourceValidationError::SchemaMismatch),
                "missing {} {} was accepted",
                object.object_type,
                object.name
            );
        }
    }

    #[test]
    fn weakened_check_foreign_key_trigger_and_extra_object_are_rejected() {
        for changed_ddl in [
            PRIVACY_V1_SCHEMA_MANIFEST_DDL.replace(
                "CHECK(length(material_id) BETWEEN 1 AND 128)",
                "CHECK(length(material_id) >= 0)",
            ),
            PRIVACY_V1_SCHEMA_MANIFEST_DDL.replace(" ON DELETE CASCADE", ""),
            PRIVACY_V1_SCHEMA_MANIFEST_DDL.replace(
                "privacy egress audit is append only",
                "weakened trigger body",
            ),
            format!(
                "{PRIVACY_V1_SCHEMA_MANIFEST_DDL}\nCREATE TABLE unexpected_source_object(id TEXT);"
            ),
        ] {
            let fixture = fixture_with_ddl(&changed_ddl);
            assert_eq!(
                validate_privacy_v1_migration_source_read_only(&fixture.path),
                Err(PrivacyV1SourceValidationError::SchemaMismatch)
            );
        }
    }

    #[test]
    fn metadata_version_or_extra_metadata_is_rejected() {
        let wrong_version = exact_fixture();
        let connection = Connection::open(&wrong_version.path).expect("wrong version database");
        connection
            .execute(
                "UPDATE privacy_schema_metadata SET value='2'
                 WHERE key='schema_version'",
                [],
            )
            .expect("change version");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&wrong_version.path),
            Err(PrivacyV1SourceValidationError::SchemaVersionMismatch)
        );

        let extra_metadata = exact_fixture();
        let connection = Connection::open(&extra_metadata.path).expect("extra metadata database");
        connection
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value)
                 VALUES('workspace_identity','invented')",
                [],
            )
            .expect("insert extra metadata");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&extra_metadata.path),
            Err(PrivacyV1SourceValidationError::SchemaVersionMismatch)
        );
    }

    #[test]
    fn quick_check_and_foreign_key_failures_are_distinguished() {
        let corrupt = exact_fixture();
        let mut connection = Connection::open(&corrupt.path).expect("corrupt database");
        let transaction = connection.transaction().expect("material transaction");
        for index in 0..2_048 {
            transaction
                .execute(
                    "INSERT INTO privacy_materials(
                        material_id,source_sha256,source_name_sha256,media_type,state
                     ) VALUES(?1,?2,?3,'text/plain','registered')",
                    params![
                        format!("quick-check-material-{index:04}"),
                        sha256_hex(format!("source-{index}").as_bytes()),
                        sha256_hex(format!("name-{index}").as_bytes()),
                    ],
                )
                .expect("material row");
        }
        transaction.commit().expect("material commit");
        drop(connection);
        let length = fs::metadata(&corrupt.path)
            .expect("corrupt source metadata")
            .len();
        assert!(length > 512);
        OpenOptions::new()
            .write(true)
            .open(&corrupt.path)
            .expect("open source for corruption")
            .set_len(length - 512)
            .expect("truncate allocated data page");
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&corrupt.path),
            Err(PrivacyV1SourceValidationError::IntegrityCheckFailed)
        );

        let invalid_fk = exact_fixture();
        let connection = Connection::open(&invalid_fk.path).expect("invalid FK database");
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .expect("disable FK enforcement for corruption fixture");
        insert_review_blob(
            &connection,
            "missing-material",
            b"not-reached-protected-blob",
        );
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&invalid_fk.path),
            Err(PrivacyV1SourceValidationError::ForeignKeyViolation)
        );
    }

    #[test]
    fn application_data_boundaries_and_egress_hash_chain_fail_closed() {
        let invalid_hash = exact_fixture();
        let connection = Connection::open(&invalid_hash.path).expect("invalid hash fixture");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,source_sha256,source_name_sha256,media_type,state
                 ) VALUES('invalid-hash-material',?1,?2,'text/plain','registered')",
                params!["g".repeat(64), sha256_hex(b"valid-name")],
            )
            .expect("schema permits a length-only non-hex hash");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&invalid_hash.path),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );

        let invalid_page_count = exact_fixture();
        let connection = Connection::open(&invalid_page_count.path).expect("invalid page fixture");
        connection
            .pragma_update(None, "ignore_check_constraints", "ON")
            .expect("permit malformed page fixture");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,source_sha256,source_name_sha256,media_type,page_count,state
                 ) VALUES('invalid-page-count',?1,?2,'text/plain',-1,'registered')",
                params![sha256_hex(b"page-source"), sha256_hex(b"page-name")],
            )
            .expect("insert malformed page count");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&invalid_page_count.path),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );

        let invalid_redaction_number = exact_fixture();
        let connection =
            Connection::open(&invalid_redaction_number.path).expect("invalid redaction fixture");
        insert_material(&connection, "numeric-material");
        insert_review_blob(&connection, "numeric-material", b"not-reached");
        connection
            .pragma_update(None, "ignore_check_constraints", "ON")
            .expect("permit malformed redaction fixture");
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET policy_version=0,unresolved_high_risk_count=-1",
                [],
            )
            .expect("insert malformed redaction numbers");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&invalid_redaction_number.path),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );

        let invalid_receipt_number = exact_fixture();
        let connection =
            Connection::open(&invalid_receipt_number.path).expect("invalid receipt fixture");
        insert_material(&connection, "receipt-material");
        insert_review_blob(&connection, "receipt-material", b"not-reached");
        connection
            .pragma_update(None, "ignore_check_constraints", "ON")
            .expect("permit malformed receipt fixture");
        connection
            .execute(
                "INSERT INTO privacy_receipts(
                    receipt_id,redaction_id,signed_token,destination_kind,
                    destination_identifier_sha256,purpose,payload_sha256,
                    policy_id,policy_version,issued_at_unix,expires_at_unix
                 ) VALUES(
                    'invalid-receipt-number','synthetic-redaction',X'01',
                    'external_provider',?1,'receipt-purpose',?2,
                    'receipt-policy',0,100,101
                 )",
                params![
                    sha256_hex(b"receipt-destination"),
                    sha256_hex(b"receipt-payload")
                ],
            )
            .expect("insert malformed receipt number");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&invalid_receipt_number.path),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );

        let valid_audit = exact_fixture();
        let connection = Connection::open(&valid_audit.path).expect("valid audit fixture");
        insert_egress_event(&connection, true);
        drop(connection);
        validate_privacy_v1_migration_source_read_only(&valid_audit.path)
            .expect("valid canonical audit chain");

        let invalid_audit = exact_fixture();
        let connection = Connection::open(&invalid_audit.path).expect("invalid audit fixture");
        insert_egress_event(&connection, false);
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&invalid_audit.path),
            Err(PrivacyV1SourceValidationError::DataBoundary)
        );
    }

    #[test]
    fn current_store_and_v1_migration_validator_remain_strictly_separate() {
        let legacy = exact_fixture();
        let before = fs::read(&legacy.path).expect("legacy bytes before current initialize");
        let connection = Connection::open(&legacy.path).expect("legacy current-store check");
        assert_eq!(
            PrivacyStore::preflight_schema(&connection),
            Ok(PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 1 })
        );
        assert_eq!(
            PrivacyStore::initialize(&connection),
            Err(PrivacyStoreError::UnsupportedSchema)
        );
        drop(connection);
        assert_eq!(
            fs::read(&legacy.path).expect("legacy bytes after current initialize"),
            before
        );
        validate_privacy_v1_migration_source_read_only(&legacy.path)
            .expect("dedicated v1 validator still accepts exact legacy source");

        let current_directory = tempfile::tempdir().expect("current store directory");
        let current_path = current_directory.path().join("privacy-current.sqlite");
        let current = Connection::open(&current_path).expect("current store");
        PrivacyStore::initialize(&current).expect("initialize current v6");
        PrivacyStore::initialize(&current).expect("current initialize remains idempotent");
        drop(current);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&current_path),
            Err(PrivacyV1SourceValidationError::SchemaMismatch)
        );
    }

    #[test]
    fn unauthentic_review_payload_fails_closed() {
        let fixture = exact_fixture();
        let connection = Connection::open(&fixture.path).expect("protected payload database");
        insert_material(&connection, "synthetic-material");
        insert_review_blob(&connection, "synthetic-material", b"not-a-dpapi-blob");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&fixture.path),
            Err(PrivacyV1SourceValidationError::ProtectedReviewPayload)
        );
    }

    #[cfg(windows)]
    #[test]
    fn v031_dpapi_receipt_token_authenticates_and_tampering_fails() {
        let fixture = exact_fixture();
        let protected_review =
            protect_local(b"synthetic-review").expect("protect synthetic review payload");
        let protected_token =
            protect_local(b"rct_v1.synthetic-token").expect("protect v0.3.1 receipt token");
        let connection = Connection::open(&fixture.path).expect("receipt token fixture");
        insert_material(&connection, "synthetic-material");
        insert_review_blob(&connection, "synthetic-material", &protected_review);
        connection
            .execute(
                "INSERT INTO privacy_receipts(
                    receipt_id,redaction_id,signed_token,destination_kind,
                    destination_identifier_sha256,purpose,payload_sha256,policy_id,
                    policy_version,issued_at_unix,expires_at_unix
                 ) VALUES(
                    'synthetic-receipt','synthetic-redaction',?1,'external_provider',
                    ?2,'synthetic-purpose',?3,'synthetic-policy',1,1,2
                 )",
                params![
                    protected_token,
                    sha256_hex(b"destination"),
                    sha256_hex(b"payload"),
                ],
            )
            .expect("v0.3.1 protected receipt token");
        drop(connection);
        validate_privacy_v1_migration_source_read_only(&fixture.path)
            .expect("receipt token authenticates");

        let connection = Connection::open(&fixture.path).expect("tamper receipt token");
        let mut tampered = connection
            .query_row(
                "SELECT signed_token FROM privacy_receipts WHERE receipt_id='synthetic-receipt'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("protected token");
        let middle = tampered.len() / 2;
        tampered[middle] ^= 0x5a;
        connection
            .execute(
                "UPDATE privacy_receipts SET signed_token=?1
                 WHERE receipt_id='synthetic-receipt'",
                [tampered],
            )
            .expect("tamper token");
        drop(connection);
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&fixture.path),
            Err(PrivacyV1SourceValidationError::ProtectedReviewPayload)
        );
    }

    #[cfg(windows)]
    #[test]
    fn synthetic_dpapi_review_payload_authenticates_and_tampering_fails() {
        let fixture = exact_fixture();
        let plaintext = b"synthetic-v0.3.1-protected-review";
        let protected = protect_local(plaintext).expect("protect synthetic review");
        let connection = Connection::open(&fixture.path).expect("protected payload database");
        insert_material(&connection, "synthetic-material");
        insert_review_blob(&connection, "synthetic-material", &protected);
        drop(connection);

        let validation = validate_privacy_v1_migration_source_read_only(&fixture.path)
            .expect("DPAPI payload authenticates");
        assert_eq!(validation.protected_review_payload_count, 1);

        let connection = Connection::open(&fixture.path).expect("tamper payload database");
        let mut tampered = connection
            .query_row(
                "SELECT protected_review_blob FROM privacy_redactions
                 WHERE redaction_id='synthetic-redaction'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("protected blob");
        let middle = tampered.len() / 2;
        tampered[middle] ^= 0x5a;
        connection
            .execute(
                "UPDATE privacy_redactions SET protected_review_blob=?1
                 WHERE redaction_id='synthetic-redaction'",
                [tampered],
            )
            .expect("tamper protected review");
        drop(connection);

        assert_eq!(
            validate_privacy_v1_migration_source_read_only(&fixture.path),
            Err(PrivacyV1SourceValidationError::ProtectedReviewPayload)
        );
    }
}

#[cfg(all(test, not(windows)))]
mod non_windows_tests {
    use super::*;

    #[test]
    fn legacy_windows_dpapi_source_validation_fails_closed() {
        let path = std::env::current_dir()
            .expect("current directory")
            .join("Cargo.toml");
        assert_eq!(
            validate_privacy_v1_migration_source_read_only(path),
            Err(PrivacyV1SourceValidationError::UnsafeFilesystem)
        );
    }
}
