use crate::{
    protect_local, sha256_hex, unprotect_local, DataClassification, DestinationKind,
    DestinationScope, PrivacyEgressAuditRecord, ReceiptError, ReceiptSigner,
    ReceiptVerificationContext, ReviewState, SignedRedactionReceipt, LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const PRIVACY_STORE_SCHEMA_VERSION: i64 = 6;
const INTERMEDIATE_PRIVACY_STORE_SCHEMA_VERSION: i64 = 5;
const RISK_REVIEW_REVISION_PROFILE: &str = "privacy-risk-review-revision-v1";
pub const MAX_ACTIVE_RECEIPT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_ID_BYTES: usize = 128;
const MAX_TOKEN_BYTES: usize = 32_768;
const MAX_PROTECTED_TOKEN_BYTES: usize = 65_536;
const MAX_APPROVED_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_DISPLAY_NAME_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyStoreError {
    Database,
    UnsupportedSchema,
    InvalidInput,
    Conflict,
    NotApproved,
    ProtectedBlob,
    InvalidReceipt,
    ReceiptRevoked,
    ReceiptExpired,
    ReceiptConsumed,
}

impl PrivacyStoreError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Database => "privacy_store_database_error",
            Self::UnsupportedSchema => "privacy_store_schema_unsupported",
            Self::InvalidInput => "privacy_store_invalid_input",
            Self::Conflict => "privacy_store_conflict",
            Self::NotApproved => "redaction_not_approved",
            Self::ProtectedBlob => "privacy_store_protected_blob_error",
            Self::InvalidReceipt => "redaction_receipt_invalid",
            Self::ReceiptRevoked => "redaction_receipt_revoked",
            Self::ReceiptExpired => "redaction_receipt_expired",
            Self::ReceiptConsumed => "redaction_receipt_consumed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyStoreSchemaStatus {
    Empty,
    Current,
    UpgradeRequired { found_version: i64 },
}

impl std::fmt::Display for PrivacyStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PrivacyStoreError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterPrivacyMaterial<'a> {
    pub material_id: &'a str,
    pub project_id: Option<&'a str>,
    pub attachment_id: Option<&'a str>,
    pub source_sha256: &'a str,
    pub source_name_sha256: &'a str,
    pub media_type: &'a str,
    pub page_count: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveReviewDraft<'a> {
    pub redaction_id: &'a str,
    pub material_id: &'a str,
    pub extraction_sha256: &'a str,
    pub redacted_content_sha256: &'a str,
    pub policy_id: &'a str,
    pub policy_version: u32,
    pub detector_version: &'a str,
    pub unresolved_high_risk_count: u32,
    pub review_payload_plaintext: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadedReviewDraft {
    pub redaction_id: String,
    pub material_id: String,
    pub extraction_sha256: String,
    pub redacted_content_sha256: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub detector_version: String,
    pub unresolved_high_risk_count: u32,
    pub review_state: String,
    pub review_payload_plaintext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveRiskReviewRevision<'a> {
    pub redaction_id: &'a str,
    pub expected_previous_revision: u64,
    pub risk_sha256: &'a str,
    pub hard_gate_sha256: &'a str,
    pub action_code: &'a str,
    pub reason_codes: &'a [String],
    pub state_plaintext: &'a [u8],
}

pub struct LoadedRiskReviewRevision {
    pub redaction_id: String,
    pub revision: u64,
    pub state_sha256: String,
    pub risk_sha256: String,
    pub hard_gate_sha256: String,
    pub action_code: String,
    pub reason_codes: Vec<String>,
    pub previous_revision_hash: String,
    pub revision_hash: String,
    pub state_plaintext: Vec<u8>,
}

impl fmt::Debug for LoadedRiskReviewRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedRiskReviewRevision")
            .field("redaction_id", &self.redaction_id)
            .field("revision", &self.revision)
            .field("state_sha256", &self.state_sha256)
            .field("risk_sha256", &self.risk_sha256)
            .field("hard_gate_sha256", &self.hard_gate_sha256)
            .field("action_code", &self.action_code)
            .field("reason_codes", &self.reason_codes)
            .field("previous_revision_hash", &self.previous_revision_hash)
            .field("revision_hash", &self.revision_hash)
            .field("state_plaintext", &"<protected-risk-review-state>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RiskReviewRevisionSummary {
    pub redaction_id: String,
    pub revision: u64,
    pub state_sha256: String,
    pub risk_sha256: String,
    pub hard_gate_sha256: String,
    pub action_code: String,
    pub reason_codes: Vec<String>,
    pub previous_revision_hash: String,
    pub revision_hash: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ActiveReceiptVerification<'a> {
    pub redaction_id: &'a str,
    pub signed_token: &'a str,
    pub approved_payload: &'a [u8],
    pub destination: &'a DestinationScope,
    pub purpose: &'a str,
    pub now_unix: u64,
    pub expected_key_version: u32,
}

pub struct PrivacyStore;

impl PrivacyStore {
    /// Read-only schema inspection. This method never creates tables or updates metadata.
    pub fn preflight_schema(
        connection: &Connection,
    ) -> Result<PrivacyStoreSchemaStatus, PrivacyStoreError> {
        let has_user_schema = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE name NOT LIKE 'sqlite_%'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let metadata_exists = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type='table' AND name='privacy_schema_metadata'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if !metadata_exists {
            return if has_user_schema {
                Err(PrivacyStoreError::UnsupportedSchema)
            } else {
                Ok(PrivacyStoreSchemaStatus::Empty)
            };
        }

        let version = connection
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        let backing_table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table'
                   AND name IN ('privacy_materials','privacy_redactions')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let has_backing_tables = backing_table_count == 2;

        let Some(version) = version else {
            return Err(PrivacyStoreError::UnsupportedSchema);
        };
        let version = version
            .parse::<i64>()
            .map_err(|_| PrivacyStoreError::UnsupportedSchema)?;
        match version {
            PRIVACY_STORE_SCHEMA_VERSION if has_backing_tables => {
                Ok(PrivacyStoreSchemaStatus::Current)
            }
            PRIVACY_STORE_SCHEMA_VERSION => Err(PrivacyStoreError::UnsupportedSchema),
            1..=5 if has_backing_tables => Ok(PrivacyStoreSchemaStatus::UpgradeRequired {
                found_version: version,
            }),
            1..=5 => Err(PrivacyStoreError::UnsupportedSchema),
            _ => Err(PrivacyStoreError::UnsupportedSchema),
        }
    }

    /// Initializes a new empty store or validates an already-current store.
    ///
    /// Existing v1-v4 databases are deliberately not upgraded here: the migration
    /// contract requires the application to complete its coordinated five-component
    /// backup before the first target/schema write.
    pub fn initialize(connection: &Connection) -> Result<(), PrivacyStoreError> {
        match Self::preflight_schema(connection)? {
            PrivacyStoreSchemaStatus::Empty => create_empty_v6_schema(connection),
            PrivacyStoreSchemaStatus::Current => {
                configure_v6_connection(connection)?;
                validate_v6_schema(connection)?;
                crate::lifecycle::initialize_lifecycle_schema(connection)
            }
            PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                Err(PrivacyStoreError::UnsupportedSchema)
            }
        }
    }

    /// Explicitly performs the v1-v4 to v5 schema evolution.
    ///
    /// The caller must invoke this only after the coordinated application backup
    /// required by the case-material migration contract has completed successfully.
    pub fn upgrade_schema_after_backup(connection: &Connection) -> Result<(), PrivacyStoreError> {
        match Self::preflight_schema(connection)? {
            PrivacyStoreSchemaStatus::Empty => create_empty_v6_schema(connection),
            PrivacyStoreSchemaStatus::Current => {
                configure_v6_connection(connection)?;
                validate_v6_schema(connection)?;
                crate::lifecycle::initialize_lifecycle_schema(connection)
            }
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version } => {
                if (1..=4).contains(&found_version) {
                    upgrade_legacy_schema_to_v5(connection, found_version)?;
                }
                Self::prepare_approved_projection_schema_after_backup(connection)
            }
        }
    }

    /// Adds the nullable v6 projection columns and migration-only guards while
    /// deliberately keeping schema metadata at v5. The caller must have already
    /// established the coordinated five-component backup and capacity gate.
    pub fn prepare_approved_projection_schema_after_backup(
        connection: &Connection,
    ) -> Result<(), PrivacyStoreError> {
        configure_v6_connection(connection)?;
        match Self::preflight_schema(connection)? {
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 } => {}
            PrivacyStoreSchemaStatus::Current => return validate_v6_schema(connection),
            PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                return Err(PrivacyStoreError::UnsupportedSchema)
            }
        }
        validate_v5_schema(connection)?;
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
                .map_err(|_| PrivacyStoreError::Database)?;
        let columns = table_columns(&transaction, "privacy_redactions")?;
        for (column, declaration) in [
            (
                "approved_payload_schema_version",
                "approved_payload_schema_version INTEGER CHECK(
                    approved_payload_schema_version IS NULL
                    OR approved_payload_schema_version = 1
                 )",
            ),
            (
                "protected_approved_payload_blob",
                "protected_approved_payload_blob BLOB CHECK(
                    protected_approved_payload_blob IS NULL
                    OR length(protected_approved_payload_blob) > 0
                 )",
            ),
            (
                "approved_payload_protection_scheme",
                "approved_payload_protection_scheme TEXT CHECK(
                    approved_payload_protection_scheme IS NULL
                    OR approved_payload_protection_scheme =
                        'windows_dpapi_current_user_v1'
                 )",
            ),
            (
                "approved_risk_revision_hash",
                "approved_risk_revision_hash TEXT CHECK(
                    approved_risk_revision_hash IS NULL
                    OR length(approved_risk_revision_hash) = 64
                 )",
            ),
        ] {
            if !columns.contains(column) {
                transaction
                    .execute_batch(&format!(
                        "ALTER TABLE privacy_redactions ADD COLUMN {declaration};"
                    ))
                    .map_err(|_| PrivacyStoreError::Database)?;
            }
        }
        install_projection_migration_guards(&transaction)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }

    /// Finalizes v6 only after every active ready approved generation has a
    /// complete projection. A ready approved generation revoked before this
    /// migration may remain projection-free; post-v6 revocation preserves an
    /// already-created immutable complete projection.
    pub fn finalize_approved_projection_schema_after_backup(
        connection: &Connection,
    ) -> Result<(), PrivacyStoreError> {
        configure_v6_connection(connection)?;
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
                .map_err(|_| PrivacyStoreError::Database)?;
        let version = transaction
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        if version.as_deref() != Some("5") {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
        let columns = table_columns(&transaction, "privacy_redactions")?;
        if [
            "approved_payload_schema_version",
            "protected_approved_payload_blob",
            "approved_payload_protection_scheme",
            "approved_risk_revision_hash",
        ]
        .iter()
        .any(|column| !columns.contains(*column))
        {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
        let invalid_projection_count = transaction
            .query_row(
                "SELECT COUNT(*)
                 FROM privacy_redactions
                 WHERE
                   (
                     (approved_payload_schema_version IS NULL)
                     + (protected_approved_payload_blob IS NULL)
                     + (approved_payload_protection_scheme IS NULL)
                     + (approved_risk_revision_hash IS NULL)
                   ) NOT IN (0,4)
                   OR (
                     review_state='approved' AND generation_status='ready'
                     AND revocation_state='active' AND revoked_at IS NULL
                     AND approved_payload_schema_version IS NULL
                   )
                   OR (
                     approved_payload_schema_version IS NOT NULL
                     AND (
                       review_state <> 'approved'
                       OR generation_status <> 'ready'
                       OR NOT (
                         (revocation_state='active' AND revoked_at IS NULL)
                         OR (revocation_state='revoked' AND revoked_at IS NOT NULL)
                       )
                       OR approved_payload_sha256 IS NULL
                       OR approved_payload_schema_version <> 1
                       OR protected_approved_payload_blob IS NULL
                       OR approved_payload_protection_scheme <>
                          'windows_dpapi_current_user_v1'
                       OR approved_risk_revision_hash IS NULL
                       OR risk_revision <= 0
                       OR unresolved_high_risk_count <> 0
                     )
                   )",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if invalid_projection_count != 0 {
            return Err(PrivacyStoreError::Conflict);
        }
        install_v6_security_triggers(&transaction)?;
        transaction
            .execute("DROP TRIGGER IF EXISTS trg_privacy_v6_approval_blocked", [])
            .map_err(|_| PrivacyStoreError::Database)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_schema_metadata
                 SET value=?1,updated_at=CURRENT_TIMESTAMP
                 WHERE key='schema_version' AND value='5'",
                [PRIVACY_STORE_SCHEMA_VERSION.to_string()],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        validate_v6_schema(&transaction)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }

    pub fn register_material(
        connection: &Connection,
        input: &RegisterPrivacyMaterial<'_>,
    ) -> Result<(), PrivacyStoreError> {
        valid_id(input.material_id)?;
        valid_optional_id(input.project_id)?;
        valid_optional_id(input.attachment_id)?;
        valid_hash(input.source_sha256)?;
        valid_hash(input.source_name_sha256)?;
        valid_id(input.media_type)?;
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,attachment_id,source_sha256,
                    source_name_sha256,media_type,page_count,source_kind,
                    extraction_status,migration_status,state
                 ) VALUES(
                    ?1,?2,?3,?4,?5,?6,?7,
                    CASE WHEN ?3 IS NULL THEN 'local_review' ELSE 'vault' END,
                    'registered',
                    CASE WHEN ?2 IS NULL THEN 'unassigned' ELSE 'ready' END,
                    'registered'
                 )",
                params![
                    input.material_id,
                    input.project_id,
                    input.attachment_id,
                    input.source_sha256,
                    input.source_name_sha256,
                    input.media_type,
                    input.page_count,
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        Ok(())
    }

    /// Stores a material display name only as a DPAPI-protected blob plus its SHA-256.
    ///
    /// `expected_row_version` provides optimistic concurrency for migration and workflow
    /// callers. The returned value is the exact committed row version.
    pub fn set_material_display_name(
        connection: &Connection,
        material_id: &str,
        expected_row_version: Option<u64>,
        display_name_plaintext: &str,
    ) -> Result<u64, PrivacyStoreError> {
        valid_id(material_id)?;
        if display_name_plaintext.is_empty()
            || display_name_plaintext.len() > MAX_DISPLAY_NAME_BYTES
            || display_name_plaintext.chars().any(char::is_control)
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let expected_row_version = expected_row_version
            .map(|version| i64::try_from(version).map_err(|_| PrivacyStoreError::InvalidInput))
            .transpose()?;
        let protected = protect_local(display_name_plaintext.as_bytes())
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let display_name_sha256 = sha256_hex(display_name_plaintext.as_bytes());
        let row_version = connection
            .query_row(
                "UPDATE privacy_materials
                 SET protected_display_name=?3,display_name_sha256=?4,
                     display_name_protection_scheme=?5,
                     updated_at=CURRENT_TIMESTAMP,row_version=row_version+1
                 WHERE material_id=?1
                   AND (?2 IS NULL OR row_version=?2)
                 RETURNING row_version",
                params![
                    material_id,
                    expected_row_version,
                    protected,
                    display_name_sha256,
                    LOCAL_PROTECTION_SCHEME,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?
            .ok_or(PrivacyStoreError::Conflict)?;
        u64::try_from(row_version).map_err(|_| PrivacyStoreError::Database)
    }

    /// Allocates the next generation under an immediate write lock when called
    /// outside an existing transaction. Callers that pass an existing transaction
    /// must have opened it with `TransactionBehavior::Immediate`.
    pub fn save_review_draft(
        connection: &Connection,
        input: &SaveReviewDraft<'_>,
    ) -> Result<(), PrivacyStoreError> {
        valid_id(input.redaction_id)?;
        valid_id(input.material_id)?;
        valid_hash(input.extraction_sha256)?;
        valid_hash(input.redacted_content_sha256)?;
        valid_id(input.policy_id)?;
        valid_id(input.detector_version)?;
        if input.policy_version == 0 {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let protected = protect_local(input.review_payload_plaintext)
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        if connection.is_autocommit() {
            let transaction =
                rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
                    .map_err(|_| PrivacyStoreError::Database)?;
            save_review_draft_rows(&transaction, input, &protected)?;
            transaction
                .commit()
                .map_err(|_| PrivacyStoreError::Database)
        } else {
            save_review_draft_rows(connection, input, &protected)
        }
    }

    /// Replaces a pending review payload only when its exact redacted-content hash still matches.
    /// The caller is expected to execute this together with an append-only risk revision inside
    /// one SQLite transaction, preventing the editable draft and risk state from diverging.
    pub fn update_review_draft_exact(
        connection: &Connection,
        redaction_id: &str,
        expected_redacted_sha256: &str,
        redacted_content_sha256: &str,
        unresolved_high_risk_count: u32,
        review_payload_plaintext: &[u8],
    ) -> Result<(), PrivacyStoreError> {
        valid_id(redaction_id)?;
        valid_hash(expected_redacted_sha256)?;
        valid_hash(redacted_content_sha256)?;
        if review_payload_plaintext.is_empty() {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let protected = protect_local(review_payload_plaintext)
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let changed = connection
            .execute(
                "UPDATE privacy_redactions
                 SET redacted_content_sha256=?3,unresolved_high_risk_count=?4,
                     protected_review_blob=?5,protection_scheme=?6,
                     row_version=row_version+1
                 WHERE redaction_id=?1 AND review_state='review_required'
                   AND redacted_content_sha256=?2",
                params![
                    redaction_id,
                    expected_redacted_sha256,
                    redacted_content_sha256,
                    unresolved_high_risk_count,
                    protected,
                    LOCAL_PROTECTION_SCHEME,
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        Ok(())
    }

    pub fn append_risk_review_revision(
        connection: &Connection,
        input: &SaveRiskReviewRevision<'_>,
    ) -> Result<RiskReviewRevisionSummary, PrivacyStoreError> {
        valid_id(input.redaction_id)?;
        valid_hash(input.risk_sha256)?;
        valid_hash(input.hard_gate_sha256)?;
        valid_id(input.action_code)?;
        if input.state_plaintext.is_empty() || input.reason_codes.len() > 64 {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let unique_reasons = input.reason_codes.iter().collect::<BTreeSet<_>>();
        if unique_reasons.len() != input.reason_codes.len()
            || input
                .reason_codes
                .iter()
                .any(|reason| valid_id(reason).is_err())
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let reason_codes_json = serde_json::to_string(input.reason_codes)
            .map_err(|_| PrivacyStoreError::InvalidInput)?;
        if reason_codes_json.len() > 65_536 {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let previous = connection
            .query_row(
                "SELECT revision,revision_hash FROM privacy_risk_review_revisions
                 WHERE redaction_id=?1 ORDER BY revision DESC LIMIT 1",
                [input.redaction_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        let (previous_revision, previous_revision_hash) = match previous {
            Some((revision, hash)) => (
                u64::try_from(revision).map_err(|_| PrivacyStoreError::Database)?,
                hash,
            ),
            None => (0, String::new()),
        };
        if previous_revision != input.expected_previous_revision {
            return Err(PrivacyStoreError::Conflict);
        }
        let revision = previous_revision
            .checked_add(1)
            .ok_or(PrivacyStoreError::InvalidInput)?;
        let state_sha256 = sha256_hex(input.state_plaintext);
        let protected =
            protect_local(input.state_plaintext).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let protected_sha256 = sha256_hex(&protected);
        let revision_hash = risk_review_revision_hash(&RiskReviewRevisionHashInput {
            redaction_id: input.redaction_id,
            revision,
            state_sha256: &state_sha256,
            risk_sha256: input.risk_sha256,
            hard_gate_sha256: input.hard_gate_sha256,
            action_code: input.action_code,
            reason_codes_json: &reason_codes_json,
            protected_sha256: &protected_sha256,
            previous_revision_hash: &previous_revision_hash,
        });
        let revision_sql = i64::try_from(revision).map_err(|_| PrivacyStoreError::InvalidInput)?;
        let changed = connection
            .execute(
                "INSERT INTO privacy_risk_review_revisions(
                    redaction_id,revision,state_sha256,risk_sha256,hard_gate_sha256,
                    action_code,reason_codes_json,protected_state_blob,protection_scheme,
                    previous_revision_hash,revision_hash
                 )
                 SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11
                 WHERE EXISTS(SELECT 1 FROM privacy_redactions WHERE redaction_id=?1)",
                params![
                    input.redaction_id,
                    revision_sql,
                    state_sha256,
                    input.risk_sha256,
                    input.hard_gate_sha256,
                    input.action_code,
                    reason_codes_json,
                    protected,
                    LOCAL_PROTECTION_SCHEME,
                    previous_revision_hash,
                    revision_hash,
                ],
            )
            .map_err(|error| {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                    PrivacyStoreError::Conflict
                } else {
                    PrivacyStoreError::Database
                }
            })?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        Ok(RiskReviewRevisionSummary {
            redaction_id: input.redaction_id.to_owned(),
            revision,
            state_sha256,
            risk_sha256: input.risk_sha256.to_owned(),
            hard_gate_sha256: input.hard_gate_sha256.to_owned(),
            action_code: input.action_code.to_owned(),
            reason_codes: input.reason_codes.to_vec(),
            previous_revision_hash,
            revision_hash,
        })
    }

    pub fn load_latest_risk_review_revision(
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<Option<LoadedRiskReviewRevision>, PrivacyStoreError> {
        valid_id(redaction_id)?;
        let row = connection
            .query_row(
                "SELECT revision,state_sha256,risk_sha256,hard_gate_sha256,action_code,
                        reason_codes_json,protected_state_blob,protection_scheme,
                        previous_revision_hash,revision_hash
                 FROM privacy_risk_review_revisions
                 WHERE redaction_id=?1 ORDER BY revision DESC LIMIT 1",
                [redaction_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        let Some((
            revision,
            state_sha256,
            risk_sha256,
            hard_gate_sha256,
            action_code,
            reason_codes_json,
            protected,
            scheme,
            previous_revision_hash,
            revision_hash,
        )) = row
        else {
            return Ok(None);
        };
        if scheme != LOCAL_PROTECTION_SCHEME {
            return Err(PrivacyStoreError::ProtectedBlob);
        }
        let revision = u64::try_from(revision).map_err(|_| PrivacyStoreError::Database)?;
        let reason_codes: Vec<String> =
            serde_json::from_str(&reason_codes_json).map_err(|_| PrivacyStoreError::Database)?;
        let protected_sha256 = sha256_hex(&protected);
        let expected_revision_hash = risk_review_revision_hash(&RiskReviewRevisionHashInput {
            redaction_id,
            revision,
            state_sha256: &state_sha256,
            risk_sha256: &risk_sha256,
            hard_gate_sha256: &hard_gate_sha256,
            action_code: &action_code,
            reason_codes_json: &reason_codes_json,
            protected_sha256: &protected_sha256,
            previous_revision_hash: &previous_revision_hash,
        });
        if expected_revision_hash != revision_hash {
            return Err(PrivacyStoreError::Conflict);
        }
        let state_plaintext =
            unprotect_local(&protected).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        if sha256_hex(&state_plaintext) != state_sha256 {
            return Err(PrivacyStoreError::Conflict);
        }
        Ok(Some(LoadedRiskReviewRevision {
            redaction_id: redaction_id.to_owned(),
            revision,
            state_sha256,
            risk_sha256,
            hard_gate_sha256,
            action_code,
            reason_codes,
            previous_revision_hash,
            revision_hash,
            state_plaintext,
        }))
    }

    pub fn load_review_draft(
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<LoadedReviewDraft, PrivacyStoreError> {
        valid_id(redaction_id)?;
        let row = connection
            .query_row(
                "SELECT redaction_id,material_id,extraction_sha256,redacted_content_sha256,
                        policy_id,policy_version,detector_version,unresolved_high_risk_count,
                        review_state,protected_review_blob
                 FROM privacy_redactions WHERE redaction_id=?1",
                [redaction_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, u32>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, u32>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?
            .ok_or(PrivacyStoreError::Conflict)?;
        let plaintext = unprotect_local(&row.9).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        Ok(LoadedReviewDraft {
            redaction_id: row.0,
            material_id: row.1,
            extraction_sha256: row.2,
            redacted_content_sha256: row.3,
            policy_id: row.4,
            policy_version: row.5,
            detector_version: row.6,
            unresolved_high_risk_count: row.7,
            review_state: row.8,
            review_payload_plaintext: plaintext,
        })
    }

    /// Applies the unified-catalog deletion semantics without destroying review history.
    ///
    /// The material is tombstoned, every active generation and receipt is revoked, and every
    /// active selection is invalidated in one immediate transaction. Protected review payloads,
    /// risk revisions, generation rows, receipts, and selection history remain available for
    /// audit and retention processing.
    pub fn tombstone_redaction_material_exact(
        connection: &mut Connection,
        redaction_id: &str,
        expected_source_sha256: &str,
        expected_extraction_sha256: &str,
        revoked_at_unix: u64,
    ) -> Result<bool, PrivacyStoreError> {
        valid_id(redaction_id)?;
        valid_hash(expected_source_sha256)?;
        valid_hash(expected_extraction_sha256)?;
        let revoked_at_unix =
            i64::try_from(revoked_at_unix).map_err(|_| PrivacyStoreError::InvalidInput)?;
        if revoked_at_unix == 0 {
            return Err(PrivacyStoreError::InvalidInput);
        }

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
        let identity = transaction
            .query_row(
                "SELECT generation.material_id,material.source_sha256,
                        generation.extraction_sha256,material.deleted_at
                 FROM privacy_redactions AS generation
                 JOIN privacy_materials AS material
                   ON material.material_id=generation.material_id
                 WHERE generation.redaction_id=?1",
                [redaction_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        let Some((material_id, source_sha256, extraction_sha256, deleted_at)) = identity else {
            transaction
                .commit()
                .map_err(|_| PrivacyStoreError::Database)?;
            return Ok(false);
        };
        if source_sha256 != expected_source_sha256
            || extraction_sha256 != expected_extraction_sha256
        {
            return Err(PrivacyStoreError::Conflict);
        }
        if deleted_at.is_some() {
            transaction
                .commit()
                .map_err(|_| PrivacyStoreError::Database)?;
            return Ok(false);
        }

        transaction
            .execute(
                "UPDATE case_material_selections
                 SET invalidated_at=CURRENT_TIMESTAMP,
                     invalidation_reason='material_deleted',
                     row_version=row_version+1
                 WHERE material_id=?1
                   AND deselected_at IS NULL
                   AND invalidated_at IS NULL",
                [material_id.as_str()],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .execute(
                "UPDATE privacy_receipts
                 SET revoked_at_unix=COALESCE(revoked_at_unix,?2)
                 WHERE redaction_id IN(
                   SELECT redaction_id FROM privacy_redactions WHERE material_id=?1
                 )",
                params![material_id.as_str(), revoked_at_unix],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .execute(
                "UPDATE privacy_redactions
                 SET revocation_state='revoked',
                     revoked_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE material_id=?1
                   AND revocation_state='active'
                   AND revoked_at IS NULL",
                [material_id.as_str()],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_materials
                 SET state='revoked',
                     deleted_at=CURRENT_TIMESTAMP,
                     updated_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE material_id=?1 AND deleted_at IS NULL",
                [material_id],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)?;
        Ok(true)
    }

    pub fn approve_review(
        connection: &mut Connection,
        redaction_id: &str,
        expected_redacted_sha256: &str,
        approved_redacted_content_sha256: &str,
        approved_payload_sha256: &str,
        reviewed_by_sha256: &str,
        approved_review_payload_plaintext: &[u8],
    ) -> Result<(), PrivacyStoreError> {
        valid_id(redaction_id)?;
        valid_hash(expected_redacted_sha256)?;
        valid_hash(approved_redacted_content_sha256)?;
        valid_hash(approved_payload_sha256)?;
        valid_hash(reviewed_by_sha256)?;
        if approved_review_payload_plaintext.is_empty()
            || approved_review_payload_plaintext.len() > MAX_APPROVED_PAYLOAD_BYTES
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let protected_review_blob = protect_local(approved_review_payload_plaintext)
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let transaction = connection
            .transaction()
            .map_err(|_| PrivacyStoreError::Database)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_redactions
                 SET review_state='approved',generation_status='blocked',
                     approved_payload_sha256=?2,
                     reviewed_by_sha256=?3,protected_review_blob=?5,
                     redacted_content_sha256=?6,reviewed_at=CURRENT_TIMESTAMP,
                     approved_at=CURRENT_TIMESTAMP,row_version=row_version+1
                 WHERE redaction_id=?1 AND review_state='review_required'
                   AND unresolved_high_risk_count=0 AND redacted_content_sha256=?4",
                params![
                    redaction_id,
                    approved_payload_sha256,
                    reviewed_by_sha256,
                    expected_redacted_sha256,
                    protected_review_blob,
                    approved_redacted_content_sha256,
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        transaction
            .execute(
                "UPDATE privacy_materials
                 SET state='approved',updated_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE material_id=(
                    SELECT material_id FROM privacy_redactions WHERE redaction_id=?1
                 )",
                [redaction_id],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }
    /// Atomically appends the exact publication-bound risk revision and approves the matching
    /// editable review. A stale risk revision or draft hash rolls back both changes.
    pub fn approve_review_with_risk_revision(
        connection: &mut Connection,
        input: &ApproveReviewWithRiskRevision<'_>,
    ) -> Result<(), PrivacyStoreError> {
        valid_id(input.redaction_id)?;
        valid_hash(input.expected_redacted_sha256)?;
        valid_hash(input.approved_redacted_content_sha256)?;
        valid_hash(input.approved_payload_sha256)?;
        valid_hash(input.reviewed_by_sha256)?;
        if input.risk_revision.redaction_id != input.redaction_id
            || input.approved_review_payload_plaintext.is_empty()
            || input.approved_review_payload_plaintext.len() > MAX_APPROVED_PAYLOAD_BYTES
            || input.approved_payload_plaintext.is_empty()
            || input.approved_payload_plaintext.len() > MAX_APPROVED_PAYLOAD_BYTES
            || sha256_hex(input.approved_payload_plaintext) != input.approved_payload_sha256
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let protected_review_blob = protect_local(input.approved_review_payload_plaintext)
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let protected_approved_payload_blob = protect_local(input.approved_payload_plaintext)
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let transaction = connection
            .transaction()
            .map_err(|_| PrivacyStoreError::Database)?;
        let risk = Self::append_risk_review_revision(&transaction, &input.risk_revision)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_redactions
                 SET review_state='approved',approved_payload_sha256=?2,
                     reviewed_by_sha256=?3,protected_review_blob=?5,
                     redacted_content_sha256=?6,reviewed_at=CURRENT_TIMESTAMP,
                     approved_at=CURRENT_TIMESTAMP,
                     approved_payload_schema_version=1,
                     protected_approved_payload_blob=?7,
                     approved_payload_protection_scheme=?8,
                     approved_risk_revision_hash=?9,
                     row_version=row_version+1
                 WHERE redaction_id=?1 AND unresolved_high_risk_count=0
                   AND redacted_content_sha256=?4
                   AND review_state='review_required'
                   AND risk_revision=?10
                   AND approved_payload_schema_version IS NULL
                   AND protected_approved_payload_blob IS NULL
                   AND approved_payload_protection_scheme IS NULL
                   AND approved_risk_revision_hash IS NULL",
                params![
                    input.redaction_id,
                    input.approved_payload_sha256,
                    input.reviewed_by_sha256,
                    input.expected_redacted_sha256,
                    protected_review_blob,
                    input.approved_redacted_content_sha256,
                    protected_approved_payload_blob,
                    LOCAL_PROTECTION_SCHEME,
                    risk.revision_hash,
                    i64::try_from(risk.revision).map_err(|_| PrivacyStoreError::InvalidInput)?,
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        transaction
            .execute(
                "UPDATE privacy_materials
                 SET state='approved',updated_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE material_id=(
                    SELECT material_id FROM privacy_redactions WHERE redaction_id=?1
                 )",
                [input.redaction_id],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }

    pub fn persist_receipt(
        connection: &mut Connection,
        redaction_id: &str,
        signer: &ReceiptSigner,
        receipt: &SignedRedactionReceipt,
        signed_token: &str,
        approved_payload: &[u8],
        now_unix: u64,
    ) -> Result<(), PrivacyStoreError> {
        valid_id(redaction_id)?;
        valid_id(&receipt.claims.receipt_id)?;
        if signed_token.len() > MAX_TOKEN_BYTES
            || !signed_token.starts_with("rct_v1.")
            || approved_payload.is_empty()
            || approved_payload.len() > MAX_APPROVED_PAYLOAD_BYTES
            || receipt.claims.review_state != ReviewState::Approved
            || receipt.claims.unresolved_high_risk_count != 0
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let decoded = signer
            .decode_token(signed_token)
            .map_err(|_| PrivacyStoreError::InvalidReceipt)?;
        if decoded != *receipt {
            return Err(PrivacyStoreError::InvalidReceipt);
        }
        let expires_at = receipt
            .claims
            .expires_at_unix
            .ok_or(PrivacyStoreError::InvalidReceipt)?;
        let ttl = expires_at
            .checked_sub(receipt.claims.issued_at_unix)
            .ok_or(PrivacyStoreError::InvalidReceipt)?;
        if ttl > MAX_ACTIVE_RECEIPT_TTL_SECONDS {
            return Err(PrivacyStoreError::InvalidReceipt);
        }
        signer
            .verify(
                receipt,
                &ReceiptVerificationContext {
                    payload: approved_payload,
                    destination: &receipt.claims.destination,
                    purpose: &receipt.claims.purpose,
                    policy_id: &receipt.claims.policy_id,
                    policy_version: receipt.claims.policy_version,
                    detector_version: &receipt.claims.detector_version,
                    now_unix,
                },
            )
            .map_err(map_receipt_error)?;
        let protected_token =
            protect_local(signed_token.as_bytes()).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        if protected_token.len() > MAX_PROTECTED_TOKEN_BYTES {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let issued = i64::try_from(receipt.claims.issued_at_unix)
            .map_err(|_| PrivacyStoreError::InvalidInput)?;
        let expires = i64::try_from(expires_at).map_err(|_| PrivacyStoreError::InvalidInput)?;
        let transaction = connection
            .transaction()
            .map_err(|_| PrivacyStoreError::Database)?;
        let provenance = transaction
            .query_row(
                "SELECT m.source_sha256,r.extraction_sha256,r.redacted_content_sha256,
                        r.approved_payload_sha256,r.policy_id,r.policy_version,
                        r.detector_version,r.unresolved_high_risk_count,r.review_state,m.state
                 FROM privacy_redactions r
                 JOIN privacy_materials m ON m.material_id=r.material_id
                 WHERE r.redaction_id=?1",
                [redaction_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, u32>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, u32>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?
            .ok_or(PrivacyStoreError::NotApproved)?;
        if provenance.7 != 0
            || provenance.8 != "approved"
            || !matches!(provenance.9.as_str(), "approved" | "outbound_ready")
        {
            return Err(PrivacyStoreError::NotApproved);
        }
        if receipt.claims.source_sha256.len() != 1
            || receipt.claims.source_sha256.first() != Some(&provenance.0)
            || receipt.claims.extraction_sha256 != provenance.1
            || receipt.claims.redacted_content_sha256 != provenance.2
            || provenance.3.as_deref() != Some(receipt.claims.approved_payload_sha256.as_str())
            || receipt.claims.policy_id != provenance.4
            || receipt.claims.policy_version != provenance.5
            || receipt.claims.detector_version != provenance.6
        {
            return Err(PrivacyStoreError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO privacy_receipts(
                    receipt_id,redaction_id,signed_token,destination_kind,
                    destination_identifier_sha256,purpose,payload_sha256,
                    policy_id,policy_version,issued_at_unix,expires_at_unix
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    &receipt.claims.receipt_id,
                    redaction_id,
                    &protected_token,
                    destination_kind(&receipt.claims.destination.kind),
                    sha256_hex(receipt.claims.destination.identifier.as_bytes()),
                    &receipt.claims.purpose,
                    &receipt.claims.approved_payload_sha256,
                    &receipt.claims.policy_id,
                    receipt.claims.policy_version,
                    issued,
                    expires,
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .execute(
                "UPDATE privacy_materials
                 SET state='outbound_ready',updated_at=CURRENT_TIMESTAMP,
                     row_version=row_version+1
                 WHERE material_id=(
                    SELECT material_id FROM privacy_redactions WHERE redaction_id=?1
                 )",
                [redaction_id],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }

    pub fn verify_active_receipt_token(
        connection: &Connection,
        signer: &ReceiptSigner,
        verification: &ActiveReceiptVerification<'_>,
    ) -> Result<SignedRedactionReceipt, PrivacyStoreError> {
        valid_id(verification.redaction_id)?;
        valid_id(verification.purpose)?;
        valid_id(&verification.destination.identifier)?;
        if verification.signed_token.len() > MAX_TOKEN_BYTES
            || !verification.signed_token.starts_with("rct_v1.")
            || verification.approved_payload.is_empty()
            || verification.approved_payload.len() > MAX_APPROVED_PAYLOAD_BYTES
            || verification.now_unix == 0
            || verification.expected_key_version == 0
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let receipt = signer
            .decode_token(verification.signed_token)
            .map_err(|_| PrivacyStoreError::InvalidReceipt)?;
        valid_id(&receipt.claims.receipt_id)?;
        if receipt.claims.key_version != verification.expected_key_version {
            return Err(PrivacyStoreError::InvalidReceipt);
        }
        let expires_at = receipt
            .claims
            .expires_at_unix
            .ok_or(PrivacyStoreError::InvalidReceipt)?;
        let ttl = expires_at
            .checked_sub(receipt.claims.issued_at_unix)
            .ok_or(PrivacyStoreError::InvalidReceipt)?;
        if ttl > MAX_ACTIVE_RECEIPT_TTL_SECONDS {
            return Err(PrivacyStoreError::InvalidReceipt);
        }
        let row = connection
            .query_row(
                "SELECT p.signed_token,p.revoked_at_unix,p.consumed_at_unix,m.source_sha256,
                        r.extraction_sha256,r.redacted_content_sha256,
                        r.approved_payload_sha256,r.policy_id,r.policy_version,
                        r.detector_version,r.unresolved_high_risk_count,
                        r.review_state,m.state
                 FROM privacy_receipts p
                 JOIN privacy_redactions r ON r.redaction_id=p.redaction_id
                 JOIN privacy_materials m ON m.material_id=r.material_id
                 WHERE p.receipt_id=?1 AND p.redaction_id=?2",
                params![&receipt.claims.receipt_id, verification.redaction_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, u32>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, u32>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?
            .ok_or(PrivacyStoreError::InvalidReceipt)?;
        if row.1.is_some() {
            return Err(PrivacyStoreError::ReceiptRevoked);
        }
        if row.2.is_some() {
            return Err(PrivacyStoreError::ReceiptConsumed);
        }
        let stored_token = unprotect_local(&row.0).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        if !constant_time_bytes_eq(&stored_token, verification.signed_token.as_bytes()) {
            return Err(PrivacyStoreError::InvalidReceipt);
        }
        if row.10 != 0 || row.11 != "approved" || row.12 != "outbound_ready" {
            return Err(PrivacyStoreError::NotApproved);
        }
        if receipt.claims.source_sha256.len() != 1
            || receipt.claims.source_sha256.first() != Some(&row.3)
            || receipt.claims.extraction_sha256 != row.4
            || receipt.claims.redacted_content_sha256 != row.5
            || row.6.as_deref() != Some(receipt.claims.approved_payload_sha256.as_str())
            || receipt.claims.policy_id != row.7
            || receipt.claims.policy_version != row.8
            || receipt.claims.detector_version != row.9
        {
            return Err(PrivacyStoreError::InvalidReceipt);
        }
        signer
            .verify(
                &receipt,
                &ReceiptVerificationContext {
                    payload: verification.approved_payload,
                    destination: verification.destination,
                    purpose: verification.purpose,
                    policy_id: &row.7,
                    policy_version: row.8,
                    detector_version: &row.9,
                    now_unix: verification.now_unix,
                },
            )
            .map_err(map_receipt_error)?;
        Ok(receipt)
    }

    /// Atomically consumes an already verified approval immediately before the
    /// first external Provider write. Consumption is deliberately irreversible:
    /// a timeout or unknown network result must require a fresh human approval
    /// instead of risking a duplicate disclosure after restart or retry.
    pub fn consume_receipt_for_dispatch(
        connection: &mut Connection,
        receipt_id: &str,
        redaction_id: &str,
        consumption_id: &str,
        now_unix: u64,
    ) -> Result<(), PrivacyStoreError> {
        valid_id(receipt_id)?;
        valid_id(redaction_id)?;
        valid_id(consumption_id)?;
        if now_unix == 0 {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let consumed = i64::try_from(now_unix).map_err(|_| PrivacyStoreError::InvalidInput)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_receipts
                 SET consumed_at_unix=?4,consumption_id=?3
                 WHERE receipt_id=?1 AND redaction_id=?2
                   AND revoked_at_unix IS NULL AND consumed_at_unix IS NULL
                   AND issued_at_unix<=?4 AND expires_at_unix>?4",
                params![receipt_id, redaction_id, consumption_id, consumed],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            let state = transaction
                .query_row(
                    "SELECT revoked_at_unix,consumed_at_unix,issued_at_unix,expires_at_unix
                     FROM privacy_receipts WHERE receipt_id=?1 AND redaction_id=?2",
                    params![receipt_id, redaction_id],
                    |row| {
                        Ok((
                            row.get::<_, Option<i64>>(0)?,
                            row.get::<_, Option<i64>>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| PrivacyStoreError::Database)?;
            return match state {
                None => Err(PrivacyStoreError::InvalidReceipt),
                Some((Some(_), _, _, _)) => Err(PrivacyStoreError::ReceiptRevoked),
                Some((_, Some(_), _, _)) => Err(PrivacyStoreError::ReceiptConsumed),
                Some((_, _, issued_at, _)) if consumed < issued_at => {
                    Err(PrivacyStoreError::InvalidReceipt)
                }
                Some((_, _, _, expires_at)) if consumed >= expires_at => {
                    Err(PrivacyStoreError::ReceiptExpired)
                }
                Some(_) => Err(PrivacyStoreError::Conflict),
            };
        }
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    }

    pub fn revoke_receipt(
        connection: &Connection,
        receipt_id: &str,
        revoked_at_unix: u64,
    ) -> Result<(), PrivacyStoreError> {
        valid_id(receipt_id)?;
        let revoked =
            i64::try_from(revoked_at_unix).map_err(|_| PrivacyStoreError::InvalidInput)?;
        let changed = connection
            .execute(
                "UPDATE privacy_receipts SET revoked_at_unix=?2
                 WHERE receipt_id=?1 AND revoked_at_unix IS NULL",
                params![receipt_id, revoked],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        Ok(())
    }

    pub fn append_egress_audit(
        connection: &mut Connection,
        event_id: &str,
        audit: &PrivacyEgressAuditRecord,
    ) -> Result<String, PrivacyStoreError> {
        let persisted_classification =
            classification(audit.classification).ok_or(PrivacyStoreError::InvalidInput)?;
        valid_id(event_id)?;
        valid_id(&audit.purpose)?;
        valid_hash(&audit.payload_sha256)?;
        valid_hash(&audit.destination_identifier_sha256)?;
        valid_id(&audit.policy_id)?;
        valid_id(&audit.detector_version)?;
        valid_optional_id(audit.receipt_id.as_deref())?;
        valid_id(&audit.reason_code)?;
        let residual = serde_json::to_string(&audit.residual_counts)
            .map_err(|_| PrivacyStoreError::InvalidInput)?;
        if residual.len() > 65_536 {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let occurred =
            i64::try_from(audit.occurred_at_unix).map_err(|_| PrivacyStoreError::InvalidInput)?;
        let payload_bytes =
            i64::try_from(audit.payload_bytes).map_err(|_| PrivacyStoreError::InvalidInput)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
        let previous = transaction
            .query_row(
                "SELECT event_hash FROM privacy_egress_audit ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?
            .unwrap_or_default();
        let canonical = serde_json::to_vec(audit).map_err(|_| PrivacyStoreError::InvalidInput)?;
        let mut chain = Vec::with_capacity(event_id.len() + previous.len() + canonical.len() + 2);
        chain.extend_from_slice(event_id.as_bytes());
        chain.push(0);
        chain.extend_from_slice(previous.as_bytes());
        chain.push(0);
        chain.extend_from_slice(&canonical);
        let event_hash = sha256_hex(&chain);
        transaction
            .execute(
                "INSERT INTO privacy_egress_audit(
                    event_id,occurred_at_unix,classification,destination_kind,
                    destination_identifier_sha256,purpose,payload_sha256,payload_bytes,
                    policy_id,policy_version,detector_version,receipt_id,
                    residual_counts_json,allowed,reason_code,previous_event_hash,event_hash
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
                params![
                    event_id,
                    occurred,
                    persisted_classification,
                    destination_kind(&audit.destination_kind),
                    &audit.destination_identifier_sha256,
                    &audit.purpose,
                    &audit.payload_sha256,
                    payload_bytes,
                    &audit.policy_id,
                    audit.policy_version,
                    &audit.detector_version,
                    &audit.receipt_id,
                    residual,
                    audit.allowed,
                    &audit.reason_code,
                    previous,
                    event_hash,
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)?;
        Ok(event_hash)
    }
}

fn save_review_draft_rows(
    connection: &Connection,
    input: &SaveReviewDraft<'_>,
    protected: &[u8],
) -> Result<(), PrivacyStoreError> {
    connection
        .execute(
            "INSERT INTO privacy_redactions(
                redaction_id,material_id,generation_number,generation_status,
                extraction_sha256,redacted_content_sha256,policy_id,policy_version,
                detector_version,unresolved_high_risk_count,review_state,risk_revision,
                protected_review_blob,protection_scheme
             ) VALUES(
                ?1,?2,
                (SELECT COALESCE(MAX(generation_number),0)+1
                 FROM privacy_redactions WHERE material_id=?2),
                'ready',?3,?4,?5,?6,?7,?8,'review_required',0,?9,?10
             )",
            params![
                input.redaction_id,
                input.material_id,
                input.extraction_sha256,
                input.redacted_content_sha256,
                input.policy_id,
                input.policy_version,
                input.detector_version,
                input.unresolved_high_risk_count,
                protected,
                LOCAL_PROTECTION_SCHEME,
            ],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                PrivacyStoreError::Conflict
            } else {
                PrivacyStoreError::Database
            }
        })?;
    let changed = connection
        .execute(
            "UPDATE privacy_materials
             SET state='review_required',updated_at=CURRENT_TIMESTAMP,
                 row_version=row_version+1
             WHERE material_id=?1",
            [input.material_id],
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    if changed != 1 {
        return Err(PrivacyStoreError::Conflict);
    }
    Ok(())
}

const V5_BASE_SCHEMA_SQL: &str = "
    CREATE TABLE IF NOT EXISTS privacy_schema_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS privacy_materials (
        material_id TEXT PRIMARY KEY CHECK(length(material_id) BETWEEN 1 AND 128),
        project_id TEXT CHECK(project_id IS NULL OR length(project_id) BETWEEN 1 AND 128),
        legacy_case_id TEXT CHECK(
            legacy_case_id IS NULL OR length(legacy_case_id) BETWEEN 1 AND 128
        ),
        attachment_id TEXT CHECK(
            attachment_id IS NULL OR length(attachment_id) BETWEEN 1 AND 128
        ),
        protected_display_name BLOB,
        display_name_sha256 TEXT CHECK(
            display_name_sha256 IS NULL OR length(display_name_sha256) = 64
        ),
        display_name_protection_scheme TEXT,
        source_sha256 TEXT CHECK(source_sha256 IS NULL OR length(source_sha256) = 64),
        source_name_sha256 TEXT CHECK(
            source_name_sha256 IS NULL OR length(source_name_sha256) = 64
        ),
        media_type TEXT CHECK(
            media_type IS NULL OR length(media_type) BETWEEN 1 AND 128
        ),
        page_count INTEGER CHECK(page_count IS NULL OR page_count BETWEEN 0 AND 10000),
        source_kind TEXT NOT NULL CHECK(source_kind IN (
            'vault','local_review','user_attachment','legacy_reference'
        )),
        extraction_status TEXT NOT NULL CHECK(length(extraction_status) BETWEEN 1 AND 128),
        migration_status TEXT NOT NULL CHECK(migration_status IN (
            'ready','unassigned','legacy_reference','blocked'
        )),
        state TEXT NOT NULL CHECK(state IN (
            'registered','assessing','extracting_native','ocr_required','ocr_running',
            'extracted','redacting','review_required','approved','outbound_ready',
            'failed','blocked','stale','revoked'
        )),
        row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        deleted_at TEXT,
        CHECK(
            (protected_display_name IS NULL
             AND display_name_sha256 IS NULL
             AND display_name_protection_scheme IS NULL)
            OR
            (protected_display_name IS NOT NULL
             AND length(protected_display_name) > 0
             AND display_name_sha256 IS NOT NULL
             AND display_name_protection_scheme = 'windows_dpapi_current_user_v1')
        ),
        CHECK(
            source_sha256 IS NOT NULL
            OR migration_status IN ('legacy_reference','blocked')
        ),
        CHECK(
            media_type IS NOT NULL
            OR migration_status IN ('legacy_reference','blocked')
        ),
        CHECK(migration_status <> 'ready' OR project_id IS NOT NULL),
        CHECK(migration_status <> 'unassigned' OR project_id IS NULL)
    );
    CREATE TABLE IF NOT EXISTS privacy_redactions (
        redaction_id TEXT PRIMARY KEY CHECK(length(redaction_id) BETWEEN 1 AND 128),
        material_id TEXT NOT NULL,
        generation_number INTEGER NOT NULL CHECK(generation_number > 0),
        generation_status TEXT NOT NULL DEFAULT 'ready' CHECK(
            generation_status IN ('ready','blocked','legacy_id')
        ),
        extraction_sha256 TEXT NOT NULL CHECK(length(extraction_sha256) = 64),
        redacted_content_sha256 TEXT NOT NULL CHECK(length(redacted_content_sha256) = 64),
        approved_payload_sha256 TEXT CHECK(
            approved_payload_sha256 IS NULL OR length(approved_payload_sha256) = 64
        ),
        approved_payload_schema_version INTEGER CHECK(
            approved_payload_schema_version IS NULL
            OR approved_payload_schema_version = 1
        ),
        protected_approved_payload_blob BLOB CHECK(
            protected_approved_payload_blob IS NULL
            OR length(protected_approved_payload_blob) > 0
        ),
        approved_payload_protection_scheme TEXT CHECK(
            approved_payload_protection_scheme IS NULL
            OR approved_payload_protection_scheme = 'windows_dpapi_current_user_v1'
        ),
        approved_risk_revision_hash TEXT CHECK(
            approved_risk_revision_hash IS NULL
            OR length(approved_risk_revision_hash) = 64
        ),
        policy_id TEXT NOT NULL CHECK(length(policy_id) BETWEEN 1 AND 128),
        policy_version INTEGER NOT NULL CHECK(policy_version > 0),
        detector_version TEXT NOT NULL CHECK(length(detector_version) BETWEEN 1 AND 128),
        unresolved_high_risk_count INTEGER NOT NULL CHECK(unresolved_high_risk_count >= 0),
        review_state TEXT NOT NULL CHECK(
            review_state IN ('review_required','approved','revoked','stale')
        ),
        risk_revision INTEGER NOT NULL DEFAULT 0 CHECK(risk_revision >= 0),
        protected_review_blob BLOB NOT NULL CHECK(length(protected_review_blob) > 0),
        protection_scheme TEXT NOT NULL CHECK(
            protection_scheme = 'windows_dpapi_current_user_v1'
        ),
        reviewed_by_sha256 TEXT CHECK(
            reviewed_by_sha256 IS NULL OR length(reviewed_by_sha256) = 64
        ),
        approved_at TEXT,
        revocation_state TEXT NOT NULL DEFAULT 'active' CHECK(
            revocation_state IN ('active','revoked','revoked_legacy_time_unknown')
        ),
        revoked_at TEXT,
        row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        reviewed_at TEXT,
        CHECK(
            (revocation_state = 'active' AND revoked_at IS NULL)
            OR (revocation_state = 'revoked' AND revoked_at IS NOT NULL)
            OR (revocation_state = 'revoked_legacy_time_unknown' AND revoked_at IS NULL)
        ),
        CHECK(
            (
                approved_payload_schema_version IS NULL
                AND protected_approved_payload_blob IS NULL
                AND approved_payload_protection_scheme IS NULL
                AND approved_risk_revision_hash IS NULL
            )
            OR
            (
                approved_payload_schema_version = 1
                AND protected_approved_payload_blob IS NOT NULL
                AND approved_payload_protection_scheme =
                    'windows_dpapi_current_user_v1'
                AND approved_risk_revision_hash IS NOT NULL
            )
        ),
        CHECK(
            review_state <> 'approved'
            OR generation_status <> 'ready'
            OR revocation_state <> 'active'
            OR (
                approved_payload_sha256 IS NOT NULL
                AND approved_payload_schema_version = 1
                AND protected_approved_payload_blob IS NOT NULL
                AND approved_payload_protection_scheme =
                    'windows_dpapi_current_user_v1'
                AND approved_risk_revision_hash IS NOT NULL
                AND risk_revision > 0
                AND unresolved_high_risk_count = 0
            )
        ),
        CHECK(
            approved_payload_schema_version IS NULL
            OR (
                review_state = 'approved'
                AND generation_status = 'ready'
                AND revocation_state IN ('active','revoked')
                AND approved_payload_sha256 IS NOT NULL
                AND approved_payload_schema_version = 1
                AND protected_approved_payload_blob IS NOT NULL
                AND approved_payload_protection_scheme =
                    'windows_dpapi_current_user_v1'
                AND approved_risk_revision_hash IS NOT NULL
                AND risk_revision > 0
                AND unresolved_high_risk_count = 0
            )
        ),
        FOREIGN KEY(material_id)
            REFERENCES privacy_materials(material_id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS privacy_risk_review_revisions (
        redaction_id TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK(revision > 0),
        state_sha256 TEXT NOT NULL CHECK(length(state_sha256) = 64),
        risk_sha256 TEXT NOT NULL CHECK(length(risk_sha256) = 64),
        hard_gate_sha256 TEXT NOT NULL CHECK(length(hard_gate_sha256) = 64),
        action_code TEXT NOT NULL CHECK(length(action_code) BETWEEN 1 AND 128),
        reason_codes_json TEXT NOT NULL CHECK(
            json_valid(reason_codes_json)
            AND json_type(reason_codes_json) = 'array'
            AND length(reason_codes_json) <= 65536
        ),
        protected_state_blob BLOB NOT NULL CHECK(length(protected_state_blob) > 0),
        protection_scheme TEXT NOT NULL CHECK(
            protection_scheme = 'windows_dpapi_current_user_v1'
        ),
        previous_revision_hash TEXT NOT NULL CHECK(length(previous_revision_hash) IN (0,64)),
        revision_hash TEXT NOT NULL UNIQUE CHECK(length(revision_hash) = 64),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(redaction_id, revision),
        FOREIGN KEY(redaction_id)
            REFERENCES privacy_redactions(redaction_id) ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS idx_privacy_risk_review_latest
        ON privacy_risk_review_revisions(redaction_id, revision DESC);
    CREATE TRIGGER IF NOT EXISTS trg_privacy_risk_review_no_update
    BEFORE UPDATE ON privacy_risk_review_revisions BEGIN
        SELECT RAISE(ABORT, 'privacy risk review revisions are append only');
    END;
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
        consumed_at_unix INTEGER CHECK(
            consumed_at_unix IS NULL OR consumed_at_unix > 0
        ),
        consumption_id TEXT CHECK(
            consumption_id IS NULL OR length(consumption_id) BETWEEN 1 AND 128
        ),
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
";

const V5_UNIFIED_SCHEMA_SQL: &str = "
    CREATE INDEX IF NOT EXISTS idx_privacy_materials_project
        ON privacy_materials(project_id, migration_status, updated_at);
    CREATE INDEX IF NOT EXISTS idx_privacy_materials_migration
        ON privacy_materials(migration_status, source_kind, updated_at);
    CREATE INDEX IF NOT EXISTS idx_privacy_materials_display_name_hash
        ON privacy_materials(display_name_sha256);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_privacy_redactions_generation
        ON privacy_redactions(material_id, generation_number);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_privacy_redactions_identity_material
        ON privacy_redactions(redaction_id, material_id);
    CREATE INDEX IF NOT EXISTS idx_privacy_redactions_material
        ON privacy_redactions(material_id, generation_number);

    CREATE TRIGGER IF NOT EXISTS trg_privacy_material_row_version
    BEFORE UPDATE ON privacy_materials
    WHEN NEW.row_version <> OLD.row_version + 1
    BEGIN
        SELECT RAISE(ABORT, 'privacy material row version must advance exactly once');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_privacy_material_legacy_case_immutable
    BEFORE UPDATE ON privacy_materials
    WHEN OLD.legacy_case_id IS NOT NULL
         AND NEW.legacy_case_id IS NOT OLD.legacy_case_id
    BEGIN
        SELECT RAISE(ABORT, 'legacy case migration evidence is immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_privacy_material_approved_source_immutable
    BEFORE UPDATE ON privacy_materials
    WHEN EXISTS(
        SELECT 1 FROM privacy_redactions
        WHERE material_id=OLD.material_id AND review_state='approved'
    )
    AND (
        NEW.source_sha256 IS NOT OLD.source_sha256
        OR NEW.source_kind IS NOT OLD.source_kind
    )
    BEGIN
        SELECT RAISE(ABORT, 'approved generation source identity is immutable');
    END;

    CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_row_version
    BEFORE UPDATE ON privacy_redactions
    WHEN NEW.row_version <> OLD.row_version + 1
    BEGIN
        SELECT RAISE(ABORT, 'redaction generation row version must advance exactly once');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_generation_immutable
    BEFORE UPDATE ON privacy_redactions
    WHEN NEW.redaction_id IS NOT OLD.redaction_id
         OR NEW.material_id IS NOT OLD.material_id
         OR NEW.generation_number IS NOT OLD.generation_number
    BEGIN
        SELECT RAISE(ABORT, 'redaction generation identity is immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_approved_immutable
    BEFORE UPDATE ON privacy_redactions
    WHEN OLD.review_state='approved'
    AND (
        NEW.review_state IS NOT OLD.review_state
        OR NEW.extraction_sha256 IS NOT OLD.extraction_sha256
        OR NEW.redacted_content_sha256 IS NOT OLD.redacted_content_sha256
        OR NEW.approved_payload_sha256 IS NOT OLD.approved_payload_sha256
        OR NEW.policy_id IS NOT OLD.policy_id
        OR NEW.policy_version IS NOT OLD.policy_version
        OR NEW.detector_version IS NOT OLD.detector_version
        OR NEW.risk_revision IS NOT OLD.risk_revision
        OR NEW.protected_review_blob IS NOT OLD.protected_review_blob
        OR NEW.protection_scheme IS NOT OLD.protection_scheme
        OR NEW.reviewed_by_sha256 IS NOT OLD.reviewed_by_sha256
        OR NEW.approved_at IS NOT OLD.approved_at
        OR NEW.reviewed_at IS NOT OLD.reviewed_at
    )
    BEGIN
        SELECT RAISE(ABORT, 'approved redaction generation content is immutable');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_revocation_transition
    BEFORE UPDATE ON privacy_redactions
    WHEN (
        NEW.revocation_state IS NOT OLD.revocation_state
        OR NEW.revoked_at IS NOT OLD.revoked_at
    )
    AND NOT (
        OLD.revocation_state='active'
        AND OLD.revoked_at IS NULL
        AND NEW.revocation_state='revoked'
        AND NEW.revoked_at IS NOT NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'redaction generation revocation is one way');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_privacy_risk_review_project_revision
    AFTER INSERT ON privacy_risk_review_revisions
    BEGIN
        UPDATE privacy_redactions
        SET risk_revision=NEW.revision,row_version=row_version+1
        WHERE redaction_id=NEW.redaction_id
          AND review_state='review_required'
          AND risk_revision=NEW.revision-1;
        SELECT CASE WHEN changes() <> 1
            THEN RAISE(ABORT, 'risk revision projection conflict')
        END;
    END;

    CREATE TABLE IF NOT EXISTS case_material_selections (
        selection_id TEXT PRIMARY KEY CHECK(length(selection_id) BETWEEN 1 AND 128),
        project_id TEXT NOT NULL CHECK(length(project_id) BETWEEN 1 AND 128),
        material_id TEXT NOT NULL CHECK(length(material_id) BETWEEN 1 AND 128),
        redaction_id TEXT NOT NULL CHECK(length(redaction_id) BETWEEN 1 AND 128),
        purpose TEXT NOT NULL CHECK(length(purpose) BETWEEN 1 AND 128),
        selected_by_user INTEGER NOT NULL CHECK(selected_by_user = 1),
        selected_at TEXT NOT NULL CHECK(length(selected_at) > 0),
        selected_generation_number INTEGER NOT NULL CHECK(selected_generation_number > 0),
        selected_approved_payload_sha256 TEXT NOT NULL CHECK(
            length(selected_approved_payload_sha256) = 64
        ),
        selected_risk_revision INTEGER NOT NULL CHECK(selected_risk_revision > 0),
        deselected_at TEXT,
        invalidated_at TEXT,
        invalidation_reason TEXT CHECK(
            invalidation_reason IS NULL OR length(invalidation_reason) BETWEEN 1 AND 128
        ),
        row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
        CHECK(NOT(deselected_at IS NOT NULL AND invalidated_at IS NOT NULL)),
        CHECK(
            (invalidated_at IS NULL AND invalidation_reason IS NULL)
            OR (invalidated_at IS NOT NULL AND invalidation_reason IS NOT NULL)
        )
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_case_material_selection_active
        ON case_material_selections(project_id, material_id, purpose)
        WHERE deselected_at IS NULL AND invalidated_at IS NULL;
    CREATE INDEX IF NOT EXISTS idx_case_material_selection_generation
        ON case_material_selections(redaction_id, selected_generation_number);
    CREATE TRIGGER IF NOT EXISTS trg_case_material_selection_validate_insert
    BEFORE INSERT ON case_material_selections
    WHEN NOT EXISTS(
        SELECT 1
        FROM privacy_materials AS material
        JOIN privacy_redactions AS generation
          ON generation.material_id=material.material_id
        WHERE material.material_id=NEW.material_id
          AND material.project_id=NEW.project_id
          AND material.migration_status='ready'
          AND material.deleted_at IS NULL
          AND generation.redaction_id=NEW.redaction_id
          AND generation.generation_number=NEW.selected_generation_number
          AND generation.generation_status='ready'
          AND generation.review_state='approved'
          AND generation.approved_payload_sha256=NEW.selected_approved_payload_sha256
          AND generation.risk_revision=NEW.selected_risk_revision
          AND generation.revocation_state='active'
          AND generation.revoked_at IS NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'case material selection target is not eligible');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_selection_one_way_update
    BEFORE UPDATE ON case_material_selections
    WHEN NEW.selection_id IS NOT OLD.selection_id
      OR NEW.project_id IS NOT OLD.project_id
      OR NEW.material_id IS NOT OLD.material_id
      OR NEW.redaction_id IS NOT OLD.redaction_id
      OR NEW.purpose IS NOT OLD.purpose
      OR NEW.selected_by_user IS NOT OLD.selected_by_user
      OR NEW.selected_at IS NOT OLD.selected_at
      OR NEW.selected_generation_number IS NOT OLD.selected_generation_number
      OR NEW.selected_approved_payload_sha256 IS NOT OLD.selected_approved_payload_sha256
      OR NEW.selected_risk_revision IS NOT OLD.selected_risk_revision
      OR OLD.deselected_at IS NOT NULL
      OR OLD.invalidated_at IS NOT NULL
      OR NEW.row_version <> OLD.row_version + 1
      OR NOT(
          (NEW.deselected_at IS NOT NULL
           AND NEW.invalidated_at IS NULL
           AND NEW.invalidation_reason IS NULL)
          OR
          (NEW.deselected_at IS NULL
           AND NEW.invalidated_at IS NOT NULL
           AND NEW.invalidation_reason IS NOT NULL)
      )
    BEGIN
        SELECT RAISE(ABORT, 'case material selection history is append preserving');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_selection_no_delete
    BEFORE DELETE ON case_material_selections
    BEGIN
        SELECT RAISE(ABORT, 'case material selection history is append preserving');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_active_selection_no_material_delete
    BEFORE DELETE ON privacy_materials
    WHEN EXISTS(
        SELECT 1 FROM case_material_selections
        WHERE material_id=OLD.material_id
          AND deselected_at IS NULL
          AND invalidated_at IS NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'active case material selection must be invalidated first');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_active_selection_no_generation_delete
    BEFORE DELETE ON privacy_redactions
    WHEN EXISTS(
        SELECT 1 FROM case_material_selections
        WHERE redaction_id=OLD.redaction_id
          AND deselected_at IS NULL
          AND invalidated_at IS NULL
    )
    BEGIN
        SELECT RAISE(ABORT, 'active case material selection must be invalidated first');
    END;

    CREATE TABLE IF NOT EXISTS case_material_migration_ledger (
        migration_id TEXT NOT NULL CHECK(length(migration_id) BETWEEN 1 AND 128),
        source_store TEXT NOT NULL CHECK(length(source_store) BETWEEN 1 AND 128),
        source_table TEXT NOT NULL CHECK(length(source_table) BETWEEN 1 AND 128),
        source_key TEXT NOT NULL CHECK(length(source_key) BETWEEN 1 AND 256),
        source_fingerprint TEXT NOT NULL CHECK(length(source_fingerprint) = 64),
        target_material_id TEXT NOT NULL CHECK(length(target_material_id) BETWEEN 1 AND 128),
        target_redaction_id TEXT CHECK(
            target_redaction_id IS NULL OR length(target_redaction_id) BETWEEN 1 AND 128
        ),
        assigned_generation_number INTEGER CHECK(
            assigned_generation_number IS NULL OR assigned_generation_number > 0
        ),
        result_state TEXT NOT NULL CHECK(
            result_state IN ('migrated','legacy_reference','blocked')
        ),
        error_code TEXT CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
        started_at TEXT NOT NULL CHECK(length(started_at) > 0),
        completed_at TEXT NOT NULL CHECK(length(completed_at) > 0),
        PRIMARY KEY(migration_id, source_store, source_table, source_key)
    );
    CREATE INDEX IF NOT EXISTS idx_case_material_migration_target
        ON case_material_migration_ledger(target_material_id, target_redaction_id);
    CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_ledger_no_update
    BEFORE UPDATE ON case_material_migration_ledger
    BEGIN
        SELECT RAISE(ABORT, 'case material migration ledger is append only');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_ledger_no_delete
    BEFORE DELETE ON case_material_migration_ledger
    BEGIN
        SELECT RAISE(ABORT, 'case material migration ledger is append only');
    END;

    CREATE TABLE IF NOT EXISTS case_material_migration_events (
        migration_event_id TEXT PRIMARY KEY CHECK(
            length(migration_event_id) BETWEEN 1 AND 128
        ),
        migration_id TEXT NOT NULL,
        source_store TEXT NOT NULL,
        source_table TEXT NOT NULL,
        source_key TEXT NOT NULL,
        event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 128),
        source_fingerprint TEXT CHECK(
            source_fingerprint IS NULL OR length(source_fingerprint) = 64
        ),
        target_material_id TEXT CHECK(
            target_material_id IS NULL OR length(target_material_id) BETWEEN 1 AND 128
        ),
        target_redaction_id TEXT CHECK(
            target_redaction_id IS NULL OR length(target_redaction_id) BETWEEN 1 AND 128
        ),
        assigned_generation_number INTEGER CHECK(
            assigned_generation_number IS NULL OR assigned_generation_number > 0
        ),
        result_state TEXT CHECK(
            result_state IS NULL OR result_state IN ('migrated','legacy_reference','blocked')
        ),
        error_code TEXT CHECK(error_code IS NULL OR length(error_code) BETWEEN 1 AND 128),
        occurred_at TEXT NOT NULL CHECK(length(occurred_at) > 0),
        FOREIGN KEY(migration_id, source_store, source_table, source_key)
          REFERENCES case_material_migration_ledger(
              migration_id, source_store, source_table, source_key
          )
    );
    CREATE INDEX IF NOT EXISTS idx_case_material_migration_events_source
        ON case_material_migration_events(
            migration_id, source_store, source_table, source_key, occurred_at
        );
    CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_events_no_update
    BEFORE UPDATE ON case_material_migration_events
    BEGIN
        SELECT RAISE(ABORT, 'case material migration events are append only');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_events_no_delete
    BEFORE DELETE ON case_material_migration_events
    BEGIN
        SELECT RAISE(ABORT, 'case material migration events are append only');
    END;

    CREATE TABLE IF NOT EXISTS case_material_legacy_references (
        legacy_reference_id TEXT PRIMARY KEY CHECK(
            length(legacy_reference_id) BETWEEN 1 AND 128
        ),
        material_id TEXT NOT NULL CHECK(length(material_id) BETWEEN 1 AND 128),
        migration_id TEXT NOT NULL CHECK(length(migration_id) BETWEEN 1 AND 128),
        source_store TEXT NOT NULL CHECK(length(source_store) BETWEEN 1 AND 128),
        source_table TEXT NOT NULL CHECK(length(source_table) BETWEEN 1 AND 128),
        source_key TEXT NOT NULL CHECK(length(source_key) BETWEEN 1 AND 256),
        protected_storage_reference_blob BLOB NOT NULL CHECK(
            length(protected_storage_reference_blob) > 0
        ),
        storage_reference_sha256 TEXT NOT NULL CHECK(
            length(storage_reference_sha256) = 64
        ),
        protection_scheme TEXT NOT NULL CHECK(
            protection_scheme = 'windows_dpapi_current_user_v1'
        ),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(migration_id, source_store, source_table, source_key)
    );
    CREATE INDEX IF NOT EXISTS idx_case_material_legacy_reference_material
        ON case_material_legacy_references(material_id);
    CREATE TRIGGER IF NOT EXISTS trg_case_material_legacy_reference_validate
    BEFORE INSERT ON case_material_legacy_references
    WHEN NOT EXISTS(
        SELECT 1 FROM privacy_materials
        WHERE material_id=NEW.material_id
          AND source_kind='legacy_reference'
          AND migration_status IN ('legacy_reference','blocked')
    )
    BEGIN
        SELECT RAISE(ABORT, 'legacy reference material is not isolated');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_legacy_reference_no_update
    BEFORE UPDATE ON case_material_legacy_references
    BEGIN
        SELECT RAISE(ABORT, 'legacy references are append only');
    END;
    CREATE TRIGGER IF NOT EXISTS trg_case_material_legacy_reference_no_delete
    BEFORE DELETE ON case_material_legacy_references
    BEGIN
        SELECT RAISE(ABORT, 'legacy references are append only');
    END;
";

const V5_APPEND_ONLY_TRIGGER_SQL: &[(&str, &str)] = &[
    (
        "trg_case_material_migration_ledger_no_update",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_ledger_no_update
         BEFORE UPDATE ON case_material_migration_ledger
         BEGIN
             SELECT RAISE(ABORT, 'case material migration ledger is append only');
         END;",
    ),
    (
        "trg_case_material_migration_ledger_no_delete",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_ledger_no_delete
         BEFORE DELETE ON case_material_migration_ledger
         BEGIN
             SELECT RAISE(ABORT, 'case material migration ledger is append only');
         END;",
    ),
    (
        "trg_case_material_migration_ledger_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_ledger_no_replace
         BEFORE INSERT ON case_material_migration_ledger
         WHEN EXISTS(
             SELECT 1 FROM case_material_migration_ledger AS existing
             WHERE existing.migration_id=NEW.migration_id
               AND existing.source_store=NEW.source_store
               AND existing.source_table=NEW.source_table
               AND existing.source_key=NEW.source_key
         )
         BEGIN
             SELECT RAISE(ABORT, 'case material migration ledger is append only');
         END;",
    ),
    (
        "trg_case_material_migration_events_no_update",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_events_no_update
         BEFORE UPDATE ON case_material_migration_events
         BEGIN
             SELECT RAISE(ABORT, 'case material migration events are append only');
         END;",
    ),
    (
        "trg_case_material_migration_events_no_delete",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_events_no_delete
         BEFORE DELETE ON case_material_migration_events
         BEGIN
             SELECT RAISE(ABORT, 'case material migration events are append only');
         END;",
    ),
    (
        "trg_case_material_migration_events_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_events_no_replace
         BEFORE INSERT ON case_material_migration_events
         WHEN EXISTS(
             SELECT 1 FROM case_material_migration_events AS existing
             WHERE existing.migration_event_id=NEW.migration_event_id
         )
         BEGIN
             SELECT RAISE(ABORT, 'case material migration events are append only');
         END;",
    ),
    (
        "trg_case_material_legacy_reference_validate",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_legacy_reference_validate
         BEFORE INSERT ON case_material_legacy_references
         WHEN NOT EXISTS(
             SELECT 1 FROM privacy_materials
             WHERE material_id=NEW.material_id
               AND source_kind='legacy_reference'
               AND migration_status IN ('legacy_reference','blocked')
         )
         BEGIN
             SELECT RAISE(ABORT, 'legacy reference material is not isolated');
         END;",
    ),
    (
        "trg_case_material_legacy_reference_no_update",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_legacy_reference_no_update
         BEFORE UPDATE ON case_material_legacy_references
         BEGIN
             SELECT RAISE(ABORT, 'legacy references are append only');
         END;",
    ),
    (
        "trg_case_material_legacy_reference_no_delete",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_legacy_reference_no_delete
         BEFORE DELETE ON case_material_legacy_references
         BEGIN
             SELECT RAISE(ABORT, 'legacy references are append only');
         END;",
    ),
    (
        "trg_case_material_legacy_reference_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_legacy_reference_no_replace
         BEFORE INSERT ON case_material_legacy_references
         WHEN EXISTS(
             SELECT 1 FROM case_material_legacy_references AS existing
             WHERE existing.legacy_reference_id=NEW.legacy_reference_id
                OR (
                  existing.migration_id=NEW.migration_id
                  AND existing.source_store=NEW.source_store
                  AND existing.source_table=NEW.source_table
                  AND existing.source_key=NEW.source_key
                )
         )
         BEGIN
             SELECT RAISE(ABORT, 'legacy references are append only');
         END;",
    ),
];

const PROJECTION_MIGRATION_GUARD_SQL: &[(&str, &str)] = &[
    (
        "trg_privacy_v6_approval_blocked",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_v6_approval_blocked
         BEFORE UPDATE ON privacy_redactions
         WHEN OLD.review_state <> 'approved' AND NEW.review_state = 'approved'
         BEGIN
             SELECT RAISE(ABORT, 'approved projection migration is incomplete');
         END;",
    ),
    (
        "trg_privacy_risk_review_no_delete",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_risk_review_no_delete
         BEFORE DELETE ON privacy_risk_review_revisions
         WHEN NOT EXISTS(
             SELECT 1
             FROM privacy_cleanup_candidates AS candidate
             JOIN privacy_cleanup_journal AS journal
               ON journal.cleanup_id=candidate.cleanup_id
             JOIN privacy_cleanup_redaction_evidence AS evidence
               ON evidence.cleanup_id=candidate.cleanup_id
              AND evidence.redaction_id=candidate.target_id
             WHERE candidate.target_kind='redaction'
               AND candidate.target_id=OLD.redaction_id
               AND candidate.state='pending'
               AND journal.state='prepared'
               AND journal.candidate_count>0
               AND evidence.expected_sha256=candidate.expected_sha256
         )
         BEGIN
             SELECT RAISE(ABORT, 'privacy risk review revisions are append only');
         END;",
    ),
    (
        "trg_privacy_risk_review_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_risk_review_no_replace
         BEFORE INSERT ON privacy_risk_review_revisions
         WHEN EXISTS(
             SELECT 1 FROM privacy_risk_review_revisions AS existing
             WHERE existing.redaction_id=NEW.redaction_id
               AND existing.revision=NEW.revision
         )
         BEGIN
             SELECT RAISE(ABORT, 'privacy risk review revisions are append only');
         END;",
    ),
    (
        "trg_case_material_selection_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_selection_no_replace
         BEFORE INSERT ON case_material_selections
         WHEN EXISTS(
             SELECT 1 FROM case_material_selections AS existing
             WHERE existing.selection_id=NEW.selection_id
         )
         BEGIN
             SELECT RAISE(ABORT, 'case material selection history is append preserving');
         END;",
    ),
];

const V6_SECURITY_TRIGGER_SQL: &[(&str, &str)] = &[
    (
        "trg_privacy_redaction_approved_immutable",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_approved_immutable
         BEFORE UPDATE ON privacy_redactions
         WHEN OLD.review_state='approved'
         AND (
             NEW.review_state IS NOT OLD.review_state
             OR NEW.extraction_sha256 IS NOT OLD.extraction_sha256
             OR NEW.redacted_content_sha256 IS NOT OLD.redacted_content_sha256
             OR NEW.approved_payload_sha256 IS NOT OLD.approved_payload_sha256
             OR NEW.approved_payload_schema_version
                IS NOT OLD.approved_payload_schema_version
             OR NEW.protected_approved_payload_blob
                IS NOT OLD.protected_approved_payload_blob
             OR NEW.approved_payload_protection_scheme
                IS NOT OLD.approved_payload_protection_scheme
             OR NEW.approved_risk_revision_hash IS NOT OLD.approved_risk_revision_hash
             OR NEW.policy_id IS NOT OLD.policy_id
             OR NEW.policy_version IS NOT OLD.policy_version
             OR NEW.detector_version IS NOT OLD.detector_version
             OR NEW.risk_revision IS NOT OLD.risk_revision
             OR NEW.protected_review_blob IS NOT OLD.protected_review_blob
             OR NEW.protection_scheme IS NOT OLD.protection_scheme
             OR NEW.reviewed_by_sha256 IS NOT OLD.reviewed_by_sha256
             OR NEW.approved_at IS NOT OLD.approved_at
             OR NEW.reviewed_at IS NOT OLD.reviewed_at
         )
         BEGIN
             SELECT RAISE(ABORT, 'approved redaction generation content is immutable');
         END;",
    ),
    (
        "trg_privacy_redaction_projection_shape_insert",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_projection_shape_insert
         BEFORE INSERT ON privacy_redactions
         WHEN (
             (
               (NEW.approved_payload_schema_version IS NULL)
               + (NEW.protected_approved_payload_blob IS NULL)
               + (NEW.approved_payload_protection_scheme IS NULL)
               + (NEW.approved_risk_revision_hash IS NULL)
             ) NOT IN (0,4)
             OR (
               NEW.review_state='approved' AND NEW.generation_status='ready'
               AND NEW.revocation_state='active' AND NEW.revoked_at IS NULL
               AND NEW.approved_payload_schema_version IS NULL
             )
             OR (
               NEW.approved_payload_schema_version IS NOT NULL
               AND (
                 NEW.review_state <> 'approved'
                 OR NEW.generation_status <> 'ready'
                 OR NOT (
                   (NEW.revocation_state='active' AND NEW.revoked_at IS NULL)
                   OR (NEW.revocation_state='revoked' AND NEW.revoked_at IS NOT NULL)
                 )
                 OR NEW.approved_payload_sha256 IS NULL
                 OR NEW.approved_payload_schema_version <> 1
                 OR NEW.protected_approved_payload_blob IS NULL
                 OR NEW.approved_payload_protection_scheme <>
                    'windows_dpapi_current_user_v1'
                 OR NEW.approved_risk_revision_hash IS NULL
                 OR NEW.risk_revision <= 0
                 OR NEW.unresolved_high_risk_count <> 0
               )
             )
         )
         BEGIN
             SELECT RAISE(ABORT, 'approved projection tuple is invalid');
         END;",
    ),
    (
        "trg_privacy_redaction_projection_shape_update",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_projection_shape_update
         BEFORE UPDATE ON privacy_redactions
         WHEN (
             (
               (NEW.approved_payload_schema_version IS NULL)
               + (NEW.protected_approved_payload_blob IS NULL)
               + (NEW.approved_payload_protection_scheme IS NULL)
               + (NEW.approved_risk_revision_hash IS NULL)
             ) NOT IN (0,4)
             OR (
               NEW.review_state='approved' AND NEW.generation_status='ready'
               AND NEW.revocation_state='active' AND NEW.revoked_at IS NULL
               AND NEW.approved_payload_schema_version IS NULL
             )
             OR (
               NEW.approved_payload_schema_version IS NOT NULL
               AND (
                 NEW.review_state <> 'approved'
                 OR NEW.generation_status <> 'ready'
                 OR NOT (
                   (NEW.revocation_state='active' AND NEW.revoked_at IS NULL)
                   OR (NEW.revocation_state='revoked' AND NEW.revoked_at IS NOT NULL)
                 )
                 OR NEW.approved_payload_sha256 IS NULL
                 OR NEW.approved_payload_schema_version <> 1
                 OR NEW.protected_approved_payload_blob IS NULL
                 OR NEW.approved_payload_protection_scheme <>
                    'windows_dpapi_current_user_v1'
                 OR NEW.approved_risk_revision_hash IS NULL
                 OR NEW.risk_revision <= 0
                 OR NEW.unresolved_high_risk_count <> 0
               )
             )
         )
         BEGIN
             SELECT RAISE(ABORT, 'approved projection tuple is invalid');
         END;",
    ),
    (
        "trg_privacy_redaction_projection_no_delete",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_projection_no_delete
         BEFORE DELETE ON privacy_redactions
         WHEN OLD.approved_payload_schema_version IS NOT NULL
         AND NOT EXISTS(
             SELECT 1
             FROM privacy_cleanup_candidates AS candidate
             JOIN privacy_cleanup_journal AS journal
               ON journal.cleanup_id=candidate.cleanup_id
             JOIN privacy_cleanup_redaction_evidence AS evidence
               ON evidence.cleanup_id=candidate.cleanup_id
              AND evidence.redaction_id=candidate.target_id
             WHERE candidate.target_kind='redaction'
               AND candidate.target_id=OLD.redaction_id
               AND candidate.state='pending'
               AND journal.state='prepared'
               AND journal.candidate_count>0
               AND evidence.redaction_id=OLD.redaction_id
               AND evidence.material_id=OLD.material_id
               AND evidence.generation_number=OLD.generation_number
               AND evidence.expected_sha256=candidate.expected_sha256
         )
         BEGIN
             SELECT RAISE(ABORT, 'approved projection is append preserving');
         END;",
    ),
    (
        "trg_privacy_redaction_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_redaction_no_replace
         BEFORE INSERT ON privacy_redactions
         WHEN EXISTS(
             SELECT 1 FROM privacy_redactions AS existing
             WHERE existing.redaction_id=NEW.redaction_id
         )
         BEGIN
             SELECT RAISE(ABORT, 'redaction generation identity is append preserving');
         END;",
    ),
    (
        "trg_privacy_risk_review_no_delete",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_risk_review_no_delete
         BEFORE DELETE ON privacy_risk_review_revisions
         WHEN NOT EXISTS(
             SELECT 1
             FROM privacy_cleanup_candidates AS candidate
             JOIN privacy_cleanup_journal AS journal
               ON journal.cleanup_id=candidate.cleanup_id
             JOIN privacy_cleanup_redaction_evidence AS evidence
               ON evidence.cleanup_id=candidate.cleanup_id
              AND evidence.redaction_id=candidate.target_id
             WHERE candidate.target_kind='redaction'
               AND candidate.target_id=OLD.redaction_id
               AND candidate.state='pending'
               AND journal.state='prepared'
               AND journal.candidate_count>0
               AND evidence.expected_sha256=candidate.expected_sha256
         )
         BEGIN
             SELECT RAISE(ABORT, 'privacy risk review revisions are append only');
         END;",
    ),
    (
        "trg_privacy_risk_review_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_privacy_risk_review_no_replace
         BEFORE INSERT ON privacy_risk_review_revisions
         WHEN EXISTS(
             SELECT 1 FROM privacy_risk_review_revisions AS existing
             WHERE existing.redaction_id=NEW.redaction_id
               AND existing.revision=NEW.revision
         )
         BEGIN
             SELECT RAISE(ABORT, 'privacy risk review revisions are append only');
         END;",
    ),
    (
        "trg_case_material_selection_no_replace",
        "CREATE TRIGGER IF NOT EXISTS trg_case_material_selection_no_replace
         BEFORE INSERT ON case_material_selections
         WHEN EXISTS(
             SELECT 1 FROM case_material_selections AS existing
             WHERE existing.selection_id=NEW.selection_id
         )
         BEGIN
             SELECT RAISE(ABORT, 'case material selection history is append preserving');
         END;",
    ),
];

fn configure_v6_connection(connection: &Connection) -> Result<(), PrivacyStoreError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| PrivacyStoreError::Database)?;
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .map_err(|_| PrivacyStoreError::Database)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| PrivacyStoreError::Database)
}

fn install_projection_migration_guards(connection: &Connection) -> Result<(), PrivacyStoreError> {
    for (_, sql) in PROJECTION_MIGRATION_GUARD_SQL {
        connection
            .execute_batch(sql)
            .map_err(|_| PrivacyStoreError::Database)?;
    }
    Ok(())
}

fn install_v6_security_triggers(connection: &Connection) -> Result<(), PrivacyStoreError> {
    for (name, sql) in V6_SECURITY_TRIGGER_SQL {
        connection
            .execute_batch(&format!("DROP TRIGGER IF EXISTS {name};"))
            .map_err(|_| PrivacyStoreError::Database)?;
        connection
            .execute_batch(sql)
            .map_err(|_| PrivacyStoreError::Database)?;
    }
    Ok(())
}

fn ensure_v5_append_only_insert_guards(connection: &Connection) -> Result<(), PrivacyStoreError> {
    for (_, sql) in V5_APPEND_ONLY_TRIGGER_SQL {
        connection
            .execute_batch(sql)
            .map_err(|_| PrivacyStoreError::Database)?;
    }
    Ok(())
}

fn create_empty_v6_schema(connection: &Connection) -> Result<(), PrivacyStoreError> {
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|_| PrivacyStoreError::Database)?;
    connection
        .pragma_update(None, "recursive_triggers", "ON")
        .map_err(|_| PrivacyStoreError::Database)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| PrivacyStoreError::Database)?;
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
    transaction
        .execute_batch(V5_BASE_SCHEMA_SQL)
        .map_err(|_| PrivacyStoreError::Database)?;
    transaction
        .execute_batch(V5_UNIFIED_SCHEMA_SQL)
        .map_err(|_| PrivacyStoreError::Database)?;
    ensure_v5_append_only_insert_guards(&transaction)?;
    crate::lifecycle::initialize_lifecycle_schema(&transaction)?;
    install_v6_security_triggers(&transaction)?;
    transaction
        .execute(
            "INSERT INTO privacy_schema_metadata(key,value,updated_at)
             VALUES('schema_version',?1,CURRENT_TIMESTAMP)
             ON CONFLICT(key) DO UPDATE
             SET value=excluded.value,updated_at=CURRENT_TIMESTAMP",
            [PRIVACY_STORE_SCHEMA_VERSION.to_string()],
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    validate_v6_schema(&transaction)?;
    transaction
        .commit()
        .map_err(|_| PrivacyStoreError::Database)
}

fn upgrade_legacy_schema_to_v5(
    connection: &Connection,
    found_version: i64,
) -> Result<(), PrivacyStoreError> {
    if !(1..=4).contains(&found_version) {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }
    let foreign_keys_enabled = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyStoreError::Database)?;
    if foreign_keys_enabled {
        connection
            .pragma_update(None, "foreign_keys", "OFF")
            .map_err(|_| PrivacyStoreError::Database)?;
    }

    let upgrade_result = (|| {
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)
                .map_err(|_| PrivacyStoreError::Database)?;
        transaction
            .execute_batch(V5_BASE_SCHEMA_SQL)
            .map_err(|_| PrivacyStoreError::Database)?;
        ensure_receipt_consumption_columns(&transaction)?;
        rebuild_unified_backing_tables(&transaction)?;
        transaction
            .execute_batch(V5_UNIFIED_SCHEMA_SQL)
            .map_err(|_| PrivacyStoreError::Database)?;
        ensure_v5_append_only_insert_guards(&transaction)?;
        crate::lifecycle::initialize_lifecycle_schema(&transaction)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_schema_metadata
                 SET value=?1,updated_at=CURRENT_TIMESTAMP
                 WHERE key='schema_version' AND value=?2",
                params![
                    INTERMEDIATE_PRIVACY_STORE_SCHEMA_VERSION.to_string(),
                    found_version.to_string()
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        validate_v5_schema(&transaction)?;
        transaction
            .commit()
            .map_err(|_| PrivacyStoreError::Database)
    })();

    let restore_result = if foreign_keys_enabled {
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| PrivacyStoreError::Database)
    } else {
        Ok(())
    };
    upgrade_result.and(restore_result)
}

fn ensure_receipt_consumption_columns(connection: &Connection) -> Result<(), PrivacyStoreError> {
    let receipt_columns = table_columns(connection, "privacy_receipts")?;
    if !receipt_columns.contains("consumed_at_unix") {
        connection
            .execute(
                "ALTER TABLE privacy_receipts ADD COLUMN consumed_at_unix INTEGER
                 CHECK(consumed_at_unix IS NULL OR consumed_at_unix > 0)",
                [],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
    }
    if !receipt_columns.contains("consumption_id") {
        connection
            .execute(
                "ALTER TABLE privacy_receipts ADD COLUMN consumption_id TEXT
                 CHECK(consumption_id IS NULL OR length(consumption_id) BETWEEN 1 AND 128)",
                [],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
    }
    Ok(())
}

fn rebuild_unified_backing_tables(connection: &Connection) -> Result<(), PrivacyStoreError> {
    let required_material_columns = [
        "material_id",
        "project_id",
        "attachment_id",
        "source_sha256",
        "source_name_sha256",
        "media_type",
        "page_count",
        "state",
        "created_at",
        "updated_at",
    ];
    let required_redaction_columns = [
        "redaction_id",
        "material_id",
        "extraction_sha256",
        "redacted_content_sha256",
        "approved_payload_sha256",
        "policy_id",
        "policy_version",
        "detector_version",
        "unresolved_high_risk_count",
        "review_state",
        "protected_review_blob",
        "protection_scheme",
        "reviewed_by_sha256",
        "created_at",
        "reviewed_at",
    ];
    let material_columns = table_columns(connection, "privacy_materials")?;
    let redaction_columns = table_columns(connection, "privacy_redactions")?;
    if required_material_columns
        .iter()
        .any(|column| !material_columns.contains(*column))
        || required_redaction_columns
            .iter()
            .any(|column| !redaction_columns.contains(*column))
    {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }

    connection
        .execute_batch(
            "
            DROP TABLE IF EXISTS privacy_materials_v5_upgrade;
            CREATE TABLE privacy_materials_v5_upgrade (
                material_id TEXT PRIMARY KEY CHECK(length(material_id) BETWEEN 1 AND 128),
                project_id TEXT CHECK(
                    project_id IS NULL OR length(project_id) BETWEEN 1 AND 128
                ),
                legacy_case_id TEXT CHECK(
                    legacy_case_id IS NULL OR length(legacy_case_id) BETWEEN 1 AND 128
                ),
                attachment_id TEXT CHECK(
                    attachment_id IS NULL OR length(attachment_id) BETWEEN 1 AND 128
                ),
                protected_display_name BLOB,
                display_name_sha256 TEXT CHECK(
                    display_name_sha256 IS NULL OR length(display_name_sha256) = 64
                ),
                display_name_protection_scheme TEXT,
                source_sha256 TEXT CHECK(
                    source_sha256 IS NULL OR length(source_sha256) = 64
                ),
                source_name_sha256 TEXT CHECK(
                    source_name_sha256 IS NULL OR length(source_name_sha256) = 64
                ),
                media_type TEXT CHECK(
                    media_type IS NULL OR length(media_type) BETWEEN 1 AND 128
                ),
                page_count INTEGER CHECK(
                    page_count IS NULL OR page_count BETWEEN 0 AND 10000
                ),
                source_kind TEXT NOT NULL CHECK(source_kind IN (
                    'vault','local_review','user_attachment','legacy_reference'
                )),
                extraction_status TEXT NOT NULL CHECK(
                    length(extraction_status) BETWEEN 1 AND 128
                ),
                migration_status TEXT NOT NULL CHECK(migration_status IN (
                    'ready','unassigned','legacy_reference','blocked'
                )),
                state TEXT NOT NULL CHECK(state IN (
                    'registered','assessing','extracting_native','ocr_required','ocr_running',
                    'extracted','redacting','review_required','approved','outbound_ready',
                    'failed','blocked','stale','revoked'
                )),
                row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                deleted_at TEXT,
                CHECK(
                    (protected_display_name IS NULL
                     AND display_name_sha256 IS NULL
                     AND display_name_protection_scheme IS NULL)
                    OR
                    (protected_display_name IS NOT NULL
                     AND length(protected_display_name) > 0
                     AND display_name_sha256 IS NOT NULL
                     AND display_name_protection_scheme =
                         'windows_dpapi_current_user_v1')
                ),
                CHECK(
                    source_sha256 IS NOT NULL
                    OR migration_status IN ('legacy_reference','blocked')
                ),
                CHECK(
                    media_type IS NOT NULL
                    OR migration_status IN ('legacy_reference','blocked')
                ),
                CHECK(migration_status <> 'ready' OR project_id IS NOT NULL),
                CHECK(migration_status <> 'unassigned' OR project_id IS NULL)
            );
            INSERT INTO privacy_materials_v5_upgrade(
                material_id,project_id,legacy_case_id,attachment_id,
                protected_display_name,display_name_sha256,
                display_name_protection_scheme,source_sha256,source_name_sha256,
                media_type,page_count,source_kind,extraction_status,migration_status,
                state,row_version,created_at,updated_at,deleted_at
            )
            SELECT
                material_id,NULL,project_id,attachment_id,
                NULL,NULL,NULL,source_sha256,source_name_sha256,
                media_type,page_count,'local_review',state,'unassigned',
                state,1,created_at,updated_at,NULL
            FROM privacy_materials;
            DROP TABLE privacy_materials;
            ALTER TABLE privacy_materials_v5_upgrade RENAME TO privacy_materials;

            DROP TABLE IF EXISTS privacy_redactions_v5_upgrade;
            CREATE TABLE privacy_redactions_v5_upgrade (
                redaction_id TEXT PRIMARY KEY CHECK(length(redaction_id) BETWEEN 1 AND 128),
                material_id TEXT NOT NULL,
                generation_number INTEGER NOT NULL CHECK(generation_number > 0),
                generation_status TEXT NOT NULL DEFAULT 'ready' CHECK(
                    generation_status IN ('ready','blocked','legacy_id')
                ),
                extraction_sha256 TEXT NOT NULL CHECK(length(extraction_sha256) = 64),
                redacted_content_sha256 TEXT NOT NULL CHECK(
                    length(redacted_content_sha256) = 64
                ),
                approved_payload_sha256 TEXT CHECK(
                    approved_payload_sha256 IS NULL OR
                    length(approved_payload_sha256) = 64
                ),
                policy_id TEXT NOT NULL CHECK(length(policy_id) BETWEEN 1 AND 128),
                policy_version INTEGER NOT NULL CHECK(policy_version > 0),
                detector_version TEXT NOT NULL CHECK(
                    length(detector_version) BETWEEN 1 AND 128
                ),
                unresolved_high_risk_count INTEGER NOT NULL CHECK(
                    unresolved_high_risk_count >= 0
                ),
                review_state TEXT NOT NULL CHECK(
                    review_state IN ('review_required','approved','revoked','stale')
                ),
                risk_revision INTEGER NOT NULL DEFAULT 0 CHECK(risk_revision >= 0),
                protected_review_blob BLOB NOT NULL CHECK(
                    length(protected_review_blob) > 0
                ),
                protection_scheme TEXT NOT NULL CHECK(
                    protection_scheme = 'windows_dpapi_current_user_v1'
                ),
                reviewed_by_sha256 TEXT CHECK(
                    reviewed_by_sha256 IS NULL OR length(reviewed_by_sha256) = 64
                ),
                approved_at TEXT,
                revocation_state TEXT NOT NULL DEFAULT 'active' CHECK(
                    revocation_state IN (
                        'active','revoked','revoked_legacy_time_unknown'
                    )
                ),
                revoked_at TEXT,
                row_version INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TEXT,
                CHECK(
                    (revocation_state = 'active' AND revoked_at IS NULL)
                    OR (revocation_state = 'revoked' AND revoked_at IS NOT NULL)
                    OR (
                        revocation_state = 'revoked_legacy_time_unknown'
                        AND revoked_at IS NULL
                    )
                ),
                FOREIGN KEY(material_id)
                    REFERENCES privacy_materials(material_id) ON DELETE CASCADE
            );
            WITH ranked AS (
                SELECT
                    redaction_id,
                    ROW_NUMBER() OVER(
                        PARTITION BY material_id
                        ORDER BY created_at ASC, redaction_id ASC
                    ) AS generation_number
                FROM privacy_redactions
            )
            INSERT INTO privacy_redactions_v5_upgrade(
                redaction_id,material_id,generation_number,generation_status,
                extraction_sha256,redacted_content_sha256,approved_payload_sha256,
                policy_id,policy_version,detector_version,unresolved_high_risk_count,
                review_state,risk_revision,protected_review_blob,protection_scheme,
                reviewed_by_sha256,approved_at,revocation_state,revoked_at,
                row_version,created_at,reviewed_at
            )
            SELECT
                redaction.redaction_id,
                redaction.material_id,
                ranked.generation_number,
                CASE
                    WHEN redaction.review_state='approved'
                     AND (
                         redaction.approved_payload_sha256 IS NULL
                         OR redaction.unresolved_high_risk_count <> 0
                         OR NOT EXISTS(
                             SELECT 1
                             FROM privacy_risk_review_revisions AS risk
                             WHERE risk.redaction_id=redaction.redaction_id
                         )
                     )
                    THEN 'blocked'
                    ELSE 'ready'
                END,
                redaction.extraction_sha256,
                redaction.redacted_content_sha256,
                redaction.approved_payload_sha256,
                redaction.policy_id,
                redaction.policy_version,
                redaction.detector_version,
                redaction.unresolved_high_risk_count,
                redaction.review_state,
                COALESCE((
                    SELECT MAX(risk.revision)
                    FROM privacy_risk_review_revisions AS risk
                    WHERE risk.redaction_id=redaction.redaction_id
                ),0),
                redaction.protected_review_blob,
                redaction.protection_scheme,
                redaction.reviewed_by_sha256,
                CASE
                    WHEN redaction.review_state='approved'
                     AND redaction.reviewed_at IS NOT NULL
                     AND datetime(redaction.reviewed_at) IS NOT NULL
                    THEN redaction.reviewed_at
                    ELSE NULL
                END,
                CASE
                    WHEN redaction.review_state='revoked'
                    THEN 'revoked_legacy_time_unknown'
                    ELSE 'active'
                END,
                NULL,
                1,
                redaction.created_at,
                redaction.reviewed_at
            FROM privacy_redactions AS redaction
            JOIN ranked ON ranked.redaction_id=redaction.redaction_id;
            DROP TABLE privacy_redactions;
            ALTER TABLE privacy_redactions_v5_upgrade RENAME TO privacy_redactions;
            ",
        )
        .map_err(|_| PrivacyStoreError::Database)
}

fn table_columns(
    connection: &Connection,
    table: &str,
) -> Result<BTreeSet<String>, PrivacyStoreError> {
    let sql = format!("PRAGMA table_info({table})");
    let mut statement = connection
        .prepare(&sql)
        .map_err(|_| PrivacyStoreError::Database)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|_| PrivacyStoreError::Database)?;
    rows.collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| PrivacyStoreError::Database)
}

fn validate_v5_schema(connection: &Connection) -> Result<(), PrivacyStoreError> {
    let version = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?;
    if version.as_deref() != Some("5") {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }

    for (kind, name) in [
        ("table", "privacy_materials"),
        ("table", "privacy_redactions"),
        ("table", "case_material_selections"),
        ("table", "case_material_migration_ledger"),
        ("table", "case_material_migration_events"),
        ("table", "case_material_legacy_references"),
        ("index", "idx_privacy_redactions_generation"),
        ("index", "idx_case_material_selection_active"),
        ("trigger", "trg_privacy_redaction_generation_immutable"),
        ("trigger", "trg_privacy_redaction_approved_immutable"),
        ("trigger", "trg_case_material_selection_no_delete"),
        ("trigger", "trg_case_material_migration_ledger_no_update"),
        ("trigger", "trg_case_material_migration_ledger_no_delete"),
        ("trigger", "trg_case_material_migration_ledger_no_replace"),
        ("trigger", "trg_case_material_migration_events_no_update"),
        ("trigger", "trg_case_material_migration_events_no_delete"),
        ("trigger", "trg_case_material_migration_events_no_replace"),
        ("trigger", "trg_case_material_legacy_reference_validate"),
        ("trigger", "trg_case_material_legacy_reference_no_update"),
        ("trigger", "trg_case_material_legacy_reference_no_delete"),
        ("trigger", "trg_case_material_legacy_reference_no_replace"),
    ] {
        let exists = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2
                 )",
                params![kind, name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if !exists {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }
    for (name, canonical_sql) in V5_APPEND_ONLY_TRIGGER_SQL {
        let stored_sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        let Some(stored_sql) = stored_sql else {
            return Err(PrivacyStoreError::UnsupportedSchema);
        };
        if normalize_v5_trigger_sql(&stored_sql) != normalize_v5_trigger_sql(canonical_sql) {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }
    for forbidden in ["case_materials", "redaction_generations"] {
        let exists = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1
                 )",
                [forbidden],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if exists {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }

    let material_columns = table_columns(connection, "privacy_materials")?;
    for column in [
        "project_id",
        "legacy_case_id",
        "protected_display_name",
        "display_name_sha256",
        "source_kind",
        "extraction_status",
        "migration_status",
        "row_version",
        "deleted_at",
    ] {
        if !material_columns.contains(column) {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }
    let redaction_columns = table_columns(connection, "privacy_redactions")?;
    for column in [
        "generation_number",
        "generation_status",
        "risk_revision",
        "approved_at",
        "revocation_state",
        "revoked_at",
        "row_version",
    ] {
        if !redaction_columns.contains(column) {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }

    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| PrivacyStoreError::Database)?;
    let mut rows = foreign_key_check
        .query([])
        .map_err(|_| PrivacyStoreError::Database)?;
    if rows
        .next()
        .map_err(|_| PrivacyStoreError::Database)?
        .is_some()
    {
        return Err(PrivacyStoreError::Conflict);
    }
    Ok(())
}

fn validate_v6_schema(connection: &Connection) -> Result<(), PrivacyStoreError> {
    let version = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| PrivacyStoreError::Database)?;
    if version.as_deref() != Some("6") {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }
    let foreign_keys = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyStoreError::Database)?;
    let recursive_triggers = connection
        .pragma_query_value(None, "recursive_triggers", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyStoreError::Database)?;
    let trusted_schema = connection
        .pragma_query_value(None, "trusted_schema", |row| row.get::<_, bool>(0))
        .map_err(|_| PrivacyStoreError::Database)?;
    if !foreign_keys || !recursive_triggers || trusted_schema {
        return Err(PrivacyStoreError::UnsupportedSchema);
    }

    for (kind, name) in [
        ("table", "privacy_materials"),
        ("table", "privacy_redactions"),
        ("table", "privacy_risk_review_revisions"),
        ("table", "case_material_selections"),
        ("table", "case_material_migration_ledger"),
        ("table", "case_material_migration_events"),
        ("table", "case_material_legacy_references"),
        ("index", "idx_privacy_redactions_generation"),
        ("index", "idx_case_material_selection_active"),
        ("trigger", "trg_privacy_redaction_generation_immutable"),
        ("trigger", "trg_case_material_selection_no_delete"),
        ("trigger", "trg_privacy_risk_review_no_update"),
    ] {
        let exists = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master WHERE type=?1 AND name=?2
                 )",
                params![kind, name],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if !exists {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }
    for (name, canonical_sql) in V5_APPEND_ONLY_TRIGGER_SQL
        .iter()
        .chain(V6_SECURITY_TRIGGER_SQL.iter())
    {
        let stored_sql = connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        let Some(stored_sql) = stored_sql else {
            return Err(PrivacyStoreError::UnsupportedSchema);
        };
        if normalize_v5_trigger_sql(&stored_sql) != normalize_v5_trigger_sql(canonical_sql) {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }
    let redaction_columns = table_columns(connection, "privacy_redactions")?;
    for column in [
        "generation_number",
        "generation_status",
        "risk_revision",
        "approved_at",
        "revocation_state",
        "revoked_at",
        "row_version",
        "approved_payload_schema_version",
        "protected_approved_payload_blob",
        "approved_payload_protection_scheme",
        "approved_risk_revision_hash",
    ] {
        if !redaction_columns.contains(column) {
            return Err(PrivacyStoreError::UnsupportedSchema);
        }
    }
    let invalid_projection_count = connection
        .query_row(
            "SELECT COUNT(*)
             FROM privacy_redactions
             WHERE
               (
                 (approved_payload_schema_version IS NULL)
                 + (protected_approved_payload_blob IS NULL)
                 + (approved_payload_protection_scheme IS NULL)
                 + (approved_risk_revision_hash IS NULL)
               ) NOT IN (0,4)
               OR (
                 review_state='approved' AND generation_status='ready'
                 AND revocation_state='active' AND revoked_at IS NULL
                 AND approved_payload_schema_version IS NULL
               )
               OR (
                 approved_payload_schema_version IS NOT NULL
                 AND (
                   review_state <> 'approved'
                   OR generation_status <> 'ready'
                   OR NOT (
                     (revocation_state='active' AND revoked_at IS NULL)
                     OR (revocation_state='revoked' AND revoked_at IS NOT NULL)
                   )
                   OR approved_payload_sha256 IS NULL
                   OR approved_payload_schema_version <> 1
                   OR protected_approved_payload_blob IS NULL
                   OR approved_payload_protection_scheme <>
                      'windows_dpapi_current_user_v1'
                   OR approved_risk_revision_hash IS NULL
                   OR risk_revision <= 0
                   OR unresolved_high_risk_count <> 0
                 )
               )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| PrivacyStoreError::Database)?;
    if invalid_projection_count != 0 {
        return Err(PrivacyStoreError::Conflict);
    }
    let mut foreign_key_check = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| PrivacyStoreError::Database)?;
    let mut rows = foreign_key_check
        .query([])
        .map_err(|_| PrivacyStoreError::Database)?;
    if rows
        .next()
        .map_err(|_| PrivacyStoreError::Database)?
        .is_some()
    {
        return Err(PrivacyStoreError::Conflict);
    }
    Ok(())
}

fn normalize_v5_trigger_sql(sql: &str) -> String {
    let normalized = sql
        .trim()
        .trim_end_matches(';')
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    normalized
        .strip_prefix("create trigger if not exists ")
        .map_or(normalized.clone(), |suffix| {
            format!("create trigger {suffix}")
        })
}

struct RiskReviewRevisionHashInput<'a> {
    redaction_id: &'a str,
    revision: u64,
    state_sha256: &'a str,
    risk_sha256: &'a str,
    hard_gate_sha256: &'a str,
    action_code: &'a str,
    reason_codes_json: &'a str,
    protected_sha256: &'a str,
    previous_revision_hash: &'a str,
}

fn risk_review_revision_hash(input: &RiskReviewRevisionHashInput<'_>) -> String {
    sha256_hex(
        format!(
            "{RISK_REVIEW_REVISION_PROFILE}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            input.redaction_id,
            input.revision,
            input.state_sha256,
            input.risk_sha256,
            input.hard_gate_sha256,
            input.action_code,
            input.reason_codes_json,
            input.protected_sha256,
            input.previous_revision_hash,
        )
        .as_bytes(),
    )
}

fn valid_id(value: &str) -> Result<(), PrivacyStoreError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        Err(PrivacyStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn valid_optional_id(value: Option<&str>) -> Result<(), PrivacyStoreError> {
    if let Some(value) = value {
        valid_id(value)?;
    }
    Ok(())
}

fn valid_hash(value: &str) -> Result<(), PrivacyStoreError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(PrivacyStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn map_receipt_error(error: ReceiptError) -> PrivacyStoreError {
    match error {
        ReceiptError::Expired => PrivacyStoreError::ReceiptExpired,
        ReceiptError::Revoked => PrivacyStoreError::ReceiptRevoked,
        ReceiptError::NotApproved | ReceiptError::UnresolvedHighRisk => {
            PrivacyStoreError::NotApproved
        }
        ReceiptError::KeyTooShort
        | ReceiptError::InvalidClaims
        | ReceiptError::InvalidToken
        | ReceiptError::InvalidMac
        | ReceiptError::PayloadMismatch
        | ReceiptError::DestinationMismatch
        | ReceiptError::PurposeMismatch
        | ReceiptError::PolicyMismatch
        | ReceiptError::DetectorMismatch => PrivacyStoreError::InvalidReceipt,
    }
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

const fn destination_kind(value: &DestinationKind) -> &'static str {
    match value {
        DestinationKind::ExternalProvider => "external_provider",
        DestinationKind::ExternalMcpHost => "external_mcp_host",
        DestinationKind::VerifiedLocalProvider => "verified_local_provider",
    }
}

const fn classification(value: DataClassification) -> Option<&'static str> {
    match value {
        DataClassification::LegalPublic => Some("legal_public"),
        DataClassification::ProductPublic => Some("product_public"),
        DataClassification::InteractiveUserProvided => None,
        DataClassification::CaseRaw => Some("case_raw"),
        DataClassification::CaseRedactedPending => Some("case_redacted_pending"),
        DataClassification::CaseRedactedApproved => Some("case_redacted_approved"),
        DataClassification::Secret => Some("secret"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DestinationScope, ReceiptSigner, RedactionReceiptClaims, REDACTION_VERSION};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Barrier},
        thread,
        time::Duration,
    };

    fn hash(value: &[u8]) -> String {
        sha256_hex(value)
    }

    fn setup() -> Connection {
        let connection = Connection::open_in_memory().expect("database");
        connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .expect("foreign keys");
        PrivacyStore::initialize(&connection).expect("schema");
        connection
    }

    fn legacy_store(version: i64) -> Connection {
        let connection = Connection::open_in_memory().expect("legacy database");
        connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .expect("legacy foreign keys");
        connection
            .execute_batch(&format!(
                "
                CREATE TABLE privacy_schema_metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO privacy_schema_metadata(key,value)
                VALUES('schema_version','{version}');
                CREATE TABLE privacy_materials(
                    material_id TEXT PRIMARY KEY,
                    project_id TEXT,
                    attachment_id TEXT,
                    source_sha256 TEXT NOT NULL,
                    source_name_sha256 TEXT NOT NULL,
                    media_type TEXT NOT NULL,
                    page_count INTEGER,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE privacy_redactions(
                    redaction_id TEXT PRIMARY KEY,
                    material_id TEXT NOT NULL,
                    extraction_sha256 TEXT NOT NULL,
                    redacted_content_sha256 TEXT NOT NULL,
                    approved_payload_sha256 TEXT,
                    policy_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,
                    detector_version TEXT NOT NULL,
                    unresolved_high_risk_count INTEGER NOT NULL,
                    review_state TEXT NOT NULL,
                    protected_review_blob BLOB NOT NULL,
                    protection_scheme TEXT NOT NULL,
                    reviewed_by_sha256 TEXT,
                    created_at TEXT NOT NULL,
                    reviewed_at TEXT,
                    FOREIGN KEY(material_id) REFERENCES privacy_materials(material_id)
                );
                INSERT INTO privacy_materials(
                    material_id,project_id,attachment_id,source_sha256,
                    source_name_sha256,media_type,page_count,state,created_at,updated_at
                ) VALUES
                    ('legacy-material-a','case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',NULL,
                     '{source_a}','{name_a}','application/pdf',3,'review_required',
                     '2025-01-01 00:00:00','2025-01-02 00:00:00'),
                    ('legacy-material-b',NULL,NULL,
                     '{source_b}','{name_b}','text/plain',1,'review_required',
                     '2025-01-01 00:00:00','2025-01-02 00:00:00');
                INSERT INTO privacy_redactions(
                    redaction_id,material_id,extraction_sha256,redacted_content_sha256,
                    approved_payload_sha256,policy_id,policy_version,detector_version,
                    unresolved_high_risk_count,review_state,protected_review_blob,
                    protection_scheme,reviewed_by_sha256,created_at,reviewed_at
                ) VALUES
                    ('redaction-c','legacy-material-a','{extract_c}','{redacted_c}',NULL,
                     'policy',1,'detector',0,'review_required',x'01',
                     'windows_dpapi_current_user_v1',NULL,'2025-01-03 00:00:00',NULL),
                    ('redaction-b','legacy-material-a','{extract_b}','{redacted_b}',NULL,
                     'policy',1,'detector',0,'review_required',x'02',
                     'windows_dpapi_current_user_v1',NULL,'2025-01-02 00:00:00',NULL),
                    ('redaction-a','legacy-material-a','{extract_a}','{redacted_a}',NULL,
                     'policy',1,'detector',0,'review_required',x'03',
                     'windows_dpapi_current_user_v1',NULL,'2025-01-02 00:00:00',NULL),
                    ('redaction-z','legacy-material-b','{extract_z}','{redacted_z}',NULL,
                     'policy',1,'detector',0,'review_required',x'04',
                     'windows_dpapi_current_user_v1',NULL,'2025-01-04 00:00:00',NULL);
                ",
                source_a = hash(b"legacy-source-a"),
                name_a = hash(b"legacy-name-a"),
                source_b = hash(b"legacy-source-b"),
                name_b = hash(b"legacy-name-b"),
                extract_a = hash(b"extract-a"),
                redacted_a = hash(b"redacted-a"),
                extract_b = hash(b"extract-b"),
                redacted_b = hash(b"redacted-b"),
                extract_c = hash(b"extract-c"),
                redacted_c = hash(b"redacted-c"),
                extract_z = hash(b"extract-z"),
                redacted_z = hash(b"redacted-z"),
            ))
            .expect("legacy schema and rows");
        connection
    }

    fn insert_approved_generation(
        connection: &Connection,
        project_id: &str,
        material_id: &str,
        redaction_id: &str,
        generation_number: i64,
        risk_revision: i64,
        approved_payload_sha256: &str,
    ) {
        if !connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM privacy_materials WHERE material_id=?1
                 )",
                [material_id],
                |row| row.get::<_, bool>(0),
            )
            .expect("material existence")
        {
            connection
                .execute(
                    "INSERT INTO privacy_materials(
                        material_id,project_id,source_sha256,source_name_sha256,
                        media_type,source_kind,extraction_status,migration_status,state
                     ) VALUES(
                        ?1,?2,?3,?4,'application/pdf','local_review',
                        'extracted','ready','approved'
                     )",
                    params![
                        material_id,
                        project_id,
                        hash(format!("{material_id}-source").as_bytes()),
                        hash(format!("{material_id}-name").as_bytes())
                    ],
                )
                .expect("approved material");
        }
        connection
            .execute(
                "INSERT INTO privacy_redactions(
                    redaction_id,material_id,generation_number,generation_status,
                    extraction_sha256,redacted_content_sha256,approved_payload_sha256,
                    policy_id,policy_version,detector_version,
                    unresolved_high_risk_count,review_state,risk_revision,
                    protected_review_blob,protection_scheme,reviewed_by_sha256,
                    approved_at,revocation_state,row_version,created_at,reviewed_at,
                    approved_payload_schema_version,protected_approved_payload_blob,
                    approved_payload_protection_scheme,approved_risk_revision_hash
                 ) VALUES(
                     ?1,?2,?3,'ready',?4,?5,?6,'policy',1,'detector',0,
                     'approved',?7,x'01','windows_dpapi_current_user_v1',?8,
                     '2025-02-01 00:00:00','active',1,
                     '2025-01-01 00:00:00','2025-02-01 00:00:00',
                     1,x'02','windows_dpapi_current_user_v1',?9
                 )",
                params![
                    redaction_id,
                    material_id,
                    generation_number,
                    hash(format!("{redaction_id}-extraction").as_bytes()),
                    hash(format!("{redaction_id}-content").as_bytes()),
                    approved_payload_sha256,
                    risk_revision,
                    hash(b"reviewer"),
                    hash(format!("{redaction_id}-risk-head").as_bytes()),
                ],
            )
            .expect("approved generation");
    }

    fn register(connection: &Connection) {
        PrivacyStore::register_material(
            connection,
            &RegisterPrivacyMaterial {
                material_id: "material-1",
                project_id: Some("project-1"),
                attachment_id: Some("attachment-1"),
                source_sha256: &hash(b"source"),
                source_name_sha256: &hash(b"name"),
                media_type: "application/pdf",
                page_count: Some(2),
            },
        )
        .expect("material");
    }

    #[cfg(windows)]
    #[test]
    fn review_blob_is_protected_and_approval_is_hash_bound() {
        let mut connection = setup();
        register(&connection);
        let plaintext = r#"{"mapping":{"张三":"[姓名1]"},"redacted":"[姓名1]"}"#;
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id: "redaction-1",
                material_id: "material-1",
                extraction_sha256: &hash(b"extraction"),
                redacted_content_sha256: &hash(b"redacted"),
                policy_id: "cn-legal-default",
                policy_version: 1,
                detector_version: REDACTION_VERSION,
                unresolved_high_risk_count: 0,
                review_payload_plaintext: plaintext.as_bytes(),
            },
        )
        .expect("draft");
        let blob = connection
            .query_row(
                "SELECT protected_review_blob FROM privacy_redactions WHERE redaction_id='redaction-1'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("blob");
        assert!(!blob
            .windows("张三".len())
            .any(|value| value == "张三".as_bytes()));
        let loaded = PrivacyStore::load_review_draft(&connection, "redaction-1").expect("load");
        assert_eq!(loaded.review_payload_plaintext, plaintext.as_bytes());
        assert_eq!(
            PrivacyStore::approve_review(
                &mut connection,
                "redaction-1",
                &hash(b"wrong"),
                &hash(b"wrong final redacted"),
                &hash(b"payload"),
                &hash(b"reviewer"),
                b"wrong final review",
            ),
            Err(PrivacyStoreError::Conflict)
        );
        PrivacyStore::approve_review(
            &mut connection,
            "redaction-1",
            &hash(b"redacted"),
            &hash(b"final approved review"),
            &hash(b"payload"),
            &hash(b"reviewer"),
            b"final approved review",
        )
        .expect("approve");
        let approved = PrivacyStore::load_review_draft(&connection, "redaction-1").expect("load");
        assert_eq!(approved.review_payload_plaintext, b"final approved review");
        assert_eq!(
            approved.redacted_content_sha256,
            hash(b"final approved review")
        );
    }

    #[cfg(windows)]
    #[test]
    fn risk_review_revisions_are_encrypted_hash_chained_and_optimistic() {
        let connection = setup();
        register(&connection);
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id: "redaction-risk-1",
                material_id: "material-1",
                extraction_sha256: &hash(b"risk-extraction"),
                redacted_content_sha256: &hash(b"risk-redacted"),
                policy_id: "cn-legal-risk-v1",
                policy_version: 1,
                detector_version: REDACTION_VERSION,
                unresolved_high_risk_count: 1,
                review_payload_plaintext: b"review-draft",
            },
        )
        .expect("draft");

        let private_state = br#"{"private":"private-case-value-do-not-store","revision":1}"#;
        let first = PrivacyStore::append_risk_review_revision(
            &connection,
            &SaveRiskReviewRevision {
                redaction_id: "redaction-risk-1",
                expected_previous_revision: 0,
                risk_sha256: &hash(b"risk-1"),
                hard_gate_sha256: &hash(b"gates-1"),
                action_code: "review_initialized",
                reason_codes: &["p1_unresolved".to_owned()],
                state_plaintext: private_state,
            },
        )
        .expect("first revision");
        assert_eq!(first.revision, 1);
        assert!(first.previous_revision_hash.is_empty());

        let (ordinary, protected) = connection
            .query_row(
                "SELECT redaction_id||state_sha256||risk_sha256||hard_gate_sha256||
                        action_code||reason_codes_json||previous_revision_hash||revision_hash,
                        protected_state_blob
                 FROM privacy_risk_review_revisions
                 WHERE redaction_id='redaction-risk-1' AND revision=1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .expect("stored revision");
        assert!(!ordinary.contains("private-case-value-do-not-store"));
        assert!(!protected
            .windows(private_state.len())
            .any(|value| value == private_state));

        let loaded =
            PrivacyStore::load_latest_risk_review_revision(&connection, "redaction-risk-1")
                .expect("load")
                .expect("latest");
        assert_eq!(loaded.state_plaintext, private_state);
        assert!(!format!("{loaded:?}").contains("private-case-value-do-not-store"));

        let second_state = br#"{"revision":2,"resolution":"accepted"}"#;
        let second = PrivacyStore::append_risk_review_revision(
            &connection,
            &SaveRiskReviewRevision {
                redaction_id: "redaction-risk-1",
                expected_previous_revision: 1,
                risk_sha256: &hash(b"risk-2"),
                hard_gate_sha256: &hash(b"gates-2"),
                action_code: "accept_replacement",
                reason_codes: &[],
                state_plaintext: second_state,
            },
        )
        .expect("second revision");
        assert_eq!(second.revision, 2);
        assert_eq!(second.previous_revision_hash, first.revision_hash);
        assert_eq!(
            PrivacyStore::append_risk_review_revision(
                &connection,
                &SaveRiskReviewRevision {
                    redaction_id: "redaction-risk-1",
                    expected_previous_revision: 1,
                    risk_sha256: &hash(b"risk-stale"),
                    hard_gate_sha256: &hash(b"gates-stale"),
                    action_code: "stale_action",
                    reason_codes: &[],
                    state_plaintext: b"stale",
                },
            ),
            Err(PrivacyStoreError::Conflict)
        );
        assert!(connection
            .execute(
                "UPDATE privacy_risk_review_revisions SET action_code='tamper'
                 WHERE redaction_id='redaction-risk-1' AND revision=2",
                [],
            )
            .is_err());

        connection
            .execute_batch("DROP TRIGGER trg_privacy_risk_review_no_update;")
            .expect("drop test trigger");
        connection
            .execute(
                "UPDATE privacy_risk_review_revisions SET protected_state_blob=x'00'
                 WHERE redaction_id='redaction-risk-1' AND revision=2",
                [],
            )
            .expect("tamper for validation");
        assert_eq!(
            PrivacyStore::load_latest_risk_review_revision(&connection, "redaction-risk-1")
                .map(|_| ()),
            Err(PrivacyStoreError::Conflict)
        );
    }

    #[cfg(windows)]
    #[test]
    fn approval_and_risk_revision_commit_atomically_and_reject_stale_revision() {
        let mut connection = setup();
        register(&connection);
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id: "redaction-risk-approval-1",
                material_id: "material-1",
                extraction_sha256: &hash(b"approval-extraction"),
                redacted_content_sha256: &hash(b"approval-redacted-v1"),
                policy_id: "cn-legal-risk-v1",
                policy_version: 1,
                detector_version: REDACTION_VERSION,
                unresolved_high_risk_count: 0,
                review_payload_plaintext: b"approval-review-v1",
            },
        )
        .expect("draft");
        PrivacyStore::append_risk_review_revision(
            &connection,
            &SaveRiskReviewRevision {
                redaction_id: "redaction-risk-approval-1",
                expected_previous_revision: 0,
                risk_sha256: &hash(b"approval-risk-v1"),
                hard_gate_sha256: &hash(b"approval-gates-v1"),
                action_code: "review_initialized",
                reason_codes: &[],
                state_plaintext: b"approval-risk-state-v1",
            },
        )
        .expect("initial revision");

        let approved_redacted_sha256 = hash(b"approval-redacted-v2");
        let approved_payload_sha256 = hash(b"approval-payload");
        let reviewed_by_sha256 = hash(b"approval-reviewer");
        let risk_sha256 = hash(b"approval-risk-v2");
        let hard_gate_sha256 = hash(b"approval-gates-v2");
        macro_rules! approval {
            ($expected_previous_revision:expr, $expected_redacted_sha256:expr) => {
                ApproveReviewWithRiskRevision {
                    redaction_id: "redaction-risk-approval-1",
                    expected_redacted_sha256: $expected_redacted_sha256,
                    approved_redacted_content_sha256: &approved_redacted_sha256,
                    approved_payload_sha256: &approved_payload_sha256,
                    reviewed_by_sha256: &reviewed_by_sha256,
                    approved_review_payload_plaintext: b"approval-review-v2",
                    approved_payload_plaintext: b"approval-payload",
                    risk_revision: SaveRiskReviewRevision {
                        redaction_id: "redaction-risk-approval-1",
                        expected_previous_revision: $expected_previous_revision,
                        risk_sha256: &risk_sha256,
                        hard_gate_sha256: &hard_gate_sha256,
                        action_code: "bind_publication_context",
                        reason_codes: &[],
                        state_plaintext: b"approval-risk-state-v2",
                    },
                }
            };
        }

        assert_eq!(
            PrivacyStore::approve_review_with_risk_revision(
                &mut connection,
                &approval!(0, &hash(b"approval-redacted-v1")),
            ),
            Err(PrivacyStoreError::Conflict)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT review_state FROM privacy_redactions
                     WHERE redaction_id='redaction-risk-approval-1'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .expect("review state"),
            "review_required"
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_risk_review_revisions
                     WHERE redaction_id='redaction-risk-approval-1'",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .expect("revision count"),
            1
        );

        assert_eq!(
            PrivacyStore::approve_review_with_risk_revision(
                &mut connection,
                &approval!(1, &hash(b"wrong-redacted-hash")),
            ),
            Err(PrivacyStoreError::Conflict)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_risk_review_revisions
                     WHERE redaction_id='redaction-risk-approval-1'",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .expect("rolled back revision count"),
            1
        );

        PrivacyStore::approve_review_with_risk_revision(
            &mut connection,
            &approval!(1, &hash(b"approval-redacted-v1")),
        )
        .expect("atomic approval");
        let approved = PrivacyStore::load_review_draft(&connection, "redaction-risk-approval-1")
            .expect("approved review");
        assert_eq!(approved.review_state, "approved");
        assert_eq!(
            approved.redacted_content_sha256,
            hash(b"approval-redacted-v2")
        );
        assert_eq!(
            PrivacyStore::load_latest_risk_review_revision(
                &connection,
                "redaction-risk-approval-1",
            )
            .expect("latest revision")
            .expect("revision")
            .revision,
            2
        );
    }

    #[test]
    fn incomplete_legacy_metadata_is_rejected_without_initialization_writes() {
        let connection = Connection::open_in_memory().expect("database");
        connection
            .execute_batch(
                "CREATE TABLE privacy_schema_metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO privacy_schema_metadata(key,value)
                 VALUES('schema_version','2');",
            )
            .expect("legacy metadata");
        assert_eq!(
            PrivacyStore::initialize(&connection),
            Err(PrivacyStoreError::UnsupportedSchema)
        );
        let version = connection
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("version");
        assert_eq!(version, "2");
        let table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name='privacy_risk_review_revisions'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .expect("risk table");
        assert_eq!(table_count, 0);
        let receipt_table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name='privacy_receipts'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .expect("receipt table");
        assert_eq!(receipt_table_count, 0);
    }

    #[test]
    fn material_registration_distinguishes_vault_from_local_review_sources() {
        let connection = setup();
        register(&connection);
        PrivacyStore::register_material(
            &connection,
            &RegisterPrivacyMaterial {
                material_id: "material-local",
                project_id: Some("project-1"),
                attachment_id: None,
                source_sha256: &hash(b"local-source"),
                source_name_sha256: &hash(b"local-name"),
                media_type: "text/plain",
                page_count: Some(1),
            },
        )
        .expect("local material");
        let sources = connection
            .query_row(
                "SELECT
                    (SELECT source_kind FROM privacy_materials
                     WHERE material_id='material-1'),
                    (SELECT source_kind FROM privacy_materials
                     WHERE material_id='material-local')",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .expect("source kinds");
        assert_eq!(sources, ("vault".to_owned(), "local_review".to_owned()));
    }

    #[cfg(windows)]
    #[test]
    fn material_display_name_is_protected_hashed_and_optimistically_versioned() {
        let connection = setup();
        register(&connection);
        let display_name = "张三起诉状.pdf";
        let row_version = PrivacyStore::set_material_display_name(
            &connection,
            "material-1",
            Some(1),
            display_name,
        )
        .expect("protect display name");
        assert_eq!(row_version, 2);
        let stored = connection
            .query_row(
                "SELECT protected_display_name,display_name_sha256,
                        display_name_protection_scheme,row_version
                 FROM privacy_materials WHERE material_id='material-1'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("stored display name");
        assert_eq!(stored.1, hash(display_name.as_bytes()));
        assert_eq!(stored.2, LOCAL_PROTECTION_SCHEME);
        assert_eq!(stored.3, 2);
        assert_eq!(
            unprotect_local(&stored.0).expect("unprotect display name"),
            display_name.as_bytes()
        );
        assert!(!stored
            .0
            .windows(display_name.len())
            .any(|window| window == display_name.as_bytes()));
        assert_eq!(
            PrivacyStore::set_material_display_name(
                &connection,
                "material-1",
                Some(1),
                "stale-name.pdf",
            ),
            Err(PrivacyStoreError::Conflict)
        );
        assert_eq!(
            PrivacyStore::set_material_display_name(&connection, "material-1", Some(2), ""),
            Err(PrivacyStoreError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    fn concurrent_generation_allocation_uses_immediate_lock_and_remains_unique() {
        let directory = tempfile::tempdir().expect("generation directory");
        let database_path = directory.path().join("privacy-workflow.sqlite");
        let connection = Connection::open(&database_path).expect("open generation database");
        connection
            .execute_batch("PRAGMA foreign_keys=ON;")
            .expect("foreign keys");
        PrivacyStore::initialize(&connection).expect("schema");
        PrivacyStore::register_material(
            &connection,
            &RegisterPrivacyMaterial {
                material_id: "material-concurrent",
                project_id: Some("case-project-concurrent"),
                attachment_id: None,
                source_sha256: &hash(b"concurrent-source"),
                source_name_sha256: &hash(b"concurrent-name"),
                media_type: "text/plain",
                page_count: Some(1),
            },
        )
        .expect("concurrent material");
        drop(connection);

        let barrier = Arc::new(Barrier::new(2));
        let workers = (0..2)
            .map(|ordinal| {
                let database_path = database_path.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let connection =
                        Connection::open(database_path).expect("open generation worker");
                    connection
                        .busy_timeout(Duration::from_secs(5))
                        .expect("worker busy timeout");
                    connection
                        .execute_batch("PRAGMA foreign_keys=ON;")
                        .expect("worker foreign keys");
                    let redaction_id = format!("redaction-concurrent-{ordinal}");
                    let extraction = hash(format!("extraction-{ordinal}").as_bytes());
                    let redacted = hash(format!("redacted-{ordinal}").as_bytes());
                    barrier.wait();
                    PrivacyStore::save_review_draft(
                        &connection,
                        &SaveReviewDraft {
                            redaction_id: &redaction_id,
                            material_id: "material-concurrent",
                            extraction_sha256: &extraction,
                            redacted_content_sha256: &redacted,
                            policy_id: "policy",
                            policy_version: 1,
                            detector_version: "detector",
                            unresolved_high_risk_count: 0,
                            review_payload_plaintext: redaction_id.as_bytes(),
                        },
                    )
                    .expect("serialize generation allocation");
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("generation worker exits");
        }

        let connection = Connection::open(database_path).expect("reopen generation database");
        let numbers = {
            let mut statement = connection
                .prepare(
                    "SELECT generation_number FROM privacy_redactions
                     WHERE material_id='material-concurrent'
                     ORDER BY generation_number",
                )
                .expect("generation numbers");
            statement
                .query_map([], |row| row.get::<_, i64>(0))
                .expect("generation number rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect generation numbers")
        };
        assert_eq!(numbers, vec![1, 2]);
    }

    #[test]
    fn schema_preflight_only_classifies_a_truly_empty_sqlite_database_as_empty() {
        let empty = Connection::open_in_memory().expect("empty database");
        assert_eq!(
            PrivacyStore::preflight_schema(&empty).expect("empty preflight"),
            PrivacyStoreSchemaStatus::Empty
        );

        let missing_marker = Connection::open_in_memory().expect("missing marker database");
        missing_marker
            .execute_batch("CREATE TABLE historical_private_rows(id TEXT PRIMARY KEY);")
            .expect("create unmarked historical table");
        assert_eq!(
            PrivacyStore::preflight_schema(&missing_marker),
            Err(PrivacyStoreError::UnsupportedSchema)
        );

        let incomplete_marker = Connection::open_in_memory().expect("incomplete marker database");
        incomplete_marker
            .execute_batch(
                "CREATE TABLE privacy_schema_metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );",
            )
            .expect("create marker without version");
        assert_eq!(
            PrivacyStore::preflight_schema(&incomplete_marker),
            Err(PrivacyStoreError::UnsupportedSchema)
        );

        let marker_without_backing =
            Connection::open_in_memory().expect("marker without backing database");
        marker_without_backing
            .execute_batch(
                "CREATE TABLE privacy_schema_metadata(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO privacy_schema_metadata(key,value)
                 VALUES('schema_version','4');",
            )
            .expect("create incomplete v4 marker");
        assert_eq!(
            PrivacyStore::preflight_schema(&marker_without_backing),
            Err(PrivacyStoreError::UnsupportedSchema)
        );
    }

    #[test]
    fn legacy_stores_require_explicit_post_backup_upgrade_and_all_versions_upgrade() {
        for version in 1..=4 {
            let connection = legacy_store(version);
            connection
                .pragma_update(None, "query_only", "ON")
                .expect("read-only preflight mode");
            assert_eq!(
                PrivacyStore::preflight_schema(&connection).expect("read-only preflight"),
                PrivacyStoreSchemaStatus::UpgradeRequired {
                    found_version: version
                }
            );
            assert_eq!(
                PrivacyStore::initialize(&connection),
                Err(PrivacyStoreError::UnsupportedSchema)
            );
            connection
                .pragma_update(None, "query_only", "OFF")
                .expect("leave read-only preflight mode");
            let unchanged_version: String = connection
                .query_row(
                    "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                    [],
                    |row| row.get(0),
                )
                .expect("legacy version remains");
            assert_eq!(unchanged_version, version.to_string());
            assert!(!table_columns(&connection, "privacy_redactions")
                .expect("legacy columns")
                .contains("generation_number"));

            PrivacyStore::upgrade_schema_after_backup(&connection)
                .expect("explicit post-backup upgrade");
            assert_eq!(
                PrivacyStore::preflight_schema(&connection).expect("intermediate preflight"),
                PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 }
            );
            PrivacyStore::finalize_approved_projection_schema_after_backup(&connection)
                .expect("finalize empty approved projection migration");
            PrivacyStore::initialize(&connection).expect("v6 initialize is idempotent");
            PrivacyStore::upgrade_schema_after_backup(&connection)
                .expect("explicit upgrade is idempotent at v6");

            let counts = connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM privacy_materials),
                        (SELECT COUNT(*) FROM privacy_redactions),
                        (SELECT COUNT(*) FROM case_material_selections)",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .expect("unified row counts");
            assert_eq!(counts, (2, 4, 0));
            let parallel_table_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master
                     WHERE type='table'
                       AND name IN ('case_materials','redaction_generations')",
                    [],
                    |row| row.get(0),
                )
                .expect("parallel backing check");
            assert_eq!(parallel_table_count, 0);
        }
    }

    #[test]
    fn v5_finalize_allows_pre_migration_revoked_approved_row_without_projection() {
        let connection = legacy_store(4);
        PrivacyStore::upgrade_schema_after_backup(&connection).expect("prepare v5 projection");
        connection
            .execute_batch("DROP TRIGGER trg_privacy_v6_approval_blocked;")
            .expect("seed a historical pre-guard row");
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET review_state='approved',
                     approved_payload_sha256=?1,
                     reviewed_by_sha256=?2,
                     approved_at='2026-07-30 00:00:00',
                     reviewed_at='2026-07-30 00:00:00',
                     risk_revision=1,
                     revocation_state='revoked',
                     revoked_at='2026-07-30 01:00:00',
                     row_version=row_version+1
                 WHERE redaction_id='redaction-a'",
                params![hash(b"legacy revoked payload"), hash(b"legacy reviewer")],
            )
            .expect("seed pre-migration revoked approval");

        PrivacyStore::finalize_approved_projection_schema_after_backup(&connection)
            .expect("revoked pre-migration approval may remain projection-free");
        PrivacyStore::initialize(&connection).expect("validate finalized v6");
        assert!(connection
            .query_row(
                "SELECT
                       approved_payload_schema_version IS NULL
                       AND protected_approved_payload_blob IS NULL
                       AND approved_payload_protection_scheme IS NULL
                       AND approved_risk_revision_hash IS NULL
                     FROM privacy_redactions WHERE redaction_id='redaction-a'",
                [],
                |row| row.get::<_, bool>(0),
            )
            .expect("projection absence"));
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET row_version=row_version+1
                 WHERE redaction_id='redaction-a'",
                [],
            )
            .expect("revoked projection-free row remains a valid v6 shape");
        assert!(connection
            .execute(
                "UPDATE privacy_redactions
                 SET approved_payload_schema_version=1,
                     protected_approved_payload_blob=x'01',
                     approved_payload_protection_scheme=
                       'windows_dpapi_current_user_v1',
                     approved_risk_revision_hash=?1,
                     row_version=row_version+1
                 WHERE redaction_id='redaction-a'",
                [hash(b"late projection risk head")],
            )
            .is_err());
    }

    #[test]
    fn v5_finalize_rejects_active_ready_approved_row_without_projection() {
        let connection = legacy_store(4);
        PrivacyStore::upgrade_schema_after_backup(&connection).expect("prepare v5 projection");
        connection
            .execute_batch("DROP TRIGGER trg_privacy_v6_approval_blocked;")
            .expect("seed a historical pre-guard row");
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET review_state='approved',
                     approved_payload_sha256=?1,
                     reviewed_by_sha256=?2,
                     approved_at='2026-07-30 00:00:00',
                     reviewed_at='2026-07-30 00:00:00',
                     risk_revision=1,
                     row_version=row_version+1
                 WHERE redaction_id='redaction-a'",
                params![hash(b"active missing payload"), hash(b"active reviewer")],
            )
            .expect("seed active approved row without projection");

        assert_eq!(
            PrivacyStore::finalize_approved_projection_schema_after_backup(&connection),
            Err(PrivacyStoreError::Conflict)
        );
        assert_eq!(
            PrivacyStore::preflight_schema(&connection).expect("v5 remains"),
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 }
        );
    }

    #[test]
    fn generation_backfill_is_stable_contiguous_and_new_numbers_never_reorder() {
        let connection = legacy_store(4);
        PrivacyStore::upgrade_schema_after_backup(&connection).expect("upgrade v4");
        let assigned = {
            let mut statement = connection
                .prepare(
                    "SELECT redaction_id,generation_number
                     FROM privacy_redactions
                     WHERE material_id='legacy-material-a'
                     ORDER BY generation_number",
                )
                .expect("generation statement");
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .expect("generation rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("generation assignments")
        };
        assert_eq!(
            assigned,
            vec![
                ("redaction-a".to_owned(), 1),
                ("redaction-b".to_owned(), 2),
                ("redaction-c".to_owned(), 3),
            ]
        );

        PrivacyStore::finalize_approved_projection_schema_after_backup(&connection)
            .expect("finalize v6");
        PrivacyStore::initialize(&connection).expect("repeat v6 initialization");
        let unchanged = {
            let mut statement = connection
                .prepare(
                    "SELECT redaction_id,generation_number
                     FROM privacy_redactions
                     WHERE material_id='legacy-material-a'
                     ORDER BY generation_number",
                )
                .expect("repeat generation statement");
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .expect("repeat generation rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("repeat assignments")
        };
        assert_eq!(unchanged, assigned);

        connection
            .execute(
                "INSERT INTO privacy_redactions(
                    redaction_id,material_id,generation_number,generation_status,
                    extraction_sha256,redacted_content_sha256,policy_id,policy_version,
                    detector_version,unresolved_high_risk_count,review_state,risk_revision,
                    protected_review_blob,protection_scheme,revocation_state,row_version,
                    created_at
                 ) VALUES(
                    'redaction-new','legacy-material-a',
                    (SELECT MAX(generation_number)+1 FROM privacy_redactions
                     WHERE material_id='legacy-material-a'),
                    'ready',?1,?2,'policy',1,'detector',0,'review_required',0,
                    x'05','windows_dpapi_current_user_v1','active',1,
                    '2020-01-01 00:00:00'
                 )",
                params![hash(b"new-extraction"), hash(b"new-redacted")],
            )
            .expect("append generation under write statement");
        let new_number: i64 = connection
            .query_row(
                "SELECT generation_number FROM privacy_redactions
                 WHERE redaction_id='redaction-new'",
                [],
                |row| row.get(0),
            )
            .expect("new generation number");
        assert_eq!(new_number, 4);
        assert!(connection
            .execute(
                "UPDATE privacy_redactions
                 SET generation_number=5,row_version=row_version+1
                 WHERE redaction_id='redaction-a'",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT INTO privacy_redactions(
                    redaction_id,material_id,generation_number,generation_status,
                    extraction_sha256,redacted_content_sha256,policy_id,policy_version,
                    detector_version,unresolved_high_risk_count,review_state,risk_revision,
                    protected_review_blob,protection_scheme,revocation_state,row_version
                 ) VALUES(
                    'redaction-duplicate','legacy-material-a',4,'ready',?1,?2,
                    'policy',1,'detector',0,'review_required',0,x'06',
                    'windows_dpapi_current_user_v1','active',1
                 )",
                params![hash(b"duplicate-extraction"), hash(b"duplicate-redacted")],
            )
            .is_err());
    }

    #[test]
    fn approved_generation_and_source_identity_are_immutable() {
        let connection = setup();
        let payload_sha256 = hash(b"approved-payload");
        insert_approved_generation(
            &connection,
            "case-project-one",
            "material-approved",
            "redaction-approved",
            1,
            1,
            &payload_sha256,
        );
        for sql in [
            "UPDATE privacy_redactions
             SET redacted_content_sha256=lower(hex(randomblob(32))),
                 row_version=row_version+1
             WHERE redaction_id='redaction-approved'",
            "UPDATE privacy_redactions
             SET risk_revision=2,row_version=row_version+1
             WHERE redaction_id='redaction-approved'",
            "UPDATE privacy_redactions
             SET protected_review_blob=x'02',row_version=row_version+1
             WHERE redaction_id='redaction-approved'",
            "UPDATE privacy_materials
             SET source_sha256=lower(hex(randomblob(32))),row_version=row_version+1
             WHERE material_id='material-approved'",
            "UPDATE privacy_materials
             SET state='outbound_ready'
             WHERE material_id='material-approved'",
        ] {
            assert!(
                connection.execute_batch(sql).is_err(),
                "immutable mutation unexpectedly succeeded: {sql}"
            );
        }
        connection
            .execute(
                "UPDATE privacy_redactions
                 SET revocation_state='revoked',
                     revoked_at='2025-03-01 00:00:00',
                     row_version=row_version+1
                 WHERE redaction_id='redaction-approved'",
                [],
            )
            .expect("one-way revocation");
        PrivacyStore::initialize(&connection)
            .expect("post-v6 revocation retains a valid immutable projection");
        assert_eq!(
            connection
                .query_row(
                    "SELECT approved_payload_schema_version,
                            approved_payload_protection_scheme
                     FROM privacy_redactions
                     WHERE redaction_id='redaction-approved'",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )
                .expect("retained projection"),
            (1, LOCAL_PROTECTION_SCHEME.to_owned())
        );
        assert!(connection
            .execute(
                "UPDATE privacy_redactions
                 SET revocation_state='active',revoked_at=NULL,
                     row_version=row_version+1
                 WHERE redaction_id='redaction-approved'",
                [],
            )
            .is_err());
    }

    #[test]
    fn selections_are_case_scoped_approved_only_and_append_preserving() {
        let connection = setup();
        let payload_sha256 = hash(b"selection-payload");
        insert_approved_generation(
            &connection,
            "case-project-one",
            "material-selection",
            "redaction-selection",
            1,
            3,
            &payload_sha256,
        );
        let insert_selection = |selection_id: &str, project_id: &str| {
            connection.execute(
                "INSERT INTO case_material_selections(
                    selection_id,project_id,material_id,redaction_id,purpose,
                    selected_by_user,selected_at,selected_generation_number,
                    selected_approved_payload_sha256,selected_risk_revision,row_version
                 ) VALUES(
                    ?1,?2,'material-selection','redaction-selection',
                    'interactive_case_work',1,'2025-03-01 00:00:00',1,?3,3,1
                 )",
                params![selection_id, project_id, &payload_sha256],
            )
        };
        insert_selection("selection-one", "case-project-one").expect("active selection");
        assert!(insert_selection("selection-duplicate", "case-project-one").is_err());
        assert!(insert_selection("selection-cross-case", "case-project-two").is_err());
        assert!(connection
            .execute(
                "DELETE FROM privacy_materials
                 WHERE material_id='material-selection'",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "UPDATE case_material_selections
                 SET purpose='rewritten',row_version=row_version+1
                 WHERE selection_id='selection-one'",
                [],
            )
            .is_err());
        connection
            .execute(
                "UPDATE case_material_selections
                 SET deselected_at='2025-03-02 00:00:00',row_version=row_version+1
                 WHERE selection_id='selection-one'",
                [],
            )
            .expect("one-way deselection");
        assert!(connection
            .execute(
                "UPDATE case_material_selections
                 SET invalidated_at='2025-03-03 00:00:00',
                     invalidation_reason='generation_revoked',
                     row_version=row_version+1
                 WHERE selection_id='selection-one'",
                [],
            )
            .is_err());
        insert_selection("selection-two", "case-project-one").expect("replacement is a new row");
        assert!(connection
            .execute(
                "DELETE FROM case_material_selections
                 WHERE selection_id='selection-one'",
                [],
            )
            .is_err());
        let history_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM case_material_selections
                 WHERE project_id='case-project-one'
                   AND material_id='material-selection'
                   AND purpose='interactive_case_work'",
                [],
                |row| row.get(0),
            )
            .expect("selection history count");
        assert_eq!(history_count, 2);
    }

    #[test]
    fn catalog_tombstone_revokes_all_generations_receipts_and_active_selections_without_deleting_history(
    ) {
        let mut connection = setup();
        let payload_one = hash(b"tombstone-payload-one");
        let payload_two = hash(b"tombstone-payload-two");
        insert_approved_generation(
            &connection,
            "case-project-tombstone",
            "material-tombstone",
            "redaction-tombstone-one",
            1,
            2,
            &payload_one,
        );
        insert_approved_generation(
            &connection,
            "case-project-tombstone",
            "material-tombstone",
            "redaction-tombstone-two",
            2,
            4,
            &payload_two,
        );
        for (receipt_id, redaction_id, payload) in [
            (
                "receipt-tombstone-one",
                "redaction-tombstone-one",
                payload_one.as_str(),
            ),
            (
                "receipt-tombstone-two",
                "redaction-tombstone-two",
                payload_two.as_str(),
            ),
        ] {
            connection
                .execute(
                    "INSERT INTO privacy_receipts(
                        receipt_id,redaction_id,signed_token,destination_kind,
                        destination_identifier_sha256,purpose,payload_sha256,
                        policy_id,policy_version,issued_at_unix,expires_at_unix
                     ) VALUES(
                        ?1,?2,'signed-test-token','external_provider',?3,
                        'case_summary',?4,'policy',1,100,300
                     )",
                    params![receipt_id, redaction_id, hash(b"provider"), payload],
                )
                .expect("generation receipt");
        }
        connection
            .execute(
                "INSERT INTO case_material_selections(
                    selection_id,project_id,material_id,redaction_id,purpose,
                    selected_by_user,selected_at,selected_generation_number,
                    selected_approved_payload_sha256,selected_risk_revision,row_version
                 ) VALUES(
                    'selection-tombstone','case-project-tombstone',
                    'material-tombstone','redaction-tombstone-two',
                    'interactive_case_work',1,'2025-03-01 00:00:00',2,?1,4,1
                 )",
                [&payload_two],
            )
            .expect("active selection");
        let source_sha256 = connection
            .query_row(
                "SELECT source_sha256 FROM privacy_materials
                 WHERE material_id='material-tombstone'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("material source hash");
        let extraction_sha256 = hash(b"redaction-tombstone-one-extraction");

        assert!(PrivacyStore::tombstone_redaction_material_exact(
            &mut connection,
            "redaction-tombstone-one",
            &source_sha256,
            &extraction_sha256,
            200,
        )
        .expect("tombstone material"));
        let retained = connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM privacy_materials
                    WHERE material_id='material-tombstone'
                      AND state='revoked' AND deleted_at IS NOT NULL),
                   (SELECT COUNT(*) FROM privacy_redactions
                    WHERE material_id='material-tombstone'
                      AND revocation_state='revoked' AND revoked_at IS NOT NULL),
                   (SELECT COUNT(*) FROM privacy_receipts
                    WHERE redaction_id IN(
                      'redaction-tombstone-one','redaction-tombstone-two'
                    ) AND revoked_at_unix=200),
                   (SELECT COUNT(*) FROM case_material_selections
                    WHERE selection_id='selection-tombstone'
                      AND invalidated_at IS NOT NULL
                      AND invalidation_reason='material_deleted')
                 ",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .expect("retained tombstone history");
        assert_eq!(retained, (1, 2, 2, 1));
        assert!(!PrivacyStore::tombstone_redaction_material_exact(
            &mut connection,
            "redaction-tombstone-one",
            &source_sha256,
            &extraction_sha256,
            201,
        )
        .expect("repeat tombstone is idempotent"));
    }

    #[test]
    fn privacy_store_source_has_no_physical_material_delete_escape_hatch() {
        let source = include_str!("store.rs");
        let legacy_method_name = ["delete", "_redaction", "_material"].concat();
        let public_signature = ["pub fn ", legacy_method_name.as_str()].concat();
        let internal_signature = ["fn ", legacy_method_name.as_str(), "_internal"].concat();
        let direct_delete_sql = ["DELETE FROM privacy_", "materials WHERE material_id=?1"].concat();

        assert!(
            !source.contains(&public_signature),
            "PrivacyStore must not expose the legacy physical material deletion API"
        );
        assert!(
            !source.contains(&internal_signature),
            "PrivacyStore must not retain an internal physical deletion escape hatch"
        );
        assert!(
            !source.contains(&direct_delete_sql),
            "business deletion must use the tombstone transaction"
        );
    }

    #[test]
    fn migration_ledger_and_resolution_events_are_strictly_append_only_history() {
        let connection = setup();
        connection
            .execute_batch("PRAGMA recursive_triggers=OFF;")
            .expect("disable recursive triggers");
        let insert_sql = "
            INSERT INTO case_material_migration_ledger(
                migration_id,source_store,source_table,source_key,
                source_fingerprint,target_material_id,target_redaction_id,
                assigned_generation_number,result_state,error_code,started_at,completed_at
            ) VALUES(
                'case-material-unification-v1','user.sqlite','case_files','file-one',
                ?1,'mat-deterministic',NULL,NULL,'blocked','attachment_ambiguous',
                '2025-03-01 00:00:00','2025-03-01 00:00:01'
            )";
        let fingerprint = hash(b"case-file-fingerprint");
        connection
            .execute(insert_sql, [&fingerprint])
            .expect("terminal ledger row");
        assert!(connection
            .execute(
                &insert_sql.replacen("INSERT INTO", "INSERT OR IGNORE INTO", 1),
                [&fingerprint],
            )
            .is_err());
        assert!(connection.execute(insert_sql, [&hash(b"changed")]).is_err());
        assert!(connection
            .execute(
                &insert_sql.replacen("INSERT INTO", "INSERT OR REPLACE INTO", 1),
                [&hash(b"replacement")],
            )
            .is_err());
        let upsert_sql = format!(
            "{insert_sql}
             ON CONFLICT(migration_id,source_store,source_table,source_key)
             DO UPDATE SET source_fingerprint=excluded.source_fingerprint"
        );
        assert!(connection.execute(&upsert_sql, [&hash(b"upsert")]).is_err());
        assert!(connection
            .execute(
                "UPDATE case_material_migration_ledger
                 SET error_code='rewritten'
                 WHERE migration_id='case-material-unification-v1'
                   AND source_store='user.sqlite'
                   AND source_table='case_files'
                   AND source_key='file-one'",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM case_material_migration_ledger
                 WHERE migration_id='case-material-unification-v1'",
                [],
            )
            .is_err());
        let retained_ledger: (String, Option<String>) = connection
            .query_row(
                "SELECT source_fingerprint,error_code
                 FROM case_material_migration_ledger
                 WHERE migration_id='case-material-unification-v1'
                   AND source_store='user.sqlite'
                   AND source_table='case_files'
                   AND source_key='file-one'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("retained ledger row");
        assert_eq!(
            retained_ledger,
            (fingerprint.clone(), Some("attachment_ambiguous".to_owned()))
        );

        let event_insert_sql = "
            INSERT INTO case_material_migration_events(
                migration_event_id,migration_id,source_store,source_table,source_key,
                event_type,source_fingerprint,target_material_id,result_state,
                error_code,occurred_at
             ) VALUES(
                'migration-resolution-one','case-material-unification-v1',
                'user.sqlite','case_files','file-one','resolution_attempted',
                ?1,'mat-deterministic','blocked','attachment_still_ambiguous',
                '2025-03-02 00:00:00'
             )";
        connection
            .execute(event_insert_sql, [&fingerprint])
            .expect("append resolution event");
        assert!(connection
            .execute(
                &event_insert_sql
                    .replacen("INSERT INTO", "INSERT OR REPLACE INTO", 1)
                    .replacen("resolution_attempted", "replacement_attempted", 1),
                [&hash(b"replacement-event")],
            )
            .is_err());
        let event_upsert_sql = format!(
            "{event_insert_sql}
             ON CONFLICT(migration_event_id)
             DO UPDATE SET event_type=excluded.event_type"
        )
        .replacen("resolution_attempted", "upsert_attempted", 1);
        assert!(connection
            .execute(&event_upsert_sql, [&hash(b"upsert-event")])
            .is_err());
        assert!(connection
            .execute(
                "UPDATE case_material_migration_events
                 SET event_type='resolved'
                 WHERE migration_event_id='migration-resolution-one'",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM case_material_migration_events
                 WHERE migration_event_id='migration-resolution-one'",
                [],
            )
            .is_err());
        let retained_event: (String, String, Option<String>) = connection
            .query_row(
                "SELECT event_type,source_fingerprint,error_code
                 FROM case_material_migration_events
                 WHERE migration_event_id='migration-resolution-one'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("retained event");
        assert_eq!(
            retained_event,
            (
                "resolution_attempted".to_owned(),
                fingerprint,
                Some("attachment_still_ambiguous".to_owned())
            )
        );
    }

    #[test]
    fn unresolved_legacy_references_are_protected_isolated_and_append_only() {
        let connection = setup();
        connection
            .execute_batch("PRAGMA recursive_triggers=OFF;")
            .expect("disable recursive triggers");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,legacy_case_id,attachment_id,
                    protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,
                    media_type,page_count,source_kind,extraction_status,
                    migration_status,state,row_version
                 ) VALUES(
                    'legacy-reference-material','case-project-one',NULL,NULL,
                    NULL,NULL,NULL,NULL,NULL,NULL,NULL,'legacy_reference',
                    'unresolved','legacy_reference','blocked',1
                 )",
                [],
            )
            .expect("isolated legacy material");
        let storage_reference_sha256 = hash(b"unresolved-storage-reference");
        connection
            .execute(
                "INSERT INTO case_material_legacy_references(
                    legacy_reference_id,material_id,migration_id,source_store,
                    source_table,source_key,protected_storage_reference_blob,
                    storage_reference_sha256,protection_scheme
                 ) VALUES(
                    'legacy-reference-one','legacy-reference-material',
                    'case-material-unification-v1','user.sqlite','case_files',
                    'file-legacy',x'010203',?1,'windows_dpapi_current_user_v1'
                 )",
                [&storage_reference_sha256],
            )
            .expect("protected legacy reference");
        assert!(connection
            .execute(
                "INSERT OR REPLACE INTO case_material_legacy_references(
                    legacy_reference_id,material_id,migration_id,source_store,
                    source_table,source_key,protected_storage_reference_blob,
                    storage_reference_sha256,protection_scheme
                 ) VALUES(
                    'legacy-reference-one','legacy-reference-material',
                    'case-material-unification-v1','user.sqlite','case_files',
                    'file-legacy',x'09',?1,'windows_dpapi_current_user_v1'
                 )",
                [&hash(b"replacement-storage-reference")],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT INTO case_material_legacy_references(
                    legacy_reference_id,material_id,migration_id,source_store,
                    source_table,source_key,protected_storage_reference_blob,
                    storage_reference_sha256,protection_scheme
                 ) VALUES(
                    'legacy-reference-one','legacy-reference-material',
                    'case-material-unification-v1','user.sqlite','case_files',
                    'file-legacy',x'0a',?1,'windows_dpapi_current_user_v1'
                 )
                 ON CONFLICT(legacy_reference_id)
                 DO UPDATE SET
                   protected_storage_reference_blob=excluded.protected_storage_reference_blob,
                   storage_reference_sha256=excluded.storage_reference_sha256",
                [&hash(b"upsert-storage-reference")],
            )
            .is_err());
        assert!(connection
            .execute(
                "UPDATE case_material_legacy_references
                 SET storage_reference_sha256=?1
                 WHERE legacy_reference_id='legacy-reference-one'",
                [&hash(b"rewritten")],
            )
            .is_err());
        assert!(connection
            .execute(
                "DELETE FROM case_material_legacy_references
                 WHERE legacy_reference_id='legacy-reference-one'",
                [],
            )
            .is_err());
        assert!(connection
            .execute(
                "INSERT INTO case_material_legacy_references(
                    legacy_reference_id,material_id,migration_id,source_store,
                    source_table,source_key,protected_storage_reference_blob,
                    storage_reference_sha256,protection_scheme
                 ) VALUES(
                    'legacy-reference-duplicate','legacy-reference-material',
                    'case-material-unification-v1','user.sqlite','case_files',
                    'file-legacy',x'04',?1,'windows_dpapi_current_user_v1'
                 )",
                [&storage_reference_sha256],
            )
            .is_err());
        let retained_reference: (String, String, String) = connection
            .query_row(
                "SELECT hex(protected_storage_reference_blob),
                        storage_reference_sha256,protection_scheme
                 FROM case_material_legacy_references
                 WHERE legacy_reference_id='legacy-reference-one'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("retained legacy reference");
        assert_eq!(
            retained_reference,
            (
                "010203".to_owned(),
                storage_reference_sha256,
                "windows_dpapi_current_user_v1".to_owned()
            )
        );
    }

    #[test]
    fn current_v6_initialization_rejects_missing_required_no_replace_guards() {
        let connection = setup();
        connection
            .execute_batch(
                "DROP TRIGGER trg_case_material_migration_ledger_no_replace;
                 DROP TRIGGER trg_case_material_migration_events_no_replace;
                 DROP TRIGGER trg_case_material_legacy_reference_no_replace;",
            )
            .expect("remove insert guards");
        assert_eq!(
            PrivacyStore::initialize(&connection),
            Err(PrivacyStoreError::UnsupportedSchema)
        );
    }

    #[test]
    fn current_v5_rejects_same_name_noop_append_only_guards() {
        for (trigger_name, operation, table) in [
            (
                "trg_case_material_migration_ledger_no_update",
                "UPDATE",
                "case_material_migration_ledger",
            ),
            (
                "trg_case_material_migration_ledger_no_delete",
                "DELETE",
                "case_material_migration_ledger",
            ),
            (
                "trg_case_material_migration_ledger_no_replace",
                "INSERT",
                "case_material_migration_ledger",
            ),
            (
                "trg_case_material_migration_events_no_update",
                "UPDATE",
                "case_material_migration_events",
            ),
            (
                "trg_case_material_migration_events_no_delete",
                "DELETE",
                "case_material_migration_events",
            ),
            (
                "trg_case_material_migration_events_no_replace",
                "INSERT",
                "case_material_migration_events",
            ),
            (
                "trg_case_material_legacy_reference_validate",
                "INSERT",
                "case_material_legacy_references",
            ),
            (
                "trg_case_material_legacy_reference_no_update",
                "UPDATE",
                "case_material_legacy_references",
            ),
            (
                "trg_case_material_legacy_reference_no_delete",
                "DELETE",
                "case_material_legacy_references",
            ),
            (
                "trg_case_material_legacy_reference_no_replace",
                "INSERT",
                "case_material_legacy_references",
            ),
        ] {
            let connection = setup();
            connection
                .execute_batch(&format!(
                    "DROP TRIGGER {trigger_name};
                     CREATE TRIGGER {trigger_name}
                     BEFORE {operation} ON {table}
                     WHEN 0 BEGIN SELECT 1; END;"
                ))
                .expect("install same-name no-op trigger");
            assert!(matches!(
                PrivacyStore::initialize(&connection),
                Err(PrivacyStoreError::UnsupportedSchema)
            ));
            assert!(matches!(
                PrivacyStore::upgrade_schema_after_backup(&connection),
                Err(PrivacyStoreError::UnsupportedSchema)
            ));
            let stored_sql: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?1",
                    [trigger_name],
                    |row| row.get(0),
                )
                .expect("forged trigger remains");
            assert!(stored_sql.to_ascii_lowercase().contains("when 0"));
        }
    }

    #[test]
    fn egress_audit_is_append_only_and_contains_no_plaintext() {
        let mut connection = setup();
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: 100,
            classification: DataClassification::CaseRaw,
            destination_kind: DestinationKind::ExternalProvider,
            destination_identifier_sha256: hash(b"provider"),
            purpose: "assistant_chat".to_owned(),
            payload_sha256: hash("张三".as_bytes()),
            payload_bytes: "张三".len(),
            policy_id: "cn-legal-default".to_owned(),
            policy_version: 1,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id: None,
            residual_counts: BTreeMap::from([("person_name".to_owned(), 1)]),
            allowed: false,
            reason_code: "classification_forbidden".to_owned(),
        };
        let event_hash =
            PrivacyStore::append_egress_audit(&mut connection, "event-1", &audit).expect("audit");
        assert_eq!(event_hash.len(), 64);
        let wire = connection
            .query_row(
                "SELECT destination_identifier_sha256||payload_sha256||
                        residual_counts_json||reason_code
                 FROM privacy_egress_audit WHERE event_id='event-1'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("row");
        assert!(!wire.contains("张三"));
        assert!(!wire.contains("provider"));
        assert!(connection
            .execute(
                "UPDATE privacy_egress_audit SET allowed=1 WHERE event_id='event-1'",
                []
            )
            .is_err());
    }

    #[test]
    fn interactive_audit_is_not_persisted_into_the_v5_classification_schema() {
        let mut connection = setup();
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: 100,
            classification: DataClassification::InteractiveUserProvided,
            destination_kind: DestinationKind::ExternalProvider,
            destination_identifier_sha256: hash(b"provider"),
            purpose: "assistant_interactive_chat".to_owned(),
            payload_sha256: hash(b"user-provided-content"),
            payload_bytes: 21,
            policy_id: "cn-legal-default".to_owned(),
            policy_version: 1,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id: None,
            residual_counts: BTreeMap::from([("phone_number".to_owned(), 1)]),
            allowed: true,
            reason_code: "allowed".to_owned(),
        };

        assert_eq!(
            PrivacyStore::append_egress_audit(&mut connection, "interactive-event", &audit),
            Err(PrivacyStoreError::InvalidInput)
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM privacy_egress_audit", [], |row| {
                    row.get::<_, u32>(0)
                })
                .expect("audit row count"),
            0
        );
        assert_eq!(PRIVACY_STORE_SCHEMA_VERSION, 6);
    }

    #[cfg(windows)]
    #[test]
    fn receipt_persistence_requires_exact_approved_payload() {
        let mut connection = setup();
        register(&connection);
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id: "redaction-1",
                material_id: "material-1",
                extraction_sha256: &hash(b"extraction"),
                redacted_content_sha256: &hash(b"redacted"),
                policy_id: "cn-legal-default",
                policy_version: 1,
                detector_version: REDACTION_VERSION,
                unresolved_high_risk_count: 0,
                review_payload_plaintext: b"review",
            },
        )
        .expect("draft");
        let payload = b"approved payload";
        PrivacyStore::approve_review(
            &mut connection,
            "redaction-1",
            &hash(b"redacted"),
            &hash(payload),
            &hash(payload),
            &hash(b"reviewer"),
            payload,
        )
        .expect("approve");
        let signer = ReceiptSigner::new([4u8; 32]).expect("signer");
        let receipt = signer
            .issue(RedactionReceiptClaims {
                receipt_id: String::new(),
                source_sha256: vec![hash(b"source")],
                extraction_sha256: hash(b"extraction"),
                redacted_content_sha256: hash(payload),
                approved_payload_sha256: hash(payload),
                policy_id: "cn-legal-default".to_owned(),
                policy_version: 1,
                detector_version: REDACTION_VERSION.to_owned(),
                destination: DestinationScope {
                    kind: DestinationKind::ExternalProvider,
                    identifier: "provider-1".to_owned(),
                },
                purpose: "assistant_chat".to_owned(),
                unresolved_high_risk_count: 0,
                review_state: ReviewState::Approved,
                issued_at_unix: 100,
                expires_at_unix: Some(200),
                key_version: 1,
            })
            .expect("receipt");
        let token = signer.encode_token(&receipt).expect("token");
        PrivacyStore::persist_receipt(
            &mut connection,
            "redaction-1",
            &signer,
            &receipt,
            &token,
            payload,
            150,
        )
        .expect("persist");
        let count = connection
            .query_row("SELECT COUNT(*) FROM privacy_receipts", [], |row| {
                row.get::<_, u32>(0)
            })
            .expect("count");
        assert_eq!(count, 1);
        let (stored_type, protected_token) = connection
            .query_row(
                "SELECT typeof(signed_token),signed_token FROM privacy_receipts WHERE receipt_id=?1",
                [&receipt.claims.receipt_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .expect("stored protected token");
        assert_eq!(stored_type, "blob");
        let plaintext_token = unprotect_local(&protected_token).expect("unprotect token");
        assert_eq!(plaintext_token, token.as_bytes());
        assert!(!protected_token
            .windows(b"rct_v1.".len())
            .any(|window| window == b"rct_v1."));
        let destination = receipt.claims.destination.clone();
        let verification = ActiveReceiptVerification {
            redaction_id: "redaction-1",
            signed_token: &token,
            approved_payload: payload,
            destination: &destination,
            purpose: "assistant_chat",
            now_unix: 150,
            expected_key_version: 1,
        };
        let active = PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification)
            .expect("active receipt");
        assert_eq!(active, receipt);
        assert_eq!(
            PrivacyStore::verify_active_receipt_token(
                &connection,
                &signer,
                &ActiveReceiptVerification {
                    approved_payload: b"tampered",
                    ..verification
                },
            ),
            Err(PrivacyStoreError::InvalidReceipt)
        );
        assert_eq!(
            PrivacyStore::verify_active_receipt_token(
                &connection,
                &signer,
                &ActiveReceiptVerification {
                    now_unix: 200,
                    ..verification
                },
            ),
            Err(PrivacyStoreError::ReceiptExpired)
        );
        PrivacyStore::consume_receipt_for_dispatch(
            &mut connection,
            &receipt.claims.receipt_id,
            "redaction-1",
            "dispatch-once-1",
            150,
        )
        .expect("first exact dispatch claim");
        assert_eq!(
            PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification),
            Err(PrivacyStoreError::ReceiptConsumed)
        );
        assert_eq!(
            PrivacyStore::consume_receipt_for_dispatch(
                &mut connection,
                &receipt.claims.receipt_id,
                "redaction-1",
                "dispatch-replay-2",
                151,
            ),
            Err(PrivacyStoreError::ReceiptConsumed)
        );
        PrivacyStore::revoke_receipt(&connection, &receipt.claims.receipt_id, 160).expect("revoke");
        assert_eq!(
            PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification),
            Err(PrivacyStoreError::ReceiptRevoked)
        );
    }

    #[cfg(windows)]
    #[test]
    fn tombstoning_redaction_material_preserves_history_and_audit_chain() {
        fn chained_event_hash(
            event_id: &str,
            previous: &str,
            audit: &PrivacyEgressAuditRecord,
        ) -> String {
            let canonical = serde_json::to_vec(audit).expect("canonical audit");
            let mut chain =
                Vec::with_capacity(event_id.len() + previous.len() + canonical.len() + 2);
            chain.extend_from_slice(event_id.as_bytes());
            chain.push(0);
            chain.extend_from_slice(previous.as_bytes());
            chain.push(0);
            chain.extend_from_slice(&canonical);
            sha256_hex(&chain)
        }

        let mut connection = setup();
        register(&connection);
        for (redaction_id, review) in [
            ("redaction-1", b"review one".as_slice()),
            ("redaction-2", b"review two".as_slice()),
        ] {
            PrivacyStore::save_review_draft(
                &connection,
                &SaveReviewDraft {
                    redaction_id,
                    material_id: "material-1",
                    extraction_sha256: &hash(b"extraction"),
                    redacted_content_sha256: &hash(b"redacted"),
                    policy_id: "cn-legal-default",
                    policy_version: 1,
                    detector_version: REDACTION_VERSION,
                    unresolved_high_risk_count: 0,
                    review_payload_plaintext: review,
                },
            )
            .expect("draft");
        }

        let payload = b"approved payload";
        PrivacyStore::approve_review(
            &mut connection,
            "redaction-1",
            &hash(b"redacted"),
            &hash(payload),
            &hash(payload),
            &hash(b"reviewer"),
            payload,
        )
        .expect("approve");
        let signer = ReceiptSigner::new([8u8; 32]).expect("signer");
        let receipt = signer
            .issue(RedactionReceiptClaims {
                receipt_id: String::new(),
                source_sha256: vec![hash(b"source")],
                extraction_sha256: hash(b"extraction"),
                redacted_content_sha256: hash(payload),
                approved_payload_sha256: hash(payload),
                policy_id: "cn-legal-default".to_owned(),
                policy_version: 1,
                detector_version: REDACTION_VERSION.to_owned(),
                destination: DestinationScope {
                    kind: DestinationKind::ExternalProvider,
                    identifier: "provider-1".to_owned(),
                },
                purpose: "assistant_chat".to_owned(),
                unresolved_high_risk_count: 0,
                review_state: ReviewState::Approved,
                issued_at_unix: 100,
                expires_at_unix: Some(200),
                key_version: 1,
            })
            .expect("receipt");
        let token = signer.encode_token(&receipt).expect("token");
        PrivacyStore::persist_receipt(
            &mut connection,
            "redaction-1",
            &signer,
            &receipt,
            &token,
            payload,
            150,
        )
        .expect("persist");

        let destination = receipt.claims.destination.clone();
        let verification = ActiveReceiptVerification {
            redaction_id: "redaction-1",
            signed_token: &token,
            approved_payload: payload,
            destination: &destination,
            purpose: "assistant_chat",
            now_unix: 150,
            expected_key_version: 1,
        };
        PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification)
            .expect("active before tombstone");
        let (blob_count, protected_bytes) = connection
            .query_row(
                "SELECT COUNT(*),COALESCE(SUM(length(protected_review_blob)),0)
                 FROM privacy_redactions WHERE material_id='material-1'",
                [],
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("protected blobs");
        assert_eq!(blob_count, 2);
        assert!(protected_bytes > 0);
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM privacy_receipts", [], |row| {
                    row.get::<_, u32>(0)
                })
                .expect("receipt count"),
            1
        );

        let audit_one = PrivacyEgressAuditRecord {
            occurred_at_unix: 151,
            classification: DataClassification::CaseRedactedApproved,
            destination_kind: DestinationKind::ExternalProvider,
            destination_identifier_sha256: hash(b"provider-1"),
            purpose: "assistant_chat".to_owned(),
            payload_sha256: hash(payload),
            payload_bytes: payload.len(),
            policy_id: "cn-legal-default".to_owned(),
            policy_version: 1,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id: Some(receipt.claims.receipt_id.clone()),
            residual_counts: BTreeMap::new(),
            allowed: true,
            reason_code: "receipt_authorized".to_owned(),
        };
        let first_hash =
            PrivacyStore::append_egress_audit(&mut connection, "delete-test-event-1", &audit_one)
                .expect("first audit");
        assert_eq!(
            first_hash,
            chained_event_hash("delete-test-event-1", "", &audit_one)
        );
        let audit_two = PrivacyEgressAuditRecord {
            occurred_at_unix: 152,
            reason_code: "delivery_completed".to_owned(),
            ..audit_one.clone()
        };
        let second_hash =
            PrivacyStore::append_egress_audit(&mut connection, "delete-test-event-2", &audit_two)
                .expect("second audit");
        assert_eq!(
            second_hash,
            chained_event_hash("delete-test-event-2", &first_hash, &audit_two)
        );

        let source_sha256 = hash(b"source");
        let extraction_sha256 = hash(b"extraction");
        assert_eq!(
            PrivacyStore::tombstone_redaction_material_exact(
                &mut connection,
                "",
                &source_sha256,
                &extraction_sha256,
                160,
            ),
            Err(PrivacyStoreError::InvalidInput)
        );
        assert!(!PrivacyStore::tombstone_redaction_material_exact(
            &mut connection,
            "unknown-redaction",
            &source_sha256,
            &extraction_sha256,
            160,
        )
        .expect("unknown identifier"));
        PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification)
            .expect("unknown tombstone changes nothing");

        assert!(PrivacyStore::tombstone_redaction_material_exact(
            &mut connection,
            "redaction-1",
            &source_sha256,
            &extraction_sha256,
            160,
        )
        .expect("tombstone material"));
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_materials
                     WHERE material_id='material-1'
                       AND state='revoked'
                       AND deleted_at IS NOT NULL",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .expect("tombstoned material"),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_redactions
                     WHERE material_id='material-1'
                       AND revocation_state='revoked'
                       AND revoked_at IS NOT NULL",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .expect("revoked generations"),
            2
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_receipts
                     WHERE redaction_id='redaction-1' AND revoked_at_unix=160",
                    [],
                    |row| row.get::<_, u32>(0),
                )
                .expect("revoked receipt"),
            1
        );
        PrivacyStore::load_review_draft(&connection, "redaction-2")
            .expect("review history remains readable for audit and retention");
        assert_eq!(
            PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification),
            Err(PrivacyStoreError::ReceiptRevoked)
        );

        let audit_rows = {
            let mut statement = connection
                .prepare(
                    "SELECT event_id,previous_event_hash,event_hash
                     FROM privacy_egress_audit ORDER BY rowid",
                )
                .expect("audit statement");
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .expect("audit rows")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect audit rows")
        };
        assert_eq!(
            audit_rows,
            vec![
                (
                    "delete-test-event-1".to_owned(),
                    String::new(),
                    first_hash.clone()
                ),
                ("delete-test-event-2".to_owned(), first_hash, second_hash),
            ]
        );
        assert!(connection
            .execute(
                "DELETE FROM privacy_egress_audit WHERE event_id='delete-test-event-1'",
                []
            )
            .is_err());
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApproveReviewWithRiskRevision<'a> {
    pub redaction_id: &'a str,
    pub expected_redacted_sha256: &'a str,
    pub approved_redacted_content_sha256: &'a str,
    pub approved_payload_sha256: &'a str,
    pub reviewed_by_sha256: &'a str,
    pub approved_review_payload_plaintext: &'a [u8],
    pub approved_payload_plaintext: &'a [u8],
    pub risk_revision: SaveRiskReviewRevision<'a>,
}
