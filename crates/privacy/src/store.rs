use crate::{
    protect_local, sha256_hex, unprotect_local, DataClassification, DestinationKind,
    DestinationScope, PrivacyEgressAuditRecord, ReceiptError, ReceiptSigner,
    ReceiptVerificationContext, ReviewState, SignedRedactionReceipt, LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt};

pub const PRIVACY_STORE_SCHEMA_VERSION: i64 = 4;
const RISK_REVIEW_REVISION_PROFILE: &str = "privacy-risk-review-revision-v1";
pub const MAX_ACTIVE_RECEIPT_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_ID_BYTES: usize = 128;
const MAX_TOKEN_BYTES: usize = 32_768;
const MAX_PROTECTED_TOKEN_BYTES: usize = 65_536;
const MAX_APPROVED_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;

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
    pub fn initialize(connection: &Connection) -> Result<(), PrivacyStoreError> {
        connection
            .execute_batch(
                "
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
                    previous_revision_hash TEXT NOT NULL CHECK(
                        length(previous_revision_hash) IN (0,64)
                    ),
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
                ",
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let receipt_columns = {
            let mut statement = connection
                .prepare("PRAGMA table_info(privacy_receipts)")
                .map_err(|_| PrivacyStoreError::Database)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(1))
                .map_err(|_| PrivacyStoreError::Database)?;
            rows.collect::<Result<BTreeSet<_>, _>>()
                .map_err(|_| PrivacyStoreError::Database)?
        };
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
        let version = connection
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        match version {
            Some(value) if value == PRIVACY_STORE_SCHEMA_VERSION.to_string() => {
                crate::lifecycle::initialize_lifecycle_schema(connection)?;
            }
            Some(value) if value == "1" || value == "2" || value == "3" => {
                crate::lifecycle::initialize_lifecycle_schema(connection)?;
                let changed = connection
                    .execute(
                        "UPDATE privacy_schema_metadata SET value=?1,updated_at=CURRENT_TIMESTAMP
                         WHERE key='schema_version' AND value=?2",
                        rusqlite::params![PRIVACY_STORE_SCHEMA_VERSION.to_string(), value],
                    )
                    .map_err(|_| PrivacyStoreError::Database)?;
                if changed != 1 {
                    return Err(PrivacyStoreError::Conflict);
                }
            }
            None => {
                crate::lifecycle::initialize_lifecycle_schema(connection)?;
                connection
                    .execute(
                        "INSERT INTO privacy_schema_metadata(key,value) VALUES('schema_version',?1)",
                        [PRIVACY_STORE_SCHEMA_VERSION.to_string()],
                    )
                    .map_err(|_| PrivacyStoreError::Database)?;
            }
            Some(_) => return Err(PrivacyStoreError::UnsupportedSchema),
        }
        Ok(())
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
                    source_name_sha256,media_type,page_count,state
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,'registered')",
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
        connection
            .execute(
                "INSERT INTO privacy_redactions(
                    redaction_id,material_id,extraction_sha256,redacted_content_sha256,
                    policy_id,policy_version,detector_version,unresolved_high_risk_count,
                    review_state,protected_review_blob,protection_scheme
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,'review_required',?9,?10)",
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
            .map_err(|_| PrivacyStoreError::Database)?;
        connection
            .execute(
                "UPDATE privacy_materials
                 SET state='review_required',updated_at=CURRENT_TIMESTAMP
                 WHERE material_id=?1",
                [input.material_id],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        Ok(())
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
                     protected_review_blob=?5,protection_scheme=?6
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

    /// Permanently removes the local review material identified by a redaction.
    ///
    /// Deleting the material intentionally cascades to every review draft and
    /// receipt for that material. Hash-only egress audit rows are independent
    /// and remain append-only. A well-formed but unknown identifier returns
    /// `Ok(false)`.
    pub fn delete_redaction_material(
        connection: &mut Connection,
        redaction_id: &str,
    ) -> Result<bool, PrivacyStoreError> {
        Self::delete_redaction_material_internal(connection, redaction_id, None)
    }

    pub fn delete_redaction_material_exact(
        connection: &mut Connection,
        redaction_id: &str,
        expected_source_sha256: &str,
        expected_extraction_sha256: &str,
    ) -> Result<bool, PrivacyStoreError> {
        valid_hash(expected_source_sha256)?;
        valid_hash(expected_extraction_sha256)?;
        Self::delete_redaction_material_internal(
            connection,
            redaction_id,
            Some((expected_source_sha256, expected_extraction_sha256)),
        )
    }

    fn delete_redaction_material_internal(
        connection: &mut Connection,
        redaction_id: &str,
        expected_identity: Option<(&str, &str)>,
    ) -> Result<bool, PrivacyStoreError> {
        valid_id(redaction_id)?;
        connection
            .pragma_update(None, "secure_delete", "ON")
            .map_err(|_| PrivacyStoreError::Database)?;
        let secure_delete = connection
            .pragma_query_value(None, "secure_delete", |row| row.get::<_, i64>(0))
            .map_err(|_| PrivacyStoreError::Database)?;
        if secure_delete != 1 {
            return Err(PrivacyStoreError::Database);
        }
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| PrivacyStoreError::Database)?;
        let foreign_keys = connection
            .pragma_query_value(None, "foreign_keys", |row| row.get::<_, i64>(0))
            .map_err(|_| PrivacyStoreError::Database)?;
        if foreign_keys != 1 {
            return Err(PrivacyStoreError::Database);
        }

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| PrivacyStoreError::Database)?;
        let identity = transaction
            .query_row(
                "SELECT r.material_id,m.source_sha256,r.extraction_sha256
                 FROM privacy_redactions r
                 JOIN privacy_materials m ON m.material_id=r.material_id
                 WHERE r.redaction_id=?1",
                [redaction_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        let Some((material_id, source_sha256, extraction_sha256)) = identity else {
            transaction
                .commit()
                .map_err(|_| PrivacyStoreError::Database)?;
            return Ok(false);
        };
        if let Some((expected_source_sha256, expected_extraction_sha256)) = expected_identity {
            if source_sha256 != expected_source_sha256
                || extraction_sha256 != expected_extraction_sha256
            {
                return Err(PrivacyStoreError::Conflict);
            }
        }
        let changed = transaction
            .execute(
                "DELETE FROM privacy_materials WHERE material_id=?1",
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
                 SET review_state='approved',approved_payload_sha256=?2,
                     reviewed_by_sha256=?3,protected_review_blob=?5,
                     redacted_content_sha256=?6,reviewed_at=CURRENT_TIMESTAMP
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
                "UPDATE privacy_materials SET state='approved',updated_at=CURRENT_TIMESTAMP
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
        {
            return Err(PrivacyStoreError::InvalidInput);
        }
        let protected_review_blob = protect_local(input.approved_review_payload_plaintext)
            .map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        let transaction = connection
            .transaction()
            .map_err(|_| PrivacyStoreError::Database)?;
        Self::append_risk_review_revision(&transaction, &input.risk_revision)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_redactions
                 SET review_state='approved',approved_payload_sha256=?2,
                     reviewed_by_sha256=?3,protected_review_blob=?5,
                     redacted_content_sha256=?6,reviewed_at=CURRENT_TIMESTAMP
                 WHERE redaction_id=?1 AND unresolved_high_risk_count=0
                   AND redacted_content_sha256=?4
                   AND (review_state='review_required'
                        OR (review_state='approved' AND approved_payload_sha256=?2))",
                params![
                    input.redaction_id,
                    input.approved_payload_sha256,
                    input.reviewed_by_sha256,
                    input.expected_redacted_sha256,
                    protected_review_blob,
                    input.approved_redacted_content_sha256,
                ],
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        if changed != 1 {
            return Err(PrivacyStoreError::Conflict);
        }
        transaction
            .execute(
                "UPDATE privacy_materials SET state='approved',updated_at=CURRENT_TIMESTAMP
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
                "UPDATE privacy_materials SET state='outbound_ready',updated_at=CURRENT_TIMESTAMP
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
                    classification(audit.classification),
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

const fn classification(value: DataClassification) -> &'static str {
    match value {
        DataClassification::LegalPublic => "legal_public",
        DataClassification::ProductPublic => "product_public",
        DataClassification::CaseRaw => "case_raw",
        DataClassification::CaseRedactedPending => "case_redacted_pending",
        DataClassification::CaseRedactedApproved => "case_redacted_approved",
        DataClassification::Secret => "secret",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DestinationScope, ReceiptSigner, RedactionReceiptClaims, REDACTION_VERSION};
    use std::collections::BTreeMap;

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
    fn schema_v2_migrates_to_risk_review_and_receipt_consumption_schema_v4() {
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
        PrivacyStore::initialize(&connection).expect("migrate");
        let version = connection
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("version");
        assert_eq!(version, "4");
        let table_count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name='privacy_risk_review_revisions'",
                [],
                |row| row.get::<_, u32>(0),
            )
            .expect("risk table");
        assert_eq!(table_count, 1);
        let receipt_columns = {
            let mut statement = connection
                .prepare("PRAGMA table_info(privacy_receipts)")
                .expect("receipt columns");
            statement
                .query_map([], |row| row.get::<_, String>(1))
                .expect("receipt column rows")
                .collect::<Result<BTreeSet<_>, _>>()
                .expect("receipt column names")
        };
        assert!(receipt_columns.contains("consumed_at_unix"));
        assert!(receipt_columns.contains("consumption_id"));
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
            reason_code: "raw_material_forbidden".to_owned(),
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
    fn deleting_redaction_material_removes_secrets_and_preserves_audit_chain() {
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
            .expect("active before deletion");
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

        connection
            .pragma_update(None, "secure_delete", "OFF")
            .expect("disable for validation test");
        assert_eq!(
            PrivacyStore::delete_redaction_material(&mut connection, ""),
            Err(PrivacyStoreError::InvalidInput)
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "secure_delete", |row| row.get::<_, i64>(0))
                .expect("secure delete mode"),
            0
        );
        assert!(
            !PrivacyStore::delete_redaction_material(&mut connection, "unknown-redaction")
                .expect("unknown identifier")
        );
        PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification)
            .expect("unknown deletion changes nothing");

        assert!(
            PrivacyStore::delete_redaction_material(&mut connection, "redaction-1")
                .expect("delete material")
        );
        assert_eq!(
            connection
                .pragma_query_value(None, "secure_delete", |row| row.get::<_, i64>(0))
                .expect("secure delete mode"),
            1
        );
        for table in [
            "privacy_materials",
            "privacy_redactions",
            "privacy_receipts",
        ] {
            let count = connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, u32>(0)
                })
                .expect("cascade count");
            assert_eq!(count, 0, "{table} should be empty");
        }
        assert_eq!(
            PrivacyStore::load_review_draft(&connection, "redaction-2"),
            Err(PrivacyStoreError::Conflict)
        );
        assert_eq!(
            PrivacyStore::verify_active_receipt_token(&connection, &signer, &verification),
            Err(PrivacyStoreError::InvalidReceipt)
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
    pub risk_revision: SaveRiskReviewRevision<'a>,
}
