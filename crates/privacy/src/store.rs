use crate::{
    protect_local, sha256_hex, unprotect_local, DataClassification, DestinationKind,
    DestinationScope, PrivacyEgressAuditRecord, ReceiptError, ReceiptSigner,
    ReceiptVerificationContext, ReviewState, SignedRedactionReceipt, LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};

pub const PRIVACY_STORE_SCHEMA_VERSION: i64 = 1;
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
                ",
            )
            .map_err(|_| PrivacyStoreError::Database)?;
        let version = connection
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?;
        match version {
            Some(value) if value != PRIVACY_STORE_SCHEMA_VERSION.to_string() => {
                return Err(PrivacyStoreError::UnsupportedSchema);
            }
            Some(_) => {}
            None => {
                connection
                    .execute(
                        "INSERT INTO privacy_schema_metadata(key,value) VALUES('schema_version',?1)",
                        [PRIVACY_STORE_SCHEMA_VERSION.to_string()],
                    )
                    .map_err(|_| PrivacyStoreError::Database)?;
            }
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
                "SELECT p.signed_token,p.revoked_at_unix,m.source_sha256,
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
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, u32>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, u32>(9)?,
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| PrivacyStoreError::Database)?
            .ok_or(PrivacyStoreError::InvalidReceipt)?;
        if row.1.is_some() {
            return Err(PrivacyStoreError::ReceiptRevoked);
        }
        let stored_token = unprotect_local(&row.0).map_err(|_| PrivacyStoreError::ProtectedBlob)?;
        if !constant_time_bytes_eq(&stored_token, verification.signed_token.as_bytes()) {
            return Err(PrivacyStoreError::InvalidReceipt);
        }
        if row.9 != 0 || row.10 != "approved" || row.11 != "outbound_ready" {
            return Err(PrivacyStoreError::NotApproved);
        }
        if receipt.claims.source_sha256.len() != 1
            || receipt.claims.source_sha256.first() != Some(&row.2)
            || receipt.claims.extraction_sha256 != row.3
            || receipt.claims.redacted_content_sha256 != row.4
            || row.5.as_deref() != Some(receipt.claims.approved_payload_sha256.as_str())
            || receipt.claims.policy_id != row.6
            || receipt.claims.policy_version != row.7
            || receipt.claims.detector_version != row.8
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
                    policy_id: &row.6,
                    policy_version: row.7,
                    detector_version: &row.8,
                    now_unix: verification.now_unix,
                },
            )
            .map_err(map_receipt_error)?;
        Ok(receipt)
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
