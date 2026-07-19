use legal_services::CitationValidateRequest;
use privacy::{
    ActiveReceiptVerification, DataClassification, DestinationKind, DestinationScope,
    EgressCandidate, EgressPolicyEngine, PrivacyEgressAuditRecord, PrivacyStore, PrivacyStoreError,
    ReceiptSigner, PRIVACY_STORE_SCHEMA_VERSION,
};
#[cfg(windows)]
use providers::{
    windows_credentials::WindowsCredentialStore, CredentialStore, ProviderCredentialKey,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::{Map, Value};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
#[cfg(windows)]
use zeroize::Zeroizing;

pub const REDACTED_CASE_DESTINATION_IDENTIFIER: &str = "lawyer-assistance-mcp:redacted_case";
pub const CITATION_VALIDATE_PURPOSE: &str = "mcp.citation_validate.v1";

const POLICY_ID: &str = "cn-legal-default";
const POLICY_VERSION: u32 = 1;
#[cfg(windows)]
const RECEIPT_KEY_SERVICE: &str = "LawyerAssistancePrivacy";
#[cfg(windows)]
const RECEIPT_KEY_PROVIDER: &str = "redaction-receipt-signing";
#[cfg(windows)]
const RECEIPT_KEY_ACCOUNT: &str = "v1";
const RECEIPT_KEY_VERSION: u32 = 1;
const MAX_APPROVED_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_RECEIPT_TOKEN_BYTES: usize = 16 * 1024;
const MAX_RECEIPT_TTL_SECONDS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptGateError {
    CredentialUnavailable,
    CredentialInvalid,
    ReceiptStateUnavailable,
    ReceiptRevoked,
    InvalidEnvelope,
    PayloadTooLarge,
    InvalidReceipt,
    InvalidApprovedPayload,
    ClockInvalid,
}

impl ReceiptGateError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::CredentialUnavailable => "receipt_key_unavailable",
            Self::CredentialInvalid => "receipt_key_invalid",
            Self::ReceiptStateUnavailable => "receipt_state_unavailable",
            Self::ReceiptRevoked => "redaction_receipt_revoked",
            Self::InvalidEnvelope => "redaction_receipt_envelope_invalid",
            Self::PayloadTooLarge => "privacy_payload_too_large",
            Self::InvalidReceipt => "redaction_receipt_rejected",
            Self::InvalidApprovedPayload => "approved_payload_invalid",
            Self::ClockInvalid => "clock_invalid",
        }
    }
}

impl fmt::Display for ReceiptGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReceiptGateError {}

#[derive(Clone)]
pub struct RedactedReceiptGate {
    signer: ReceiptSigner,
    receipt_database_path: PathBuf,
}

impl fmt::Debug for RedactedReceiptGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedReceiptGate")
            .field("signer", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEnvelope {
    approved_payload_json: String,
    redaction_receipt: String,
}

impl RedactedReceiptGate {
    /// Read the App receipt-signing key from one fixed Windows Credential
    /// Manager target. This never creates a key and never consults arguments,
    /// configuration files, or environment variables.
    pub fn load_from_windows_credentials(
        user_database_path: &Path,
    ) -> Result<Self, ReceiptGateError> {
        #[cfg(windows)]
        {
            let receipt_database_path = resolve_receipt_database(user_database_path)?;
            let store = WindowsCredentialStore::with_service_prefix(RECEIPT_KEY_SERVICE);
            let key = ProviderCredentialKey::new(RECEIPT_KEY_PROVIDER, RECEIPT_KEY_ACCOUNT);
            let secret = store
                .read_api_key(&key)
                .map_err(|_| ReceiptGateError::CredentialUnavailable)?
                .ok_or(ReceiptGateError::CredentialUnavailable)?;
            let secret_hex = Zeroizing::new(secret.expose_secret().to_owned());
            let key_bytes =
                decode_32_byte_hex(&secret_hex).ok_or(ReceiptGateError::CredentialInvalid)?;
            let signer =
                ReceiptSigner::new(key_bytes).map_err(|_| ReceiptGateError::CredentialInvalid)?;
            Ok(Self {
                signer,
                receipt_database_path,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = user_database_path;
            Err(ReceiptGateError::CredentialUnavailable)
        }
    }

    /// Trusted in-process construction for embedding and transport tests.
    pub fn from_signer_and_database(
        signer: ReceiptSigner,
        user_database_path: &Path,
    ) -> Result<Self, ReceiptGateError> {
        Ok(Self {
            signer,
            receipt_database_path: resolve_receipt_database(user_database_path)?,
        })
    }

    /// Consume and verify a wrapper around the exact approved business bytes.
    ///
    /// Only the parsed CitationValidateRequest is returned. The receipt and its
    /// approved JSON string cannot reach legal-services, logs, or MCP output.
    pub fn verify_citation_call(
        &self,
        arguments: Map<String, Value>,
    ) -> Result<CitationValidateRequest, ReceiptGateError> {
        let envelope: ReceiptEnvelope = serde_json::from_value(Value::Object(arguments))
            .map_err(|_| ReceiptGateError::InvalidEnvelope)?;
        let payload = envelope.approved_payload_json.as_bytes();
        if payload.is_empty()
            || payload.len() > MAX_APPROVED_PAYLOAD_BYTES
            || envelope.redaction_receipt.is_empty()
            || envelope.redaction_receipt.len() > MAX_RECEIPT_TOKEN_BYTES
        {
            return Err(ReceiptGateError::PayloadTooLarge);
        }

        let receipt = self
            .signer
            .decode_token(&envelope.redaction_receipt)
            .map_err(|_| ReceiptGateError::InvalidReceipt)?;
        let destination = DestinationScope {
            kind: DestinationKind::ExternalMcpHost,
            identifier: REDACTED_CASE_DESTINATION_IDENTIFIER.to_owned(),
        };
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ReceiptGateError::ClockInvalid)?
            .as_secs();
        let expires_at = receipt
            .claims
            .expires_at_unix
            .ok_or(ReceiptGateError::InvalidReceipt)?;
        let ttl = expires_at
            .checked_sub(receipt.claims.issued_at_unix)
            .ok_or(ReceiptGateError::InvalidReceipt)?;
        if receipt.claims.key_version != RECEIPT_KEY_VERSION
            || ttl > MAX_RECEIPT_TTL_SECONDS
            || receipt.claims.issued_at_unix > now_unix
            || now_unix >= expires_at
        {
            return Err(ReceiptGateError::InvalidReceipt);
        }
        self.verify_persisted_receipt(
            &receipt.claims.receipt_id,
            &envelope.redaction_receipt,
            payload,
            &destination,
            now_unix,
        )?;
        let engine = EgressPolicyEngine::new(self.signer.clone(), POLICY_ID, POLICY_VERSION)
            .map_err(|_| ReceiptGateError::InvalidReceipt)?;
        let (authorized, mut audit) = engine.authorize_with_audit(&EgressCandidate {
            payload,
            classification: DataClassification::CaseRedactedApproved,
            destination: &destination,
            purpose: CITATION_VALIDATE_PURPOSE,
            receipt: Some(&receipt),
            now_unix,
        });
        let authorized = authorized.map_err(|_| ReceiptGateError::InvalidReceipt)?;
        let request = serde_json::from_slice::<CitationValidateRequest>(authorized.payload())
            .map_err(|_| ReceiptGateError::InvalidApprovedPayload)?;
        audit.reason_code = "mcp_citation_attempt_authorized".to_owned();
        self.append_authorized_call_audit(&audit)?;
        Ok(request)
    }

    fn append_authorized_call_audit(
        &self,
        audit: &PrivacyEgressAuditRecord,
    ) -> Result<(), ReceiptGateError> {
        let mut connection = Connection::open_with_flags(
            &self.receipt_database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
        connection
            .busy_timeout(Duration::from_secs(2))
            .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
        connection
            .execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
            .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
        let event_id = format!("mcp_{}", Uuid::new_v4().simple());
        PrivacyStore::append_egress_audit(&mut connection, &event_id, audit)
            .map(|_| ())
            .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)
    }

    fn verify_persisted_receipt(
        &self,
        receipt_id: &str,
        signed_token: &str,
        approved_payload: &[u8],
        destination: &DestinationScope,
        now_unix: u64,
    ) -> Result<(), ReceiptGateError> {
        let connection = Connection::open_with_flags(
            &self.receipt_database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
        let schema_version = connection
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
        if schema_version != Some(PRIVACY_STORE_SCHEMA_VERSION.to_string()) {
            return Err(ReceiptGateError::ReceiptStateUnavailable);
        }
        let redaction_id = connection
            .query_row(
                "SELECT redaction_id FROM privacy_receipts WHERE receipt_id=?1",
                [receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?
            .ok_or(ReceiptGateError::InvalidReceipt)?;
        match PrivacyStore::verify_active_receipt_token(
            &connection,
            &self.signer,
            &ActiveReceiptVerification {
                redaction_id: &redaction_id,
                signed_token,
                approved_payload,
                destination,
                purpose: CITATION_VALIDATE_PURPOSE,
                now_unix,
                expected_key_version: RECEIPT_KEY_VERSION,
            },
        ) {
            Ok(_) => Ok(()),
            Err(PrivacyStoreError::ReceiptRevoked) => Err(ReceiptGateError::ReceiptRevoked),
            Err(
                PrivacyStoreError::Database
                | PrivacyStoreError::UnsupportedSchema
                | PrivacyStoreError::ProtectedBlob,
            ) => Err(ReceiptGateError::ReceiptStateUnavailable),
            Err(_) => Err(ReceiptGateError::InvalidReceipt),
        }
    }
}

fn resolve_receipt_database(user_database_path: &Path) -> Result<PathBuf, ReceiptGateError> {
    let app_data_directory = user_database_path
        .parent()
        .ok_or(ReceiptGateError::ReceiptStateUnavailable)?;
    let canonical_app_data = fs::canonicalize(app_data_directory)
        .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
    let privacy_directory = app_data_directory.join("privacy");
    let privacy_metadata = fs::symlink_metadata(&privacy_directory)
        .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
    if !privacy_metadata.is_dir() || has_forbidden_reparse_point(&privacy_metadata) {
        return Err(ReceiptGateError::ReceiptStateUnavailable);
    }
    let canonical_privacy = fs::canonicalize(&privacy_directory)
        .map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
    if canonical_privacy.parent() != Some(canonical_app_data.as_path()) {
        return Err(ReceiptGateError::ReceiptStateUnavailable);
    }
    let candidate = privacy_directory.join("privacy-workflow.sqlite");
    let candidate_metadata =
        fs::symlink_metadata(&candidate).map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
    if !candidate_metadata.is_file() || has_forbidden_reparse_point(&candidate_metadata) {
        return Err(ReceiptGateError::ReceiptStateUnavailable);
    }
    let canonical_candidate =
        fs::canonicalize(candidate).map_err(|_| ReceiptGateError::ReceiptStateUnavailable)?;
    if canonical_candidate.parent() != Some(canonical_privacy.as_path()) {
        return Err(ReceiptGateError::ReceiptStateUnavailable);
    }
    Ok(canonical_candidate)
}

fn has_forbidden_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_type().is_symlink()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(windows)]
fn decode_32_byte_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut output = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(output)
}

#[cfg(windows)]
const fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use privacy::{
        sha256_hex, DestinationKind, PrivacyStore, RedactionReceiptClaims, RegisterPrivacyMaterial,
        ReviewState, SaveReviewDraft, REDACTION_VERSION,
    };
    use rusqlite::Connection;
    use serde_json::json;
    use tempfile::TempDir;

    struct ReceiptFixture {
        _temporary: TempDir,
        gate: RedactedReceiptGate,
        privacy_database_path: PathBuf,
        payload: Vec<u8>,
        token: String,
        receipt_id: String,
    }

    impl ReceiptFixture {
        fn arguments(&self) -> Map<String, Value> {
            envelope(&self.payload, &self.token)
        }

        fn revoke(&self) {
            let connection =
                Connection::open(&self.privacy_database_path).expect("open privacy database");
            PrivacyStore::revoke_receipt(&connection, &self.receipt_id, unix_now())
                .expect("revoke receipt");
        }
    }

    fn approved_citation_payload() -> Vec<u8> {
        serde_json::to_vec(&CitationValidateRequest {
            schema_version: 1,
            answer: "[src:civil-code-465]".to_owned(),
            allowed_source_ids: vec!["civil-code-465".to_owned()],
            case_date: None,
            include_expired: false,
        })
        .expect("citation payload")
    }

    fn envelope(payload: &[u8], token: &str) -> Map<String, Value> {
        json!({
            "approved_payload_json": String::from_utf8(payload.to_vec()).expect("UTF-8 payload"),
            "redaction_receipt": token,
        })
        .as_object()
        .expect("receipt envelope")
        .clone()
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_secs()
    }

    fn make_fixture(
        payload: Vec<u8>,
        configure: impl FnOnce(&mut RedactionReceiptClaims, u64),
        persist: bool,
    ) -> ReceiptFixture {
        let temporary = tempfile::tempdir().expect("temporary app data");
        let user_database_path =
            database::ensure_user_database(temporary.path()).expect("user database");
        let privacy_directory = temporary.path().join("privacy");
        fs::create_dir(&privacy_directory).expect("privacy directory");
        let privacy_database_path = privacy_directory.join("privacy-workflow.sqlite");
        let mut connection = Connection::open(&privacy_database_path).expect("privacy database");
        PrivacyStore::initialize(&connection).expect("privacy schema");

        let signer = ReceiptSigner::new([0x5au8; 32]).expect("receipt signer");
        let now_unix = unix_now();
        let source_sha256 = sha256_hex(b"source");
        let extraction_sha256 = sha256_hex(b"extraction");
        let redacted_content_sha256 = sha256_hex(b"redacted");
        let mut claims = RedactionReceiptClaims {
            receipt_id: String::new(),
            source_sha256: vec![source_sha256.clone()],
            extraction_sha256: extraction_sha256.clone(),
            redacted_content_sha256: redacted_content_sha256.clone(),
            approved_payload_sha256: sha256_hex(&payload),
            policy_id: POLICY_ID.to_owned(),
            policy_version: POLICY_VERSION,
            detector_version: REDACTION_VERSION.to_owned(),
            destination: DestinationScope {
                kind: DestinationKind::ExternalMcpHost,
                identifier: REDACTED_CASE_DESTINATION_IDENTIFIER.to_owned(),
            },
            purpose: CITATION_VALIDATE_PURPOSE.to_owned(),
            unresolved_high_risk_count: 0,
            review_state: ReviewState::Approved,
            issued_at_unix: now_unix.saturating_sub(5),
            expires_at_unix: Some(now_unix + 120),
            key_version: RECEIPT_KEY_VERSION,
        };
        configure(&mut claims, now_unix);

        PrivacyStore::register_material(
            &connection,
            &RegisterPrivacyMaterial {
                material_id: "material-mcp",
                project_id: Some("project-mcp"),
                attachment_id: Some("attachment-mcp"),
                source_sha256: claims.source_sha256.first().expect("single source hash"),
                source_name_sha256: &sha256_hex(b"name"),
                media_type: "application/pdf",
                page_count: Some(1),
            },
        )
        .expect("register material");
        PrivacyStore::save_review_draft(
            &connection,
            &SaveReviewDraft {
                redaction_id: "redaction-mcp",
                material_id: "material-mcp",
                extraction_sha256: &claims.extraction_sha256,
                redacted_content_sha256: &claims.redacted_content_sha256,
                policy_id: &claims.policy_id,
                policy_version: claims.policy_version,
                detector_version: &claims.detector_version,
                unresolved_high_risk_count: 0,
                review_payload_plaintext: b"review",
            },
        )
        .expect("save review");
        PrivacyStore::approve_review(
            &mut connection,
            "redaction-mcp",
            &claims.redacted_content_sha256,
            &claims.redacted_content_sha256,
            &claims.approved_payload_sha256,
            &sha256_hex(b"reviewer"),
            &payload,
        )
        .expect("approve review");
        let receipt = signer.issue(claims).expect("issue receipt");
        let token = signer.encode_token(&receipt).expect("encode receipt");
        if persist {
            PrivacyStore::persist_receipt(
                &mut connection,
                "redaction-mcp",
                &signer,
                &receipt,
                &token,
                &payload,
                receipt.claims.issued_at_unix,
            )
            .expect("persist receipt");
        }
        drop(connection);
        let gate = RedactedReceiptGate::from_signer_and_database(signer, &user_database_path)
            .expect("receipt gate");
        ReceiptFixture {
            _temporary: temporary,
            gate,
            privacy_database_path,
            payload,
            token,
            receipt_id: receipt.claims.receipt_id,
        }
    }

    #[test]
    fn accepts_only_exact_persisted_citation_payload_and_redacts_debug() {
        let fixture = make_fixture(approved_citation_payload(), |_, _| {}, true);
        let request = fixture
            .gate
            .verify_citation_call(fixture.arguments())
            .expect("valid persisted receipt");
        assert_eq!(request.schema_version, 1);
        assert_eq!(request.allowed_source_ids, ["civil-code-465"]);
        let debug = format!("{:?}", fixture.gate);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&fixture.token));
        assert!(!debug.contains("privacy-workflow.sqlite"));

        let connection = Connection::open(&fixture.privacy_database_path).expect("open audit DB");
        let audit = connection
            .query_row(
                "SELECT payload_sha256, destination_identifier_sha256, purpose,
                        allowed, reason_code, residual_counts_json
                 FROM privacy_egress_audit",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .expect("actual MCP attempt audit");
        assert_eq!(audit.0.len(), 64);
        assert_eq!(audit.1.len(), 64);
        assert_eq!(audit.2, CITATION_VALIDATE_PURPOSE);
        assert_eq!(audit.3, 1);
        assert_eq!(audit.4, "mcp_citation_attempt_authorized");
        let wire = format!("{audit:?}");
        assert!(!wire.contains(&fixture.token));
        assert!(!wire.contains("civil-code-465"));
    }

    #[test]
    fn rejects_envelope_payload_and_token_mutations() {
        let fixture = make_fixture(approved_citation_payload(), |_, _| {}, true);
        assert_eq!(
            fixture.gate.verify_citation_call(Map::new()),
            Err(ReceiptGateError::InvalidEnvelope)
        );
        let mut payload = fixture.payload.clone();
        let last = payload.last_mut().expect("payload byte");
        *last = if *last == b'}' { b' ' } else { b'}' };
        assert_eq!(
            fixture
                .gate
                .verify_citation_call(envelope(&payload, &fixture.token)),
            Err(ReceiptGateError::InvalidReceipt)
        );
        let mut token = fixture.token.clone().into_bytes();
        let last = token.last_mut().expect("token byte");
        *last = if *last == b'a' { b'b' } else { b'a' };
        let token = String::from_utf8(token).expect("mutated token");
        assert_eq!(
            fixture
                .gate
                .verify_citation_call(envelope(&fixture.payload, &token)),
            Err(ReceiptGateError::InvalidReceipt)
        );
    }

    #[test]
    fn rejects_expired_revoked_and_unpersisted_receipts() {
        let expired = make_fixture(
            approved_citation_payload(),
            |claims, now| {
                claims.issued_at_unix = now.saturating_sub(120);
                claims.expires_at_unix = Some(now.saturating_sub(60));
            },
            true,
        );
        assert_eq!(
            expired.gate.verify_citation_call(expired.arguments()),
            Err(ReceiptGateError::InvalidReceipt)
        );

        let revoked = make_fixture(approved_citation_payload(), |_, _| {}, true);
        revoked.revoke();
        assert_eq!(
            revoked.gate.verify_citation_call(revoked.arguments()),
            Err(ReceiptGateError::ReceiptRevoked)
        );

        let unpersisted = make_fixture(approved_citation_payload(), |_, _| {}, false);
        assert_eq!(
            unpersisted
                .gate
                .verify_citation_call(unpersisted.arguments()),
            Err(ReceiptGateError::InvalidReceipt)
        );
    }

    #[test]
    fn rejects_wrong_scope_purpose_key_version_and_mcp_ttl() {
        let cases = [
            make_fixture(
                approved_citation_payload(),
                |claims, _| claims.destination.identifier = "other-mcp-host".to_owned(),
                true,
            ),
            make_fixture(
                approved_citation_payload(),
                |claims, _| claims.purpose = "local.safe_pdf".to_owned(),
                true,
            ),
            make_fixture(
                approved_citation_payload(),
                |claims, _| claims.key_version = RECEIPT_KEY_VERSION + 1,
                true,
            ),
            make_fixture(
                approved_citation_payload(),
                |claims, now| {
                    claims.issued_at_unix = now.saturating_sub(1);
                    claims.expires_at_unix = Some(now + MAX_RECEIPT_TTL_SECONDS + 1);
                },
                true,
            ),
        ];
        for fixture in cases {
            assert_eq!(
                fixture.gate.verify_citation_call(fixture.arguments()),
                Err(ReceiptGateError::InvalidReceipt)
            );
        }
    }

    #[test]
    fn rejects_page_receipts_non_citation_json_and_residual_sensitive_content() {
        let page_payload = br#"{"schemaVersion":1,"kind":"local.safe_pdf","pages":[1]}"#.to_vec();
        let page = make_fixture(page_payload, |_, _| {}, true);
        assert_eq!(
            page.gate.verify_citation_call(page.arguments()),
            Err(ReceiptGateError::InvalidApprovedPayload)
        );

        let sensitive = serde_json::to_vec(&CitationValidateRequest {
            schema_version: 1,
            answer: "call 13800138000".to_owned(),
            allowed_source_ids: vec!["civil-code-465".to_owned()],
            case_date: None,
            include_expired: false,
        })
        .expect("sensitive citation payload");
        let sensitive = make_fixture(sensitive, |_, _| {}, true);
        assert_eq!(
            sensitive.gate.verify_citation_call(sensitive.arguments()),
            Err(ReceiptGateError::InvalidReceipt)
        );
    }
}
