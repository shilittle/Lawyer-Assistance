use crate::{
    receipt::{
        sha256_hex, DestinationKind, DestinationScope, ReceiptError, ReceiptSigner,
        ReceiptVerificationContext, SignedRedactionReceipt,
    },
    RedactionSummary, Redactor, REDACTION_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const DEFAULT_MAX_EGRESS_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    LegalPublic,
    ProductPublic,
    #[default]
    CaseRaw,
    CaseRedactedPending,
    CaseRedactedApproved,
    Secret,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResidualScanResult {
    pub passed: bool,
    pub counts: BTreeMap<String, usize>,
    pub detector_version: String,
}

pub fn scan_residual(payload: &[u8]) -> Result<ResidualScanResult, EgressError> {
    let text = std::str::from_utf8(payload).map_err(|_| EgressError::NonUtf8Payload)?;
    let mut redactor = Redactor::default();
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(object)) => {
            let mut value = Value::Object(object);
            redactor.redact_json(&mut value);
        }
        Ok(Value::Array(array)) => {
            let mut value = Value::Array(array);
            redactor.redact_json(&mut value);
        }
        Ok(Value::String(value)) => {
            let _ = redactor.redact(&value);
        }
        Ok(Value::Null | Value::Bool(_) | Value::Number(_)) | Err(_) => {
            let _ = redactor.redact(text);
        }
    }
    let RedactionSummary {
        counts, changed, ..
    } = redactor.summary();
    Ok(ResidualScanResult {
        passed: !changed,
        counts,
        detector_version: REDACTION_VERSION.to_owned(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressError {
    PayloadTooLarge,
    NonUtf8Payload,
    ClassificationForbidden,
    ReceiptRequired,
    ResidualSensitiveContent,
    InvalidPolicy,
    Receipt(ReceiptError),
}

impl EgressError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PayloadTooLarge => "privacy_payload_too_large",
            Self::NonUtf8Payload => "privacy_payload_non_utf8",
            Self::ClassificationForbidden => "raw_material_forbidden",
            Self::ReceiptRequired => "redaction_required",
            Self::ResidualSensitiveContent => "residual_sensitive_content",
            Self::InvalidPolicy => "privacy_policy_invalid",
            Self::Receipt(error) => error.code(),
        }
    }
}

impl std::fmt::Display for EgressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for EgressError {}

impl From<ReceiptError> for EgressError {
    fn from(value: ReceiptError) -> Self {
        Self::Receipt(value)
    }
}

#[derive(Debug, Clone)]
pub struct EgressCandidate<'a> {
    pub payload: &'a [u8],
    pub classification: DataClassification,
    pub destination: &'a DestinationScope,
    pub purpose: &'a str,
    pub receipt: Option<&'a SignedRedactionReceipt>,
    pub now_unix: u64,
}

#[derive(Clone)]
pub struct ApprovedOutboundPayload {
    payload: Vec<u8>,
    payload_sha256: String,
    destination: DestinationScope,
    classification: DataClassification,
    receipt_id: Option<String>,
}

impl ApprovedOutboundPayload {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    pub fn payload_sha256(&self) -> &str {
        &self.payload_sha256
    }

    pub fn destination(&self) -> &DestinationScope {
        &self.destination
    }

    pub const fn classification(&self) -> DataClassification {
        self.classification
    }

    pub fn receipt_id(&self) -> Option<&str> {
        self.receipt_id.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyEgressAuditRecord {
    pub occurred_at_unix: u64,
    pub classification: DataClassification,
    pub destination_kind: DestinationKind,
    pub destination_identifier_sha256: String,
    pub purpose: String,
    pub payload_sha256: String,
    pub payload_bytes: usize,
    pub policy_id: String,
    pub policy_version: u32,
    pub detector_version: String,
    pub receipt_id: Option<String>,
    pub residual_counts: BTreeMap<String, usize>,
    pub allowed: bool,
    pub reason_code: String,
}

#[derive(Clone)]
pub struct EgressPolicyEngine {
    signer: ReceiptSigner,
    policy_id: String,
    policy_version: u32,
    max_payload_bytes: usize,
    allow_verified_local_raw: bool,
}

impl EgressPolicyEngine {
    pub fn new(
        signer: ReceiptSigner,
        policy_id: impl Into<String>,
        policy_version: u32,
    ) -> Result<Self, EgressError> {
        let policy_id = policy_id.into();
        if policy_id.is_empty()
            || policy_id.len() > 128
            || policy_id.chars().any(char::is_control)
            || policy_version == 0
        {
            return Err(EgressError::InvalidPolicy);
        }
        Ok(Self {
            signer,
            policy_id,
            policy_version,
            max_payload_bytes: DEFAULT_MAX_EGRESS_BYTES,
            allow_verified_local_raw: false,
        })
    }

    pub fn set_max_payload_bytes(&mut self, max_payload_bytes: usize) -> Result<(), EgressError> {
        if max_payload_bytes == 0 {
            return Err(EgressError::InvalidPolicy);
        }
        self.max_payload_bytes = max_payload_bytes;
        Ok(())
    }

    pub fn set_verified_local_raw(&mut self, allowed: bool) {
        self.allow_verified_local_raw = allowed;
    }

    pub fn authorize(
        &self,
        candidate: &EgressCandidate<'_>,
    ) -> Result<ApprovedOutboundPayload, EgressError> {
        self.authorize_with_audit(candidate).0
    }

    pub fn authorize_with_audit(
        &self,
        candidate: &EgressCandidate<'_>,
    ) -> (
        Result<ApprovedOutboundPayload, EgressError>,
        PrivacyEgressAuditRecord,
    ) {
        let scan = scan_residual(candidate.payload);
        let result = self.authorize_scanned(candidate, scan.as_ref().ok());
        let error = result.as_ref().err().copied();
        let residual_counts = scan
            .as_ref()
            .map(|value| value.counts.clone())
            .unwrap_or_default();
        let receipt_id = candidate
            .receipt
            .map(|receipt| receipt.claims.receipt_id.clone());
        let audit = PrivacyEgressAuditRecord {
            occurred_at_unix: candidate.now_unix,
            classification: candidate.classification,
            destination_kind: candidate.destination.kind.clone(),
            destination_identifier_sha256: sha256_hex(candidate.destination.identifier.as_bytes()),
            purpose: candidate.purpose.to_owned(),
            payload_sha256: sha256_hex(candidate.payload),
            payload_bytes: candidate.payload.len(),
            policy_id: self.policy_id.clone(),
            policy_version: self.policy_version,
            detector_version: REDACTION_VERSION.to_owned(),
            receipt_id,
            residual_counts,
            allowed: error.is_none(),
            reason_code: error.map(EgressError::code).unwrap_or("allowed").to_owned(),
        };
        (result, audit)
    }

    fn authorize_scanned(
        &self,
        candidate: &EgressCandidate<'_>,
        scan: Option<&ResidualScanResult>,
    ) -> Result<ApprovedOutboundPayload, EgressError> {
        if candidate.payload.len() > self.max_payload_bytes {
            return Err(EgressError::PayloadTooLarge);
        }
        let scan = scan.ok_or(EgressError::NonUtf8Payload)?;
        if !scan.passed {
            return Err(EgressError::ResidualSensitiveContent);
        }
        match candidate.classification {
            DataClassification::LegalPublic | DataClassification::ProductPublic => {}
            DataClassification::CaseRedactedApproved => {
                let receipt = candidate.receipt.ok_or(EgressError::ReceiptRequired)?;
                self.signer.verify(
                    receipt,
                    &ReceiptVerificationContext {
                        payload: candidate.payload,
                        destination: candidate.destination,
                        purpose: candidate.purpose,
                        policy_id: &self.policy_id,
                        policy_version: self.policy_version,
                        detector_version: REDACTION_VERSION,
                        now_unix: candidate.now_unix,
                    },
                )?;
            }
            DataClassification::CaseRaw
                if candidate.destination.kind == DestinationKind::VerifiedLocalProvider
                    && self.allow_verified_local_raw => {}
            DataClassification::CaseRaw
            | DataClassification::CaseRedactedPending
            | DataClassification::Secret => {
                return Err(EgressError::ClassificationForbidden);
            }
        }
        Ok(ApprovedOutboundPayload {
            payload: candidate.payload.to_vec(),
            payload_sha256: sha256_hex(candidate.payload),
            destination: candidate.destination.clone(),
            classification: candidate.classification,
            receipt_id: candidate
                .receipt
                .map(|receipt| receipt.claims.receipt_id.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{RedactionReceiptClaims, ReviewState};

    fn signer() -> ReceiptSigner {
        ReceiptSigner::new([3u8; 32]).expect("key")
    }

    fn destination(kind: DestinationKind) -> DestinationScope {
        DestinationScope {
            kind,
            identifier: "destination-1".to_owned(),
        }
    }

    fn approved_receipt(
        signer: &ReceiptSigner,
        payload: &[u8],
        destination: DestinationScope,
    ) -> SignedRedactionReceipt {
        signer
            .issue(RedactionReceiptClaims {
                receipt_id: String::new(),
                source_sha256: vec![sha256_hex(b"source")],
                extraction_sha256: sha256_hex(b"extraction"),
                redacted_content_sha256: sha256_hex(b"redacted"),
                approved_payload_sha256: sha256_hex(payload),
                policy_id: "cn-legal-default".to_owned(),
                policy_version: 1,
                detector_version: REDACTION_VERSION.to_owned(),
                destination,
                purpose: "assistant_chat".to_owned(),
                unresolved_high_risk_count: 0,
                review_state: ReviewState::Approved,
                issued_at_unix: 100,
                expires_at_unix: Some(1_000),
                key_version: 1,
            })
            .expect("receipt")
    }

    #[test]
    fn valid_placeholders_pass_residual_scan_without_masking_trailing_raw_values() {
        let approved =
            r#"{"partyName":"[姓名1]","answer":"原告：[姓名1]，电话[电话号码1]。"}"#.as_bytes();
        let scan = scan_residual(approved).expect("scan approved placeholders");
        assert!(scan.passed);
        assert!(scan.counts.is_empty());

        let trailing_raw = r#"{"answer":"原告：[姓名1]张三。"}"#.as_bytes();
        let scan = scan_residual(trailing_raw).expect("scan malformed placeholder");
        assert!(!scan.passed);
        assert_eq!(scan.counts.get("person_name"), Some(&1));
    }

    #[test]
    fn json_scalar_values_cannot_bypass_residual_detection() {
        for payload in [b"13800138000".as_slice(), br#""13800138000""#.as_slice()] {
            let scan = scan_residual(payload).expect("scan JSON scalar mobile number");
            assert!(!scan.passed);
            assert_eq!(scan.counts.get("phone_number"), Some(&1));
        }
    }
    #[test]
    fn public_payload_without_residual_sensitive_content_is_allowed() {
        let signer = signer();
        let engine = EgressPolicyEngine::new(signer, "cn-legal-default", 1).expect("engine");
        let destination = destination(DestinationKind::ExternalMcpHost);
        let payload = r#"{"law":"中华人民共和国民法典","article":577}"#.as_bytes();
        let candidate = EgressCandidate {
            payload,
            classification: DataClassification::LegalPublic,
            destination: &destination,
            purpose: "legal_search",
            receipt: None,
            now_unix: 500,
        };
        let approved = engine.authorize(&candidate).expect("approved");
        assert_eq!(approved.payload(), payload);
    }

    #[test]
    fn raw_and_pending_case_data_are_denied_by_default() {
        let engine = EgressPolicyEngine::new(signer(), "cn-legal-default", 1).expect("engine");
        let destination = destination(DestinationKind::ExternalProvider);
        for classification in [
            DataClassification::CaseRaw,
            DataClassification::CaseRedactedPending,
            DataClassification::Secret,
        ] {
            let candidate = EgressCandidate {
                payload: b"opaque",
                classification,
                destination: &destination,
                purpose: "assistant_chat",
                receipt: None,
                now_unix: 500,
            };
            assert_eq!(
                engine.authorize(&candidate).err(),
                Some(EgressError::ClassificationForbidden)
            );
        }
    }

    #[test]
    fn approved_case_payload_requires_exact_receipt_and_clean_residual_scan() {
        let signer = signer();
        let engine =
            EgressPolicyEngine::new(signer.clone(), "cn-legal-default", 1).expect("engine");
        let destination = destination(DestinationKind::ExternalProvider);
        let payload = br#"{"party":"[name1]","request":"repayment"}"#;
        let receipt = approved_receipt(&signer, payload, destination.clone());
        let candidate = EgressCandidate {
            payload,
            classification: DataClassification::CaseRedactedApproved,
            destination: &destination,
            purpose: "assistant_chat",
            receipt: Some(&receipt),
            now_unix: 500,
        };
        assert!(engine.authorize(&candidate).is_ok());

        let sensitive_payload = r#"{"party_name":"张三","phone":"13800138000"}"#.as_bytes();
        let sensitive_receipt = approved_receipt(&signer, sensitive_payload, destination.clone());
        let sensitive = EgressCandidate {
            payload: sensitive_payload,
            receipt: Some(&sensitive_receipt),
            ..candidate
        };
        assert_eq!(
            engine.authorize(&sensitive).err(),
            Some(EgressError::ResidualSensitiveContent)
        );
    }

    #[test]
    fn audit_contains_hashes_and_counts_but_not_payload() {
        let engine = EgressPolicyEngine::new(signer(), "cn-legal-default", 1).expect("engine");
        let destination = destination(DestinationKind::ExternalProvider);
        let payload = r#"{"party_name":"张三"}"#.as_bytes();
        let candidate = EgressCandidate {
            payload,
            classification: DataClassification::CaseRaw,
            destination: &destination,
            purpose: "assistant_chat",
            receipt: None,
            now_unix: 500,
        };
        let (result, audit) = engine.authorize_with_audit(&candidate);
        assert!(result.is_err());
        let wire = serde_json::to_string(&audit).expect("audit JSON");
        assert!(!wire.contains("张三"));
        assert!(!wire.contains("destination-1"));
        assert!(wire.contains("residual_sensitive_content"));
    }

    #[test]
    fn verified_local_raw_requires_explicit_engine_configuration() {
        let mut engine = EgressPolicyEngine::new(signer(), "cn-legal-default", 1).expect("engine");
        let destination = destination(DestinationKind::VerifiedLocalProvider);
        let candidate = EgressCandidate {
            payload: b"opaque-case-data",
            classification: DataClassification::CaseRaw,
            destination: &destination,
            purpose: "local_analysis",
            receipt: None,
            now_unix: 500,
        };
        assert!(engine.authorize(&candidate).is_err());
        engine.set_verified_local_raw(true);
        assert!(engine.authorize(&candidate).is_ok());
    }
}
