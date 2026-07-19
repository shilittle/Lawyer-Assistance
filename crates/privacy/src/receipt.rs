use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const RECEIPT_TOKEN_PREFIX: &str = "rct_v1";
pub const MIN_RECEIPT_KEY_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewState {
    ReviewRequired,
    Approved,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DestinationKind {
    ExternalProvider,
    ExternalMcpHost,
    VerifiedLocalProvider,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationScope {
    pub kind: DestinationKind,
    pub identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RedactionReceiptClaims {
    pub receipt_id: String,
    pub source_sha256: Vec<String>,
    pub extraction_sha256: String,
    pub redacted_content_sha256: String,
    pub approved_payload_sha256: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub detector_version: String,
    pub destination: DestinationScope,
    pub purpose: String,
    pub unresolved_high_risk_count: u32,
    pub review_state: ReviewState,
    pub issued_at_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub key_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedRedactionReceipt {
    pub claims: RedactionReceiptClaims,
    pub mac_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptVerificationContext<'a> {
    pub payload: &'a [u8],
    pub destination: &'a DestinationScope,
    pub purpose: &'a str,
    pub policy_id: &'a str,
    pub policy_version: u32,
    pub detector_version: &'a str,
    pub now_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    KeyTooShort,
    InvalidClaims,
    InvalidToken,
    InvalidMac,
    NotApproved,
    Revoked,
    Expired,
    PayloadMismatch,
    DestinationMismatch,
    PurposeMismatch,
    PolicyMismatch,
    DetectorMismatch,
    UnresolvedHighRisk,
}

impl ReceiptError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::KeyTooShort => "receipt_key_too_short",
            Self::InvalidClaims => "redaction_receipt_invalid",
            Self::InvalidToken => "redaction_receipt_invalid",
            Self::InvalidMac => "redaction_receipt_invalid",
            Self::NotApproved => "redaction_not_approved",
            Self::Revoked => "redaction_receipt_revoked",
            Self::Expired => "redaction_receipt_expired",
            Self::PayloadMismatch => "redaction_stale",
            Self::DestinationMismatch => "redaction_receipt_destination_mismatch",
            Self::PurposeMismatch => "redaction_receipt_purpose_mismatch",
            Self::PolicyMismatch => "privacy_policy_mismatch",
            Self::DetectorMismatch => "privacy_detector_mismatch",
            Self::UnresolvedHighRisk => "review_required",
        }
    }
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ReceiptError {}

#[derive(Clone)]
pub struct ReceiptSigner {
    key: Vec<u8>,
}

impl ReceiptSigner {
    pub fn new(key: impl AsRef<[u8]>) -> Result<Self, ReceiptError> {
        let key = key.as_ref();
        if key.len() < MIN_RECEIPT_KEY_BYTES {
            return Err(ReceiptError::KeyTooShort);
        }
        Ok(Self { key: key.to_vec() })
    }

    pub fn issue(
        &self,
        mut claims: RedactionReceiptClaims,
    ) -> Result<SignedRedactionReceipt, ReceiptError> {
        normalize_and_validate_claims(&mut claims)?;
        if claims.receipt_id.is_empty() {
            let seed = serde_json::to_vec(&claims).map_err(|_| ReceiptError::InvalidClaims)?;
            claims.receipt_id = format!("rct_{}", &sha256_hex(&seed)[..24]);
        }
        validate_identifier(&claims.receipt_id)?;
        let message = serde_json::to_vec(&claims).map_err(|_| ReceiptError::InvalidClaims)?;
        Ok(SignedRedactionReceipt {
            claims,
            mac_hex: hex(&hmac_sha256(&self.key, &message)),
        })
    }

    pub fn verify(
        &self,
        receipt: &SignedRedactionReceipt,
        context: &ReceiptVerificationContext<'_>,
    ) -> Result<(), ReceiptError> {
        let mut normalized = receipt.claims.clone();
        normalize_and_validate_claims(&mut normalized)?;
        if normalized != receipt.claims {
            return Err(ReceiptError::InvalidClaims);
        }
        let message =
            serde_json::to_vec(&receipt.claims).map_err(|_| ReceiptError::InvalidClaims)?;
        let expected = hex(&hmac_sha256(&self.key, &message));
        if !constant_time_eq(expected.as_bytes(), receipt.mac_hex.as_bytes()) {
            return Err(ReceiptError::InvalidMac);
        }
        match receipt.claims.review_state {
            ReviewState::Approved => {}
            ReviewState::Revoked => return Err(ReceiptError::Revoked),
            ReviewState::ReviewRequired => return Err(ReceiptError::NotApproved),
        }
        if receipt.claims.unresolved_high_risk_count != 0 {
            return Err(ReceiptError::UnresolvedHighRisk);
        }
        if receipt
            .claims
            .expires_at_unix
            .is_some_and(|expires| context.now_unix >= expires)
        {
            return Err(ReceiptError::Expired);
        }
        if receipt.claims.issued_at_unix > context.now_unix {
            return Err(ReceiptError::InvalidClaims);
        }
        if receipt.claims.approved_payload_sha256 != sha256_hex(context.payload) {
            return Err(ReceiptError::PayloadMismatch);
        }
        if &receipt.claims.destination != context.destination {
            return Err(ReceiptError::DestinationMismatch);
        }
        if receipt.claims.purpose != context.purpose {
            return Err(ReceiptError::PurposeMismatch);
        }
        if receipt.claims.policy_id != context.policy_id
            || receipt.claims.policy_version != context.policy_version
        {
            return Err(ReceiptError::PolicyMismatch);
        }
        if receipt.claims.detector_version != context.detector_version {
            return Err(ReceiptError::DetectorMismatch);
        }
        Ok(())
    }

    pub fn encode_token(&self, receipt: &SignedRedactionReceipt) -> Result<String, ReceiptError> {
        let payload =
            serde_json::to_vec(&receipt.claims).map_err(|_| ReceiptError::InvalidClaims)?;
        Ok(format!(
            "{RECEIPT_TOKEN_PREFIX}.{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            receipt.mac_hex
        ))
    }

    pub fn decode_token(&self, token: &str) -> Result<SignedRedactionReceipt, ReceiptError> {
        let mut parts = token.split('.');
        if parts.next() != Some(RECEIPT_TOKEN_PREFIX) {
            return Err(ReceiptError::InvalidToken);
        }
        let payload = parts.next().ok_or(ReceiptError::InvalidToken)?;
        let mac_hex = parts.next().ok_or(ReceiptError::InvalidToken)?;
        if parts.next().is_some() || mac_hex.len() != 64 || !mac_hex.bytes().all(is_hex) {
            return Err(ReceiptError::InvalidToken);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| ReceiptError::InvalidToken)?;
        let claims = serde_json::from_slice(&bytes).map_err(|_| ReceiptError::InvalidToken)?;
        Ok(SignedRedactionReceipt {
            claims,
            mac_hex: mac_hex.to_owned(),
        })
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn normalize_and_validate_claims(claims: &mut RedactionReceiptClaims) -> Result<(), ReceiptError> {
    claims.source_sha256.sort();
    claims.source_sha256.dedup();
    if claims.source_sha256.is_empty()
        || claims.policy_version == 0
        || claims.key_version == 0
        || claims.issued_at_unix == 0
        || claims
            .expires_at_unix
            .is_some_and(|expires| expires <= claims.issued_at_unix)
        || claims.source_sha256.iter().any(|value| !valid_hash(value))
        || !valid_hash(&claims.extraction_sha256)
        || !valid_hash(&claims.redacted_content_sha256)
        || !valid_hash(&claims.approved_payload_sha256)
    {
        return Err(ReceiptError::InvalidClaims);
    }
    validate_identifier(&claims.destination.identifier)?;
    validate_identifier(&claims.policy_id)?;
    validate_identifier(&claims.detector_version)?;
    validate_identifier(&claims.purpose)?;
    if !claims.receipt_id.is_empty() {
        validate_identifier(&claims.receipt_id)?;
    }
    let unique = claims.source_sha256.iter().collect::<BTreeSet<_>>();
    if unique.len() != claims.source_sha256.len() {
        return Err(ReceiptError::InvalidClaims);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ReceiptError> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err(ReceiptError::InvalidClaims)
    } else {
        Ok(())
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(is_hex)
}

fn is_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        let digest = Sha256::digest(key);
        normalized[..digest.len()].copy_from_slice(&digest);
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(payload: &[u8]) -> RedactionReceiptClaims {
        RedactionReceiptClaims {
            receipt_id: String::new(),
            source_sha256: vec![sha256_hex(b"source")],
            extraction_sha256: sha256_hex(b"extraction"),
            redacted_content_sha256: sha256_hex(b"redacted"),
            approved_payload_sha256: sha256_hex(payload),
            policy_id: "cn-legal-default".to_owned(),
            policy_version: 1,
            detector_version: "detector-v1".to_owned(),
            destination: DestinationScope {
                kind: DestinationKind::ExternalProvider,
                identifier: "provider-profile-1".to_owned(),
            },
            purpose: "assistant_chat".to_owned(),
            unresolved_high_risk_count: 0,
            review_state: ReviewState::Approved,
            issued_at_unix: 1_700_000_000,
            expires_at_unix: Some(1_800_000_000),
            key_version: 1,
        }
    }

    fn context<'a>(
        payload: &'a [u8],
        destination: &'a DestinationScope,
    ) -> ReceiptVerificationContext<'a> {
        ReceiptVerificationContext {
            payload,
            destination,
            purpose: "assistant_chat",
            policy_id: "cn-legal-default",
            policy_version: 1,
            detector_version: "detector-v1",
            now_unix: 1_750_000_000,
        }
    }

    #[test]
    fn receipt_binds_exact_payload_destination_and_policy() {
        let payload = br#"{"message":"[name1]"}"#;
        let signer = ReceiptSigner::new([7u8; 32]).expect("key");
        let receipt = signer.issue(claims(payload)).expect("receipt");
        signer
            .verify(&receipt, &context(payload, &receipt.claims.destination))
            .expect("valid receipt");

        let mut wrong_payload = context(b"changed", &receipt.claims.destination);
        assert_eq!(
            signer.verify(&receipt, &wrong_payload),
            Err(ReceiptError::PayloadMismatch)
        );
        wrong_payload.payload = payload;
        wrong_payload.policy_version = 2;
        assert_eq!(
            signer.verify(&receipt, &wrong_payload),
            Err(ReceiptError::PolicyMismatch)
        );
    }

    #[test]
    fn token_tampering_and_expiry_fail_closed() {
        let payload = b"approved";
        let signer = ReceiptSigner::new([9u8; 32]).expect("key");
        let receipt = signer.issue(claims(payload)).expect("receipt");
        let token = signer.encode_token(&receipt).expect("token");
        let decoded = signer.decode_token(&token).expect("decode");
        signer
            .verify(&decoded, &context(payload, &decoded.claims.destination))
            .expect("valid");

        let mut tampered = decoded.clone();
        tampered.claims.purpose = "different".to_owned();
        assert_eq!(
            signer.verify(&tampered, &context(payload, &tampered.claims.destination)),
            Err(ReceiptError::InvalidMac)
        );
        let mut expired_context = context(payload, &decoded.claims.destination);
        expired_context.now_unix = 1_800_000_000;
        assert_eq!(
            signer.verify(&decoded, &expired_context),
            Err(ReceiptError::Expired)
        );
    }

    #[test]
    fn unresolved_review_and_short_keys_are_rejected() {
        assert!(matches!(
            ReceiptSigner::new([1u8; 16]),
            Err(ReceiptError::KeyTooShort)
        ));
        let payload = b"pending";
        let signer = ReceiptSigner::new([1u8; 32]).expect("key");
        let mut pending = claims(payload);
        pending.review_state = ReviewState::ReviewRequired;
        let receipt = signer.issue(pending).expect("receipt");
        assert_eq!(
            signer.verify(&receipt, &context(payload, &receipt.claims.destination)),
            Err(ReceiptError::NotApproved)
        );
    }
}
