use crate::{ServiceError, SERVICE_SCHEMA_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaseMaterialAuditDetail {
    pub material_id: String,
    pub attachment_id: String,
    pub root_id: String,
    pub relative_path: String,
    pub content_sha256: String,
    pub extracted_text_sha256: String,
    pub segments_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CompletedAuditDetails {
    pub schema_version: u16,
    pub proposal_hash: Option<String>,
    pub generation_hash: Option<String>,
    pub before_revision: Option<String>,
    pub after_revision: Option<String>,
    /// Legacy absolute-path field. New export audits leave this empty and use
    /// the opaque root identity plus relative path below.
    #[serde(default)]
    pub export_path: Option<String>,
    #[serde(default)]
    pub output_root_id: Option<String>,
    #[serde(default)]
    pub relative_export_path: Option<String>,
    pub content_sha256: Option<String>,
    pub byte_len: Option<usize>,
    pub record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub case_materials: Vec<CaseMaterialAuditDetail>,
}

impl CompletedAuditDetails {
    pub(crate) fn case_apply(
        proposal_hash: String,
        before_revision: String,
        after_revision: String,
        case_materials: Vec<CaseMaterialAuditDetail>,
    ) -> Self {
        Self {
            schema_version: SERVICE_SCHEMA_VERSION,
            proposal_hash: Some(proposal_hash),
            generation_hash: None,
            before_revision: Some(before_revision),
            after_revision: Some(after_revision),
            export_path: None,
            output_root_id: None,
            relative_export_path: None,
            content_sha256: None,
            byte_len: None,
            record_id: None,
            case_materials,
        }
    }

    pub(crate) fn document_export(
        generation_hash: String,
        revision: String,
        output_root_id: String,
        relative_export_path: String,
        content_sha256: String,
        byte_len: usize,
        record_id: String,
    ) -> Self {
        Self {
            schema_version: SERVICE_SCHEMA_VERSION,
            proposal_hash: None,
            generation_hash: Some(generation_hash),
            before_revision: Some(revision.clone()),
            after_revision: Some(revision),
            export_path: None,
            output_root_id: Some(output_root_id),
            relative_export_path: Some(relative_export_path),
            content_sha256: Some(content_sha256),
            byte_len: Some(byte_len),
            record_id: Some(record_id),
            case_materials: Vec::new(),
        }
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn hash_serializable<T: Serialize>(value: &T) -> Result<String, ServiceError> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

pub(crate) fn validate_sha256(field: &'static str, value: &str) -> Result<(), ServiceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ServiceError::invalid(
            field,
            "hash must be a lowercase 64-character SHA-256 value",
        ));
    }
    Ok(())
}

pub(crate) fn validate_idempotency_key(value: &str) -> Result<(), ServiceError> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(ServiceError::invalid(
            "idempotencyKey",
            "idempotency key must be non-empty and at most 256 bytes",
        ));
    }
    Ok(())
}
