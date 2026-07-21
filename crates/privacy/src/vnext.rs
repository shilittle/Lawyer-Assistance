//! Strict vNext domain contracts for the encrypted-vault and approved-workspace pipeline.
//!
//! This module deliberately contains no filesystem paths and no raw private values.

use serde::{
    de::{DeserializeOwned, Error as DeError, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt::{self, Write as _},
};

pub const DOMAIN_SCHEMA_VERSION: &str = "lawyer-assistance-privacy-domain-v2";
pub const CANONICAL_JSON_VERSION: &str = "canonical-json-v1";
pub const APPROVED_MATERIAL_MANIFEST_VERSION: &str = "approved-material-manifest-v1";
pub const WORK_PRODUCT_MANIFEST_VERSION: &str = "work-product-manifest-v1";
pub const APPROVED_CLASSIFICATION: &str = "CASE_REDACTED_APPROVED";
pub const MAX_REASON_CODES: usize = 64;
pub const MAX_VERSION_VALUES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VNextSchemaError {
    InvalidOpaqueId,
    InvalidSha256,
    ConfidenceOutOfRange,
    DuplicateJsonKey,
    FloatingPointNotAllowed,
    ControlCharacterNotAllowed,
    InvalidJson,
    InvalidSchema,
    InvalidManifest,
    InvalidRiskEvaluation,
}

impl fmt::Display for VNextSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOpaqueId => "invalid opaque identifier",
            Self::InvalidSha256 => "invalid SHA-256 value",
            Self::ConfidenceOutOfRange => "confidence is outside the allowed range",
            Self::DuplicateJsonKey => "duplicate JSON key",
            Self::FloatingPointNotAllowed => "floating-point JSON value is not allowed",
            Self::ControlCharacterNotAllowed => "control character is not allowed",
            Self::InvalidJson => "invalid JSON value",
            Self::InvalidSchema => "invalid domain schema",
            Self::InvalidManifest => "invalid manifest",
            Self::InvalidRiskEvaluation => "invalid risk evaluation",
        })
    }
}

impl Error for VNextSchemaError {}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, VNextSchemaError> {
                let value = value.into();
                let Some(suffix) = value.strip_prefix($prefix) else {
                    return Err(VNextSchemaError::InvalidOpaqueId);
                };
                if !valid_lower_hex(suffix, 32) {
                    return Err(VNextSchemaError::InvalidOpaqueId);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

opaque_id!(WorkspaceInstanceId, "ws_");
opaque_id!(CaseId, "case_");
opaque_id!(MaterialId, "mat_");
opaque_id!(ObjectId, "obj_");
opaque_id!(FindingId, "fnd_");
opaque_id!(ClusterId, "clu_");
opaque_id!(PublicationId, "pub_");
opaque_id!(WorkProductId, "wp_");
opaque_id!(ReceiptId, "rct_");
opaque_id!(TransactionId, "tx_");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    pub fn parse(value: impl Into<String>) -> Result<Self, VNextSchemaError> {
        let value = value.into();
        if !valid_lower_hex(&value, 64) {
            return Err(VNextSchemaError::InvalidSha256);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sha256Hex {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ConfidencePpm(u32);

impl ConfidencePpm {
    pub const MAX: u32 = 1_000_000;

    pub const fn new(value: u32) -> Result<Self, VNextSchemaError> {
        if value <= Self::MAX {
            Ok(Self(value))
        } else {
            Err(VNextSchemaError::ConfidenceOutOfRange)
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for ConfidencePpm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u32::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialState {
    Imported,
    Assessing,
    ExtractingNative,
    OcrRequired,
    OcrRunning,
    Extracted,
    Redacting,
    ReviewRequired,
    Approved,
    Published,
    Stale,
    Revoked,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationState {
    Prepared,
    Staged,
    Published,
    Committed,
    RolledBack,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewResolution {
    Unresolved,
    Accepted,
    Modified,
    NotSensitive,
    ClusterMerged,
    ClusterSplit,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    PersonName,
    OrganizationName,
    CaseNumber,
    IdentityNumber,
    PassportNumber,
    PhoneNumber,
    LandlineNumber,
    BankAccount,
    EmailAddress,
    Address,
    OrganizationCode,
    BusinessLicenseNumber,
    VehiclePlate,
    IpAddress,
    SocialAccount,
    PaymentAccount,
    AccountName,
    ContractNumber,
    TrackingNumber,
    PropertyCertificateNumber,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    P0Blocking,
    P1High,
    P2Medium,
    P3Resolved,
    Informational,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentRoute {
    AutoApprovalEligible,
    QuickReviewRequired,
    FullReviewRequired,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    Human,
    ShadowHuman,
    Automatic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoApprovalPolicyMode {
    Strict,
    Balanced,
    Batch,
    Shadow,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceIsolationLevel {
    UserBoundaryOnly,
    StrongServiceBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrivateValueRefV1 {
    pub object_id: ObjectId,
    pub object_version: u64,
    pub value_locator_hash: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FindingGeometryV1 {
    pub coordinate_system: String,
    pub bbox_micropoints: Option<[i64; 4]>,
    pub polygon_micropoints: Vec<[i64; 2]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HumanOverrideV1 {
    pub resolution: ReviewResolution,
    pub reason_code: String,
    pub actor_hash: Sha256Hex,
    pub resolved_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrivacyFindingV1 {
    pub finding_id: FindingId,
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub page_index: u32,
    pub block_id: String,
    pub start_offset: u32,
    pub end_offset: u32,
    pub geometry: Option<FindingGeometryV1>,
    pub entity_type: EntityType,
    pub detector_sources: Vec<String>,
    pub detector_versions: BTreeMap<String, String>,
    pub model_versions: BTreeMap<String, String>,
    pub raw_score_ppm: Option<ConfidencePpm>,
    pub calibrated_confidence_ppm: Option<ConfidencePpm>,
    pub ocr_confidence_ppm: Option<ConfidencePpm>,
    pub layout_confidence_ppm: Option<ConfidencePpm>,
    pub normalization_evidence_hash: Option<Sha256Hex>,
    pub confusable_evidence_hash: Option<Sha256Hex>,
    pub case_dictionary_match: bool,
    pub cluster_id: Option<ClusterId>,
    pub detector_agreement: bool,
    pub severity: FindingSeverity,
    pub review_priority: u32,
    pub reason_codes: Vec<String>,
    pub proposed_replacement: String,
    pub resolution_state: ReviewResolution,
    pub human_override: Option<HumanOverrideV1>,
    pub provenance_hash: Sha256Hex,
    pub private_value_ref: PrivateValueRefV1,
}

impl PrivacyFindingV1 {
    pub fn validate(&self) -> Result<(), VNextSchemaError> {
        if self.document_version == 0
            || self.start_offset >= self.end_offset
            || self.block_id.is_empty()
            || self.detector_sources.is_empty()
            || self.detector_sources.len() > MAX_VERSION_VALUES
            || self.detector_versions.len() > MAX_VERSION_VALUES
            || self.model_versions.len() > MAX_VERSION_VALUES
            || self.reason_codes.len() > MAX_REASON_CODES
            || self.proposed_replacement.is_empty()
        {
            return Err(VNextSchemaError::InvalidSchema);
        }
        validate_safe_strings(self.detector_sources.iter().map(String::as_str))?;
        validate_safe_strings(self.reason_codes.iter().map(String::as_str))?;
        reject_control_chars(&self.block_id)?;
        reject_control_chars(&self.proposed_replacement)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageRiskV1 {
    pub page_index: u32,
    pub p0_count: u32,
    pub p1_count: u32,
    pub p2_count: u32,
    pub p3_count: u32,
    pub ocr_min_ppm: Option<ConfidencePpm>,
    pub ocr_mean_ppm: Option<ConfidencePpm>,
    pub ocr_p10_ppm: Option<ConfidencePpm>,
    pub coverage_ppm: ConfidencePpm,
    pub unknown_long_number_count: u32,
    pub unresolved_entity_counts: BTreeMap<EntityType, u32>,
    pub visual_risks: Vec<String>,
    pub completeness_passed: bool,
    pub detector_conflict_count: u32,
    pub cluster_inconsistency_count: u32,
    pub visual_review_required: bool,
    pub readiness_score: u32,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HardGateResultV1 {
    pub gate_id: String,
    pub passed: bool,
    pub blocking: bool,
    pub reason_codes: Vec<String>,
    pub evidence_hashes: Vec<Sha256Hex>,
}

pub const REQUIRED_HARD_GATES: [&str; 17] = [
    "qualified_processing_chain",
    "complete_pages_and_order",
    "no_p0",
    "no_unresolved_p1",
    "ocr_thresholds",
    "visual_risks_resolved",
    "required_dictionary_entities_stable",
    "deterministic_high_risk_fields_resolved",
    "detector_conflicts_resolved",
    "cluster_alias_consistency",
    "independent_residual_scan",
    "provenance_receiptable",
    "calibrated_policy",
    "approval_mode_allows_automatic",
    "organization_policy_allows_automatic",
    "publication_target_fixed",
    "exact_worker_model_qualification",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HardGateEvaluationV1 {
    pub gates: Vec<HardGateResultV1>,
    pub evaluated_at_unix: u64,
    pub evaluation_hash: Sha256Hex,
}

impl HardGateEvaluationV1 {
    pub fn validate(&self) -> Result<(), VNextSchemaError> {
        let ids = self
            .gates
            .iter()
            .map(|gate| gate.gate_id.as_str())
            .collect::<BTreeSet<_>>();
        if self.gates.len() != REQUIRED_HARD_GATES.len()
            || ids.len() != REQUIRED_HARD_GATES.len()
            || REQUIRED_HARD_GATES.iter().any(|gate| !ids.contains(gate))
        {
            return Err(VNextSchemaError::InvalidRiskEvaluation);
        }
        for gate in &self.gates {
            reject_control_chars(&gate.gate_id)?;
            validate_safe_strings(gate.reason_codes.iter().map(String::as_str))?;
            if gate.reason_codes.len() > MAX_REASON_CODES || (!gate.passed && !gate.blocking) {
                return Err(VNextSchemaError::InvalidRiskEvaluation);
            }
        }
        Ok(())
    }

    pub fn all_blocking_gates_passed(&self) -> bool {
        self.gates.iter().all(|gate| gate.passed || !gate.blocking)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DocumentRiskV1 {
    pub route: DocumentRoute,
    pub readiness_score: u32,
    pub page_risks: Vec<PageRiskV1>,
    pub total_p0: u32,
    pub total_p1: u32,
    pub total_p2: u32,
    pub hard_gate_evaluation_hash: Sha256Hex,
    pub finding_summary_hash: Sha256Hex,
    pub policy_id: String,
    pub policy_version: u64,
    pub policy_sha256: Sha256Hex,
    pub calibration_evidence_version: Option<String>,
    pub qualification_report_id: Option<String>,
    pub reason_codes: Vec<String>,
}

impl DocumentRiskV1 {
    pub fn validate(&self, gates: &HardGateEvaluationV1) -> Result<(), VNextSchemaError> {
        gates.validate()?;
        let p0 = self
            .page_risks
            .iter()
            .map(|page| page.p0_count)
            .sum::<u32>();
        let p1 = self
            .page_risks
            .iter()
            .map(|page| page.p1_count)
            .sum::<u32>();
        let p2 = self
            .page_risks
            .iter()
            .map(|page| page.p2_count)
            .sum::<u32>();
        if self.policy_id.is_empty()
            || self.policy_version == 0
            || self.reason_codes.len() > MAX_REASON_CODES
            || p0 != self.total_p0
            || p1 != self.total_p1
            || p2 != self.total_p2
            || self.hard_gate_evaluation_hash != gates.evaluation_hash
            || (matches!(self.route, DocumentRoute::AutoApprovalEligible)
                && (p0 > 0 || p1 > 0 || !gates.all_blocking_gates_passed()))
            || (matches!(self.route, DocumentRoute::Blocked) && gates.all_blocking_gates_passed())
        {
            return Err(VNextSchemaError::InvalidRiskEvaluation);
        }
        reject_control_chars(&self.policy_id)?;
        validate_safe_strings(self.reason_codes.iter().map(String::as_str))?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovedMaterialManifestV1 {
    pub schema_version: String,
    pub classification: String,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub publication_id: PublicationId,
    pub content_media_type: String,
    pub content_sha256: Sha256Hex,
    pub content_bytes: u64,
    pub source_sha256: Sha256Hex,
    pub extraction_sha256: Sha256Hex,
    pub ocr_output_sha256: Option<Sha256Hex>,
    pub finding_summary_hash: Sha256Hex,
    pub hard_gate_evaluation_hash: Sha256Hex,
    pub policy_id: String,
    pub policy_version: u64,
    pub policy_sha256: Sha256Hex,
    pub detector_versions: BTreeMap<String, String>,
    pub model_versions: BTreeMap<String, String>,
    pub worker_sha256: Option<Sha256Hex>,
    pub model_manifest_sha256: Option<Sha256Hex>,
    pub qualification_report_id: Option<String>,
    pub calibration_evidence_version: Option<String>,
    pub dictionary_revision_hash: Sha256Hex,
    pub mapping_revision_hash: Sha256Hex,
    pub approval_mode: ApprovalMode,
    pub readiness_score: u32,
    pub unresolved_p0: u32,
    pub unresolved_p1: u32,
    pub unresolved_p2: u32,
    pub destination_scope: String,
    pub purpose: String,
    pub workspace_isolation_level: WorkspaceIsolationLevel,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub receipt_id: ReceiptId,
    pub receipt_nonce: String,
    pub revocation_epoch: u64,
}

impl ApprovedMaterialManifestV1 {
    pub fn validate(&self) -> Result<(), VNextSchemaError> {
        if self.schema_version != APPROVED_MATERIAL_MANIFEST_VERSION
            || self.classification != APPROVED_CLASSIFICATION
            || self.document_version == 0
            || self.content_bytes == 0
            || self.policy_version == 0
            || self.detector_versions.len() > MAX_VERSION_VALUES
            || self.model_versions.len() > MAX_VERSION_VALUES
            || self.unresolved_p0 != 0
            || self.unresolved_p1 != 0
            || self.issued_at_unix >= self.expires_at_unix
            || self.content_media_type.is_empty()
            || self.destination_scope.is_empty()
            || self.purpose.is_empty()
            || self.receipt_nonce.is_empty()
        {
            return Err(VNextSchemaError::InvalidManifest);
        }
        for value in [
            self.schema_version.as_str(),
            self.classification.as_str(),
            self.content_media_type.as_str(),
            self.policy_id.as_str(),
            self.destination_scope.as_str(),
            self.purpose.as_str(),
            self.receipt_nonce.as_str(),
        ] {
            reject_control_chars(value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignedApprovedMaterialManifestV1 {
    pub claims: ApprovedMaterialManifestV1,
    pub canonical_claims_sha256: Sha256Hex,
    pub signing_algorithm: String,
    pub signing_key_id: String,
    pub signing_key_version: u64,
    pub signature: String,
}

impl SignedApprovedMaterialManifestV1 {
    pub fn validate_structure(&self) -> Result<(), VNextSchemaError> {
        self.claims.validate()?;
        if self.signing_algorithm.is_empty()
            || self.signing_key_id.is_empty()
            || self.signing_key_version == 0
            || self.signature.is_empty()
        {
            return Err(VNextSchemaError::InvalidManifest);
        }
        let canonical = canonical_json_v1(&self.claims)?;
        let computed = crate::sha256_hex(&canonical);
        if self.canonical_claims_sha256.as_str() != computed {
            return Err(VNextSchemaError::InvalidManifest);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ApprovedMaterialRefV1 {
    pub material_id: MaterialId,
    pub document_version: u64,
    pub publication_id: PublicationId,
    pub manifest_sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WorkProductManifestV1 {
    pub schema_version: String,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub case_id: CaseId,
    pub work_product_id: WorkProductId,
    pub version: u64,
    pub expected_parent_version: Option<u64>,
    pub task_type: String,
    pub status: String,
    pub source_approved_refs: Vec<ApprovedMaterialRefV1>,
    pub content_media_type: String,
    pub content_sha256: Sha256Hex,
    pub content_bytes: u64,
    pub placeholder_policy_version: String,
    pub residual_scan_hash: Sha256Hex,
    pub author_tool: String,
    pub author_tool_version: String,
    pub created_at_unix: u64,
}

impl WorkProductManifestV1 {
    pub fn validate(&self) -> Result<(), VNextSchemaError> {
        if self.schema_version != WORK_PRODUCT_MANIFEST_VERSION
            || self.version == 0
            || self.content_bytes == 0
            || self.source_approved_refs.is_empty()
            || self.source_approved_refs.len() > 256
            || self.task_type.is_empty()
            || self.status.is_empty()
            || self.content_media_type.is_empty()
            || self.placeholder_policy_version.is_empty()
            || self.author_tool.is_empty()
            || self.author_tool_version.is_empty()
            || (self.version == 1 && self.expected_parent_version.is_some())
            || (self.version > 1 && self.expected_parent_version != Some(self.version - 1))
        {
            return Err(VNextSchemaError::InvalidManifest);
        }
        let mut references = BTreeSet::new();
        for reference in &self.source_approved_refs {
            if reference.document_version == 0
                || !references.insert((
                    reference.material_id.as_str(),
                    reference.document_version,
                    reference.publication_id.as_str(),
                ))
            {
                return Err(VNextSchemaError::InvalidManifest);
            }
        }
        Ok(())
    }
}

/// Serialize claims using canonical-json-v1: sorted object keys and integer-only numbers.
pub fn canonical_json_v1<T: Serialize>(value: &T) -> Result<Vec<u8>, VNextSchemaError> {
    let value = serde_json::to_value(value).map_err(|_| VNextSchemaError::InvalidJson)?;
    let mut output = String::new();
    write_canonical(&value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_canonical(value: &Value, output: &mut String) -> Result<(), VNextSchemaError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => {
            if let Some(value) = value.as_i64() {
                write!(output, "{value}").map_err(|_| VNextSchemaError::InvalidJson)?;
            } else if let Some(value) = value.as_u64() {
                write!(output, "{value}").map_err(|_| VNextSchemaError::InvalidJson)?;
            } else {
                return Err(VNextSchemaError::FloatingPointNotAllowed);
            }
        }
        Value::String(value) => {
            reject_control_chars(value)?;
            output.push_str(
                &serde_json::to_string(value).map_err(|_| VNextSchemaError::InvalidJson)?,
            );
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.iter().enumerate() {
                reject_control_chars(key)?;
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key).map_err(|_| VNextSchemaError::InvalidJson)?,
                );
                output.push(':');
                let item = values.get(*key).ok_or(VNextSchemaError::InvalidJson)?;
                write_canonical(item, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

/// Reject duplicate keys, floats and control characters before typed deserialization.
///
/// Target structs use deny_unknown_fields to complete strict schema validation.
pub fn strict_json_v1_from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, VNextSchemaError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| classify_json_error(&error.to_string()))?;
    deserializer
        .end()
        .map_err(|_| VNextSchemaError::InvalidJson)?;
    serde_json::from_value(value.0).map_err(|_| VNextSchemaError::InvalidSchema)
}

fn classify_json_error(error: &str) -> VNextSchemaError {
    if error.contains("duplicate JSON key") {
        VNextSchemaError::DuplicateJsonKey
    } else if error.contains("floating-point") {
        VNextSchemaError::FloatingPointNotAllowed
    } else if error.contains("control character") {
        VNextSchemaError::ControlCharacterNotAllowed
    } else {
        VNextSchemaError::InvalidJson
    }
}

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict canonical-json-v1 input")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Err(E::custom("floating-point JSON value is not allowed"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        reject_control_chars(value).map_err(E::custom)?;
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        reject_control_chars(&value).map_err(E::custom)?;
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictValue>()? {
            values.push(value.0);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            reject_control_chars(&key).map_err(A::Error::custom)?;
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom("duplicate JSON key"));
            }
            let value = map.next_value::<StrictValue>()?;
            values.insert(key, value.0);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

fn reject_control_chars(value: &str) -> Result<(), VNextSchemaError> {
    if value.chars().any(char::is_control) {
        return Err(VNextSchemaError::ControlCharacterNotAllowed);
    }
    Ok(())
}

fn validate_safe_strings<'a>(
    values: impl Iterator<Item = &'a str>,
) -> Result<(), VNextSchemaError> {
    for value in values {
        if value.is_empty() {
            return Err(VNextSchemaError::InvalidSchema);
        }
        reject_control_chars(value)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hash(seed: &[u8]) -> Sha256Hex {
        Sha256Hex::parse(crate::sha256_hex(seed)).expect("valid hash")
    }

    #[test]
    fn opaque_ids_and_hashes_are_strict_lowercase() {
        assert!(CaseId::parse("case_0123456789abcdef0123456789abcdef").is_ok());
        assert!(CaseId::parse("case_ABCDEF00000000000000000000000000").is_err());
        assert!(CaseId::parse("mat_0123456789abcdef0123456789abcdef").is_err());
        assert!(Sha256Hex::parse("a".repeat(64)).is_ok());
        assert!(Sha256Hex::parse("A".repeat(64)).is_err());
    }

    #[test]
    fn confidence_is_bounded() {
        assert!(ConfidencePpm::new(1_000_000).is_ok());
        assert!(ConfidencePpm::new(1_000_001).is_err());
    }

    #[test]
    fn canonical_json_sorts_recursively_and_rejects_float_and_controls() {
        let value = json!({"z": 2, "a": {"y": 1, "b": true}});
        assert_eq!(
            canonical_json_v1(&value).expect("canonical"),
            br#"{"a":{"b":true,"y":1},"z":2}"#
        );
        assert_eq!(
            canonical_json_v1(&json!({"score": 0.5})),
            Err(VNextSchemaError::FloatingPointNotAllowed)
        );
        assert_eq!(
            canonical_json_v1(&json!({"text": "line\nfeed"})),
            Err(VNextSchemaError::ControlCharacterNotAllowed)
        );
    }

    #[test]
    fn strict_parser_rejects_duplicate_unknown_float_and_control_fields() {
        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct Sample {
            count: u64,
        }

        assert_eq!(
            strict_json_v1_from_slice::<Sample>(br#"{"count":1,"count":2}"#),
            Err(VNextSchemaError::DuplicateJsonKey)
        );
        assert_eq!(
            strict_json_v1_from_slice::<Sample>(br#"{"count":1,"extra":2}"#),
            Err(VNextSchemaError::InvalidSchema)
        );
        assert_eq!(
            strict_json_v1_from_slice::<Value>(br#"{"score":0.5}"#),
            Err(VNextSchemaError::FloatingPointNotAllowed)
        );
        assert_eq!(
            strict_json_v1_from_slice::<Value>(b"{\"text\":\"line\\nfeed\"}"),
            Err(VNextSchemaError::ControlCharacterNotAllowed)
        );
    }

    #[test]
    fn automatic_route_cannot_bypass_p0() {
        let gates = HardGateEvaluationV1 {
            gates: REQUIRED_HARD_GATES
                .iter()
                .map(|gate| HardGateResultV1 {
                    gate_id: (*gate).to_owned(),
                    passed: true,
                    blocking: true,
                    reason_codes: Vec::new(),
                    evidence_hashes: vec![hash(gate.as_bytes())],
                })
                .collect(),
            evaluated_at_unix: 1,
            evaluation_hash: hash(b"gates"),
        };
        let mut risk = DocumentRiskV1 {
            route: DocumentRoute::AutoApprovalEligible,
            readiness_score: 100,
            page_risks: vec![PageRiskV1 {
                page_index: 0,
                p0_count: 0,
                p1_count: 0,
                p2_count: 0,
                p3_count: 0,
                ocr_min_ppm: None,
                ocr_mean_ppm: None,
                ocr_p10_ppm: None,
                coverage_ppm: ConfidencePpm::new(1_000_000).expect("valid confidence"),
                unknown_long_number_count: 0,
                unresolved_entity_counts: BTreeMap::new(),
                visual_risks: Vec::new(),
                completeness_passed: true,
                detector_conflict_count: 0,
                cluster_inconsistency_count: 0,
                visual_review_required: false,
                readiness_score: 100,
                reason_codes: Vec::new(),
            }],
            total_p0: 0,
            total_p1: 0,
            total_p2: 0,
            hard_gate_evaluation_hash: gates.evaluation_hash.clone(),
            finding_summary_hash: hash(b"findings"),
            policy_id: "strict".to_owned(),
            policy_version: 1,
            policy_sha256: hash(b"policy"),
            calibration_evidence_version: Some("cal-v1".to_owned()),
            qualification_report_id: Some("qual-v1".to_owned()),
            reason_codes: Vec::new(),
        };
        assert!(risk.validate(&gates).is_ok());
        risk.page_risks[0].p0_count = 1;
        risk.total_p0 = 1;
        assert!(risk.validate(&gates).is_err());
    }
}
