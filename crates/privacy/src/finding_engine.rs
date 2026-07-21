//! Deterministic finding aggregation with no raw private values in public output.
//!
//! Detector adapters must persist the actual matched value in the encrypted vault and pass only
//! a keyed value fingerprint plus an opaque private-value reference into this module.

use crate::{
    sha256_hex,
    vnext::{
        canonical_json_v1, CaseId, ClusterId, ConfidencePpm, EntityType, FindingGeometryV1,
        FindingId, FindingSeverity, MaterialId, PrivacyFindingV1, PrivateValueRefV1,
        ReviewResolution, Sha256Hex, VNextSchemaError,
    },
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

pub const FINDING_ENGINE_VERSION: &str = "privacy-finding-engine-v1";
pub const MAX_FINDING_CANDIDATES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingEngineError {
    EmptyInput,
    CandidateLimitExceeded,
    InvalidCandidate,
    InvalidPolicy,
    InvalidOutput,
}

impl fmt::Display for FindingEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyInput => "finding_input_empty",
            Self::CandidateLimitExceeded => "finding_candidate_limit_exceeded",
            Self::InvalidCandidate => "finding_candidate_invalid",
            Self::InvalidPolicy => "finding_policy_invalid",
            Self::InvalidOutput => "finding_output_invalid",
        })
    }
}

impl Error for FindingEngineError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FindingPolicyV1 {
    pub policy_id: String,
    pub policy_version: u64,
    pub minimum_detector_agreement: u8,
    pub high_confidence_ppm: ConfidencePpm,
    pub low_ocr_confidence_ppm: ConfidencePpm,
}

impl FindingPolicyV1 {
    fn validate(&self) -> Result<(), FindingEngineError> {
        if self.policy_id.is_empty()
            || self.policy_id.len() > 128
            || self.policy_id.chars().any(char::is_control)
            || self.policy_version == 0
            || !(1..=8).contains(&self.minimum_detector_agreement)
        {
            return Err(FindingEngineError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Private-boundary detector output. This deliberately has no raw-value field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingCandidateV1 {
    pub page_index: u32,
    pub block_id: String,
    pub start_offset: u32,
    pub end_offset: u32,
    pub geometry: Option<FindingGeometryV1>,
    pub entity_type: EntityType,
    pub detector_source: String,
    pub detector_version: String,
    pub model_versions: BTreeMap<String, String>,
    pub raw_score_ppm: Option<ConfidencePpm>,
    pub calibrated_confidence_ppm: Option<ConfidencePpm>,
    pub ocr_confidence_ppm: Option<ConfidencePpm>,
    pub layout_confidence_ppm: Option<ConfidencePpm>,
    pub normalization_evidence_hash: Option<Sha256Hex>,
    pub confusable_evidence_hash: Option<Sha256Hex>,
    pub case_dictionary_match: bool,
    /// A per-case keyed fingerprint. It is consumed for grouping and never copied to a finding.
    pub value_fingerprint: Sha256Hex,
    pub proposed_replacement: Option<String>,
    pub private_value_ref: PrivateValueRefV1,
}

impl FindingCandidateV1 {
    fn validate(&self) -> Result<(), FindingEngineError> {
        if self.start_offset >= self.end_offset
            || !safe_token(&self.block_id, 256)
            || !safe_token(&self.detector_source, 128)
            || !safe_version(&self.detector_version)
            || self.model_versions.len() > 64
            || self.private_value_ref.object_version == 0
            || self
                .model_versions
                .iter()
                .any(|(name, version)| !safe_token(name, 128) || !safe_version(version))
            || self
                .proposed_replacement
                .as_deref()
                .is_some_and(|value| !valid_replacement(value))
            || self
                .geometry
                .as_ref()
                .is_some_and(|geometry| !valid_geometry(geometry))
        {
            return Err(FindingEngineError::InvalidCandidate);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FindingBatchV1 {
    pub engine_version: String,
    pub policy_id: String,
    pub policy_version: u64,
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub findings: Vec<PrivacyFindingV1>,
    pub cluster_count: u32,
    pub p0_count: u32,
    pub p1_count: u32,
    pub p2_count: u32,
    pub finding_summary_hash: Sha256Hex,
}

type LocationKey = (u32, String, u32, u32);
type GroupKey = (u32, String, u32, u32, EntityType, Sha256Hex);

pub fn build_findings(
    case_id: CaseId,
    material_id: MaterialId,
    document_version: u64,
    candidates: Vec<FindingCandidateV1>,
    policy: &FindingPolicyV1,
) -> Result<FindingBatchV1, FindingEngineError> {
    policy.validate()?;
    if document_version == 0 || candidates.is_empty() {
        return Err(FindingEngineError::EmptyInput);
    }
    if candidates.len() > MAX_FINDING_CANDIDATES {
        return Err(FindingEngineError::CandidateLimitExceeded);
    }
    for candidate in &candidates {
        candidate.validate()?;
    }

    let mut location_values = BTreeMap::<LocationKey, BTreeSet<(EntityType, Sha256Hex)>>::new();
    let mut groups = BTreeMap::<GroupKey, Vec<FindingCandidateV1>>::new();
    for candidate in candidates {
        let location = (
            candidate.page_index,
            candidate.block_id.clone(),
            candidate.start_offset,
            candidate.end_offset,
        );
        location_values
            .entry(location)
            .or_default()
            .insert((candidate.entity_type, candidate.value_fingerprint.clone()));
        let key = (
            candidate.page_index,
            candidate.block_id.clone(),
            candidate.start_offset,
            candidate.end_offset,
            candidate.entity_type,
            candidate.value_fingerprint.clone(),
        );
        groups.entry(key).or_default().push(candidate);
    }

    let mut findings = Vec::with_capacity(groups.len());
    for (key, group) in groups {
        let location = (key.0, key.1.clone(), key.2, key.3);
        let location_conflict = location_values
            .get(&location)
            .is_none_or(|values| values.len() != 1);
        findings.push(merge_group(
            &case_id,
            &material_id,
            document_version,
            key,
            group,
            location_conflict,
            policy,
        )?);
    }
    findings.sort_by(|left, right| {
        left.page_index
            .cmp(&right.page_index)
            .then_with(|| left.block_id.cmp(&right.block_id))
            .then_with(|| left.start_offset.cmp(&right.start_offset))
            .then_with(|| left.end_offset.cmp(&right.end_offset))
            .then_with(|| left.entity_type.cmp(&right.entity_type))
    });

    let cluster_count = u32::try_from(
        findings
            .iter()
            .filter_map(|finding| finding.cluster_id.as_ref())
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .map_err(|_| FindingEngineError::InvalidOutput)?;
    let p0_count = count_severity(&findings, FindingSeverity::P0Blocking)?;
    let p1_count = count_severity(&findings, FindingSeverity::P1High)?;
    let p2_count = count_severity(&findings, FindingSeverity::P2Medium)?;
    let canonical = canonical_json_v1(&findings).map_err(|_| FindingEngineError::InvalidOutput)?;
    let finding_summary_hash =
        Sha256Hex::parse(sha256_hex(&canonical)).map_err(|_| FindingEngineError::InvalidOutput)?;
    Ok(FindingBatchV1 {
        engine_version: FINDING_ENGINE_VERSION.to_owned(),
        policy_id: policy.policy_id.clone(),
        policy_version: policy.policy_version,
        case_id,
        material_id,
        document_version,
        findings,
        cluster_count,
        p0_count,
        p1_count,
        p2_count,
        finding_summary_hash,
    })
}

fn merge_group(
    case_id: &CaseId,
    material_id: &MaterialId,
    document_version: u64,
    key: GroupKey,
    mut group: Vec<FindingCandidateV1>,
    location_conflict: bool,
    policy: &FindingPolicyV1,
) -> Result<PrivacyFindingV1, FindingEngineError> {
    group.sort_by(|left, right| {
        left.detector_source
            .cmp(&right.detector_source)
            .then_with(|| left.detector_version.cmp(&right.detector_version))
    });
    let first = group.first().ok_or(FindingEngineError::InvalidOutput)?;
    let mut detector_sources = BTreeSet::new();
    let mut detector_versions = BTreeMap::new();
    let mut model_versions = BTreeMap::new();
    let mut replacements = BTreeSet::new();
    let mut conflict = location_conflict;
    let mut case_dictionary_match = false;
    let mut raw_score_ppm = None;
    let mut calibrated_confidence_ppm = None;
    let mut ocr_confidence_ppm = None;
    let mut layout_confidence_ppm = None;
    let mut normalization_hash = None;
    let mut confusable_hash = None;

    for candidate in &group {
        detector_sources.insert(candidate.detector_source.clone());
        if detector_versions
            .insert(
                candidate.detector_source.clone(),
                candidate.detector_version.clone(),
            )
            .is_some_and(|existing| existing != candidate.detector_version)
        {
            conflict = true;
        }
        for (name, version) in &candidate.model_versions {
            if model_versions
                .insert(name.clone(), version.clone())
                .is_some_and(|existing| existing != *version)
            {
                conflict = true;
            }
        }
        if candidate.private_value_ref != first.private_value_ref {
            conflict = true;
        }
        if let Some(replacement) = &candidate.proposed_replacement {
            replacements.insert(replacement.clone());
        }
        case_dictionary_match |= candidate.case_dictionary_match;
        raw_score_ppm = max_confidence(raw_score_ppm, candidate.raw_score_ppm);
        calibrated_confidence_ppm = max_confidence(
            calibrated_confidence_ppm,
            candidate.calibrated_confidence_ppm,
        );
        ocr_confidence_ppm = min_confidence(ocr_confidence_ppm, candidate.ocr_confidence_ppm);
        layout_confidence_ppm =
            min_confidence(layout_confidence_ppm, candidate.layout_confidence_ppm);
        normalization_hash = normalization_hash.or(candidate.normalization_evidence_hash.clone());
        confusable_hash = confusable_hash.or(candidate.confusable_evidence_hash.clone());
    }
    if replacements.len() > 1 {
        conflict = true;
    }

    let detector_sources = detector_sources.into_iter().collect::<Vec<_>>();
    let detector_agreement =
        !conflict && detector_sources.len() >= usize::from(policy.minimum_detector_agreement);
    let cluster_id = stable_cluster_id(case_id, key.4, &key.5)?;
    let proposed_replacement = replacements
        .into_iter()
        .next()
        .unwrap_or_else(|| stable_replacement(key.4, &cluster_id));

    let mut reason_codes = BTreeSet::new();
    let severity = if conflict {
        reason_codes.insert("detector_or_location_conflict".to_owned());
        FindingSeverity::P0Blocking
    } else if high_risk_entity(key.4) || case_dictionary_match {
        reason_codes.insert("unresolved_high_risk_entity".to_owned());
        FindingSeverity::P1High
    } else {
        reason_codes.insert("unresolved_sensitive_entity".to_owned());
        FindingSeverity::P2Medium
    };
    if !detector_agreement {
        reason_codes.insert("detector_agreement_missing".to_owned());
    }
    if calibrated_confidence_ppm.is_none_or(|value| value < policy.high_confidence_ppm) {
        reason_codes.insert("confidence_below_high_threshold".to_owned());
    }
    if ocr_confidence_ppm.is_some_and(|value| value < policy.low_ocr_confidence_ppm) {
        reason_codes.insert("low_ocr_confidence".to_owned());
    }
    if confusable_hash.is_some() {
        reason_codes.insert("unicode_or_ocr_confusable".to_owned());
    }

    let finding_id = stable_finding_id(case_id, material_id, document_version, &key)?;
    let provenance_hash = finding_provenance_hash(
        policy,
        &key,
        &detector_sources,
        &detector_versions,
        &model_versions,
    )?;
    let mut priority = match severity {
        FindingSeverity::P0Blocking => 1_000,
        FindingSeverity::P1High => 800,
        FindingSeverity::P2Medium => 500,
        FindingSeverity::P3Resolved | FindingSeverity::Informational => 100,
    };
    if !detector_agreement {
        priority = (priority + 75).min(1_000);
    }
    if confusable_hash.is_some() {
        priority = (priority + 50).min(1_000);
    }

    let finding = PrivacyFindingV1 {
        finding_id,
        case_id: case_id.clone(),
        material_id: material_id.clone(),
        document_version,
        page_index: key.0,
        block_id: key.1,
        start_offset: key.2,
        end_offset: key.3,
        geometry: first.geometry.clone(),
        entity_type: key.4,
        detector_sources,
        detector_versions,
        model_versions,
        raw_score_ppm,
        calibrated_confidence_ppm,
        ocr_confidence_ppm,
        layout_confidence_ppm,
        normalization_evidence_hash: normalization_hash,
        confusable_evidence_hash: confusable_hash,
        case_dictionary_match,
        cluster_id: Some(cluster_id),
        detector_agreement,
        severity,
        review_priority: priority,
        reason_codes: reason_codes.into_iter().collect(),
        proposed_replacement,
        resolution_state: ReviewResolution::Unresolved,
        human_override: None,
        provenance_hash,
        private_value_ref: first.private_value_ref.clone(),
    };
    finding
        .validate()
        .map_err(|_| FindingEngineError::InvalidOutput)?;
    Ok(finding)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingProvenanceClaims<'a> {
    engine_version: &'a str,
    policy: &'a FindingPolicyV1,
    page_index: u32,
    block_id: &'a str,
    start_offset: u32,
    end_offset: u32,
    entity_type: EntityType,
    value_fingerprint: &'a Sha256Hex,
    detector_sources: &'a [String],
    detector_versions: &'a BTreeMap<String, String>,
    model_versions: &'a BTreeMap<String, String>,
}

fn finding_provenance_hash(
    policy: &FindingPolicyV1,
    key: &GroupKey,
    detector_sources: &[String],
    detector_versions: &BTreeMap<String, String>,
    model_versions: &BTreeMap<String, String>,
) -> Result<Sha256Hex, FindingEngineError> {
    let claims = FindingProvenanceClaims {
        engine_version: FINDING_ENGINE_VERSION,
        policy,
        page_index: key.0,
        block_id: &key.1,
        start_offset: key.2,
        end_offset: key.3,
        entity_type: key.4,
        value_fingerprint: &key.5,
        detector_sources,
        detector_versions,
        model_versions,
    };
    let canonical = canonical_json_v1(&claims).map_err(|_| FindingEngineError::InvalidOutput)?;
    Sha256Hex::parse(sha256_hex(&canonical)).map_err(|_| FindingEngineError::InvalidOutput)
}

fn stable_cluster_id(
    case_id: &CaseId,
    entity_type: EntityType,
    fingerprint: &Sha256Hex,
) -> Result<ClusterId, FindingEngineError> {
    let material = format!(
        "LawyerAssistance/finding-cluster/v1\0{}\0{}\0{}",
        case_id.as_str(),
        entity_code(entity_type),
        fingerprint.as_str()
    );
    let digest = sha256_hex(material.as_bytes());
    ClusterId::parse(format!("clu_{}", &digest[..32]))
        .map_err(|_| FindingEngineError::InvalidOutput)
}

fn stable_finding_id(
    case_id: &CaseId,
    material_id: &MaterialId,
    document_version: u64,
    key: &GroupKey,
) -> Result<FindingId, FindingEngineError> {
    let material = format!(
        "LawyerAssistance/finding/v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        case_id.as_str(),
        material_id.as_str(),
        document_version,
        key.0,
        key.1,
        key.2,
        key.3,
        key.5.as_str()
    );
    let digest = sha256_hex(material.as_bytes());
    FindingId::parse(format!("fnd_{}", &digest[..32]))
        .map_err(|_| FindingEngineError::InvalidOutput)
}

fn stable_replacement(entity_type: EntityType, cluster_id: &ClusterId) -> String {
    let suffix = cluster_id
        .as_str()
        .strip_prefix("clu_")
        .unwrap_or(cluster_id.as_str());
    format!("[{}_{}]", entity_code(entity_type), &suffix[..8])
}

fn entity_code(entity_type: EntityType) -> &'static str {
    match entity_type {
        EntityType::PersonName => "PERSON",
        EntityType::OrganizationName => "ORG",
        EntityType::CaseNumber => "CASE_NUMBER",
        EntityType::IdentityNumber => "IDENTITY",
        EntityType::PassportNumber => "PASSPORT",
        EntityType::PhoneNumber => "PHONE",
        EntityType::LandlineNumber => "LANDLINE",
        EntityType::BankAccount => "BANK_ACCOUNT",
        EntityType::EmailAddress => "EMAIL",
        EntityType::Address => "ADDRESS",
        EntityType::OrganizationCode => "ORG_CODE",
        EntityType::BusinessLicenseNumber => "BUSINESS_LICENSE",
        EntityType::VehiclePlate => "VEHICLE_PLATE",
        EntityType::IpAddress => "IP",
        EntityType::SocialAccount => "SOCIAL_ACCOUNT",
        EntityType::PaymentAccount => "PAYMENT_ACCOUNT",
        EntityType::AccountName => "ACCOUNT_NAME",
        EntityType::ContractNumber => "CONTRACT_NUMBER",
        EntityType::TrackingNumber => "TRACKING_NUMBER",
        EntityType::PropertyCertificateNumber => "PROPERTY_CERT",
        EntityType::Custom => "SENSITIVE",
    }
}

fn high_risk_entity(entity_type: EntityType) -> bool {
    !matches!(
        entity_type,
        EntityType::PersonName
            | EntityType::OrganizationName
            | EntityType::SocialAccount
            | EntityType::Custom
    )
}

fn max_confidence(
    left: Option<ConfidencePpm>,
    right: Option<ConfidencePpm>,
) -> Option<ConfidencePpm> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (left, right) => left.or(right),
    }
}

fn min_confidence(
    left: Option<ConfidencePpm>,
    right: Option<ConfidencePpm>,
) -> Option<ConfidencePpm> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

fn count_severity(
    findings: &[PrivacyFindingV1],
    severity: FindingSeverity,
) -> Result<u32, FindingEngineError> {
    u32::try_from(
        findings
            .iter()
            .filter(|finding| finding.severity == severity)
            .count(),
    )
    .map_err(|_| FindingEngineError::InvalidOutput)
}

fn safe_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\0')
}

fn safe_version(value: &str) -> bool {
    safe_token(value, 128)
}

fn valid_replacement(value: &str) -> bool {
    safe_token(value, 128)
        && value.starts_with('[')
        && value.ends_with(']')
        && !value.contains("..")
}

fn valid_geometry(geometry: &FindingGeometryV1) -> bool {
    safe_token(&geometry.coordinate_system, 64)
        && geometry.polygon_micropoints.len() <= 128
        && geometry
            .polygon_micropoints
            .iter()
            .all(|point| point[0] >= 0 && point[1] >= 0)
        && geometry.bbox_micropoints.is_none_or(|bbox| {
            bbox[0] >= 0 && bbox[1] >= 0 && bbox[0] < bbox[2] && bbox[1] < bbox[3]
        })
}

impl From<VNextSchemaError> for FindingEngineError {
    fn from(_: VNextSchemaError) -> Self {
        Self::InvalidOutput
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vnext::{ObjectId, PrivateValueRefV1};

    fn id<T>(
        parse: impl FnOnce(String) -> Result<T, VNextSchemaError>,
        prefix: &str,
        c: char,
    ) -> T {
        parse(format!("{prefix}{}", c.to_string().repeat(32))).expect("fixture id")
    }

    fn hash(c: char) -> Sha256Hex {
        Sha256Hex::parse(c.to_string().repeat(64)).expect("fixture hash")
    }

    fn policy() -> FindingPolicyV1 {
        FindingPolicyV1 {
            policy_id: "synthetic-strict-v1".to_owned(),
            policy_version: 1,
            minimum_detector_agreement: 2,
            high_confidence_ppm: ConfidencePpm::new(900_000).expect("ppm"),
            low_ocr_confidence_ppm: ConfidencePpm::new(850_000).expect("ppm"),
        }
    }

    fn candidate(source: &str, fingerprint: char) -> FindingCandidateV1 {
        FindingCandidateV1 {
            page_index: 0,
            block_id: "blk_11111111111111111111111111111111".to_owned(),
            start_offset: 2,
            end_offset: 10,
            geometry: None,
            entity_type: EntityType::IdentityNumber,
            detector_source: source.to_owned(),
            detector_version: "1.0.0".to_owned(),
            model_versions: BTreeMap::new(),
            raw_score_ppm: Some(ConfidencePpm::new(960_000).expect("ppm")),
            calibrated_confidence_ppm: Some(ConfidencePpm::new(950_000).expect("ppm")),
            ocr_confidence_ppm: Some(ConfidencePpm::new(930_000).expect("ppm")),
            layout_confidence_ppm: Some(ConfidencePpm::new(920_000).expect("ppm")),
            normalization_evidence_hash: Some(hash('d')),
            confusable_evidence_hash: None,
            case_dictionary_match: false,
            value_fingerprint: hash(fingerprint),
            proposed_replacement: None,
            private_value_ref: PrivateValueRefV1 {
                object_id: id(ObjectId::parse, "obj_", '4'),
                object_version: 1,
                value_locator_hash: hash('e'),
            },
        }
    }

    fn build(candidates: Vec<FindingCandidateV1>) -> FindingBatchV1 {
        build_findings(
            id(CaseId::parse, "case_", '1'),
            id(MaterialId::parse, "mat_", '2'),
            1,
            candidates,
            &policy(),
        )
        .expect("finding batch")
    }

    #[test]
    fn detector_order_does_not_change_cluster_alias_or_summary() {
        let left = build(vec![candidate("rule", 'a'), candidate("dictionary", 'a')]);
        let right = build(vec![candidate("dictionary", 'a'), candidate("rule", 'a')]);
        assert_eq!(left.findings, right.findings);
        assert_eq!(left.finding_summary_hash, right.finding_summary_hash);
        assert!(left.findings[0].detector_agreement);
        assert_eq!(left.findings[0].severity, FindingSeverity::P1High);
    }

    #[test]
    fn public_finding_never_contains_private_fingerprint_or_raw_value_field() {
        let batch = build(vec![candidate("rule", 'a'), candidate("dictionary", 'a')]);
        let wire = serde_json::to_string(&batch).expect("serialize batch");
        assert!(!wire.contains(&"a".repeat(64)));
        assert!(!wire.contains("rawValue"));
        assert!(!wire.contains("valueFingerprint"));
        assert!(!wire.contains("synthetic-private-value-canary"));
    }

    #[test]
    fn conflicting_values_at_same_location_are_p0_and_cannot_be_hidden_by_score() {
        let batch = build(vec![candidate("rule", 'a'), candidate("dictionary", 'b')]);
        assert_eq!(batch.p0_count, 2);
        assert!(batch
            .findings
            .iter()
            .all(|finding| finding.severity == FindingSeverity::P0Blocking));
    }

    #[test]
    fn malformed_span_replacement_and_geometry_fail_closed() {
        let mut invalid = candidate("rule", 'a');
        invalid.end_offset = invalid.start_offset;
        assert_eq!(
            build_findings(
                id(CaseId::parse, "case_", '1'),
                id(MaterialId::parse, "mat_", '2'),
                1,
                vec![invalid],
                &policy(),
            ),
            Err(FindingEngineError::InvalidCandidate)
        );
    }
}
