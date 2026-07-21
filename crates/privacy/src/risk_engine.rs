//! Deterministic backend-only risk routing and hard-gate evaluation.

use crate::vnext::{
    canonical_json_v1, ConfidencePpm, DocumentRiskV1, DocumentRoute, EntityType,
    HardGateEvaluationV1, HardGateResultV1, PageRiskV1, Sha256Hex, VNextSchemaError,
    REQUIRED_HARD_GATES,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const RISK_ENGINE_VERSION: &str = "privacy-risk-engine-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RiskPolicyV1 {
    pub policy_id: String,
    pub policy_version: u64,
    pub policy_sha256: Sha256Hex,
    pub minimum_ocr_confidence_ppm: ConfidencePpm,
    pub minimum_ocr_coverage_ppm: ConfidencePpm,
    pub maximum_quick_review_p2: u32,
    pub calibrated_for_automatic: bool,
    pub organization_allows_automatic: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct QualificationSnapshotV1 {
    pub qualification_report_id: Option<String>,
    pub qualification_report_sha256: Option<Sha256Hex>,
    pub processing_chain_qualified: bool,
    pub exact_worker_model_match: bool,
    pub network_isolation_enforced: bool,
    pub model_manifest_trust_established: bool,
    pub production_case_ocr_authorized: bool,
    pub expires_at_unix: Option<u64>,
    pub revoked: bool,
}

impl QualificationSnapshotV1 {
    fn qualified_at(&self, now_unix: u64, ocr_used: bool) -> bool {
        let report_current = self
            .expires_at_unix
            .is_some_and(|expires_at| now_unix < expires_at);
        self.processing_chain_qualified
            && self.exact_worker_model_match
            && report_current
            && !self.revoked
            && (!ocr_used
                || (self.network_isolation_enforced
                    && self.model_manifest_trust_established
                    && self.production_case_ocr_authorized))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedApprovalRoute {
    Human,
    ShadowHuman,
    Automatic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PageAssessmentV1 {
    pub page_index: u32,
    pub p0_count: u32,
    pub p1_count: u32,
    pub p2_count: u32,
    pub p3_count: u32,
    pub ocr_used: bool,
    pub ocr_min_ppm: Option<ConfidencePpm>,
    pub ocr_mean_ppm: Option<ConfidencePpm>,
    pub ocr_p10_ppm: Option<ConfidencePpm>,
    pub coverage_ppm: ConfidencePpm,
    pub unknown_long_number_count: u32,
    pub unresolved_entity_counts: BTreeMap<EntityType, u32>,
    pub unresolved_visual_risks: Vec<String>,
    pub completeness_passed: bool,
    pub detector_conflict_count: u32,
    pub cluster_inconsistency_count: u32,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DocumentAssessmentV1 {
    pub pages: Vec<PageAssessmentV1>,
    pub finding_summary_hash: Sha256Hex,
    pub dictionary_entities_stable: bool,
    pub deterministic_high_risk_fields_resolved: bool,
    pub independent_residual_scan_passed: bool,
    pub independent_residual_scan_hash: Option<Sha256Hex>,
    pub provenance_receiptable: bool,
    pub provenance_hash: Option<Sha256Hex>,
    pub publication_target_fixed: bool,
    pub publication_target_hash: Option<Sha256Hex>,
    pub requested_approval_route: RequestedApprovalRoute,
    pub calibration_evidence_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct HardGateClaimsV1<'a> {
    engine_version: &'a str,
    evaluated_at_unix: u64,
    gates: &'a [HardGateResultV1],
}

pub fn evaluate_document(
    policy: &RiskPolicyV1,
    qualification: &QualificationSnapshotV1,
    assessment: &DocumentAssessmentV1,
    now_unix: u64,
) -> Result<(DocumentRiskV1, HardGateEvaluationV1), VNextSchemaError> {
    validate_inputs(policy, assessment)?;

    let ocr_used = assessment.pages.iter().any(|page| page.ocr_used);
    let p0 = assessment
        .pages
        .iter()
        .map(|page| page.p0_count)
        .sum::<u32>();
    let p1 = assessment
        .pages
        .iter()
        .map(|page| page.p1_count)
        .sum::<u32>();
    let p2 = assessment
        .pages
        .iter()
        .map(|page| page.p2_count)
        .sum::<u32>();
    let completeness = assessment.pages.iter().all(|page| page.completeness_passed);
    let ocr_thresholds = assessment.pages.iter().all(|page| {
        !page.ocr_used
            || (page
                .ocr_min_ppm
                .is_some_and(|value| value >= policy.minimum_ocr_confidence_ppm)
                && page.coverage_ppm >= policy.minimum_ocr_coverage_ppm)
    });
    let visual_resolved = assessment
        .pages
        .iter()
        .all(|page| page.unresolved_visual_risks.is_empty());
    let conflicts = assessment
        .pages
        .iter()
        .map(|page| page.detector_conflict_count)
        .sum::<u32>();
    let cluster_inconsistencies = assessment
        .pages
        .iter()
        .map(|page| page.cluster_inconsistency_count)
        .sum::<u32>();
    let qualification_passed = qualification.qualified_at(now_unix, ocr_used);
    let calibrated =
        policy.calibrated_for_automatic && assessment.calibration_evidence_version.is_some();
    let approval_mode_allows_automatic = matches!(
        assessment.requested_approval_route,
        RequestedApprovalRoute::Automatic
    );

    let qualification_evidence = qualification
        .qualification_report_sha256
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let residual_evidence = assessment
        .independent_residual_scan_hash
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let provenance_evidence = assessment
        .provenance_hash
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let publication_evidence = assessment
        .publication_target_hash
        .iter()
        .cloned()
        .collect::<Vec<_>>();

    let mut gates = Vec::with_capacity(REQUIRED_HARD_GATES.len());
    gates.push(gate(
        "qualified_processing_chain",
        qualification_passed,
        "processing_chain_not_qualified",
        qualification_evidence.clone(),
    ));
    gates.push(gate(
        "complete_pages_and_order",
        completeness,
        "page_completeness_failed",
        Vec::new(),
    ));
    gates.push(gate("no_p0", p0 == 0, "p0_unresolved", Vec::new()));
    gates.push(gate(
        "no_unresolved_p1",
        p1 == 0,
        "p1_unresolved",
        Vec::new(),
    ));
    gates.push(gate(
        "ocr_thresholds",
        ocr_thresholds,
        "ocr_threshold_failed",
        qualification_evidence.clone(),
    ));
    gates.push(gate(
        "visual_risks_resolved",
        visual_resolved,
        "visual_risk_unresolved",
        Vec::new(),
    ));
    gates.push(gate(
        "required_dictionary_entities_stable",
        assessment.dictionary_entities_stable,
        "dictionary_entities_unstable",
        Vec::new(),
    ));
    gates.push(gate(
        "deterministic_high_risk_fields_resolved",
        assessment.deterministic_high_risk_fields_resolved,
        "deterministic_field_unresolved",
        Vec::new(),
    ));
    gates.push(gate(
        "detector_conflicts_resolved",
        conflicts == 0,
        "detector_conflict_unresolved",
        Vec::new(),
    ));
    gates.push(gate(
        "cluster_alias_consistency",
        cluster_inconsistencies == 0,
        "cluster_alias_inconsistent",
        Vec::new(),
    ));
    gates.push(gate(
        "independent_residual_scan",
        assessment.independent_residual_scan_passed
            && assessment.independent_residual_scan_hash.is_some(),
        "residual_scan_failed",
        residual_evidence,
    ));
    gates.push(gate(
        "provenance_receiptable",
        assessment.provenance_receiptable && assessment.provenance_hash.is_some(),
        "provenance_not_receiptable",
        provenance_evidence,
    ));
    gates.push(gate(
        "calibrated_policy",
        calibrated,
        "automatic_policy_not_calibrated",
        vec![policy.policy_sha256.clone()],
    ));
    gates.push(gate(
        "approval_mode_allows_automatic",
        approval_mode_allows_automatic,
        "approval_mode_requires_human",
        Vec::new(),
    ));
    gates.push(gate(
        "organization_policy_allows_automatic",
        policy.organization_allows_automatic,
        "organization_policy_requires_human",
        vec![policy.policy_sha256.clone()],
    ));
    gates.push(gate(
        "publication_target_fixed",
        assessment.publication_target_fixed && assessment.publication_target_hash.is_some(),
        "publication_target_not_fixed",
        publication_evidence,
    ));
    gates.push(gate(
        "exact_worker_model_qualification",
        qualification.exact_worker_model_match && qualification_passed,
        "exact_worker_model_not_qualified",
        qualification_evidence,
    ));

    let claims = HardGateClaimsV1 {
        engine_version: RISK_ENGINE_VERSION,
        evaluated_at_unix: now_unix,
        gates: &gates,
    };
    let evaluation_hash = Sha256Hex::parse(crate::sha256_hex(&canonical_json_v1(&claims)?))?;
    let hard_gates = HardGateEvaluationV1 {
        gates,
        evaluated_at_unix: now_unix,
        evaluation_hash: evaluation_hash.clone(),
    };
    hard_gates.validate()?;

    let page_risks = assessment
        .pages
        .iter()
        .map(|page| to_page_risk(page, policy))
        .collect::<Vec<_>>();
    let readiness_score = document_readiness(&page_risks, p0, p1);
    let route = route_document(
        &hard_gates,
        assessment,
        p0,
        p1,
        p2,
        policy.maximum_quick_review_p2,
    );
    let reason_codes = hard_gates
        .gates
        .iter()
        .filter(|gate| !gate.passed)
        .flat_map(|gate| gate.reason_codes.iter().cloned())
        .collect::<Vec<_>>();

    let risk = DocumentRiskV1 {
        route,
        readiness_score,
        page_risks,
        total_p0: p0,
        total_p1: p1,
        total_p2: p2,
        hard_gate_evaluation_hash: evaluation_hash,
        finding_summary_hash: assessment.finding_summary_hash.clone(),
        policy_id: policy.policy_id.clone(),
        policy_version: policy.policy_version,
        policy_sha256: policy.policy_sha256.clone(),
        calibration_evidence_version: assessment.calibration_evidence_version.clone(),
        qualification_report_id: qualification.qualification_report_id.clone(),
        reason_codes,
    };
    risk.validate(&hard_gates)?;
    Ok((risk, hard_gates))
}

fn gate(
    gate_id: &str,
    passed: bool,
    failure_reason: &str,
    evidence_hashes: Vec<Sha256Hex>,
) -> HardGateResultV1 {
    HardGateResultV1 {
        gate_id: gate_id.to_owned(),
        passed,
        blocking: true,
        reason_codes: if passed {
            Vec::new()
        } else {
            vec![failure_reason.to_owned()]
        },
        evidence_hashes,
    }
}

fn to_page_risk(page: &PageAssessmentV1, policy: &RiskPolicyV1) -> PageRiskV1 {
    let visual_review_required = !page.unresolved_visual_risks.is_empty();
    let readiness_score = page_readiness(page, policy);
    PageRiskV1 {
        page_index: page.page_index,
        p0_count: page.p0_count,
        p1_count: page.p1_count,
        p2_count: page.p2_count,
        p3_count: page.p3_count,
        ocr_min_ppm: page.ocr_min_ppm,
        ocr_mean_ppm: page.ocr_mean_ppm,
        ocr_p10_ppm: page.ocr_p10_ppm,
        coverage_ppm: page.coverage_ppm,
        unknown_long_number_count: page.unknown_long_number_count,
        unresolved_entity_counts: page.unresolved_entity_counts.clone(),
        visual_risks: page.unresolved_visual_risks.clone(),
        completeness_passed: page.completeness_passed,
        detector_conflict_count: page.detector_conflict_count,
        cluster_inconsistency_count: page.cluster_inconsistency_count,
        visual_review_required,
        readiness_score,
        reason_codes: page.reason_codes.clone(),
    }
}

fn page_readiness(page: &PageAssessmentV1, policy: &RiskPolicyV1) -> u32 {
    let mut score = 100_i32;
    score -= i32::try_from(page.p0_count.saturating_mul(100)).unwrap_or(i32::MAX);
    score -= i32::try_from(page.p1_count.saturating_mul(30)).unwrap_or(i32::MAX);
    score -= i32::try_from(page.p2_count.saturating_mul(8)).unwrap_or(i32::MAX);
    score -= i32::try_from(page.detector_conflict_count.saturating_mul(15)).unwrap_or(i32::MAX);
    score -= i32::try_from(page.cluster_inconsistency_count.saturating_mul(15)).unwrap_or(i32::MAX);
    if !page.completeness_passed {
        score -= 100;
    }
    if !page.unresolved_visual_risks.is_empty() {
        score -= 40;
    }
    if page.ocr_used
        && (page
            .ocr_min_ppm
            .is_none_or(|value| value < policy.minimum_ocr_confidence_ppm)
            || page.coverage_ppm < policy.minimum_ocr_coverage_ppm)
    {
        score -= 50;
    }
    u32::try_from(score.clamp(0, 100)).unwrap_or(0)
}

fn document_readiness(pages: &[PageRiskV1], p0: u32, p1: u32) -> u32 {
    if pages.is_empty() {
        return 0;
    }
    let total = pages
        .iter()
        .map(|page| u64::from(page.readiness_score))
        .sum::<u64>();
    let average = total / u64::try_from(pages.len()).unwrap_or(u64::MAX);
    let mut score = u32::try_from(average).unwrap_or(0);
    if p0 > 0 {
        score = 0;
    } else if p1 > 0 {
        score = score.min(49);
    }
    score
}

fn route_document(
    gates: &HardGateEvaluationV1,
    assessment: &DocumentAssessmentV1,
    p0: u32,
    p1: u32,
    p2: u32,
    maximum_quick_review_p2: u32,
) -> DocumentRoute {
    let safety_gate_failed = gates.gates.iter().any(|gate| {
        !gate.passed
            && !matches!(
                gate.gate_id.as_str(),
                "no_unresolved_p1"
                    | "calibrated_policy"
                    | "approval_mode_allows_automatic"
                    | "organization_policy_allows_automatic"
            )
    });
    if p0 > 0 || safety_gate_failed {
        return DocumentRoute::Blocked;
    }
    if gates.all_blocking_gates_passed() {
        return DocumentRoute::AutoApprovalEligible;
    }
    if p1 > 0
        || p2 > maximum_quick_review_p2
        || matches!(
            assessment.requested_approval_route,
            RequestedApprovalRoute::Human
        )
    {
        DocumentRoute::FullReviewRequired
    } else {
        DocumentRoute::QuickReviewRequired
    }
}

fn validate_inputs(
    policy: &RiskPolicyV1,
    assessment: &DocumentAssessmentV1,
) -> Result<(), VNextSchemaError> {
    if policy.policy_id.is_empty()
        || policy.policy_version == 0
        || assessment.pages.is_empty()
        || assessment.pages.len() > 100_000
    {
        return Err(VNextSchemaError::InvalidRiskEvaluation);
    }
    let indexes = assessment
        .pages
        .iter()
        .map(|page| page.page_index)
        .collect::<Vec<_>>();
    if indexes
        .iter()
        .enumerate()
        .any(|(expected, actual)| u32::try_from(expected).ok() != Some(*actual))
    {
        return Err(VNextSchemaError::InvalidRiskEvaluation);
    }
    for page in &assessment.pages {
        if page.reason_codes.len() > 64
            || page.unresolved_visual_risks.len() > 64
            || page
                .ocr_min_ppm
                .zip(page.ocr_mean_ppm)
                .is_some_and(|(minimum, mean)| minimum > mean)
        {
            return Err(VNextSchemaError::InvalidRiskEvaluation);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(seed: &[u8]) -> Sha256Hex {
        Sha256Hex::parse(crate::sha256_hex(seed)).expect("hash")
    }

    fn policy() -> RiskPolicyV1 {
        RiskPolicyV1 {
            policy_id: "strict".to_owned(),
            policy_version: 1,
            policy_sha256: hash(b"policy"),
            minimum_ocr_confidence_ppm: ConfidencePpm::new(900_000).expect("confidence"),
            minimum_ocr_coverage_ppm: ConfidencePpm::new(950_000).expect("coverage"),
            maximum_quick_review_p2: 2,
            calibrated_for_automatic: true,
            organization_allows_automatic: true,
        }
    }

    fn qualification() -> QualificationSnapshotV1 {
        QualificationSnapshotV1 {
            qualification_report_id: Some("qualification-v1".to_owned()),
            qualification_report_sha256: Some(hash(b"qualification")),
            processing_chain_qualified: true,
            exact_worker_model_match: true,
            network_isolation_enforced: true,
            model_manifest_trust_established: true,
            production_case_ocr_authorized: true,
            expires_at_unix: Some(10_000),
            revoked: false,
        }
    }

    fn assessment() -> DocumentAssessmentV1 {
        DocumentAssessmentV1 {
            pages: vec![PageAssessmentV1 {
                page_index: 0,
                p0_count: 0,
                p1_count: 0,
                p2_count: 0,
                p3_count: 3,
                ocr_used: true,
                ocr_min_ppm: Some(ConfidencePpm::new(950_000).expect("confidence")),
                ocr_mean_ppm: Some(ConfidencePpm::new(980_000).expect("confidence")),
                ocr_p10_ppm: Some(ConfidencePpm::new(960_000).expect("confidence")),
                coverage_ppm: ConfidencePpm::new(990_000).expect("coverage"),
                unknown_long_number_count: 0,
                unresolved_entity_counts: BTreeMap::new(),
                unresolved_visual_risks: Vec::new(),
                completeness_passed: true,
                detector_conflict_count: 0,
                cluster_inconsistency_count: 0,
                reason_codes: Vec::new(),
            }],
            finding_summary_hash: hash(b"findings"),
            dictionary_entities_stable: true,
            deterministic_high_risk_fields_resolved: true,
            independent_residual_scan_passed: true,
            independent_residual_scan_hash: Some(hash(b"residual")),
            provenance_receiptable: true,
            provenance_hash: Some(hash(b"provenance")),
            publication_target_fixed: true,
            publication_target_hash: Some(hash(b"target")),
            requested_approval_route: RequestedApprovalRoute::Automatic,
            calibration_evidence_version: Some("cal-v1".to_owned()),
        }
    }

    #[test]
    fn qualified_document_can_be_auto_eligible() {
        let (risk, gates) =
            evaluate_document(&policy(), &qualification(), &assessment(), 1).expect("evaluate");
        assert_eq!(risk.route, DocumentRoute::AutoApprovalEligible);
        assert!(gates.all_blocking_gates_passed());
    }

    #[test]
    fn p0_blocks_even_when_readiness_inputs_are_high() {
        let mut input = assessment();
        input.pages[0].p0_count = 1;
        let (risk, _) =
            evaluate_document(&policy(), &qualification(), &input, 1).expect("evaluate");
        assert_eq!(risk.route, DocumentRoute::Blocked);
        assert_eq!(risk.readiness_score, 0);
    }

    #[test]
    fn unresolved_p1_requires_full_review_and_cannot_auto_approve() {
        let mut input = assessment();
        input.pages[0].p1_count = 1;
        let (risk, gates) =
            evaluate_document(&policy(), &qualification(), &input, 1).expect("evaluate");
        assert_eq!(risk.route, DocumentRoute::FullReviewRequired);
        assert!(risk.readiness_score <= 49);
        assert!(!gates.all_blocking_gates_passed());
        assert!(risk.reason_codes.iter().any(|code| code == "p1_unresolved"));
    }

    #[test]
    fn shadow_mode_never_auto_publishes() {
        let mut input = assessment();
        input.requested_approval_route = RequestedApprovalRoute::ShadowHuman;
        let (risk, gates) =
            evaluate_document(&policy(), &qualification(), &input, 1).expect("evaluate");
        assert_eq!(risk.route, DocumentRoute::QuickReviewRequired);
        assert!(
            !gates
                .gates
                .iter()
                .find(|gate| gate.gate_id == "approval_mode_allows_automatic")
                .expect("gate")
                .passed
        );
    }

    #[test]
    fn current_unqualified_ocr_tuple_is_blocked() {
        let mut current = qualification();
        current.network_isolation_enforced = false;
        current.model_manifest_trust_established = false;
        current.production_case_ocr_authorized = false;
        let (risk, _) = evaluate_document(&policy(), &current, &assessment(), 1).expect("evaluate");
        assert_eq!(risk.route, DocumentRoute::Blocked);
    }

    #[test]
    fn missing_calibration_requires_human_review_without_claiming_blocked_content() {
        let mut policy = policy();
        policy.calibrated_for_automatic = false;
        let (risk, _) =
            evaluate_document(&policy, &qualification(), &assessment(), 1).expect("evaluate");
        assert_eq!(risk.route, DocumentRoute::QuickReviewRequired);
    }
}
