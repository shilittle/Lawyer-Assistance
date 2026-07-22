//! Revision-bound backend review state for the privacy pipeline.
//!
//! This state contains opaque vault references, hashes, findings, and decisions. It never stores a
//! decrypted private value. Renderer views deliberately remove private-value references.

use crate::{
    case_dictionary::{merge_cluster, split_finding_cluster, DictionaryCategoryV1},
    residual_scan::{IndependentResidualScanReportV1, ResidualRiskClassV1},
    risk_engine::{
        evaluate_document, DocumentAssessmentV1, PageAssessmentV1, QualificationSnapshotV1,
        RequestedApprovalRoute, RiskPolicyV1,
    },
    sha256_hex,
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, CaseId, ClusterId, ConfidencePpm,
        DocumentRiskV1, EntityType, FindingSeverity, HardGateEvaluationV1, HumanOverrideV1,
        MaterialId, PrivacyFindingV1, ReviewResolution, Sha256Hex, VNextSchemaError,
        MAX_REASON_CODES,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

pub const REVIEW_SESSION_SCHEMA_VERSION: &str = "privacy-risk-review-session-v1";
pub const REVIEW_STATE_VIEW_SCHEMA_VERSION: &str = "privacy-risk-review-state-v1";
pub const MAX_REVIEW_HISTORY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewSessionError {
    InvalidInput,
    InvalidEvidence,
    RevisionConflict,
    FindingNotFound,
    ClusterInvalid,
    DictionaryEvidenceRequired,
    HistoryUnavailable,
    Rejected,
    RiskEvaluationFailed,
}

impl ReviewSessionError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "privacy_review_input_invalid",
            Self::InvalidEvidence => "privacy_review_evidence_invalid",
            Self::RevisionConflict => "privacy_review_revision_conflict",
            Self::FindingNotFound => "privacy_review_finding_not_found",
            Self::ClusterInvalid => "privacy_review_cluster_invalid",
            Self::DictionaryEvidenceRequired => "privacy_review_dictionary_evidence_required",
            Self::HistoryUnavailable => "privacy_review_history_unavailable",
            Self::Rejected => "privacy_review_publication_rejected",
            Self::RiskEvaluationFailed => "privacy_review_risk_evaluation_failed",
        }
    }
}

impl fmt::Display for ReviewSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ReviewSessionError {}

impl From<VNextSchemaError> for ReviewSessionError {
    fn from(_: VNextSchemaError) -> Self {
        Self::RiskEvaluationFailed
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewActionV1 {
    AcceptReplacement {
        finding_id: String,
        apply_cluster: bool,
    },
    ChangeEntityType {
        finding_id: String,
        entity_type: EntityType,
    },
    ChangePlaceholder {
        finding_id: String,
        replacement: String,
        apply_cluster: bool,
    },
    MarkNotSensitive {
        finding_id: String,
    },
    AddToDictionary {
        finding_id: String,
        category: DictionaryCategoryV1,
        required: bool,
    },
    MergeClusters {
        cluster_ids: Vec<String>,
    },
    SplitCluster {
        finding_id: String,
    },
    ResolveVisualRisk {
        page_index: u32,
        risk_code: String,
        decision: VisualRiskDecisionV1,
        reason: String,
    },
    ConfirmEditedOutput,
    BatchAcceptP3,
    RejectPublication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisualRiskDecisionV1 {
    ConfirmedRedacted,
    ConfirmedReviewedNonSensitive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VisualRiskResolutionV1 {
    pub page_index: u32,
    pub risk_code: String,
    pub decision: VisualRiskDecisionV1,
    pub reason: String,
    pub actor_hash: Sha256Hex,
    pub provenance_hash: Sha256Hex,
    pub redacted_content_sha256: Sha256Hex,
    pub resolved_at_unix: u64,
    pub evidence_hash: Sha256Hex,
}
/// Evidence already produced by the local output editor and independent residual scanner.
/// The command layer must update the output before calling `apply_action`.
pub struct VerifiedReviewActionContextV1<'a> {
    pub actor_hash: &'a Sha256Hex,
    pub occurred_at_unix: u64,
    pub verified_redacted_content_sha256: &'a Sha256Hex,
    pub provenance_hash: &'a Sha256Hex,
    pub residual_scan: &'a IndependentResidualScanReportV1,
    pub dictionary_revision_hash: Option<&'a Sha256Hex>,
}

pub struct ReviewSessionInputV1 {
    pub redaction_id: String,
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub detector_run_completed: bool,
    pub redacted_content_sha256: Sha256Hex,
    pub dictionary_revision_hash: Option<Sha256Hex>,
    pub findings: Vec<PrivacyFindingV1>,
    pub assessment: DocumentAssessmentV1,
    pub residual_scan: IndependentResidualScanReportV1,
    pub risk_policy: RiskPolicyV1,
    pub qualification: QualificationSnapshotV1,
    pub created_at_unix: u64,
}

/// Result of a real local detector or OCR rerun. No stub rerun is accepted by this API.
pub struct ReviewAnalysisReplacementV1 {
    pub findings: Vec<PrivacyFindingV1>,
    pub assessment: DocumentAssessmentV1,
    pub residual_scan: IndependentResidualScanReportV1,
    pub redacted_content_sha256: Sha256Hex,
    pub provenance_hash: Sha256Hex,
    pub action_code: String,
    pub occurred_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ReviewCheckpointV1 {
    redacted_content_sha256: Sha256Hex,
    dictionary_revision_hash: Option<Sha256Hex>,
    findings: Vec<PrivacyFindingV1>,
    assessment: DocumentAssessmentV1,
    residual_scan: IndependentResidualScanReportV1,
    visual_risk_resolutions: Vec<VisualRiskResolutionV1>,
    rejected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewSessionV1 {
    pub schema_version: String,
    pub redaction_id: String,
    pub case_id: CaseId,
    pub material_id: MaterialId,
    pub document_version: u64,
    pub detector_run_completed: bool,
    pub revision: u64,
    pub redacted_content_sha256: Sha256Hex,
    pub dictionary_revision_hash: Option<Sha256Hex>,
    pub findings: Vec<PrivacyFindingV1>,
    pub assessment: DocumentAssessmentV1,
    pub residual_scan: IndependentResidualScanReportV1,
    pub visual_risk_resolutions: Vec<VisualRiskResolutionV1>,
    pub risk_policy: RiskPolicyV1,
    pub qualification: QualificationSnapshotV1,
    pub document_risk: DocumentRiskV1,
    pub hard_gate_evaluation: HardGateEvaluationV1,
    pub rejected: bool,
    pub last_action_code: String,
    pub last_reason_codes: Vec<String>,
    undo_stack: Vec<ReviewCheckpointV1>,
    redo_stack: Vec<ReviewCheckpointV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PrivacyFindingViewV1 {
    pub finding_id: String,
    pub page_index: u32,
    pub block_id: String,
    pub start_offset: u32,
    pub end_offset: u32,
    pub entity_type: EntityType,
    pub detector_sources: Vec<String>,
    pub detector_versions: BTreeMap<String, String>,
    pub model_versions: BTreeMap<String, String>,
    pub calibrated_confidence_ppm: Option<ConfidencePpm>,
    pub ocr_confidence_ppm: Option<ConfidencePpm>,
    pub layout_confidence_ppm: Option<ConfidencePpm>,
    pub case_dictionary_match: bool,
    pub cluster_id: Option<String>,
    pub cluster_occurrence_count: u32,
    pub detector_agreement: bool,
    pub severity: FindingSeverity,
    pub review_priority: u32,
    pub reason_codes: Vec<String>,
    pub proposed_replacement: String,
    pub resolution_state: ReviewResolution,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HardGateViewV1 {
    pub gate_id: String,
    pub passed: bool,
    pub blocking: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResidualSummaryViewV1 {
    pub passed: bool,
    pub evidence_hash: String,
    pub blocking_hit_count: u32,
    pub review_hit_count: u32,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReviewStateViewV1 {
    pub schema_version: String,
    pub redaction_id: String,
    pub case_id: String,
    pub material_id: String,
    pub document_version: u64,
    pub detector_run_completed: bool,
    pub revision: u64,
    pub document_risk: DocumentRiskV1,
    pub hard_gates: Vec<HardGateViewV1>,
    pub findings: Vec<PrivacyFindingViewV1>,
    pub residual_scan: ResidualSummaryViewV1,
    pub visual_risk_resolutions: Vec<VisualRiskResolutionV1>,
    pub can_undo: bool,
    pub can_redo: bool,
    pub rejected: bool,
}

impl ReviewSessionV1 {
    pub fn new(input: ReviewSessionInputV1) -> Result<Self, ReviewSessionError> {
        if !safe_code(&input.redaction_id, 128)
            || input.created_at_unix == 0
            || input.document_version == 0
        {
            return Err(ReviewSessionError::InvalidInput);
        }
        validate_residual(&input.residual_scan, input.assessment.pages.len())?;
        let initial = evaluate_document(
            &input.risk_policy,
            &input.qualification,
            &input.assessment,
            input.created_at_unix,
        )?;
        let mut session = Self {
            schema_version: REVIEW_SESSION_SCHEMA_VERSION.to_owned(),
            redaction_id: input.redaction_id,
            case_id: input.case_id,
            material_id: input.material_id,
            document_version: input.document_version,
            detector_run_completed: input.detector_run_completed,
            revision: 1,
            redacted_content_sha256: input.redacted_content_sha256,
            dictionary_revision_hash: input.dictionary_revision_hash,
            findings: input.findings,
            assessment: input.assessment,
            residual_scan: input.residual_scan,
            visual_risk_resolutions: Vec::new(),
            risk_policy: input.risk_policy,
            qualification: input.qualification,
            document_risk: initial.0,
            hard_gate_evaluation: initial.1,
            rejected: false,
            last_action_code: "review_initialized".to_owned(),
            last_reason_codes: Vec::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
        };
        session.refresh_risk(input.created_at_unix)?;
        Ok(session)
    }

    /// Recomputes all derived risk and gate state and rejects a tampered persisted session.
    pub fn validate(&self) -> Result<(), ReviewSessionError> {
        if self.schema_version != REVIEW_SESSION_SCHEMA_VERSION
            || !safe_code(&self.redaction_id, 128)
            || self.revision == 0
            || self.document_version == 0
            || self.undo_stack.len() > MAX_REVIEW_HISTORY
            || self.redo_stack.len() > MAX_REVIEW_HISTORY
            || !safe_code(&self.last_action_code, 128)
            || self.last_reason_codes.len() > MAX_REASON_CODES
        {
            return Err(ReviewSessionError::InvalidInput);
        }
        validate_residual(&self.residual_scan, self.assessment.pages.len())?;
        validate_visual_resolutions(self)?;
        let mut recomputed = self.clone();
        recomputed.refresh_risk(self.hard_gate_evaluation.evaluated_at_unix)?;
        if recomputed.assessment != self.assessment
            || recomputed.document_risk != self.document_risk
            || recomputed.hard_gate_evaluation != self.hard_gate_evaluation
        {
            return Err(ReviewSessionError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn from_state_bytes(bytes: &[u8]) -> Result<Self, ReviewSessionError> {
        let session = strict_json_v1_from_slice::<Self>(bytes)
            .map_err(|_| ReviewSessionError::InvalidEvidence)?;
        session.validate()?;
        Ok(session)
    }
    pub fn state_bytes(&self) -> Result<Vec<u8>, ReviewSessionError> {
        self.validate()?;
        canonical_json_v1(self).map_err(|_| ReviewSessionError::InvalidEvidence)
    }

    pub fn risk_sha256(&self) -> Result<String, ReviewSessionError> {
        canonical_json_v1(&self.document_risk)
            .map(|value| sha256_hex(&value))
            .map_err(|_| ReviewSessionError::InvalidEvidence)
    }

    pub fn hard_gate_sha256(&self) -> Result<String, ReviewSessionError> {
        canonical_json_v1(&self.hard_gate_evaluation)
            .map(|value| sha256_hex(&value))
            .map_err(|_| ReviewSessionError::InvalidEvidence)
    }

    pub fn view(&self) -> Result<ReviewStateViewV1, ReviewSessionError> {
        self.validate()?;
        let mut cluster_counts = BTreeMap::<String, u32>::new();
        for finding in &self.findings {
            if let Some(cluster) = &finding.cluster_id {
                let count = cluster_counts
                    .entry(cluster.as_str().to_owned())
                    .or_default();
                *count = count.saturating_add(1);
            }
        }
        let findings = self
            .findings
            .iter()
            .map(|finding| PrivacyFindingViewV1 {
                finding_id: finding.finding_id.as_str().to_owned(),
                page_index: finding.page_index,
                block_id: finding.block_id.clone(),
                start_offset: finding.start_offset,
                end_offset: finding.end_offset,
                entity_type: finding.entity_type,
                detector_sources: finding.detector_sources.clone(),
                detector_versions: finding.detector_versions.clone(),
                model_versions: finding.model_versions.clone(),
                calibrated_confidence_ppm: finding.calibrated_confidence_ppm,
                ocr_confidence_ppm: finding.ocr_confidence_ppm,
                layout_confidence_ppm: finding.layout_confidence_ppm,
                case_dictionary_match: finding.case_dictionary_match,
                cluster_id: finding
                    .cluster_id
                    .as_ref()
                    .map(|value| value.as_str().to_owned()),
                cluster_occurrence_count: finding
                    .cluster_id
                    .as_ref()
                    .and_then(|value| cluster_counts.get(value.as_str()))
                    .copied()
                    .unwrap_or(0),
                detector_agreement: finding.detector_agreement,
                severity: finding.severity,
                review_priority: finding.review_priority,
                reason_codes: finding.reason_codes.clone(),
                proposed_replacement: finding.proposed_replacement.clone(),
                resolution_state: finding.resolution_state,
            })
            .collect();
        let hard_gates = self
            .hard_gate_evaluation
            .gates
            .iter()
            .map(|gate| HardGateViewV1 {
                gate_id: gate.gate_id.clone(),
                passed: gate.passed,
                blocking: gate.blocking,
                reason_codes: gate.reason_codes.clone(),
            })
            .collect();
        let blocking_hit_count = u32::try_from(
            self.residual_scan
                .hits
                .iter()
                .filter(|hit| hit.blocking)
                .count(),
        )
        .map_err(|_| ReviewSessionError::InvalidEvidence)?;
        let review_hit_count = u32::try_from(self.residual_scan.hits.len())
            .map_err(|_| ReviewSessionError::InvalidEvidence)?
            .saturating_sub(blocking_hit_count);
        let reason_codes = self
            .residual_scan
            .hits
            .iter()
            .map(|hit| hit.reason_code.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(ReviewStateViewV1 {
            schema_version: REVIEW_STATE_VIEW_SCHEMA_VERSION.to_owned(),
            redaction_id: self.redaction_id.clone(),
            case_id: self.case_id.as_str().to_owned(),
            material_id: self.material_id.as_str().to_owned(),
            document_version: self.document_version,
            detector_run_completed: self.detector_run_completed,
            revision: self.revision,
            document_risk: self.document_risk.clone(),
            hard_gates,
            findings,
            residual_scan: ResidualSummaryViewV1 {
                passed: self.residual_scan.passed,
                evidence_hash: self.residual_scan.evidence_hash.as_str().to_owned(),
                blocking_hit_count,
                review_hit_count,
                reason_codes,
            },
            visual_risk_resolutions: self.visual_risk_resolutions.clone(),
            can_undo: !self.undo_stack.is_empty(),
            can_redo: !self.redo_stack.is_empty(),
            rejected: self.rejected,
        })
    }

    pub fn apply_action(
        &mut self,
        expected_revision: u64,
        action: &ReviewActionV1,
        context: VerifiedReviewActionContextV1<'_>,
    ) -> Result<(), ReviewSessionError> {
        self.require_revision(expected_revision)?;
        if self.rejected && !matches!(action, ReviewActionV1::RejectPublication) {
            return Err(ReviewSessionError::Rejected);
        }
        validate_context(&context, self.assessment.pages.len())?;
        let mut next = self.clone();
        next.push_undo(self.checkpoint());
        next.redo_stack.clear();
        next.last_action_code = next.mutate(action, &context)?;
        next.last_reason_codes.clear();
        next.redacted_content_sha256 = context.verified_redacted_content_sha256.clone();
        next.residual_scan = context.residual_scan.clone();
        next.assessment.provenance_receiptable = true;
        next.assessment.provenance_hash = Some(context.provenance_hash.clone());
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(ReviewSessionError::InvalidInput)?;
        next.refresh_risk(context.occurred_at_unix)?;
        *self = next;
        Ok(())
    }

    pub fn replace_analysis(
        &mut self,
        expected_revision: u64,
        replacement: ReviewAnalysisReplacementV1,
    ) -> Result<(), ReviewSessionError> {
        self.require_revision(expected_revision)?;
        if self.rejected {
            return Err(ReviewSessionError::Rejected);
        }
        if !matches!(
            replacement.action_code.as_str(),
            "detection_rerun" | "ocr_rerun"
        ) || replacement.occurred_at_unix == 0
        {
            return Err(ReviewSessionError::InvalidInput);
        }
        validate_residual(
            &replacement.residual_scan,
            replacement.assessment.pages.len(),
        )?;
        let mut next = self.clone();
        next.push_undo(self.checkpoint());
        next.redo_stack.clear();
        next.findings = replacement.findings;
        next.assessment = replacement.assessment;
        next.assessment.provenance_receiptable = true;
        next.assessment.provenance_hash = Some(replacement.provenance_hash);
        next.residual_scan = replacement.residual_scan;
        next.visual_risk_resolutions.clear();
        next.redacted_content_sha256 = replacement.redacted_content_sha256;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(ReviewSessionError::InvalidInput)?;
        next.last_action_code = replacement.action_code;
        next.last_reason_codes.clear();
        next.refresh_risk(replacement.occurred_at_unix)?;
        *self = next;
        Ok(())
    }

    pub fn undo(
        &mut self,
        expected_revision: u64,
        occurred_at_unix: u64,
    ) -> Result<(), ReviewSessionError> {
        self.require_revision(expected_revision)?;
        if occurred_at_unix == 0 {
            return Err(ReviewSessionError::InvalidInput);
        }
        let mut next = self.clone();
        let checkpoint = next
            .undo_stack
            .pop()
            .ok_or(ReviewSessionError::HistoryUnavailable)?;
        next.push_redo(self.checkpoint());
        next.restore(checkpoint);
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(ReviewSessionError::InvalidInput)?;
        next.last_action_code = "undo".to_owned();
        next.last_reason_codes.clear();
        next.refresh_risk(occurred_at_unix)?;
        *self = next;
        Ok(())
    }

    pub fn redo(
        &mut self,
        expected_revision: u64,
        occurred_at_unix: u64,
    ) -> Result<(), ReviewSessionError> {
        self.require_revision(expected_revision)?;
        if occurred_at_unix == 0 {
            return Err(ReviewSessionError::InvalidInput);
        }
        let mut next = self.clone();
        let checkpoint = next
            .redo_stack
            .pop()
            .ok_or(ReviewSessionError::HistoryUnavailable)?;
        next.push_undo(self.checkpoint());
        next.restore(checkpoint);
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(ReviewSessionError::InvalidInput)?;
        next.last_action_code = "redo".to_owned();
        next.last_reason_codes.clear();
        next.refresh_risk(occurred_at_unix)?;
        *self = next;
        Ok(())
    }

    /// Binds the exact egress target and current trusted qualification immediately before
    /// approval. The target is part of the append-only risk revision, so an assessment computed
    /// for one destination cannot authorize another destination.
    pub fn bind_publication_context(
        &mut self,
        expected_revision: u64,
        publication_target_hash: Sha256Hex,
        requested_approval_route: RequestedApprovalRoute,
        risk_policy: RiskPolicyV1,
        qualification: QualificationSnapshotV1,
        occurred_at_unix: u64,
    ) -> Result<(), ReviewSessionError> {
        self.require_revision(expected_revision)?;
        if self.rejected || occurred_at_unix == 0 {
            return Err(if self.rejected {
                ReviewSessionError::Rejected
            } else {
                ReviewSessionError::InvalidInput
            });
        }
        let mut next = self.clone();
        next.assessment.publication_target_fixed = true;
        next.assessment.publication_target_hash = Some(publication_target_hash);
        next.assessment.requested_approval_route = requested_approval_route;
        next.risk_policy = risk_policy;
        next.qualification = qualification;
        next.revision = next
            .revision
            .checked_add(1)
            .ok_or(ReviewSessionError::InvalidInput)?;
        next.last_action_code = "bind_publication_context".to_owned();
        next.last_reason_codes.clear();
        next.refresh_risk(occurred_at_unix)?;
        *self = next;
        Ok(())
    }
    fn mutate(
        &mut self,
        action: &ReviewActionV1,
        context: &VerifiedReviewActionContextV1<'_>,
    ) -> Result<String, ReviewSessionError> {
        match action {
            ReviewActionV1::AcceptReplacement {
                finding_id,
                apply_cluster,
            } => {
                for index in self.target_indexes(finding_id, *apply_cluster)? {
                    resolve(
                        &mut self.findings[index],
                        ReviewResolution::Accepted,
                        FindingSeverity::P3Resolved,
                        "user_accepted_replacement",
                        context,
                    )?;
                }
                Ok("accept_replacement".to_owned())
            }
            ReviewActionV1::ChangeEntityType {
                finding_id,
                entity_type,
            } => {
                let index = self.finding_index(finding_id)?;
                self.findings[index].entity_type = *entity_type;
                resolve(
                    &mut self.findings[index],
                    ReviewResolution::Modified,
                    FindingSeverity::P3Resolved,
                    "user_changed_entity_type",
                    context,
                )?;
                Ok("change_entity_type".to_owned())
            }
            ReviewActionV1::ChangePlaceholder {
                finding_id,
                replacement,
                apply_cluster,
            } => {
                if !valid_replacement(replacement) {
                    return Err(ReviewSessionError::InvalidInput);
                }
                for index in self.target_indexes(finding_id, *apply_cluster)? {
                    self.findings[index].proposed_replacement = replacement.clone();
                    resolve(
                        &mut self.findings[index],
                        ReviewResolution::Modified,
                        FindingSeverity::P3Resolved,
                        "user_changed_placeholder",
                        context,
                    )?;
                }
                Ok("change_placeholder".to_owned())
            }
            ReviewActionV1::MarkNotSensitive { finding_id } => {
                let index = self.finding_index(finding_id)?;
                resolve(
                    &mut self.findings[index],
                    ReviewResolution::NotSensitive,
                    FindingSeverity::Informational,
                    "user_marked_not_sensitive",
                    context,
                )?;
                Ok("mark_not_sensitive".to_owned())
            }
            ReviewActionV1::AddToDictionary {
                finding_id,
                category,
                required,
            } => {
                let dictionary_hash = context
                    .dictionary_revision_hash
                    .ok_or(ReviewSessionError::DictionaryEvidenceRequired)?;
                let index = self.finding_index(finding_id)?;
                self.findings[index].case_dictionary_match = true;
                push_reason(
                    &mut self.findings[index],
                    if *required {
                        "user_added_required_dictionary_entry"
                    } else {
                        "user_added_dictionary_entry"
                    },
                )?;
                if self.findings[index].entity_type == EntityType::Custom {
                    self.findings[index].entity_type = category.default_entity_type();
                }
                self.dictionary_revision_hash = Some(dictionary_hash.clone());
                Ok("add_to_dictionary".to_owned())
            }
            ReviewActionV1::MergeClusters { cluster_ids } => {
                let mut clusters = cluster_ids
                    .iter()
                    .map(|value| {
                        ClusterId::parse(value.clone())
                            .map_err(|_| ReviewSessionError::ClusterInvalid)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                clusters.sort_by(|left, right| left.as_str().cmp(right.as_str()));
                clusters.dedup();
                if clusters.len() < 2 {
                    return Err(ReviewSessionError::ClusterInvalid);
                }
                let target = clusters[0].clone();
                merge_cluster(
                    &mut self.findings,
                    &clusters,
                    target,
                    context.actor_hash.clone(),
                    context.occurred_at_unix,
                )
                .map_err(|_| ReviewSessionError::ClusterInvalid)?;
                for finding in &mut self.findings {
                    if finding.resolution_state == ReviewResolution::ClusterMerged {
                        finding.severity = FindingSeverity::P3Resolved;
                    }
                }
                Ok("merge_clusters".to_owned())
            }
            ReviewActionV1::SplitCluster { finding_id } => {
                let index = self.finding_index(finding_id)?;
                split_finding_cluster(
                    &mut self.findings[index],
                    context.actor_hash.clone(),
                    context.occurred_at_unix,
                )
                .map_err(|_| ReviewSessionError::ClusterInvalid)?;
                self.findings[index].severity = FindingSeverity::P3Resolved;
                Ok("split_cluster".to_owned())
            }
            ReviewActionV1::ResolveVisualRisk {
                page_index,
                risk_code,
                decision,
                reason,
            } => {
                if !safe_code(risk_code, 128) || !safe_code(reason, 512) || reason.trim() != reason
                {
                    return Err(ReviewSessionError::InvalidInput);
                }
                let page = self
                    .assessment
                    .pages
                    .iter_mut()
                    .find(|page| page.page_index == *page_index)
                    .ok_or(ReviewSessionError::InvalidEvidence)?;
                let position = page
                    .unresolved_visual_risks
                    .iter()
                    .position(|risk| risk == risk_code)
                    .ok_or(ReviewSessionError::InvalidEvidence)?;
                page.unresolved_visual_risks.remove(position);
                let evidence_hash = visual_resolution_evidence_hash(
                    *page_index,
                    risk_code,
                    *decision,
                    reason,
                    context.actor_hash,
                    context.provenance_hash,
                    context.verified_redacted_content_sha256,
                    context.occurred_at_unix,
                )?;
                self.visual_risk_resolutions.push(VisualRiskResolutionV1 {
                    page_index: *page_index,
                    risk_code: risk_code.clone(),
                    decision: *decision,
                    reason: reason.clone(),
                    actor_hash: context.actor_hash.clone(),
                    provenance_hash: context.provenance_hash.clone(),
                    redacted_content_sha256: context.verified_redacted_content_sha256.clone(),
                    resolved_at_unix: context.occurred_at_unix,
                    evidence_hash,
                });
                self.visual_risk_resolutions.sort_by(|left, right| {
                    left.page_index
                        .cmp(&right.page_index)
                        .then_with(|| left.risk_code.cmp(&right.risk_code))
                });
                Ok("resolve_visual_risk".to_owned())
            }
            ReviewActionV1::ConfirmEditedOutput => Ok("confirm_edited_output".to_owned()),
            ReviewActionV1::BatchAcceptP3 => {
                for finding in &mut self.findings {
                    if finding.severity == FindingSeverity::P3Resolved
                        && finding.resolution_state == ReviewResolution::Unresolved
                    {
                        resolve(
                            finding,
                            ReviewResolution::Accepted,
                            FindingSeverity::P3Resolved,
                            "user_batch_accepted_p3",
                            context,
                        )?;
                    }
                }
                Ok("batch_accept_p3".to_owned())
            }
            ReviewActionV1::RejectPublication => {
                if self.rejected {
                    return Err(ReviewSessionError::Rejected);
                }
                self.rejected = true;
                Ok("reject_publication".to_owned())
            }
        }
    }

    fn refresh_risk(&mut self, now_unix: u64) -> Result<(), ReviewSessionError> {
        if now_unix == 0 {
            return Err(ReviewSessionError::InvalidInput);
        }
        validate_residual(&self.residual_scan, self.assessment.pages.len())?;
        let mut finding_ids = BTreeSet::new();
        for finding in &self.findings {
            finding
                .validate()
                .map_err(|_| ReviewSessionError::InvalidInput)?;
            if finding.case_id != self.case_id
                || finding.material_id != self.material_id
                || finding.document_version != self.document_version
                || !finding_ids.insert(finding.finding_id.as_str())
            {
                return Err(ReviewSessionError::InvalidInput);
            }
        }
        let page_ids = self
            .assessment
            .pages
            .iter()
            .map(|page| page.page_index)
            .collect::<BTreeSet<_>>();
        if page_ids.len() != self.assessment.pages.len() {
            return Err(ReviewSessionError::InvalidInput);
        }
        let mut clusters = BTreeMap::<String, BTreeSet<(EntityType, String)>>::new();
        for finding in &self.findings {
            if let Some(cluster) = &finding.cluster_id {
                clusters
                    .entry(cluster.as_str().to_owned())
                    .or_default()
                    .insert((finding.entity_type, finding.proposed_replacement.clone()));
            }
        }
        let inconsistent_clusters = clusters
            .into_iter()
            .filter_map(|(cluster, values)| (values.len() > 1).then_some(cluster))
            .collect::<BTreeSet<_>>();
        for page in &mut self.assessment.pages {
            reset_page(page);
        }
        for finding in &self.findings {
            let page = self
                .assessment
                .pages
                .iter_mut()
                .find(|page| page.page_index == finding.page_index)
                .ok_or(ReviewSessionError::InvalidInput)?;
            let unresolved = matches!(
                finding.resolution_state,
                ReviewResolution::Unresolved | ReviewResolution::Revoked
            );
            if unresolved {
                match finding.severity {
                    FindingSeverity::P0Blocking => page.p0_count = page.p0_count.saturating_add(1),
                    FindingSeverity::P1High => page.p1_count = page.p1_count.saturating_add(1),
                    FindingSeverity::P2Medium => page.p2_count = page.p2_count.saturating_add(1),
                    FindingSeverity::P3Resolved | FindingSeverity::Informational => {
                        page.p3_count = page.p3_count.saturating_add(1)
                    }
                }
                if matches!(
                    finding.severity,
                    FindingSeverity::P0Blocking
                        | FindingSeverity::P1High
                        | FindingSeverity::P2Medium
                ) {
                    let count = page
                        .unresolved_entity_counts
                        .entry(finding.entity_type)
                        .or_default();
                    *count = count.saturating_add(1);
                }
                if !finding.detector_agreement
                    || finding
                        .reason_codes
                        .iter()
                        .any(|reason| reason.contains("conflict"))
                {
                    page.detector_conflict_count = page.detector_conflict_count.saturating_add(1);
                }
            } else {
                page.p3_count = page.p3_count.saturating_add(1);
            }
            if finding
                .cluster_id
                .as_ref()
                .is_some_and(|cluster| inconsistent_clusters.contains(cluster.as_str()))
            {
                page.cluster_inconsistency_count =
                    page.cluster_inconsistency_count.saturating_add(1);
            }
        }
        for hit in &self.residual_scan.hits {
            let page = self
                .assessment
                .pages
                .iter_mut()
                .find(|page| page.page_index == hit.page_index)
                .ok_or(ReviewSessionError::InvalidEvidence)?;
            if hit.risk_class == ResidualRiskClassV1::LongDigitSequence {
                page.unknown_long_number_count = page.unknown_long_number_count.saturating_add(1);
            }
            if !page.reason_codes.contains(&hit.reason_code) {
                page.reason_codes.push(hit.reason_code.clone());
            }
        }
        if self
            .assessment
            .pages
            .iter()
            .any(|page| page.reason_codes.len() > MAX_REASON_CODES)
        {
            return Err(ReviewSessionError::InvalidInput);
        }
        self.assessment.finding_summary_hash =
            Sha256Hex::parse(sha256_hex(&canonical_json_v1(&self.findings)?))?;
        self.assessment.deterministic_high_risk_fields_resolved = self.detector_run_completed
            && self.findings.iter().all(|finding| {
                !matches!(
                    finding.resolution_state,
                    ReviewResolution::Unresolved | ReviewResolution::Revoked
                ) || !deterministic_high_risk(finding.entity_type)
            });
        self.assessment.independent_residual_scan_passed = self.residual_scan.passed;
        self.assessment.independent_residual_scan_hash =
            Some(self.residual_scan.evidence_hash.clone());
        let (risk, gates) = evaluate_document(
            &self.risk_policy,
            &self.qualification,
            &self.assessment,
            now_unix,
        )?;
        self.document_risk = risk;
        self.hard_gate_evaluation = gates;
        Ok(())
    }

    fn checkpoint(&self) -> ReviewCheckpointV1 {
        ReviewCheckpointV1 {
            redacted_content_sha256: self.redacted_content_sha256.clone(),
            dictionary_revision_hash: self.dictionary_revision_hash.clone(),
            findings: self.findings.clone(),
            assessment: self.assessment.clone(),
            residual_scan: self.residual_scan.clone(),
            visual_risk_resolutions: self.visual_risk_resolutions.clone(),
            rejected: self.rejected,
        }
    }

    fn restore(&mut self, checkpoint: ReviewCheckpointV1) {
        self.redacted_content_sha256 = checkpoint.redacted_content_sha256;
        self.dictionary_revision_hash = checkpoint.dictionary_revision_hash;
        self.findings = checkpoint.findings;
        self.assessment = checkpoint.assessment;
        self.residual_scan = checkpoint.residual_scan;
        self.visual_risk_resolutions = checkpoint.visual_risk_resolutions;
        self.rejected = checkpoint.rejected;
    }

    fn push_undo(&mut self, checkpoint: ReviewCheckpointV1) {
        bounded_push(&mut self.undo_stack, checkpoint);
    }

    fn push_redo(&mut self, checkpoint: ReviewCheckpointV1) {
        bounded_push(&mut self.redo_stack, checkpoint);
    }

    fn require_revision(&self, expected: u64) -> Result<(), ReviewSessionError> {
        if expected == self.revision {
            Ok(())
        } else {
            Err(ReviewSessionError::RevisionConflict)
        }
    }

    fn finding_index(&self, finding_id: &str) -> Result<usize, ReviewSessionError> {
        self.findings
            .iter()
            .position(|finding| finding.finding_id.as_str() == finding_id)
            .ok_or(ReviewSessionError::FindingNotFound)
    }

    fn target_indexes(
        &self,
        finding_id: &str,
        apply_cluster: bool,
    ) -> Result<Vec<usize>, ReviewSessionError> {
        let index = self.finding_index(finding_id)?;
        if !apply_cluster {
            return Ok(vec![index]);
        }
        let cluster = self.findings[index]
            .cluster_id
            .as_ref()
            .ok_or(ReviewSessionError::ClusterInvalid)?;
        Ok(self
            .findings
            .iter()
            .enumerate()
            .filter_map(|(index, finding)| {
                (finding.cluster_id.as_ref() == Some(cluster)).then_some(index)
            })
            .collect())
    }
}

fn validate_context(
    context: &VerifiedReviewActionContextV1<'_>,
    page_count: usize,
) -> Result<(), ReviewSessionError> {
    if context.occurred_at_unix == 0 {
        return Err(ReviewSessionError::InvalidInput);
    }
    validate_residual(context.residual_scan, page_count)
}

fn validate_residual(
    report: &IndependentResidualScanReportV1,
    page_count: usize,
) -> Result<(), ReviewSessionError> {
    report
        .validate()
        .map_err(|_| ReviewSessionError::InvalidEvidence)?;
    if usize::try_from(report.scanned_page_count).ok() != Some(page_count) {
        return Err(ReviewSessionError::InvalidEvidence);
    }
    Ok(())
}

fn validate_visual_resolutions(session: &ReviewSessionV1) -> Result<(), ReviewSessionError> {
    let mut resolved = BTreeSet::new();
    for resolution in &session.visual_risk_resolutions {
        if !safe_code(&resolution.risk_code, 128)
            || !safe_code(&resolution.reason, 512)
            || resolution.reason.trim() != resolution.reason
            || resolution.resolved_at_unix == 0
            || !resolved.insert((resolution.page_index, resolution.risk_code.as_str()))
        {
            return Err(ReviewSessionError::InvalidEvidence);
        }
        let page = session
            .assessment
            .pages
            .iter()
            .find(|page| page.page_index == resolution.page_index)
            .ok_or(ReviewSessionError::InvalidEvidence)?;
        if page
            .unresolved_visual_risks
            .iter()
            .any(|risk| risk == &resolution.risk_code)
            || resolution.evidence_hash
                != visual_resolution_evidence_hash(
                    resolution.page_index,
                    &resolution.risk_code,
                    resolution.decision,
                    &resolution.reason,
                    &resolution.actor_hash,
                    &resolution.provenance_hash,
                    &resolution.redacted_content_sha256,
                    resolution.resolved_at_unix,
                )?
        {
            return Err(ReviewSessionError::InvalidEvidence);
        }
    }
    for page in &session.assessment.pages {
        let mut risks = BTreeSet::new();
        if page
            .unresolved_visual_risks
            .iter()
            .any(|risk| !safe_code(risk, 128) || !risks.insert(risk.as_str()))
        {
            return Err(ReviewSessionError::InvalidEvidence);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn visual_resolution_evidence_hash(
    page_index: u32,
    risk_code: &str,
    decision: VisualRiskDecisionV1,
    reason: &str,
    actor_hash: &Sha256Hex,
    provenance_hash: &Sha256Hex,
    redacted_content_sha256: &Sha256Hex,
    resolved_at_unix: u64,
) -> Result<Sha256Hex, ReviewSessionError> {
    let decision = match decision {
        VisualRiskDecisionV1::ConfirmedRedacted => "confirmed_redacted",
        VisualRiskDecisionV1::ConfirmedReviewedNonSensitive => "confirmed_reviewed_non_sensitive",
    };
    let claims = format!(
        "LawyerAssistance/visual-risk-resolution/v1\0{page_index}\0{risk_code}\0{decision}\0{reason}\0{}\0{}\0{}\0{resolved_at_unix}",
        actor_hash.as_str(),
        provenance_hash.as_str(),
        redacted_content_sha256.as_str(),
    );
    Sha256Hex::parse(sha256_hex(claims.as_bytes())).map_err(|_| ReviewSessionError::InvalidEvidence)
}
fn resolve(
    finding: &mut PrivacyFindingV1,
    resolution: ReviewResolution,
    severity: FindingSeverity,
    reason: &str,
    context: &VerifiedReviewActionContextV1<'_>,
) -> Result<(), ReviewSessionError> {
    finding.resolution_state = resolution;
    finding.severity = severity;
    finding.human_override = Some(HumanOverrideV1 {
        resolution,
        reason_code: reason.to_owned(),
        actor_hash: context.actor_hash.clone(),
        resolved_at_unix: context.occurred_at_unix,
    });
    push_reason(finding, reason)
}

fn push_reason(finding: &mut PrivacyFindingV1, reason: &str) -> Result<(), ReviewSessionError> {
    if !finding.reason_codes.iter().any(|value| value == reason) {
        finding.reason_codes.push(reason.to_owned());
    }
    if finding.reason_codes.len() > MAX_REASON_CODES {
        return Err(ReviewSessionError::InvalidInput);
    }
    Ok(())
}

fn reset_page(page: &mut PageAssessmentV1) {
    page.p0_count = 0;
    page.p1_count = 0;
    page.p2_count = 0;
    page.p3_count = 0;
    page.unknown_long_number_count = 0;
    page.unresolved_entity_counts.clear();
    page.detector_conflict_count = 0;
    page.cluster_inconsistency_count = 0;
    page.reason_codes
        .retain(|reason| !reason.starts_with("residual_"));
}

fn bounded_push(stack: &mut Vec<ReviewCheckpointV1>, checkpoint: ReviewCheckpointV1) {
    if stack.len() == MAX_REVIEW_HISTORY {
        stack.remove(0);
    }
    stack.push(checkpoint);
}

fn deterministic_high_risk(entity: EntityType) -> bool {
    matches!(
        entity,
        EntityType::IdentityNumber
            | EntityType::PassportNumber
            | EntityType::PhoneNumber
            | EntityType::LandlineNumber
            | EntityType::BankAccount
            | EntityType::EmailAddress
            | EntityType::OrganizationCode
            | EntityType::BusinessLicenseNumber
            | EntityType::VehiclePlate
            | EntityType::IpAddress
            | EntityType::PaymentAccount
    )
}

fn safe_code(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_replacement(value: &str) -> bool {
    let value = value.trim();
    safe_code(value, 128)
        && ((value.starts_with('\u{3010}') && value.ends_with('\u{3011}'))
            || (value.starts_with('[') && value.ends_with(']')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        residual_scan::{scan_independent_residuals, IndependentResidualScanInputV1},
        risk_engine::RequestedApprovalRoute,
        vnext::{
            AutoApprovalPolicyMode, CaseId, ClusterId, FindingId, MaterialId, ObjectId,
            PrivateValueRefV1,
        },
    };

    fn hash(value: &[u8]) -> Sha256Hex {
        Sha256Hex::parse(sha256_hex(value)).expect("hash")
    }

    fn finding() -> PrivacyFindingV1 {
        PrivacyFindingV1 {
            finding_id: FindingId::parse("fnd_11111111111111111111111111111111").expect("finding"),
            case_id: CaseId::parse("case_22222222222222222222222222222222").expect("case"),
            material_id: MaterialId::parse("mat_33333333333333333333333333333333")
                .expect("material"),
            document_version: 1,
            page_index: 0,
            block_id: "block-1".to_owned(),
            start_offset: 0,
            end_offset: 18,
            geometry: None,
            entity_type: EntityType::IdentityNumber,
            detector_sources: vec!["deterministic".to_owned()],
            detector_versions: BTreeMap::from([(
                "deterministic".to_owned(),
                "deterministic-v1".to_owned(),
            )]),
            model_versions: BTreeMap::new(),
            raw_score_ppm: Some(ConfidencePpm::new(990_000).expect("score")),
            calibrated_confidence_ppm: Some(ConfidencePpm::new(990_000).expect("score")),
            ocr_confidence_ppm: None,
            layout_confidence_ppm: None,
            normalization_evidence_hash: Some(hash(b"normalization")),
            confusable_evidence_hash: None,
            case_dictionary_match: false,
            cluster_id: Some(
                ClusterId::parse("clu_44444444444444444444444444444444").expect("cluster"),
            ),
            detector_agreement: true,
            severity: FindingSeverity::P1High,
            review_priority: 900,
            reason_codes: vec!["high_risk_unresolved".to_owned()],
            proposed_replacement: "[IDENTITY_A]".to_owned(),
            resolution_state: ReviewResolution::Unresolved,
            human_override: None,
            provenance_hash: hash(b"finding-provenance"),
            private_value_ref: PrivateValueRefV1 {
                object_id: ObjectId::parse("obj_55555555555555555555555555555555").expect("object"),
                object_version: 1,
                value_locator_hash: hash(b"value-locator"),
            },
        }
    }

    fn residual() -> IndependentResidualScanReportV1 {
        let pages = vec!["[IDENTITY_A]".to_owned()];
        scan_independent_residuals(IndependentResidualScanInputV1 {
            pages: &pages,
            dictionary_terms: &[],
            source_names: &[],
        })
        .expect("residual scan")
    }

    fn assessment() -> DocumentAssessmentV1 {
        DocumentAssessmentV1 {
            pages: vec![PageAssessmentV1 {
                page_index: 0,
                p0_count: 0,
                p1_count: 1,
                p2_count: 0,
                p3_count: 0,
                ocr_used: false,
                ocr_min_ppm: None,
                ocr_mean_ppm: None,
                ocr_p10_ppm: None,
                coverage_ppm: ConfidencePpm::new(1_000_000).expect("coverage"),
                unknown_long_number_count: 0,
                unresolved_entity_counts: BTreeMap::new(),
                unresolved_visual_risks: Vec::new(),
                completeness_passed: true,
                detector_conflict_count: 0,
                cluster_inconsistency_count: 0,
                reason_codes: Vec::new(),
            }],
            finding_summary_hash: hash(b"initial-findings"),
            dictionary_entities_stable: true,
            deterministic_high_risk_fields_resolved: false,
            independent_residual_scan_passed: true,
            independent_residual_scan_hash: Some(residual().evidence_hash),
            provenance_receiptable: true,
            provenance_hash: Some(hash(b"provenance")),
            publication_target_fixed: true,
            publication_target_hash: Some(hash(b"target")),
            requested_approval_route: RequestedApprovalRoute::ShadowHuman,
            calibration_evidence_version: Some("calibration-v1".to_owned()),
        }
    }

    fn policy() -> RiskPolicyV1 {
        RiskPolicyV1 {
            policy_id: "shadow-review".to_owned(),
            policy_version: 1,
            policy_sha256: hash(b"policy"),
            minimum_ocr_confidence_ppm: ConfidencePpm::new(900_000).expect("confidence"),
            minimum_ocr_coverage_ppm: ConfidencePpm::new(950_000).expect("coverage"),
            maximum_quick_review_p2: 2,
            auto_approval_mode: AutoApprovalPolicyMode::Shadow,
            production_automatic_enabled: false,
            calibrated_for_automatic: true,
            calibration_evidence_sha256: Some(hash(b"calibration")),
            organization_allows_automatic: true,
        }
    }

    fn qualification() -> QualificationSnapshotV1 {
        QualificationSnapshotV1 {
            qualification_report_id: Some("qualified-synthetic-v1".to_owned()),
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

    fn session() -> ReviewSessionV1 {
        ReviewSessionV1::new(ReviewSessionInputV1 {
            redaction_id: "redaction-review-1".to_owned(),
            case_id: CaseId::parse("case_22222222222222222222222222222222").expect("case"),
            material_id: MaterialId::parse("mat_33333333333333333333333333333333")
                .expect("material"),
            document_version: 1,
            detector_run_completed: true,
            redacted_content_sha256: hash(b"redacted-v1"),
            dictionary_revision_hash: None,
            findings: vec![finding()],
            assessment: assessment(),
            residual_scan: residual(),
            risk_policy: policy(),
            qualification: qualification(),
            created_at_unix: 100,
        })
        .expect("session")
    }

    fn visual_session() -> ReviewSessionV1 {
        let mut assessment = assessment();
        assessment.pages[0].unresolved_visual_risks = vec!["signature_present".to_owned()];
        ReviewSessionV1::new(ReviewSessionInputV1 {
            redaction_id: "redaction-visual-1".to_owned(),
            case_id: CaseId::parse("case_22222222222222222222222222222222").expect("case"),
            material_id: MaterialId::parse("mat_33333333333333333333333333333333")
                .expect("material"),
            document_version: 1,
            detector_run_completed: true,
            redacted_content_sha256: hash(b"visual-redacted-v1"),
            dictionary_revision_hash: None,
            findings: vec![finding()],
            assessment,
            residual_scan: residual(),
            risk_policy: policy(),
            qualification: qualification(),
            created_at_unix: 100,
        })
        .expect("visual session")
    }

    #[test]
    fn edited_output_confirmation_updates_verified_hash_and_is_revision_bound() {
        let mut session = session();
        let original_hash = session.redacted_content_sha256.clone();
        let actor = hash(b"edited-output-reviewer");
        let output = hash(b"edited-redacted-v2");
        let provenance = hash(b"edited-output-provenance-v2");
        let scan = residual();

        session
            .apply_action(
                1,
                &ReviewActionV1::ConfirmEditedOutput,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor,
                    occurred_at_unix: 200,
                    verified_redacted_content_sha256: &output,
                    provenance_hash: &provenance,
                    residual_scan: &scan,
                    dictionary_revision_hash: None,
                },
            )
            .expect("confirm edited output");

        assert_eq!(session.revision, 2);
        assert_eq!(session.last_action_code, "confirm_edited_output");
        assert_eq!(session.redacted_content_sha256, output);
        assert_eq!(session.assessment.provenance_hash, Some(provenance.clone()));
        assert_eq!(session.residual_scan, scan);
        assert_eq!(
            session.apply_action(
                1,
                &ReviewActionV1::ConfirmEditedOutput,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor,
                    occurred_at_unix: 201,
                    verified_redacted_content_sha256: &output,
                    provenance_hash: &provenance,
                    residual_scan: &session.residual_scan.clone(),
                    dictionary_revision_hash: None,
                },
            ),
            Err(ReviewSessionError::RevisionConflict)
        );
        session
            .undo(2, 202)
            .expect("undo edited output confirmation");
        assert_eq!(session.redacted_content_sha256, original_hash);
    }

    #[test]
    fn visual_resolution_is_revision_bound_audited_and_ocr_rerun_invalidates_it() {
        let mut session = visual_session();
        let visual_gate = |session: &ReviewSessionV1| {
            session
                .hard_gate_evaluation
                .gates
                .iter()
                .find(|gate| gate.gate_id == "visual_risks_resolved")
                .expect("visual gate")
                .passed
        };
        assert!(!visual_gate(&session));
        let actor = hash(b"visual-reviewer");
        let output = hash(b"visual-redacted-v2");
        let provenance = hash(b"visual-provenance-v2");
        let scan = residual();
        let action = ReviewActionV1::ResolveVisualRisk {
            page_index: 0,
            risk_code: "signature_present".to_owned(),
            decision: VisualRiskDecisionV1::ConfirmedRedacted,
            reason: "reviewer_verified_signature_region_is_redacted".to_owned(),
        };
        session
            .apply_action(
                1,
                &action,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor,
                    occurred_at_unix: 200,
                    verified_redacted_content_sha256: &output,
                    provenance_hash: &provenance,
                    residual_scan: &scan,
                    dictionary_revision_hash: None,
                },
            )
            .expect("resolve visual risk");
        assert!(visual_gate(&session));
        assert!(session.assessment.pages[0]
            .unresolved_visual_risks
            .is_empty());
        assert_eq!(session.visual_risk_resolutions.len(), 1);
        assert_eq!(
            session.apply_action(
                1,
                &action,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor,
                    occurred_at_unix: 201,
                    verified_redacted_content_sha256: &output,
                    provenance_hash: &provenance,
                    residual_scan: &scan,
                    dictionary_revision_hash: None,
                },
            ),
            Err(ReviewSessionError::RevisionConflict)
        );

        let mut rerun_assessment = assessment();
        rerun_assessment.pages[0].unresolved_visual_risks = vec!["signature_present".to_owned()];
        session
            .replace_analysis(
                2,
                ReviewAnalysisReplacementV1 {
                    findings: session.findings.clone(),
                    assessment: rerun_assessment,
                    residual_scan: residual(),
                    redacted_content_sha256: hash(b"visual-redacted-v3"),
                    provenance_hash: hash(b"ocr-rerun-provenance"),
                    action_code: "ocr_rerun".to_owned(),
                    occurred_at_unix: 300,
                },
            )
            .expect("ocr rerun");
        assert!(session.visual_risk_resolutions.is_empty());
        assert!(!visual_gate(&session));

        session
            .visual_risk_resolutions
            .push(VisualRiskResolutionV1 {
                page_index: 0,
                risk_code: "fabricated_visual_risk".to_owned(),
                decision: VisualRiskDecisionV1::ConfirmedReviewedNonSensitive,
                reason: "fabricated".to_owned(),
                actor_hash: actor,
                provenance_hash: provenance,
                redacted_content_sha256: output,
                resolved_at_unix: 301,
                evidence_hash: hash(b"fabricated-evidence"),
            });
        assert_eq!(
            session.state_bytes(),
            Err(ReviewSessionError::InvalidEvidence)
        );
    }
    #[test]
    fn actions_recompute_risk_are_revision_bound_and_round_trip_strictly() {
        let mut session = session();
        assert_eq!(session.document_risk.total_p1, 1);
        let actor = hash(b"reviewer");
        let output = hash(b"redacted-v2");
        let provenance = hash(b"provenance-v2");
        let residual = residual();
        let action = ReviewActionV1::AcceptReplacement {
            finding_id: "fnd_11111111111111111111111111111111".to_owned(),
            apply_cluster: false,
        };
        session
            .apply_action(
                1,
                &action,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor,
                    occurred_at_unix: 101,
                    verified_redacted_content_sha256: &output,
                    provenance_hash: &provenance,
                    residual_scan: &residual,
                    dictionary_revision_hash: None,
                },
            )
            .expect("accept");
        assert_eq!(session.revision, 2);
        assert_eq!(session.document_risk.total_p1, 0);
        assert!(session.document_risk.shadow_would_auto_approve);
        assert!(!session.document_risk.automatic_publish_allowed);
        assert_eq!(
            session.apply_action(
                1,
                &action,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor,
                    occurred_at_unix: 102,
                    verified_redacted_content_sha256: &output,
                    provenance_hash: &provenance,
                    residual_scan: &residual,
                    dictionary_revision_hash: None,
                },
            ),
            Err(ReviewSessionError::RevisionConflict)
        );

        let view_json = serde_json::to_string(&session.view().expect("view")).expect("json");
        assert!(!view_json.contains("privateValueRef"));
        assert!(!view_json.contains("obj_55555555555555555555555555555555"));
        let bytes = session.state_bytes().expect("state bytes");
        let restored = ReviewSessionV1::from_state_bytes(&bytes).expect("strict restore");
        assert_eq!(restored, session);

        session.undo(2, 103).expect("undo");
        assert_eq!(session.revision, 3);
        assert_eq!(session.document_risk.total_p1, 1);
        session.redo(3, 104).expect("redo");
        assert_eq!(session.revision, 4);
        assert_eq!(session.document_risk.total_p1, 0);
    }

    #[test]
    fn dictionary_action_requires_persisted_revision_evidence_and_tamper_is_rejected() {
        let mut session = session();
        let actor = hash(b"reviewer");
        let output = hash(b"redacted-v1");
        let provenance = hash(b"provenance-v2");
        let residual = residual();
        let action = ReviewActionV1::AddToDictionary {
            finding_id: "fnd_11111111111111111111111111111111".to_owned(),
            category: DictionaryCategoryV1::Account,
            required: true,
        };
        assert_eq!(
            session.apply_action(
                1,
                &action,
                VerifiedReviewActionContextV1 {
                    actor_hash: &actor,
                    occurred_at_unix: 101,
                    verified_redacted_content_sha256: &output,
                    provenance_hash: &provenance,
                    residual_scan: &residual,
                    dictionary_revision_hash: None,
                },
            ),
            Err(ReviewSessionError::DictionaryEvidenceRequired)
        );
        assert_eq!(session.revision, 1);

        let bytes = session.state_bytes().expect("state");
        let mut json: serde_json::Value = serde_json::from_slice(&bytes).expect("value");
        json["documentRisk"]["totalP1"] = serde_json::json!(0);
        let tampered = serde_json::to_vec(&json).expect("tampered");
        assert_eq!(
            ReviewSessionV1::from_state_bytes(&tampered),
            Err(ReviewSessionError::InvalidEvidence)
        );
    }
}
