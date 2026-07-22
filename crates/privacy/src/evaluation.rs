//! Offline-only detector and auto-routing evaluation.
//!
//! Reports use integer parts-per-million metrics and are explicitly prohibited from qualifying the
//! running App. Production qualification requires separately signed evidence and policy review.

use crate::sha256_hex;
use crate::vnext::{canonical_json_v1, ConfidencePpm, EntityType, FindingSeverity, Sha256Hex};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

pub const OFFLINE_EVALUATION_CORPUS_VERSION: &str = "privacy-evaluation-corpus-v1";
pub const OFFLINE_EVALUATION_REPORT_VERSION: &str = "privacy-evaluation-report-v1";
pub const RELIABILITY_BIN_COUNT: u32 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineEvaluationError {
    InvalidCorpus,
    EvidenceFailed,
}
impl fmt::Display for OfflineEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCorpus => "offline_evaluation_invalid_corpus",
            Self::EvidenceFailed => "offline_evaluation_evidence_failed",
        })
    }
}
impl Error for OfflineEvaluationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvaluationItemV1 {
    pub item_id: String,
    pub document_id: String,
    pub entity_type: EntityType,
    pub expected_sensitive: bool,
    pub predicted_sensitive: bool,
    pub matched_ground_truth: bool,
    pub confidence_ppm: ConfidencePpm,
    pub auto_approval_candidate: bool,
    pub human_modified: bool,
    pub expected_severity: FindingSeverity,
    pub ocr_stratum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvaluationCorpusV1 {
    pub schema_version: String,
    pub corpus_id: String,
    pub detector_version: String,
    pub policy_version: String,
    pub synthetic_only: bool,
    pub items: Vec<EvaluationItemV1>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ConfusionMetricsV1 {
    pub true_positive: u64,
    pub false_positive: u64,
    pub false_negative: u64,
    pub true_negative: u64,
    pub precision_ppm: u32,
    pub recall_ppm: u32,
    pub false_negative_rate_ppm: u32,
    pub false_positive_rate_ppm: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReliabilityBinV1 {
    pub lower_bound_ppm: u32,
    pub upper_bound_ppm: u32,
    pub sample_count: u64,
    pub mean_confidence_ppm: u32,
    pub empirical_accuracy_ppm: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OfflineEvaluationReportV1 {
    pub schema_version: String,
    pub corpus_id: String,
    pub detector_version: String,
    pub policy_version: String,
    pub synthetic_only: bool,
    pub overall: ConfusionMetricsV1,
    pub by_entity: BTreeMap<EntityType, ConfusionMetricsV1>,
    pub by_ocr_stratum: BTreeMap<String, ConfusionMetricsV1>,
    pub document_count: u64,
    pub document_escape_count: u64,
    pub document_escape_rate_ppm: u32,
    pub expected_calibration_error_ppm: u32,
    pub reliability_bins: Vec<ReliabilityBinV1>,
    pub auto_approval_candidate_count: u64,
    pub auto_candidate_human_modified_count: u64,
    pub auto_candidate_human_modified_rate_ppm: u32,
    pub missed_p0_count: u64,
    pub missed_p1_count: u64,
    pub production_qualification_allowed: bool,
    pub qualification_reason_code: String,
    pub evidence_hash: Sha256Hex,
}

pub fn evaluate_offline_corpus(
    corpus: &EvaluationCorpusV1,
) -> Result<OfflineEvaluationReportV1, OfflineEvaluationError> {
    validate_corpus(corpus)?;
    let overall = confusion(corpus.items.iter());
    let entities = corpus
        .items
        .iter()
        .map(|item| item.entity_type)
        .collect::<BTreeSet<_>>();
    let by_entity = entities
        .into_iter()
        .map(|entity| {
            let metrics = confusion(
                corpus
                    .items
                    .iter()
                    .filter(|item| item.entity_type == entity),
            );
            (entity, metrics)
        })
        .collect::<BTreeMap<_, _>>();
    let strata = corpus
        .items
        .iter()
        .map(|item| item.ocr_stratum.clone())
        .collect::<BTreeSet<_>>();
    let by_ocr_stratum = strata
        .into_iter()
        .map(|stratum| {
            let metrics = confusion(
                corpus
                    .items
                    .iter()
                    .filter(|item| item.ocr_stratum == stratum),
            );
            (stratum, metrics)
        })
        .collect::<BTreeMap<_, _>>();
    let documents = corpus
        .items
        .iter()
        .map(|item| item.document_id.as_str())
        .collect::<BTreeSet<_>>();
    let escaped = documents
        .iter()
        .filter(|document| {
            corpus.items.iter().any(|item| {
                item.document_id == ***document
                    && item.expected_sensitive
                    && (!item.predicted_sensitive || !item.matched_ground_truth)
            })
        })
        .count();
    let auto_candidates = corpus
        .items
        .iter()
        .filter(|item| item.auto_approval_candidate)
        .count();
    let auto_modified = corpus
        .items
        .iter()
        .filter(|item| item.auto_approval_candidate && item.human_modified)
        .count();
    let missed_p0_count = corpus
        .items
        .iter()
        .filter(|item| {
            item.expected_sensitive
                && (!item.predicted_sensitive || !item.matched_ground_truth)
                && item.expected_severity == FindingSeverity::P0Blocking
        })
        .count();
    let missed_p1_count = corpus
        .items
        .iter()
        .filter(|item| {
            item.expected_sensitive
                && (!item.predicted_sensitive || !item.matched_ground_truth)
                && item.expected_severity == FindingSeverity::P1High
        })
        .count();
    let reliability_bins = reliability_bins(&corpus.items);
    let expected_calibration_error_ppm =
        expected_calibration_error(&reliability_bins, corpus.items.len());
    let mut report = OfflineEvaluationReportV1 {
        schema_version: OFFLINE_EVALUATION_REPORT_VERSION.to_owned(),
        corpus_id: corpus.corpus_id.clone(),
        detector_version: corpus.detector_version.clone(),
        policy_version: corpus.policy_version.clone(),
        synthetic_only: corpus.synthetic_only,
        overall,
        by_entity,
        by_ocr_stratum,
        document_count: u64::try_from(documents.len()).unwrap_or(u64::MAX),
        document_escape_count: u64::try_from(escaped).unwrap_or(u64::MAX),
        document_escape_rate_ppm: ratio_ppm(escaped, documents.len()),
        expected_calibration_error_ppm,
        reliability_bins,
        auto_approval_candidate_count: u64::try_from(auto_candidates).unwrap_or(u64::MAX),
        auto_candidate_human_modified_count: u64::try_from(auto_modified).unwrap_or(u64::MAX),
        auto_candidate_human_modified_rate_ppm: ratio_ppm(auto_modified, auto_candidates),
        missed_p0_count: u64::try_from(missed_p0_count).unwrap_or(u64::MAX),
        missed_p1_count: u64::try_from(missed_p1_count).unwrap_or(u64::MAX),
        production_qualification_allowed: false,
        qualification_reason_code: "offline_report_cannot_self_qualify_production".to_owned(),
        evidence_hash: parse_hash(sha256_hex(b"pending"))?,
    };
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Claims<'a> {
        schema_version: &'a str,
        corpus_id: &'a str,
        detector_version: &'a str,
        policy_version: &'a str,
        synthetic_only: bool,
        overall: &'a ConfusionMetricsV1,
        by_entity: &'a BTreeMap<EntityType, ConfusionMetricsV1>,
        by_ocr_stratum: &'a BTreeMap<String, ConfusionMetricsV1>,
        document_count: u64,
        document_escape_count: u64,
        document_escape_rate_ppm: u32,
        expected_calibration_error_ppm: u32,
        reliability_bins: &'a [ReliabilityBinV1],
        auto_approval_candidate_count: u64,
        auto_candidate_human_modified_count: u64,
        auto_candidate_human_modified_rate_ppm: u32,
        missed_p0_count: u64,
        missed_p1_count: u64,
        production_qualification_allowed: bool,
        qualification_reason_code: &'a str,
    }
    let canonical = canonical_json_v1(&Claims {
        schema_version: &report.schema_version,
        corpus_id: &report.corpus_id,
        detector_version: &report.detector_version,
        policy_version: &report.policy_version,
        synthetic_only: report.synthetic_only,
        overall: &report.overall,
        by_entity: &report.by_entity,
        by_ocr_stratum: &report.by_ocr_stratum,
        document_count: report.document_count,
        document_escape_count: report.document_escape_count,
        document_escape_rate_ppm: report.document_escape_rate_ppm,
        expected_calibration_error_ppm: report.expected_calibration_error_ppm,
        reliability_bins: &report.reliability_bins,
        auto_approval_candidate_count: report.auto_approval_candidate_count,
        auto_candidate_human_modified_count: report.auto_candidate_human_modified_count,
        auto_candidate_human_modified_rate_ppm: report.auto_candidate_human_modified_rate_ppm,
        missed_p0_count: report.missed_p0_count,
        missed_p1_count: report.missed_p1_count,
        production_qualification_allowed: report.production_qualification_allowed,
        qualification_reason_code: &report.qualification_reason_code,
    })
    .map_err(|_| OfflineEvaluationError::EvidenceFailed)?;
    report.evidence_hash = parse_hash(sha256_hex(&canonical))?;
    Ok(report)
}

fn validate_corpus(corpus: &EvaluationCorpusV1) -> Result<(), OfflineEvaluationError> {
    if corpus.schema_version != OFFLINE_EVALUATION_CORPUS_VERSION
        || corpus.corpus_id.trim().is_empty()
        || corpus.detector_version.trim().is_empty()
        || corpus.policy_version.trim().is_empty()
        || corpus.items.is_empty()
        || corpus.items.len() > 10_000_000
        || corpus.items.iter().any(|item| {
            item.item_id.trim().is_empty()
                || item.document_id.trim().is_empty()
                || item.ocr_stratum.trim().is_empty()
                || item.item_id.chars().any(char::is_control)
                || item.document_id.chars().any(char::is_control)
                || item.ocr_stratum.chars().any(char::is_control)
        })
    {
        return Err(OfflineEvaluationError::InvalidCorpus);
    }
    Ok(())
}

fn confusion<'a>(items: impl Iterator<Item = &'a EvaluationItemV1>) -> ConfusionMetricsV1 {
    let mut metrics = ConfusionMetricsV1::default();
    for item in items {
        match (
            item.expected_sensitive,
            item.predicted_sensitive && item.matched_ground_truth,
        ) {
            (true, true) => metrics.true_positive += 1,
            (true, false) => metrics.false_negative += 1,
            (false, true) => metrics.false_positive += 1,
            (false, false) => metrics.true_negative += 1,
        }
    }
    metrics.precision_ppm = ratio_u64_ppm(
        metrics.true_positive,
        metrics.true_positive + metrics.false_positive,
    );
    metrics.recall_ppm = ratio_u64_ppm(
        metrics.true_positive,
        metrics.true_positive + metrics.false_negative,
    );
    metrics.false_negative_rate_ppm = ratio_u64_ppm(
        metrics.false_negative,
        metrics.true_positive + metrics.false_negative,
    );
    metrics.false_positive_rate_ppm = ratio_u64_ppm(
        metrics.false_positive,
        metrics.false_positive + metrics.true_negative,
    );
    metrics
}

fn reliability_bins(items: &[EvaluationItemV1]) -> Vec<ReliabilityBinV1> {
    (0..RELIABILITY_BIN_COUNT)
        .map(|index| {
            let lower = index * (ConfidencePpm::MAX / RELIABILITY_BIN_COUNT);
            let upper = if index + 1 == RELIABILITY_BIN_COUNT {
                ConfidencePpm::MAX
            } else {
                (index + 1) * (ConfidencePpm::MAX / RELIABILITY_BIN_COUNT) - 1
            };
            let selected = items
                .iter()
                .filter(|item| (lower..=upper).contains(&item.confidence_ppm.get()))
                .collect::<Vec<_>>();
            let confidence_sum = selected
                .iter()
                .map(|item| u64::from(item.confidence_ppm.get()))
                .sum::<u64>();
            let correct = selected
                .iter()
                .filter(|item| {
                    item.expected_sensitive
                        == (item.predicted_sensitive && item.matched_ground_truth)
                })
                .count();
            ReliabilityBinV1 {
                lower_bound_ppm: lower,
                upper_bound_ppm: upper,
                sample_count: u64::try_from(selected.len()).unwrap_or(u64::MAX),
                mean_confidence_ppm: if selected.is_empty() {
                    0
                } else {
                    u32::try_from(
                        confidence_sum / u64::try_from(selected.len()).unwrap_or(u64::MAX),
                    )
                    .unwrap_or(0)
                },
                empirical_accuracy_ppm: ratio_ppm(correct, selected.len()),
            }
        })
        .collect()
}

fn expected_calibration_error(bins: &[ReliabilityBinV1], total: usize) -> u32 {
    if total == 0 {
        return 0;
    }
    let weighted = bins
        .iter()
        .map(|bin| {
            u64::from(bin.mean_confidence_ppm.abs_diff(bin.empirical_accuracy_ppm))
                * bin.sample_count
        })
        .sum::<u64>();
    u32::try_from(weighted / u64::try_from(total).unwrap_or(u64::MAX)).unwrap_or(u32::MAX)
}

fn ratio_ppm(numerator: usize, denominator: usize) -> u32 {
    ratio_u64_ppm(
        u64::try_from(numerator).unwrap_or(u64::MAX),
        u64::try_from(denominator).unwrap_or(u64::MAX),
    )
}

fn ratio_u64_ppm(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    u32::try_from(numerator.saturating_mul(u64::from(ConfidencePpm::MAX)) / denominator)
        .unwrap_or(ConfidencePpm::MAX)
}

fn parse_hash(value: String) -> Result<Sha256Hex, OfflineEvaluationError> {
    Sha256Hex::parse(value).map_err(|_| OfflineEvaluationError::EvidenceFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn item(
        id: &str,
        doc: &str,
        expected: bool,
        predicted: bool,
        matched: bool,
        confidence: u32,
        entity: EntityType,
        severity: FindingSeverity,
        stratum: &str,
        auto: bool,
        modified: bool,
    ) -> EvaluationItemV1 {
        EvaluationItemV1 {
            item_id: id.to_owned(),
            document_id: doc.to_owned(),
            entity_type: entity,
            expected_sensitive: expected,
            predicted_sensitive: predicted,
            matched_ground_truth: matched,
            confidence_ppm: ConfidencePpm::new(confidence).expect("ppm"),
            auto_approval_candidate: auto,
            human_modified: modified,
            expected_severity: severity,
            ocr_stratum: stratum.to_owned(),
        }
    }

    #[test]
    fn reports_all_required_metrics_and_never_self_qualifies() {
        let corpus = EvaluationCorpusV1 {
            schema_version: OFFLINE_EVALUATION_CORPUS_VERSION.to_owned(),
            corpus_id: "synthetic-golden-v1".to_owned(),
            detector_version: "detector-v1".to_owned(),
            policy_version: "policy-v1".to_owned(),
            synthetic_only: true,
            items: vec![
                item(
                    "1",
                    "doc-a",
                    true,
                    true,
                    true,
                    950_000,
                    EntityType::IdentityNumber,
                    FindingSeverity::P0Blocking,
                    "native",
                    true,
                    false,
                ),
                item(
                    "2",
                    "doc-a",
                    false,
                    true,
                    true,
                    800_000,
                    EntityType::PersonName,
                    FindingSeverity::Informational,
                    "native",
                    false,
                    false,
                ),
                item(
                    "3",
                    "doc-b",
                    true,
                    false,
                    false,
                    300_000,
                    EntityType::Address,
                    FindingSeverity::P1High,
                    "ocr_low",
                    true,
                    true,
                ),
                item(
                    "4",
                    "doc-b",
                    false,
                    false,
                    false,
                    100_000,
                    EntityType::Address,
                    FindingSeverity::Informational,
                    "ocr_low",
                    false,
                    false,
                ),
            ],
        };
        let report = evaluate_offline_corpus(&corpus).expect("report");
        assert_eq!(report.overall.true_positive, 1);
        assert_eq!(report.overall.false_positive, 1);
        assert_eq!(report.overall.false_negative, 1);
        assert_eq!(report.overall.true_negative, 1);
        assert_eq!(report.document_escape_count, 1);
        assert_eq!(report.missed_p1_count, 1);
        assert_eq!(report.reliability_bins.len(), 10);
        assert!(!report.production_qualification_allowed);
        assert_eq!(
            report.qualification_reason_code,
            "offline_report_cannot_self_qualify_production"
        );
    }
}
