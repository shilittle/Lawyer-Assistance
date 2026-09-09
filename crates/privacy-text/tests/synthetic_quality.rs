//! Synthetic-only regression measurement. These counts describe this fixed fixture, not legal
//! production precision, recall, false-positive, or false-negative performance.

use privacy_text::{analyze, validate_analysis, CloudFinding, DictionaryEntry, Finding};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const FIXTURE: &str = include_str!("fixtures/redaction-regression-synthetic-v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FixtureSet {
    schema_version: String,
    synthetic_only: bool,
    cases: Vec<FixtureCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct FixtureCase {
    id: String,
    category: String,
    text: String,
    dictionary: Vec<DictionaryEntry>,
    cloud: Vec<CloudFinding>,
    expected_needs_review: bool,
    expected: Vec<ExpectedFinding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFinding {
    text: String,
    kind: String,
    strategy: String,
}

#[derive(Default)]
struct Metrics {
    cases: u64,
    positive_cases: u64,
    automatically_ready_cases: u64,
    automatically_ready_positive_cases: u64,
    pending_cases: u64,
    expected_entities: u64,
    observed_entities: u64,
    true_positive: u64,
    false_positive: u64,
    false_negative: u64,
    expected_automatic_entities: u64,
    deterministic_automatic: u64,
    dictionary_manual_coverage_automatic: u64,
    cloud_ner_automatic: u64,
    review_state_mismatches: u64,
    entity_count_mismatches: u64,
    strategy_mismatches: u64,
    stable_alias_mismatches: u64,
    invalid_automatic_analyses: u64,
}

#[test]
fn reports_synthetic_regression_metrics_without_claiming_production_accuracy() {
    let fixture: FixtureSet = serde_json::from_str(FIXTURE).expect("fixed synthetic fixture");
    assert_eq!(
        fixture.schema_version,
        "privacy-text-synthetic-regression-v1"
    );
    assert!(fixture.synthetic_only);
    assert!(!fixture.cases.is_empty());

    let categories = fixture
        .cases
        .iter()
        .map(|case| case.category.as_str())
        .collect::<BTreeSet<_>>();
    for required in [
        "person_cross_paragraph_positive",
        "organization_positive",
        "address_positive",
        "numeric_identifier_positive",
        "confusable_positive",
        "confusable_difficult_pending",
        "person_difficult_pending",
        "person_cross_paragraph_negative",
        "organization_negative",
        "address_negative",
        "numeric_identifier_negative",
    ] {
        assert!(categories.contains(required));
    }

    let mut metrics = Metrics::default();
    for case in &fixture.cases {
        let result = analyze(
            &case.text,
            &format!("synthetic-regression-v1-{}", case.id),
            &case.dictionary,
            &case.cloud,
            &[],
        )
        .expect("synthetic fixture analysis");
        if result.needs_review != case.expected_needs_review {
            metrics.review_state_mismatches += 1;
            println!(
                "privacy_text_synthetic_case_status case={} expected_needs_review={} actual_needs_review={} finding_summary={}",
                case.id,
                case.expected_needs_review,
                result.needs_review,
                safe_finding_summary(&result.findings),
            );
        }
        if !result.needs_review && validate_analysis(&result).is_err() {
            metrics.invalid_automatic_analyses += 1;
        }

        metrics.cases += 1;
        if !case.expected.is_empty() {
            metrics.positive_cases += 1;
        }
        if result.needs_review {
            metrics.pending_cases += 1;
        } else {
            metrics.automatically_ready_cases += 1;
            if !case.expected.is_empty() {
                metrics.automatically_ready_positive_cases += 1;
            }
        }

        let expected = expected_counts(&case.expected);
        let observed = observed_counts(&result.findings);
        let expected_count = sum_counts(&expected);
        let observed_count = sum_counts(&observed);
        let matched_count = expected
            .iter()
            .map(|(key, expected_count)| expected_count.min(observed.get(key).unwrap_or(&0)))
            .sum::<u64>();
        metrics.expected_entities += expected_count;
        metrics.expected_automatic_entities += u64::try_from(
            case.expected
                .iter()
                .filter(|finding| finding.strategy != "pending")
                .count(),
        )
        .expect("fixture count");
        metrics.observed_entities += observed_count;
        metrics.true_positive += matched_count;
        metrics.false_positive += observed_count.saturating_sub(matched_count);
        metrics.false_negative += expected_count.saturating_sub(matched_count);

        for ((text, kind, strategy), expected_count) in expected_strategy_counts(&case.expected) {
            let matching = result
                .findings
                .iter()
                .filter(|finding| finding.text == text && finding.kind == kind)
                .collect::<Vec<_>>();
            if u64::try_from(matching.len()).expect("fixture count") != expected_count {
                metrics.strategy_mismatches += 1;
            }
            for finding in matching {
                if !matches_strategy(finding, &strategy) {
                    metrics.strategy_mismatches += 1;
                }
            }
        }
        if observed_count != expected_count {
            metrics.entity_count_mismatches += 1;
        }

        for finding in result
            .findings
            .iter()
            .filter(|finding| finding.resolved && !finding.dismissed)
        {
            if has_source(finding, "dictionary") {
                metrics.dictionary_manual_coverage_automatic += 1;
            } else if has_source(finding, "deterministic") {
                metrics.deterministic_automatic += 1;
            } else if has_source(finding, "local_ner") && has_source(finding, "cloud") {
                metrics.cloud_ner_automatic += 1;
            } else {
                panic!("case {} has unclassified automatic source", case.id);
            }
        }

        let repeated = expected
            .iter()
            .filter(|(_, count)| **count > 1)
            .map(|(key, _)| key)
            .collect::<Vec<_>>();
        for (text, kind) in repeated {
            let aliases = result
                .findings
                .iter()
                .filter(|finding| finding.text == *text && finding.kind == *kind)
                .filter_map(|finding| finding.alias.as_deref())
                .collect::<BTreeSet<_>>();
            if aliases.len() != 1 {
                metrics.stable_alias_mismatches += 1;
            }
        }
    }

    println!(
        "privacy_text_synthetic_regression schema=privacy-text-synthetic-regression-v1 fixture_only=true \
cases={} expected_entities={} observed_entities={} true_positive={} false_positive={} false_negative={} \
automatic_ready_cases={} automatic_ready_rate_ppm={} positive_automatic_ready_cases={} \
positive_automatic_ready_rate_ppm={} pending_cases={} pending_rate_ppm={} \
automatic_deterministic={} automatic_dictionary_manual_coverage={} automatic_cloud_ner={} \
review_state_mismatches={} entity_count_mismatches={} strategy_mismatches={} stable_alias_mismatches={} invalid_automatic_analyses={}",
        metrics.cases,
        metrics.expected_entities,
        metrics.observed_entities,
        metrics.true_positive,
        metrics.false_positive,
        metrics.false_negative,
        metrics.automatically_ready_cases,
        ratio_ppm(metrics.automatically_ready_cases, metrics.cases),
        metrics.automatically_ready_positive_cases,
        ratio_ppm(metrics.automatically_ready_positive_cases, metrics.positive_cases),
        metrics.pending_cases,
        ratio_ppm(metrics.pending_cases, metrics.cases),
        metrics.deterministic_automatic,
        metrics.dictionary_manual_coverage_automatic,
        metrics.cloud_ner_automatic,
        metrics.review_state_mismatches,
        metrics.entity_count_mismatches,
        metrics.strategy_mismatches,
        metrics.stable_alias_mismatches,
        metrics.invalid_automatic_analyses,
    );
    assert_eq!(
        metrics.false_positive, 0,
        "synthetic false-positive regression"
    );
    assert_eq!(
        metrics.false_negative, 0,
        "synthetic false-negative regression"
    );
    assert_eq!(
        metrics.review_state_mismatches, 0,
        "synthetic review-state regression"
    );
    assert_eq!(
        metrics.entity_count_mismatches, 0,
        "synthetic entity-count regression"
    );
    assert_eq!(
        metrics.strategy_mismatches, 0,
        "synthetic source-strategy regression"
    );
    assert_eq!(
        metrics.stable_alias_mismatches, 0,
        "synthetic stable-alias regression"
    );
    assert_eq!(
        metrics.invalid_automatic_analyses, 0,
        "synthetic automatic-result validation regression"
    );
    assert_eq!(
        metrics.deterministic_automatic
            + metrics.dictionary_manual_coverage_automatic
            + metrics.cloud_ner_automatic,
        metrics.expected_automatic_entities,
        "synthetic automatic output strategy coverage"
    );
}

fn expected_counts(expected: &[ExpectedFinding]) -> BTreeMap<(String, String), u64> {
    let mut counts = BTreeMap::new();
    for finding in expected {
        *counts
            .entry((finding.text.clone(), finding.kind.clone()))
            .or_insert(0) += 1;
    }
    counts
}

fn expected_strategy_counts(
    expected: &[ExpectedFinding],
) -> BTreeMap<(String, String, String), u64> {
    let mut counts = BTreeMap::new();
    for finding in expected {
        *counts
            .entry((
                finding.text.clone(),
                finding.kind.clone(),
                finding.strategy.clone(),
            ))
            .or_insert(0) += 1;
    }
    counts
}

fn observed_counts(findings: &[Finding]) -> BTreeMap<(String, String), u64> {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts
            .entry((finding.text.clone(), finding.kind.clone()))
            .or_insert(0) += 1;
    }
    counts
}

fn sum_counts(values: &BTreeMap<(String, String), u64>) -> u64 {
    values.values().copied().sum()
}

fn has_source(finding: &Finding, source: &str) -> bool {
    finding
        .source
        .split('+')
        .any(|candidate| candidate == source)
}

fn matches_strategy(finding: &Finding, strategy: &str) -> bool {
    match strategy {
        "deterministic" => finding.resolved && has_source(finding, "deterministic"),
        "dictionary" => finding.resolved && has_source(finding, "dictionary"),
        "cloud_ner" => {
            finding.resolved
                && has_source(finding, "local_ner")
                && has_source(finding, "cloud")
                && !has_source(finding, "dictionary")
                && !has_source(finding, "deterministic")
        }
        "pending" => !finding.resolved && !finding.dismissed && finding.source == "local_ner",
        _ => false,
    }
}

fn safe_finding_summary(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|finding| format!("{}:{}:{}", finding.kind, finding.source, finding.resolved))
        .collect::<Vec<_>>()
        .join(",")
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u64 {
    numerator
        .saturating_mul(1_000_000)
        .checked_div(denominator)
        .unwrap_or(0)
}
