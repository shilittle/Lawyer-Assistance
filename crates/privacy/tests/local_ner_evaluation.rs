use privacy::{
    deterministic::{
        DeterministicDetectorError, PrivateValueSinkV1, StorePrivateValueRequestV1,
        StoredPrivateValueBindingV1,
    },
    local_ner::{
        detect_local_ner_candidates, verify_embedded_local_ner_model, LocalNerDocumentInputV1,
        LocalNerPageInputV1,
    },
    sha256_hex,
    vnext::{
        CaseId, ConfidencePpm, EntityType, MaterialId, ObjectId, PrivateValueRefV1, Sha256Hex,
    },
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

const TRAINING_FIXTURE: &[u8] = include_bytes!("fixtures/local-ner-synthetic-training-v1.json");
const EVALUATION_FIXTURE: &[u8] = include_bytes!("fixtures/local-ner-synthetic-evaluation-v1.json");
const EVALUATION_FIXTURE_SHA256: &str =
    "c7926f8b7c4d8f04ef60c917ec553074d09f3c42ee31f2732348784536d1ddb6";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Fixture {
    schema_version: String,
    synthetic_only: bool,
    examples: Vec<Example>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Example {
    id: String,
    pages: Vec<String>,
    entities: Vec<ExpectedEntity>,
    #[serde(default)]
    ocr_stratum: String,
    #[serde(default)]
    cross_page: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExpectedEntity {
    page_index: u32,
    entity_type: EntityType,
    value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SpanKey {
    page_index: u32,
    entity_type: EntityType,
    start: u32,
    end: u32,
}

struct ObservedPrivate {
    key: SpanKey,
    private_value: String,
}

struct EvaluationSink {
    observed: Vec<ObservedPrivate>,
}

impl PrivateValueSinkV1 for EvaluationSink {
    fn store_private_values(
        &mut self,
        requests: &[StorePrivateValueRequestV1<'_>],
    ) -> Result<Vec<StoredPrivateValueBindingV1>, DeterministicDetectorError> {
        requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                self.observed.push(ObservedPrivate {
                    key: SpanKey {
                        page_index: request.page_index,
                        entity_type: request.entity_type,
                        start: request.start_offset,
                        end: request.end_offset,
                    },
                    private_value: request.private_value.to_owned(),
                });
                let fingerprint = sha256_hex(
                    format!(
                        "synthetic-evaluation-key\0{}\0{}",
                        request.case_id.as_str(),
                        request.private_value
                    )
                    .as_bytes(),
                );
                Ok(StoredPrivateValueBindingV1 {
                    value_fingerprint: Sha256Hex::parse(fingerprint.clone())
                        .expect("synthetic fingerprint"),
                    private_value_ref: PrivateValueRefV1 {
                        object_id: ObjectId::parse(format!("obj_{:032x}", index.saturating_add(1)))
                            .expect("synthetic object"),
                        object_version: 1,
                        value_locator_hash: Sha256Hex::parse(fingerprint)
                            .expect("synthetic locator"),
                    },
                    proposed_replacement: format!("[synthetic-eval-{}]", index + 1),
                })
            })
            .collect()
    }
}

#[derive(Default)]
struct Counts {
    true_positive: u64,
    false_positive: u64,
    false_negative: u64,
}

fn parse_fixture(bytes: &[u8], expected_schema: &str) -> Fixture {
    let fixture: Fixture = serde_json::from_slice(bytes).expect("strict typed synthetic fixture");
    assert!(fixture.synthetic_only);
    assert_eq!(fixture.schema_version, expected_schema);
    fixture
}

fn ids() -> (CaseId, MaterialId) {
    (
        CaseId::parse("case_34343434343434343434343434343434").expect("case"),
        MaterialId::parse("mat_56565656565656565656565656565656").expect("material"),
    )
}

fn confidence_for(stratum: &str) -> Option<ConfidencePpm> {
    match stratum {
        "native" | "" => None,
        "high_ocr" => ConfidencePpm::new(970_000).ok(),
        "low_ocr" => ConfidencePpm::new(710_000).ok(),
        "confusable_ocr" => ConfidencePpm::new(620_000).ok(),
        value => panic!("unexpected synthetic OCR stratum: {value}"),
    }
}

fn expected_keys(example: &Example) -> BTreeSet<SpanKey> {
    example
        .entities
        .iter()
        .map(|entity| {
            let page = example
                .pages
                .get(entity.page_index as usize)
                .expect("expected page");
            let start = page.find(&entity.value).expect("expected synthetic value");
            SpanKey {
                page_index: entity.page_index,
                entity_type: entity.entity_type,
                start: u32::try_from(start).expect("start"),
                end: u32::try_from(start + entity.value.len()).expect("end"),
            }
        })
        .collect()
}

#[test]
fn fixed_synthetic_training_fixture_is_bound_to_model_and_decodes() {
    let fixture = parse_fixture(TRAINING_FIXTURE, "local-ner-synthetic-training-v1");
    let attestation = verify_embedded_local_ner_model().expect("embedded model attestation");
    assert_eq!(
        sha256_hex(TRAINING_FIXTURE),
        attestation.training_fixture_sha256.as_str()
    );
    for example in fixture.examples {
        let (case_id, material_id) = ids();
        let blocks = (0..example.pages.len())
            .map(|index| format!("{}-page-{index}", example.id))
            .collect::<Vec<_>>();
        let pages = example
            .pages
            .iter()
            .enumerate()
            .map(|(index, text)| LocalNerPageInputV1 {
                page_index: u32::try_from(index).expect("page"),
                block_id: &blocks[index],
                text,
                ocr_confidence_ppm: confidence_for(&example.ocr_stratum),
                layout_confidence_ppm: None,
            })
            .collect::<Vec<_>>();
        let mut sink = EvaluationSink {
            observed: Vec::new(),
        };
        let batch = detect_local_ner_candidates(
            LocalNerDocumentInputV1 {
                case_id: &case_id,
                material_id: &material_id,
                document_version: 1,
                pages: &pages,
            },
            &mut sink,
        )
        .expect("training fixture inference");
        let predicted = batch
            .candidates
            .iter()
            .map(|candidate| SpanKey {
                page_index: candidate.page_index,
                entity_type: candidate.entity_type,
                start: candidate.start_offset,
                end: candidate.end_offset,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(predicted, expected_keys(&example), "fixture {}", example.id);
        let public_wire = format!("{batch:?}");
        for private in sink.observed {
            assert!(!public_wire.contains(&private.private_value));
        }
    }
}

#[test]
fn evaluation_reports_precision_recall_fnr_fpr_ece_and_strata() {
    assert_eq!(sha256_hex(EVALUATION_FIXTURE), EVALUATION_FIXTURE_SHA256);
    let fixture = parse_fixture(EVALUATION_FIXTURE, "local-ner-synthetic-evaluation-v1");
    let mut totals = Counts::default();
    let mut by_entity = BTreeMap::<EntityType, Counts>::new();
    let mut by_ocr_stratum = BTreeMap::<String, Counts>::new();
    let mut cross_page_examples = 0_u64;
    let mut negative_examples = 0_u64;
    let mut negative_examples_with_prediction = 0_u64;
    let mut calibration_bins = vec![(0_u64, 0_u64, 0_u64); 10];

    for example in fixture.examples {
        if example.cross_page {
            cross_page_examples += 1;
        }
        let (case_id, material_id) = ids();
        let blocks = (0..example.pages.len())
            .map(|index| format!("{}-page-{index}", example.id))
            .collect::<Vec<_>>();
        let pages = example
            .pages
            .iter()
            .enumerate()
            .map(|(index, text)| LocalNerPageInputV1 {
                page_index: u32::try_from(index).expect("page"),
                block_id: &blocks[index],
                text,
                ocr_confidence_ppm: confidence_for(&example.ocr_stratum),
                layout_confidence_ppm: None,
            })
            .collect::<Vec<_>>();
        let mut sink = EvaluationSink {
            observed: Vec::new(),
        };
        let batch = detect_local_ner_candidates(
            LocalNerDocumentInputV1 {
                case_id: &case_id,
                material_id: &material_id,
                document_version: 1,
                pages: &pages,
            },
            &mut sink,
        )
        .expect("evaluation inference");
        let expected = expected_keys(&example);
        let predicted = sink
            .observed
            .iter()
            .map(|value| value.key.clone())
            .collect::<BTreeSet<_>>();
        if expected.is_empty() {
            negative_examples += 1;
            if !predicted.is_empty() {
                negative_examples_with_prediction += 1;
            }
        }
        for key in predicted.intersection(&expected) {
            totals.true_positive += 1;
            by_entity.entry(key.entity_type).or_default().true_positive += 1;
            by_ocr_stratum
                .entry(example.ocr_stratum.clone())
                .or_default()
                .true_positive += 1;
        }
        for key in predicted.difference(&expected) {
            totals.false_positive += 1;
            by_entity.entry(key.entity_type).or_default().false_positive += 1;
            by_ocr_stratum
                .entry(example.ocr_stratum.clone())
                .or_default()
                .false_positive += 1;
        }
        for key in expected.difference(&predicted) {
            totals.false_negative += 1;
            by_entity.entry(key.entity_type).or_default().false_negative += 1;
            by_ocr_stratum
                .entry(example.ocr_stratum.clone())
                .or_default()
                .false_negative += 1;
        }
        for candidate in &batch.candidates {
            let key = SpanKey {
                page_index: candidate.page_index,
                entity_type: candidate.entity_type,
                start: candidate.start_offset,
                end: candidate.end_offset,
            };
            let confidence = candidate
                .calibrated_confidence_ppm
                .expect("calibrated confidence")
                .get();
            let bin = usize::try_from(confidence / 100_000).expect("bin").min(9);
            calibration_bins[bin].0 += 1;
            calibration_bins[bin].1 += u64::from(confidence);
            calibration_bins[bin].2 += u64::from(expected.contains(&key));
        }
        let public_wire = format!("{batch:?}");
        for private in sink.observed {
            assert!(!public_wire.contains(&private.private_value));
        }
    }

    let precision_ppm = ratio_ppm(
        totals.true_positive,
        totals.true_positive + totals.false_positive,
    );
    let recall_ppm = ratio_ppm(
        totals.true_positive,
        totals.true_positive + totals.false_negative,
    );
    let fnr_ppm = ratio_ppm(
        totals.false_negative,
        totals.true_positive + totals.false_negative,
    );
    // The candidate-span universe is unbounded, so FPR is measured over the
    // fixture's explicitly predeclared negative examples rather than relabeling
    // false-discovery rate as FPR.
    let fpr_ppm = ratio_ppm(negative_examples_with_prediction, negative_examples);
    let calibration_count = calibration_bins.iter().map(|bin| bin.0).sum::<u64>();
    let weighted_calibration_error = calibration_bins
        .iter()
        .filter(|bin| bin.0 > 0)
        .map(|bin| {
            let mean_confidence = bin.1 / bin.0;
            let accuracy = bin.2 * 1_000_000 / bin.0;
            mean_confidence.abs_diff(accuracy) * bin.0
        })
        .sum::<u64>();
    let ece_ppm = weighted_calibration_error
        .checked_div(calibration_count)
        .unwrap_or(0);

    println!(
        "local_ner_eval precision_ppm={precision_ppm} recall_ppm={recall_ppm} \
         fnr_ppm={fnr_ppm} fpr_ppm={fpr_ppm} ece_ppm={ece_ppm} \
         tp={} fp={} fn={} cross_page_examples={cross_page_examples}",
        totals.true_positive, totals.false_positive, totals.false_negative,
    );

    assert!(precision_ppm >= 950_000, "precision_ppm={precision_ppm}");
    assert!(recall_ppm >= 950_000, "recall_ppm={recall_ppm}");
    assert!(fnr_ppm <= 50_000, "fnr_ppm={fnr_ppm}");
    assert!(fpr_ppm <= 100_000, "fpr_ppm={fpr_ppm}");
    assert!(ece_ppm <= 150_000, "ece_ppm={ece_ppm}");
    assert!(negative_examples >= 2);
    assert!(cross_page_examples >= 2);
    assert!(by_entity
        .values()
        .all(|counts| counts.false_negative == 0 && counts.false_positive == 0));
    assert!(by_ocr_stratum.contains_key("low_ocr"));
    assert!(by_ocr_stratum.contains_key("confusable_ocr"));
}

fn ratio_ppm(numerator: u64, denominator: u64) -> u64 {
    numerator
        .saturating_mul(1_000_000)
        .checked_div(denominator)
        .unwrap_or(0)
}
