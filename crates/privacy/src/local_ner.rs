//! Auditable fixed-version, local-only linear-chain NER for Chinese legal materials.
//!
//! The embedded model is a real weighted sequence tagger: every normalized Unicode scalar is
//! featurized, emission and transition scores are evaluated, a bounded Viterbi path is decoded,
//! and span confidence is calibrated through the model's monotone calibration table. The module
//! has no provider or network dependency. Private text is borrowed only while calling the
//! mandatory [`PrivateValueSinkV1`]; public output contains locators, hashes and opaque Vault refs.

use crate::{
    deterministic::{PrivateValueSinkV1, StorePrivateValueRequestV1, StoredPrivateValueBindingV1},
    finding_engine::FindingCandidateV1,
    sha256_hex,
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, CaseId, ConfidencePpm, EntityType,
        MaterialId, Sha256Hex,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};
use unicode_normalization::UnicodeNormalization;

pub const LOCAL_NER_DETECTOR_VERSION: &str = "privacy-local-linear-chain-ner-v1";
pub const LOCAL_NER_MODEL_VERSION: &str = "cn-legal-linear-chain-ner-2026.07.1";
pub const LOCAL_NER_MODEL_SCHEMA_VERSION: &str = "lawyer-assistance-local-ner-model-v1";
pub const LOCAL_NER_MODEL_ASSET_SHA256: &str =
    "60c1112bc85a41af897de78ee88b713fbf55064e5dcb59321e8f36b01c36cfd5";
pub const LOCAL_NER_MODEL_MANIFEST_SHA256: &str =
    "7f5eb5c36445f8f618dd0c978bfb56229252d8b8a329ac619be32291e108409d";

const EMBEDDED_MODEL: &[u8] = include_bytes!("../assets/local-ner-cn-legal-v1-final.json");
const MAX_MODEL_BYTES: usize = 2 * 1024 * 1024;
const MAX_FEATURE_WEIGHTS: usize = 8_192;
const MAX_TRANSITIONS: usize = 512;
const SCORE_NEGATIVE_INFINITY: i64 = i64::MIN / 4;
const SOFTMAX_SCALE: f64 = 256.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalNerError {
    ModelAssetMissing,
    ModelAssetTampered,
    ModelManifestInvalid,
    InvalidInput,
    InputLimitExceeded,
    PrivateValueStoreFailed,
    InvalidPrivateBinding,
    OutputInvalid,
}

impl LocalNerError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ModelAssetMissing => "local_ner_model_asset_missing",
            Self::ModelAssetTampered => "local_ner_model_asset_tampered",
            Self::ModelManifestInvalid => "local_ner_model_manifest_invalid",
            Self::InvalidInput => "local_ner_input_invalid",
            Self::InputLimitExceeded => "local_ner_input_limit_exceeded",
            Self::PrivateValueStoreFailed => "local_ner_private_store_failed",
            Self::InvalidPrivateBinding => "local_ner_private_binding_invalid",
            Self::OutputInvalid => "local_ner_output_invalid",
        }
    }
}

impl fmt::Display for LocalNerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for LocalNerError {}

/// Public, non-sensitive attestation copied into detector provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalNerModelAttestationV1 {
    pub model_version: String,
    pub model_asset_sha256: Sha256Hex,
    pub model_manifest_sha256: Sha256Hex,
    pub feature_schema_version: String,
    pub calibration_version: String,
    pub training_fixture_sha256: Sha256Hex,
}

/// A borrowed page. Deliberately has no `Debug`, `Clone` or serialization implementation.
pub struct LocalNerPageInputV1<'a> {
    pub page_index: u32,
    pub block_id: &'a str,
    pub text: &'a str,
    pub ocr_confidence_ppm: Option<ConfidencePpm>,
    pub layout_confidence_ppm: Option<ConfidencePpm>,
}

/// A borrowed document. Deliberately has no `Debug`, `Clone` or serialization implementation.
pub struct LocalNerDocumentInputV1<'a> {
    pub case_id: &'a CaseId,
    pub material_id: &'a MaterialId,
    pub document_version: u64,
    pub pages: &'a [LocalNerPageInputV1<'a>],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNerDetectionBatchV1 {
    pub attestation: LocalNerModelAttestationV1,
    pub candidates: Vec<FindingCandidateV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
enum Label {
    #[serde(rename = "O")]
    Outside,
    #[serde(rename = "B-PER")]
    BeginPerson,
    #[serde(rename = "I-PER")]
    InsidePerson,
    #[serde(rename = "B-ORG")]
    BeginOrganization,
    #[serde(rename = "I-ORG")]
    InsideOrganization,
    #[serde(rename = "B-COURT")]
    BeginCourt,
    #[serde(rename = "I-COURT")]
    InsideCourt,
    #[serde(rename = "B-ADDR")]
    BeginAddress,
    #[serde(rename = "I-ADDR")]
    InsideAddress,
}

impl Label {
    const ALL: [Self; 9] = [
        Self::Outside,
        Self::BeginPerson,
        Self::InsidePerson,
        Self::BeginOrganization,
        Self::InsideOrganization,
        Self::BeginCourt,
        Self::InsideCourt,
        Self::BeginAddress,
        Self::InsideAddress,
    ];

    const fn is_inside(self) -> bool {
        matches!(
            self,
            Self::InsidePerson | Self::InsideOrganization | Self::InsideCourt | Self::InsideAddress
        )
    }

    const fn is_begin(self) -> bool {
        matches!(
            self,
            Self::BeginPerson | Self::BeginOrganization | Self::BeginCourt | Self::BeginAddress
        )
    }

    const fn entity_type(self) -> Option<EntityType> {
        match self {
            Self::BeginPerson | Self::InsidePerson => Some(EntityType::PersonName),
            Self::BeginOrganization | Self::InsideOrganization => {
                Some(EntityType::OrganizationName)
            }
            Self::BeginCourt | Self::InsideCourt => Some(EntityType::OrganizationName),
            Self::BeginAddress | Self::InsideAddress => Some(EntityType::Address),
            Self::Outside => None,
        }
    }

    const fn same_entity(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::BeginPerson | Self::InsidePerson, Self::InsidePerson)
                | (
                    Self::BeginOrganization | Self::InsideOrganization,
                    Self::InsideOrganization
                )
                | (Self::BeginCourt | Self::InsideCourt, Self::InsideCourt)
                | (
                    Self::BeginAddress | Self::InsideAddress,
                    Self::InsideAddress
                )
        )
    }

    const fn maximum_run(self, limits: &ModelLimits) -> usize {
        match self {
            Self::BeginPerson | Self::InsidePerson => limits.maximum_person_chars,
            Self::BeginOrganization | Self::InsideOrganization => limits.maximum_organization_chars,
            Self::BeginCourt | Self::InsideCourt => limits.maximum_organization_chars,
            Self::BeginAddress | Self::InsideAddress => limits.maximum_address_chars,
            Self::Outside => 0,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Outside => "O",
            Self::BeginPerson => "B-PER",
            Self::InsidePerson => "I-PER",
            Self::BeginOrganization => "B-ORG",
            Self::InsideOrganization => "I-ORG",
            Self::BeginCourt => "B-COURT",
            Self::InsideCourt => "I-COURT",
            Self::BeginAddress => "B-ADDR",
            Self::InsideAddress => "I-ADDR",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CalibrationPoint {
    raw_ppm: u32,
    calibrated_ppm: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FeatureWeight {
    label: Label,
    feature: String,
    weight: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TransitionWeight {
    from: String,
    to: Label,
    weight: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelLexicons {
    person_cues: Vec<String>,
    organization_cues: Vec<String>,
    address_cues: Vec<String>,
    organization_suffixes: Vec<String>,
    court_suffixes: Vec<String>,
    common_surnames: Vec<String>,
    compound_surnames: Vec<String>,
    common_given_name_chars: Vec<String>,
    address_markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelLimits {
    cross_page_window_chars: usize,
    maximum_person_chars: usize,
    maximum_organization_chars: usize,
    maximum_address_chars: usize,
    maximum_spans_per_document: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelManifest {
    schema_version: String,
    model_version: String,
    feature_schema_version: String,
    calibration_version: String,
    training_fixture_sha256: String,
    labels: Vec<Label>,
    weights: Vec<FeatureWeight>,
    transitions: Vec<TransitionWeight>,
    calibration: Vec<CalibrationPoint>,
    lexicons: ModelLexicons,
    limits: ModelLimits,
}

struct LoadedModel {
    manifest: ModelManifest,
    emissions: BTreeMap<(Label, String), i32>,
    transitions: BTreeMap<(String, Label), i32>,
    attestation: LocalNerModelAttestationV1,
    person_cues: Vec<Vec<char>>,
    organization_cues: Vec<Vec<char>>,
    address_cues: Vec<Vec<char>>,
    organization_suffixes: Vec<Vec<char>>,
    court_suffixes: Vec<Vec<char>>,
    common_surnames: BTreeSet<char>,
    compound_surnames: BTreeSet<(char, char)>,
    common_given_name_chars: BTreeSet<char>,
    address_markers: BTreeSet<char>,
}

#[derive(Clone)]
struct NormalizedToken {
    value: char,
    original_start: usize,
    original_end: usize,
    transformed: bool,
}

struct NormalizedPage {
    tokens: Vec<NormalizedToken>,
}

struct InferredSpan {
    page_position: usize,
    start: usize,
    end: usize,
    entity_type: EntityType,
    raw_confidence_ppm: u32,
    calibrated_confidence_ppm: u32,
    normalization_changed: bool,
    confusable_observed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DecoderState {
    label: Label,
    run: usize,
}

struct DecoderNode {
    state: DecoderState,
    score: i64,
    previous: Option<usize>,
}

/// Verifies the raw embedded asset hash, strict schema, canonical manifest hash and model
/// invariants. Callers may use this for a local health/qualification check; inference repeats the
/// same verification on every run rather than trusting a process-global cache.
pub fn verify_embedded_local_ner_model() -> Result<LocalNerModelAttestationV1, LocalNerError> {
    load_model(EMBEDDED_MODEL).map(|model| model.attestation)
}

pub fn detect_local_ner_candidates(
    input: LocalNerDocumentInputV1<'_>,
    sink: &mut dyn PrivateValueSinkV1,
) -> Result<LocalNerDetectionBatchV1, LocalNerError> {
    validate_document_input(&input)?;
    let model = load_model(EMBEDDED_MODEL)?;
    let normalized = input
        .pages
        .iter()
        .map(|page| normalize_page(page.text))
        .collect::<Vec<_>>();
    let spans = infer_document_spans(&model, &input, &normalized)?;
    let requests = spans
        .iter()
        .map(|span| {
            let page = input
                .pages
                .get(span.page_position)
                .ok_or(LocalNerError::OutputInvalid)?;
            let private_value = page
                .text
                .get(span.start..span.end)
                .ok_or(LocalNerError::OutputInvalid)?;
            Ok(StorePrivateValueRequestV1 {
                case_id: input.case_id,
                material_id: input.material_id,
                document_version: input.document_version,
                page_index: page.page_index,
                block_id: page.block_id,
                start_offset: u32::try_from(span.start)
                    .map_err(|_| LocalNerError::OutputInvalid)?,
                end_offset: u32::try_from(span.end).map_err(|_| LocalNerError::OutputInvalid)?,
                entity_type: span.entity_type,
                private_value,
            })
        })
        .collect::<Result<Vec<_>, LocalNerError>>()?;
    let bindings = if requests.is_empty() {
        Vec::new()
    } else {
        sink.store_private_values(&requests)
            .map_err(|_| LocalNerError::PrivateValueStoreFailed)?
    };
    if bindings.len() != spans.len() {
        return Err(LocalNerError::InvalidPrivateBinding);
    }

    let mut candidates = Vec::with_capacity(spans.len());
    for (span, binding) in spans.into_iter().zip(bindings) {
        validate_binding(&binding)?;
        let page = input
            .pages
            .get(span.page_position)
            .ok_or(LocalNerError::OutputInvalid)?;
        let raw = ConfidencePpm::new(span.raw_confidence_ppm)
            .map_err(|_| LocalNerError::OutputInvalid)?;
        let calibrated = ConfidencePpm::new(span.calibrated_confidence_ppm)
            .map_err(|_| LocalNerError::OutputInvalid)?;
        let normalization_evidence_hash = evidence_hash(
            "normalization",
            page,
            span.start,
            span.end,
            span.normalization_changed,
        )?;
        let confusable_evidence_hash = span
            .confusable_observed
            .then(|| evidence_hash("confusable", page, span.start, span.end, true))
            .transpose()?;
        let mut model_versions = BTreeMap::new();
        model_versions.insert(
            "local_ner_model".to_owned(),
            model.attestation.model_version.clone(),
        );
        model_versions.insert(
            "local_ner_manifest_sha256".to_owned(),
            model.attestation.model_manifest_sha256.as_str().to_owned(),
        );
        model_versions.insert(
            "local_ner_calibration".to_owned(),
            model.attestation.calibration_version.clone(),
        );
        model_versions.insert(
            "local_ner_feature_schema".to_owned(),
            model.attestation.feature_schema_version.clone(),
        );
        candidates.push(FindingCandidateV1 {
            page_index: page.page_index,
            block_id: page.block_id.to_owned(),
            start_offset: u32::try_from(span.start).map_err(|_| LocalNerError::OutputInvalid)?,
            end_offset: u32::try_from(span.end).map_err(|_| LocalNerError::OutputInvalid)?,
            geometry: None,
            entity_type: span.entity_type,
            detector_source: "local_ner".to_owned(),
            detector_version: LOCAL_NER_DETECTOR_VERSION.to_owned(),
            model_versions,
            raw_score_ppm: Some(raw),
            calibrated_confidence_ppm: Some(calibrated),
            ocr_confidence_ppm: page.ocr_confidence_ppm,
            layout_confidence_ppm: page.layout_confidence_ppm,
            normalization_evidence_hash: Some(normalization_evidence_hash),
            confusable_evidence_hash,
            case_dictionary_match: false,
            value_fingerprint: binding.value_fingerprint,
            proposed_replacement: Some(binding.proposed_replacement),
            private_value_ref: binding.private_value_ref,
            // A model span is a valid detector observation, but it is never a deterministic
            // checksum validation and therefore cannot authorize an automatic replacement.
            validation_passed: true,
            automatic_replacement_allowed: false,
            replacement_verified: false,
        });
    }
    Ok(LocalNerDetectionBatchV1 {
        attestation: model.attestation,
        candidates,
    })
}

fn load_model(bytes: &[u8]) -> Result<LoadedModel, LocalNerError> {
    if bytes.is_empty() {
        return Err(LocalNerError::ModelAssetMissing);
    }
    if bytes.len() > MAX_MODEL_BYTES || sha256_hex(bytes) != LOCAL_NER_MODEL_ASSET_SHA256 {
        return Err(LocalNerError::ModelAssetTampered);
    }
    let manifest = strict_json_v1_from_slice::<ModelManifest>(bytes)
        .map_err(|_| LocalNerError::ModelManifestInvalid)?;
    let canonical =
        canonical_json_v1(&manifest).map_err(|_| LocalNerError::ModelManifestInvalid)?;
    if sha256_hex(&canonical) != LOCAL_NER_MODEL_MANIFEST_SHA256 {
        return Err(LocalNerError::ModelAssetTampered);
    }
    validate_manifest(&manifest)?;

    let mut emissions = BTreeMap::new();
    for weight in &manifest.weights {
        if emissions
            .insert((weight.label, weight.feature.clone()), weight.weight)
            .is_some()
        {
            return Err(LocalNerError::ModelManifestInvalid);
        }
    }
    let mut transitions = BTreeMap::new();
    for transition in &manifest.transitions {
        if transitions
            .insert((transition.from.clone(), transition.to), transition.weight)
            .is_some()
        {
            return Err(LocalNerError::ModelManifestInvalid);
        }
    }
    let attestation = LocalNerModelAttestationV1 {
        model_version: manifest.model_version.clone(),
        model_asset_sha256: parse_hash(LOCAL_NER_MODEL_ASSET_SHA256)?,
        model_manifest_sha256: parse_hash(LOCAL_NER_MODEL_MANIFEST_SHA256)?,
        feature_schema_version: manifest.feature_schema_version.clone(),
        calibration_version: manifest.calibration_version.clone(),
        training_fixture_sha256: parse_hash(&manifest.training_fixture_sha256)?,
    };
    Ok(LoadedModel {
        person_cues: char_sequences(&manifest.lexicons.person_cues),
        organization_cues: char_sequences(&manifest.lexicons.organization_cues),
        address_cues: char_sequences(&manifest.lexicons.address_cues),
        organization_suffixes: char_sequences(&manifest.lexicons.organization_suffixes),
        court_suffixes: char_sequences(&manifest.lexicons.court_suffixes),
        common_surnames: single_chars(&manifest.lexicons.common_surnames)?,
        compound_surnames: char_pairs(&manifest.lexicons.compound_surnames)?,
        common_given_name_chars: single_chars(&manifest.lexicons.common_given_name_chars)?,
        address_markers: single_chars(&manifest.lexicons.address_markers)?,
        manifest,
        emissions,
        transitions,
        attestation,
    })
}

fn validate_manifest(manifest: &ModelManifest) -> Result<(), LocalNerError> {
    if manifest.schema_version != LOCAL_NER_MODEL_SCHEMA_VERSION
        || manifest.model_version != LOCAL_NER_MODEL_VERSION
        || !safe_model_token(&manifest.feature_schema_version)
        || !safe_model_token(&manifest.calibration_version)
        || Sha256Hex::parse(manifest.training_fixture_sha256.clone()).is_err()
        || manifest.labels != Label::ALL
        || manifest.weights.is_empty()
        || manifest.weights.len() > MAX_FEATURE_WEIGHTS
        || manifest.transitions.is_empty()
        || manifest.transitions.len() > MAX_TRANSITIONS
        || manifest.calibration.len() < 2
        || manifest.calibration.len() > 64
        || !(8..=256).contains(&manifest.limits.cross_page_window_chars)
        || !(2..=8).contains(&manifest.limits.maximum_person_chars)
        || !(3..=128).contains(&manifest.limits.maximum_organization_chars)
        || !(4..=256).contains(&manifest.limits.maximum_address_chars)
        || !(1..=100_000).contains(&manifest.limits.maximum_spans_per_document)
    {
        return Err(LocalNerError::ModelManifestInvalid);
    }
    if manifest.weights.iter().any(|weight| {
        !safe_feature(&weight.feature) || !(-100_000..=100_000).contains(&weight.weight)
    }) || manifest.transitions.iter().any(|transition| {
        !(transition.from == "START"
            || Label::ALL
                .iter()
                .any(|label| label.as_str() == transition.from))
            || !(-100_000..=100_000).contains(&transition.weight)
    }) {
        return Err(LocalNerError::ModelManifestInvalid);
    }
    let first = manifest
        .calibration
        .first()
        .ok_or(LocalNerError::ModelManifestInvalid)?;
    let last = manifest
        .calibration
        .last()
        .ok_or(LocalNerError::ModelManifestInvalid)?;
    if first.raw_ppm != 0
        || last.raw_ppm != ConfidencePpm::MAX
        || manifest.calibration.iter().any(|point| {
            point.raw_ppm > ConfidencePpm::MAX || point.calibrated_ppm > ConfidencePpm::MAX
        })
        || manifest.calibration.windows(2).any(|pair| {
            pair[0].raw_ppm >= pair[1].raw_ppm || pair[0].calibrated_ppm > pair[1].calibrated_ppm
        })
    {
        return Err(LocalNerError::ModelManifestInvalid);
    }
    validate_lexicons(&manifest.lexicons)
}

fn validate_lexicons(lexicons: &ModelLexicons) -> Result<(), LocalNerError> {
    let lists = [
        &lexicons.person_cues,
        &lexicons.organization_cues,
        &lexicons.address_cues,
        &lexicons.organization_suffixes,
        &lexicons.court_suffixes,
        &lexicons.common_surnames,
        &lexicons.compound_surnames,
        &lexicons.common_given_name_chars,
        &lexicons.address_markers,
    ];
    if lists.iter().any(|list| {
        list.is_empty()
            || list.len() > 2_048
            || list.iter().any(|value| {
                value.is_empty()
                    || value.chars().count() > 32
                    || value.chars().any(char::is_control)
            })
    }) {
        return Err(LocalNerError::ModelManifestInvalid);
    }
    Ok(())
}

fn validate_document_input(input: &LocalNerDocumentInputV1<'_>) -> Result<(), LocalNerError> {
    if input.document_version == 0 || input.pages.is_empty() || input.pages.len() > 100_000 {
        return Err(LocalNerError::InvalidInput);
    }
    let mut indexes = BTreeSet::new();
    let mut total = 0_usize;
    for page in input.pages {
        if page.block_id.is_empty()
            || page.block_id.len() > 256
            || page.block_id.chars().any(char::is_control)
            || !indexes.insert(page.page_index)
        {
            return Err(LocalNerError::InvalidInput);
        }
        total = total
            .checked_add(page.text.len())
            .ok_or(LocalNerError::InputLimitExceeded)?;
    }
    if total > u32::MAX as usize {
        return Err(LocalNerError::InputLimitExceeded);
    }
    Ok(())
}

fn normalize_page(text: &str) -> NormalizedPage {
    let mut tokens = Vec::new();
    let mut pending_ignorable = false;
    for (start, character) in text.char_indices() {
        let end = start + character.len_utf8();
        if is_ignorable(character) {
            pending_ignorable = true;
            continue;
        }
        let original = character.to_string();
        let normalized = original.nfkc().collect::<String>();
        let transformed = pending_ignorable || normalized != original;
        for value in normalized.chars() {
            tokens.push(NormalizedToken {
                value,
                original_start: start,
                original_end: end,
                transformed,
            });
        }
        pending_ignorable = false;
    }
    if pending_ignorable {
        if let Some(last) = tokens.last_mut() {
            last.transformed = true;
        }
    }
    NormalizedPage { tokens }
}

fn infer_document_spans(
    model: &LoadedModel,
    input: &LocalNerDocumentInputV1<'_>,
    pages: &[NormalizedPage],
) -> Result<Vec<InferredSpan>, LocalNerError> {
    let mut output = Vec::new();
    for page_position in 0..pages.len() {
        let page = pages
            .get(page_position)
            .ok_or(LocalNerError::OutputInvalid)?;
        if page.tokens.is_empty() {
            continue;
        }
        let prefix = page_position
            .checked_sub(1)
            .and_then(|position| pages.get(position))
            .map(|previous| {
                previous
                    .tokens
                    .iter()
                    .rev()
                    .take(model.manifest.limits.cross_page_window_chars)
                    .map(|token| token.value)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let suffix = pages
            .get(page_position + 1)
            .map(|next| {
                next.tokens
                    .iter()
                    .take(model.manifest.limits.cross_page_window_chars)
                    .map(|token| token.value)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let current_start = prefix.len();
        let mut characters = prefix;
        characters.extend(page.tokens.iter().map(|token| token.value));
        let current_end = characters.len();
        characters.extend(suffix);
        let features = (0..characters.len())
            .map(|position| features_at(model, &characters, position))
            .collect::<Vec<_>>();
        let labels = viterbi_decode(model, &characters, &features)?;
        let token_probabilities =
            chosen_token_probabilities(model, &characters, &features, &labels);
        let current_labels = labels
            .get(current_start..current_end)
            .ok_or(LocalNerError::OutputInvalid)?;
        let current_probabilities = token_probabilities
            .get(current_start..current_end)
            .ok_or(LocalNerError::OutputInvalid)?;
        append_page_spans(
            model,
            input,
            page_position,
            page,
            current_labels,
            current_probabilities,
            &mut output,
        )?;
        if output.len() > model.manifest.limits.maximum_spans_per_document {
            return Err(LocalNerError::InputLimitExceeded);
        }
    }
    output.sort_by(|left, right| {
        left.page_position
            .cmp(&right.page_position)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.end.cmp(&right.end))
            .then_with(|| left.entity_type.cmp(&right.entity_type))
    });
    output.dedup_by(|left, right| {
        left.page_position == right.page_position
            && left.start == right.start
            && left.end == right.end
            && left.entity_type == right.entity_type
    });
    Ok(output)
}

fn features_at(model: &LoadedModel, characters: &[char], position: usize) -> Vec<String> {
    let character = characters[position];
    let mut features = vec![
        "bias".to_owned(),
        character_class_feature(character).to_owned(),
    ];
    if position == 0 || is_boundary(characters[position - 1]) {
        features.push("boundary_prev".to_owned());
    }
    if position + 1 == characters.len() || is_boundary(characters[position + 1]) {
        features.push("boundary_next".to_owned());
    }
    if model.common_surnames.contains(&character) {
        features.push("common_surname".to_owned());
    }
    if model.common_given_name_chars.contains(&character) {
        features.push("common_given_name_char".to_owned());
    }
    if position + 1 < characters.len()
        && model
            .compound_surnames
            .contains(&(character, characters[position + 1]))
    {
        features.push("compound_surname_start".to_owned());
    }
    if position > 0
        && model
            .compound_surnames
            .contains(&(characters[position - 1], character))
    {
        features.push("compound_surname_second".to_owned());
    }
    if model.address_markers.contains(&character) {
        features.push("address_marker".to_owned());
    }
    if position_in_any_sequence(characters, position, &model.person_cues)
        || (position_in_any_sequence(characters, position, &model.organization_cues)
            && !position_in_any_sequence(characters, position, &model.organization_suffixes))
        || position_in_any_sequence(characters, position, &model.address_cues)
    {
        features.push("inside_cue_lexeme".to_owned());
    }
    if let Some(offset) = after_cue_position(
        characters,
        position,
        &model.person_cues,
        model.manifest.limits.maximum_person_chars,
    ) {
        features.push(format!("after_person_cue_pos={offset}"));
    }
    if let Some(offset) = after_cue_position(
        characters,
        position,
        &model.organization_cues,
        model.manifest.limits.maximum_organization_chars,
    ) {
        if offset == 0 {
            features.push("after_org_cue_pos=0".to_owned());
        }
    }
    if let Some(offset) = after_cue_position(
        characters,
        position,
        &model.address_cues,
        model.manifest.limits.maximum_address_chars,
    ) {
        features.push(if offset == 0 {
            "address_candidate_start".to_owned()
        } else {
            "address_candidate_inside".to_owned()
        });
        if offset == 0 {
            features.push("after_address_cue_pos=0".to_owned());
        }
    }
    if let Some(region) = suffix_region(
        characters,
        position,
        &model.organization_suffixes,
        &model.organization_cues,
        model.manifest.limits.maximum_organization_chars,
    ) {
        if position == region.start {
            features.push("org_candidate_start".to_owned());
        } else {
            features.push("org_candidate_inside".to_owned());
        }
        if position >= region.suffix_start {
            features.push("org_suffix_char".to_owned());
        }
    }
    if let Some(region) = suffix_region(
        characters,
        position,
        &model.court_suffixes,
        &[],
        model.manifest.limits.maximum_organization_chars,
    ) {
        if position == region.start {
            features.push("court_candidate_start".to_owned());
        } else {
            features.push("court_candidate_inside".to_owned());
        }
        if position >= region.suffix_start {
            features.push("court_suffix_char".to_owned());
        }
    }
    features
}

struct FeatureRegion {
    start: usize,
    suffix_start: usize,
}

fn suffix_region(
    characters: &[char],
    position: usize,
    suffixes: &[Vec<char>],
    cues: &[Vec<char>],
    maximum: usize,
) -> Option<FeatureRegion> {
    let search_start = position.saturating_sub(maximum);
    let search_end = characters.len().min(position.saturating_add(maximum + 1));
    let mut best = None;
    for suffix_start in search_start..search_end {
        for suffix in suffixes {
            let suffix_end = suffix_start.checked_add(suffix.len())?;
            if suffix_end > characters.len()
                || characters.get(suffix_start..suffix_end)? != suffix.as_slice()
            {
                continue;
            }
            let start = region_start_before_suffix(characters, suffix_start, cues, maximum);
            if cues.is_empty()
                && (start == suffix_start
                    || characters
                        .get(start..suffix_start)
                        .is_some_and(|prefix| prefix == ['\u{4eba}', '\u{6c11}']))
            {
                continue;
            }
            if start <= position && position < suffix_end && suffix_end - start <= maximum {
                let candidate = FeatureRegion {
                    start,
                    suffix_start,
                };
                if best.as_ref().is_none_or(|current: &FeatureRegion| {
                    candidate.start > current.start
                        || (candidate.start == current.start
                            && candidate.suffix_start < current.suffix_start)
                }) {
                    best = Some(candidate);
                }
            }
        }
    }
    best
}

fn position_in_any_sequence(characters: &[char], position: usize, sequences: &[Vec<char>]) -> bool {
    sequences.iter().any(|sequence| {
        let lower = position.saturating_sub(sequence.len().saturating_sub(1));
        (lower..=position).any(|start| {
            position < start.saturating_add(sequence.len())
                && characters.get(start..start.saturating_add(sequence.len()))
                    == Some(sequence.as_slice())
        })
    })
}

fn region_start_before_suffix(
    characters: &[char],
    suffix_start: usize,
    cues: &[Vec<char>],
    maximum: usize,
) -> usize {
    let lower = suffix_start.saturating_sub(maximum);
    let mut cue_start = None;
    for possible in lower..=suffix_start {
        let cue_end = strip_separators_backward(characters, possible);
        for cue in cues {
            if cue_end >= cue.len()
                && characters.get(cue_end - cue.len()..cue_end) == Some(cue.as_slice())
            {
                cue_start = Some(possible);
            }
        }
    }
    if let Some(start) = cue_start {
        return start;
    }
    if cues.is_empty() {
        if let Some(cue_position) = (lower..suffix_start)
            .rev()
            .find(|position| characters[*position] == '\u{7531}')
        {
            return cue_position + 1;
        }
    }
    let mut start = suffix_start;
    while start > lower && is_entity_character(characters[start - 1]) {
        start -= 1;
    }
    start
}

fn after_cue_position(
    characters: &[char],
    position: usize,
    cues: &[Vec<char>],
    maximum: usize,
) -> Option<usize> {
    let lower = position.saturating_sub(maximum.saturating_sub(1));
    for entity_start in (lower..=position).rev() {
        if characters
            .get(entity_start..=position)
            .is_none_or(|slice| slice.iter().any(|character| is_boundary(*character)))
        {
            continue;
        }
        let cue_end = strip_separators_backward(characters, entity_start);
        for cue in cues {
            if cue_end >= cue.len()
                && characters.get(cue_end - cue.len()..cue_end) == Some(cue.as_slice())
            {
                return Some(position - entity_start);
            }
        }
    }
    None
}

fn strip_separators_backward(characters: &[char], mut end: usize) -> usize {
    while end > 0 && is_label_separator(characters[end - 1]) {
        end -= 1;
    }
    end
}

fn viterbi_decode(
    model: &LoadedModel,
    characters: &[char],
    features: &[Vec<String>],
) -> Result<Vec<Label>, LocalNerError> {
    if characters.len() != features.len() {
        return Err(LocalNerError::OutputInvalid);
    }
    if characters.is_empty() {
        return Ok(Vec::new());
    }
    let mut layers = Vec::<Vec<DecoderNode>>::with_capacity(characters.len());
    let mut first = Vec::new();
    for label in Label::ALL {
        if label.is_inside() || !label_allowed(label, characters[0]) {
            continue;
        }
        first.push(DecoderNode {
            state: DecoderState {
                label,
                run: if label.is_begin() { 1 } else { 0 },
            },
            score: transition_score(model, "START", label).saturating_add(emission_score(
                model,
                label,
                &features[0],
            )),
            previous: None,
        });
    }
    if first.is_empty() {
        return Err(LocalNerError::OutputInvalid);
    }
    first.sort_by_key(|node| node.state);
    layers.push(first);

    for position in 1..characters.len() {
        let previous = layers.last().ok_or(LocalNerError::OutputInvalid)?;
        let mut best = BTreeMap::<DecoderState, (i64, usize)>::new();
        for (previous_index, node) in previous.iter().enumerate() {
            for label in Label::ALL {
                if !label_allowed(label, characters[position]) {
                    continue;
                }
                let run = if label == Label::Outside {
                    0
                } else if label.is_begin() {
                    1
                } else if node.state.label.same_entity(label) {
                    node.state.run.saturating_add(1)
                } else {
                    continue;
                };
                if run > label.maximum_run(&model.manifest.limits) {
                    continue;
                }
                let state = DecoderState { label, run };
                let score = node
                    .score
                    .saturating_add(transition_score(model, node.state.label.as_str(), label))
                    .saturating_add(emission_score(model, label, &features[position]));
                match best.get_mut(&state) {
                    Some((current, prior)) if score > *current => {
                        *current = score;
                        *prior = previous_index;
                    }
                    None => {
                        best.insert(state, (score, previous_index));
                    }
                    _ => {}
                }
            }
        }
        if best.is_empty() {
            return Err(LocalNerError::OutputInvalid);
        }
        layers.push(
            best.into_iter()
                .map(|(state, (score, previous))| DecoderNode {
                    state,
                    score,
                    previous: Some(previous),
                })
                .collect(),
        );
    }
    let last = layers.last().ok_or(LocalNerError::OutputInvalid)?;
    let mut best_index = 0_usize;
    let mut best_score = SCORE_NEGATIVE_INFINITY;
    for (index, node) in last.iter().enumerate() {
        if node.score > best_score {
            best_score = node.score;
            best_index = index;
        }
    }
    let mut reversed = Vec::with_capacity(layers.len());
    let mut index = best_index;
    for layer in layers.iter().rev() {
        let node = layer.get(index).ok_or(LocalNerError::OutputInvalid)?;
        reversed.push(node.state.label);
        if let Some(previous) = node.previous {
            index = previous;
        }
    }
    reversed.reverse();
    Ok(reversed)
}

fn chosen_token_probabilities(
    model: &LoadedModel,
    characters: &[char],
    features: &[Vec<String>],
    labels: &[Label],
) -> Vec<u32> {
    (0..labels.len())
        .map(|position| {
            let previous = position.checked_sub(1).map(|index| labels[index]);
            let scores = Label::ALL
                .iter()
                .copied()
                .filter(|label| {
                    label_allowed(*label, characters[position])
                        && (!label.is_inside()
                            || previous.is_some_and(|prior| prior.same_entity(*label)))
                })
                .map(|label| {
                    let from = previous.map_or("START", Label::as_str);
                    let score = transition_score(model, from, label)
                        .saturating_add(emission_score(model, label, &features[position]));
                    (label, score)
                })
                .collect::<Vec<_>>();
            let maximum = scores
                .iter()
                .map(|(_, score)| *score)
                .max()
                .unwrap_or(SCORE_NEGATIVE_INFINITY);
            let denominator = scores
                .iter()
                .map(|(_, score)| ((*score - maximum) as f64 / SOFTMAX_SCALE).exp())
                .sum::<f64>();
            if denominator <= f64::EPSILON {
                return 0;
            }
            let selected = scores
                .iter()
                .find(|(label, _)| *label == labels[position])
                .map(|(_, score)| ((*score - maximum) as f64 / SOFTMAX_SCALE).exp())
                .unwrap_or(0.0);
            (selected / denominator * f64::from(ConfidencePpm::MAX))
                .round()
                .clamp(0.0, f64::from(ConfidencePpm::MAX)) as u32
        })
        .collect()
}

fn append_page_spans(
    model: &LoadedModel,
    input: &LocalNerDocumentInputV1<'_>,
    page_position: usize,
    page: &NormalizedPage,
    labels: &[Label],
    probabilities: &[u32],
    output: &mut Vec<InferredSpan>,
) -> Result<(), LocalNerError> {
    if page.tokens.len() != labels.len() || labels.len() != probabilities.len() {
        return Err(LocalNerError::OutputInvalid);
    }
    let mut position = 0_usize;
    while position < labels.len() {
        let label = labels[position];
        if !label.is_begin() {
            position += 1;
            continue;
        }
        let Some(entity_type) = label.entity_type() else {
            return Err(LocalNerError::OutputInvalid);
        };
        let expected_inside = match label {
            Label::BeginPerson => Label::InsidePerson,
            Label::BeginOrganization => Label::InsideOrganization,
            Label::BeginCourt => Label::InsideCourt,
            Label::BeginAddress => Label::InsideAddress,
            _ => return Err(LocalNerError::OutputInvalid),
        };
        let mut end_position = position + 1;
        while labels.get(end_position) == Some(&expected_inside) {
            end_position += 1;
        }
        let minimum = match label {
            Label::BeginPerson => 2,
            Label::BeginOrganization | Label::BeginCourt => 3,
            Label::BeginAddress => 4,
            _ => usize::MAX,
        };
        if end_position - position >= minimum {
            let first = page
                .tokens
                .get(position)
                .ok_or(LocalNerError::OutputInvalid)?;
            let last = page
                .tokens
                .get(end_position - 1)
                .ok_or(LocalNerError::OutputInvalid)?;
            let page_input = input
                .pages
                .get(page_position)
                .ok_or(LocalNerError::OutputInvalid)?;
            if first.original_start < last.original_end
                && page_input.text.is_char_boundary(first.original_start)
                && page_input.text.is_char_boundary(last.original_end)
            {
                let probability_sum = probabilities[position..end_position]
                    .iter()
                    .map(|value| u64::from(*value))
                    .sum::<u64>();
                let raw = u32::try_from(probability_sum / (end_position - position) as u64)
                    .map_err(|_| LocalNerError::OutputInvalid)?;
                let normalization_changed = page.tokens[position..end_position]
                    .iter()
                    .any(|token| token.transformed);
                let confusable_observed = normalization_changed
                    || page.tokens[position..end_position]
                        .iter()
                        .any(|token| is_ocr_confusable(token.value));
                output.push(InferredSpan {
                    page_position,
                    start: first.original_start,
                    end: last.original_end,
                    entity_type,
                    raw_confidence_ppm: raw,
                    calibrated_confidence_ppm: calibrate(model, raw),
                    normalization_changed,
                    confusable_observed,
                });
            }
        }
        position = end_position;
    }
    Ok(())
}

fn calibrate(model: &LoadedModel, raw: u32) -> u32 {
    for pair in model.manifest.calibration.windows(2) {
        let lower = &pair[0];
        let upper = &pair[1];
        if raw <= upper.raw_ppm {
            let raw_span = u64::from(upper.raw_ppm - lower.raw_ppm);
            if raw_span == 0 {
                return lower.calibrated_ppm;
            }
            let calibrated_span = u64::from(upper.calibrated_ppm - lower.calibrated_ppm);
            let offset = u64::from(raw.saturating_sub(lower.raw_ppm));
            return lower
                .calibrated_ppm
                .saturating_add(u32::try_from(offset * calibrated_span / raw_span).unwrap_or(0));
        }
    }
    model
        .manifest
        .calibration
        .last()
        .map_or(0, |point| point.calibrated_ppm)
}

fn emission_score(model: &LoadedModel, label: Label, features: &[String]) -> i64 {
    features
        .iter()
        .filter_map(|feature| model.emissions.get(&(label, feature.clone())))
        .map(|weight| i64::from(*weight))
        .sum()
}

fn transition_score(model: &LoadedModel, from: &str, to: Label) -> i64 {
    i64::from(
        model
            .transitions
            .get(&(from.to_owned(), to))
            .copied()
            .unwrap_or(-120),
    )
}

fn label_allowed(label: Label, character: char) -> bool {
    label == Label::Outside || (!character.is_whitespace() && !is_punctuation(character))
}

fn character_class_feature(character: char) -> &'static str {
    if character.is_whitespace() {
        "class=space"
    } else if is_punctuation(character) {
        "class=punct"
    } else if is_han(character) {
        "class=han"
    } else if character.is_ascii_digit() {
        "class=digit"
    } else if character.is_ascii_alphabetic() {
        "class=ascii_alpha"
    } else {
        "class=other"
    }
}

fn is_boundary(character: char) -> bool {
    character.is_whitespace() || is_punctuation(character)
}

fn is_label_separator(character: char) -> bool {
    character.is_whitespace() || matches!(character, ':' | '\u{ff1a}')
}

fn is_punctuation(character: char) -> bool {
    matches!(
        character,
        ':' | '\u{ff1a}'
            | ','
            | '\u{ff0c}'
            | ';'
            | '\u{ff1b}'
            | '.'
            | '\u{3002}'
            | '!'
            | '\u{ff01}'
            | '?'
            | '\u{ff1f}'
            | '('
            | ')'
            | '\u{ff08}'
            | '\u{ff09}'
            | '['
            | ']'
            | '\u{3010}'
            | '\u{3011}'
            | '"'
            | '\''
            | '\u{201c}'
            | '\u{201d}'
            | '\u{3001}'
            | '\u{2014}'
    )
}

fn is_entity_character(character: char) -> bool {
    is_han(character)
        || character.is_ascii_alphanumeric()
        || matches!(
            character,
            '\u{00b7}' | '-' | '_' | '(' | ')' | '\u{ff08}' | '\u{ff09}'
        )
}

fn is_han(character: char) -> bool {
    matches!(
        character as u32,
        0x3400..=0x4dbf | 0x4e00..=0x9fff | 0xf900..=0xfaff
    )
}

fn is_ignorable(character: char) -> bool {
    matches!(
        character,
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
    )
}

fn is_ocr_confusable(character: char) -> bool {
    matches!(character, '0' | 'O' | 'o' | '1' | 'I' | 'l' | '\u{3007}')
}

fn char_sequences(values: &[String]) -> Vec<Vec<char>> {
    values
        .iter()
        .map(|value| value.nfkc().collect::<String>().chars().collect())
        .collect()
}

fn single_chars(values: &[String]) -> Result<BTreeSet<char>, LocalNerError> {
    values
        .iter()
        .map(|value| {
            let mut characters = value.chars();
            let first = characters
                .next()
                .ok_or(LocalNerError::ModelManifestInvalid)?;
            if characters.next().is_some() {
                return Err(LocalNerError::ModelManifestInvalid);
            }
            Ok(first)
        })
        .collect()
}

fn char_pairs(values: &[String]) -> Result<BTreeSet<(char, char)>, LocalNerError> {
    values
        .iter()
        .map(|value| {
            let mut characters = value.chars();
            let first = characters
                .next()
                .ok_or(LocalNerError::ModelManifestInvalid)?;
            let second = characters
                .next()
                .ok_or(LocalNerError::ModelManifestInvalid)?;
            if characters.next().is_some() {
                return Err(LocalNerError::ModelManifestInvalid);
            }
            Ok((first, second))
        })
        .collect()
}

fn evidence_hash(
    kind: &str,
    page: &LocalNerPageInputV1<'_>,
    start: usize,
    end: usize,
    observed: bool,
) -> Result<Sha256Hex, LocalNerError> {
    parse_hash(sha256_hex(
        format!(
            "local-ner-evidence-v1\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            LOCAL_NER_MODEL_MANIFEST_SHA256,
            kind,
            page.page_index,
            page.block_id,
            start,
            end,
            u8::from(observed)
        )
        .as_bytes(),
    ))
}

fn validate_binding(binding: &StoredPrivateValueBindingV1) -> Result<(), LocalNerError> {
    if binding.private_value_ref.object_version == 0
        || binding.proposed_replacement.is_empty()
        || binding.proposed_replacement.len() > 128
        || binding.proposed_replacement.chars().any(char::is_control)
        || !binding.proposed_replacement.starts_with('[')
        || !binding.proposed_replacement.ends_with(']')
    {
        return Err(LocalNerError::InvalidPrivateBinding);
    }
    Ok(())
}

fn safe_model_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && value.chars().all(|character| !character.is_control())
}

fn safe_feature(value: &str) -> bool {
    safe_model_token(value) && value.len() <= 96
}

fn parse_hash(value: impl Into<String>) -> Result<Sha256Hex, LocalNerError> {
    Sha256Hex::parse(value.into()).map_err(|_| LocalNerError::ModelManifestInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vnext::{ObjectId, PrivateValueRefV1};

    struct SyntheticSink {
        seen_private_values: Vec<String>,
    }

    impl PrivateValueSinkV1 for SyntheticSink {
        fn store_private_values(
            &mut self,
            requests: &[StorePrivateValueRequestV1<'_>],
        ) -> Result<
            Vec<StoredPrivateValueBindingV1>,
            crate::deterministic::DeterministicDetectorError,
        > {
            Ok(requests
                .iter()
                .enumerate()
                .map(|(index, request)| {
                    self.seen_private_values
                        .push(request.private_value.to_owned());
                    let locator = sha256_hex(
                        format!(
                            "synthetic-keyed\0{}\0{}",
                            request.case_id.as_str(),
                            request.private_value
                        )
                        .as_bytes(),
                    );
                    StoredPrivateValueBindingV1 {
                        value_fingerprint: Sha256Hex::parse(locator.clone())
                            .expect("synthetic fingerprint"),
                        private_value_ref: PrivateValueRefV1 {
                            object_id: ObjectId::parse(format!(
                                "obj_{:032x}",
                                index.saturating_add(1)
                            ))
                            .expect("synthetic object"),
                            object_version: 1,
                            value_locator_hash: Sha256Hex::parse(locator)
                                .expect("synthetic locator"),
                        },
                        proposed_replacement: format!("[local-ner-{}]", index + 1),
                    }
                })
                .collect())
        }
    }

    fn case_id() -> CaseId {
        CaseId::parse("case_11111111111111111111111111111111").expect("case")
    }

    fn material_id() -> MaterialId {
        MaterialId::parse("mat_22222222222222222222222222222222").expect("material")
    }

    fn detect<'a>(
        pages: &'a [LocalNerPageInputV1<'a>],
    ) -> (LocalNerDetectionBatchV1, SyntheticSink) {
        let mut sink = SyntheticSink {
            seen_private_values: Vec::new(),
        };
        let batch = detect_local_ner_candidates(
            LocalNerDocumentInputV1 {
                case_id: &case_id(),
                material_id: &material_id(),
                document_version: 1,
                pages,
            },
            &mut sink,
        )
        .expect("local model detection");
        (batch, sink)
    }

    #[test]
    fn embedded_model_is_hash_verified_and_auditable() {
        let attestation = verify_embedded_local_ner_model().expect("verified model");
        assert_eq!(attestation.model_version, LOCAL_NER_MODEL_VERSION);
        assert_eq!(
            attestation.model_asset_sha256.as_str(),
            LOCAL_NER_MODEL_ASSET_SHA256
        );
        assert_eq!(
            attestation.model_manifest_sha256.as_str(),
            LOCAL_NER_MODEL_MANIFEST_SHA256
        );
        let mut tampered = EMBEDDED_MODEL.to_vec();
        let position = tampered
            .iter()
            .position(|byte| *byte == b'9')
            .expect("asset contains digit");
        tampered[position] = b'8';
        assert!(matches!(
            load_model(&tampered),
            Err(LocalNerError::ModelAssetTampered)
        ));
        assert!(matches!(
            load_model(b""),
            Err(LocalNerError::ModelAssetMissing)
        ));
    }

    #[test]
    fn weighted_viterbi_detects_person_organization_court_and_address() {
        let text = concat!(
            "\u{539f}\u{544a}\u{ff1a}\u{5f20}\u{4e09}\u{ff0c}",
            "\u{88ab}\u{544a}\u{5355}\u{4f4d}\u{ff1a}\u{661f}\u{6cb3}\u{79d1}\u{6280}\u{6709}\u{9650}\u{516c}\u{53f8}\u{ff0c}",
            "\u{53d7}\u{7406}\u{673a}\u{5173}\u{ff1a}\u{4e1c}\u{6e56}\u{533a}\u{4eba}\u{6c11}\u{6cd5}\u{9662}\u{ff0c}",
            "\u{4f4f}\u{5740}\u{ff1a}\u{6e56}\u{5317}\u{7701}\u{6c5f}\u{57ce}\u{5e02}\u{4e1c}\u{6e56}\u{533a}\u{6c11}\u{4e3b}\u{8def}\u{516b}\u{53f7}\u{3002}"
        );
        let pages = [LocalNerPageInputV1 {
            page_index: 0,
            block_id: "page-0",
            text,
            ocr_confidence_ppm: ConfidencePpm::new(980_000).ok(),
            layout_confidence_ppm: ConfidencePpm::new(990_000).ok(),
        }];
        let (batch, sink) = detect(&pages);
        assert!(sink
            .seen_private_values
            .iter()
            .any(|value| value == "\u{5f20}\u{4e09}"));
        assert!(sink.seen_private_values.iter().any(
            |value| value == "\u{661f}\u{6cb3}\u{79d1}\u{6280}\u{6709}\u{9650}\u{516c}\u{53f8}"
        ));
        assert!(sink
            .seen_private_values
            .iter()
            .any(|value| value == "\u{4e1c}\u{6e56}\u{533a}\u{4eba}\u{6c11}\u{6cd5}\u{9662}"));
        assert!(sink
            .seen_private_values
            .iter()
            .any(|value| value.contains("\u{6c11}\u{4e3b}\u{8def}")));
        assert!(batch
            .candidates
            .iter()
            .all(|candidate| !candidate.automatic_replacement_allowed));
        let wire = serde_json::to_string(&batch.attestation).expect("attestation JSON");
        for private in sink.seen_private_values {
            assert!(!wire.contains(&private));
        }
    }

    #[test]
    fn nfkc_zero_width_confusable_and_cross_page_context_are_bound_to_evidence() {
        let first = "\u{539f}\u{544a}\u{59d3}\u{540d}\u{ff1a}";
        let second = "\u{5f20}\u{200b}\u{ff33}\u{ff0c}\u{4eca}\u{65e5}\u{5230}\u{5ead}\u{3002}";
        let pages = [
            LocalNerPageInputV1 {
                page_index: 0,
                block_id: "page-0",
                text: first,
                ocr_confidence_ppm: None,
                layout_confidence_ppm: None,
            },
            LocalNerPageInputV1 {
                page_index: 1,
                block_id: "page-1",
                text: second,
                ocr_confidence_ppm: ConfidencePpm::new(700_000).ok(),
                layout_confidence_ppm: None,
            },
        ];
        let (batch, sink) = detect(&pages);
        assert_eq!(sink.seen_private_values, vec!["\u{5f20}\u{200b}\u{ff33}"]);
        assert_eq!(batch.candidates.len(), 1);
        assert!(batch.candidates[0].confusable_evidence_hash.is_some());
        assert!(batch.candidates[0].normalization_evidence_hash.is_some());
        assert_eq!(batch.candidates[0].page_index, 1);
    }

    #[test]
    fn output_is_deterministic_and_never_contains_raw_values() {
        let text = "\u{539f}\u{544a}\u{ff1a}\u{674e}\u{660e}\u{ff0c}\u{4f4f}\u{5740}\u{ff1a}\u{6d77}\u{6ee8}\u{5e02}\u{65b0}\u{57ce}\u{533a}\u{5efa}\u{8bbe}\u{8def}\u{4e5d}\u{53f7}\u{3002}";
        let pages = [LocalNerPageInputV1 {
            page_index: 4,
            block_id: "stable-block",
            text,
            ocr_confidence_ppm: None,
            layout_confidence_ppm: None,
        }];
        let (left, left_sink) = detect(&pages);
        let (right, right_sink) = detect(&pages);
        assert_eq!(left, right);
        assert_eq!(
            left_sink.seen_private_values,
            right_sink.seen_private_values
        );
        let wire = format!("{left:?}");
        for private in left_sink.seen_private_values {
            assert!(!wire.contains(&private));
        }
    }
}
