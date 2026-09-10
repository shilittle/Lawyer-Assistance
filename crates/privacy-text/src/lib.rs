//! Local-only text redaction bridge for the Web workspace.
//!
//! This crate accepts already-read attachment bytes, performs deterministic local analysis, and
//! returns a redacted result suitable for encrypted persistence. It deliberately has no logging
//! surface. Types carrying original text intentionally do **not** implement `Debug`.

use privacy::{
    deterministic::{
        detect_finding_candidates, DetectionContextV1, DeterministicDetectorError,
        PrivateValueSinkV1, StorePrivateValueRequestV1, StoredPrivateValueBindingV1,
    },
    local_ner::{detect_local_ner_candidates, LocalNerDocumentInputV1, LocalNerPageInputV1},
    normalize_sensitive_text,
    residual_scan::{
        scan_independent_residuals, IndependentResidualScanInputV1, ResidualDictionaryTermV1,
        ResidualHitV1, ResidualRiskClassV1,
    },
    sha256_hex,
    vnext::{CaseId, EntityType, MaterialId, ObjectId, PrivateValueRefV1, Sha256Hex},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    io::{Cursor, Write},
    sync::OnceLock,
};
use zip::{write::SimpleFileOptions, CompressionMethod, DateTime, ZipWriter};

const MAX_NAMESPACE_BYTES: usize = 256;
const MAX_FINDINGS: usize = 100_000;
const MAX_DICTIONARY_ENTRIES: usize = 4_096;
const MAX_CLOUD_FINDINGS: usize = 4_096;
const MAX_DISMISSED_FINDINGS: usize = 100_000;
const MAX_AI_FINDINGS: usize = 8_192;
const MAX_AI_FINDING_TEXT_BYTES: usize = 16 * 1024;
// A model range below this confidence is retained for human review, but cannot independently
// authorize a replacement. Dictionary and deterministic evidence keep their existing rules.
const MIN_AI_AUTOMATIC_CONFIDENCE_PPM: u32 = 900_000;

const CONTENT_TYPES_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
const ROOT_RELS_XML: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;

/// Stable error codes only. No error contains attachment, original-text, finding, or path data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TextError {
    InvalidInput,
    InvalidNamespace,
    InputRejected,
    IncompleteDocx,
    CorruptDocx,
    UnsafeDocx,
    InvalidTextEncoding,
    UnsupportedTextEncoding,
    UnsupportedExportFormat,
    CloudFindingAbsent,
    AnalysisFailed,
    TooManyFindings,
    ResultNeedsReview,
    ResidualRisk,
    ExportVerificationFailed,
    EvidenceVerificationFailed,
}

impl TextError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "privacy_text_invalid_input",
            Self::InvalidNamespace => "privacy_text_invalid_namespace",
            Self::InputRejected => "privacy_text_input_rejected",
            Self::IncompleteDocx => "docx_extraction_incomplete",
            Self::CorruptDocx => "docx_corrupt_or_encrypted",
            Self::UnsafeDocx => "docx_unsafe_package",
            Self::InvalidTextEncoding => "privacy_text_invalid_text_encoding",
            Self::UnsupportedTextEncoding => "privacy_text_unsupported_text_encoding",
            Self::UnsupportedExportFormat => "privacy_text_unsupported_export_format",
            Self::CloudFindingAbsent => "privacy_text_cloud_finding_absent",
            Self::AnalysisFailed => "privacy_text_analysis_failed",
            Self::TooManyFindings => "privacy_text_too_many_findings",
            Self::ResultNeedsReview => "privacy_text_result_needs_review",
            Self::ResidualRisk => "privacy_text_residual_risk",
            Self::ExportVerificationFailed => "privacy_text_export_verification_failed",
            Self::EvidenceVerificationFailed => "privacy_text_evidence_verification_failed",
        }
    }
}

impl fmt::Display for TextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for TextError {}

/// A manually-confirmed exact dictionary term. `text` is sensitive and must be encrypted by the
/// caller before persistence. This type deliberately does not implement `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DictionaryEntry {
    pub text: String,
    pub kind: String,
    pub alias: Option<String>,
}

/// An already-authorized cloud detector candidate. It is only corroborating evidence and never
/// supplies a replacement by itself. This type deliberately does not implement `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CloudFinding {
    pub text: String,
    pub kind: String,
}

/// A model supplied entity occurrence. Unlike [`CloudFinding`], this value carries the exact
/// UTF-8 byte range chosen by the model. The source text and range are still verified locally
/// before this becomes a replacement candidate; the model never supplies the replacement alias.
/// This type deliberately does not implement `Debug` because `text` is sensitive.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AiFinding {
    /// Exact original UTF-8 substring copied by the model.
    pub text: String,
    pub kind: String,
    /// Inclusive byte offset in the original UTF-8 source.
    pub start: usize,
    /// Exclusive byte offset in the original UTF-8 source.
    pub end: usize,
    /// Optional model confidence in parts per million. Values above 1_000_000 are rejected.
    #[serde(default)]
    pub confidence_ppm: Option<u32>,
}

/// One sensitive match. It is encrypted-persistence material, not a log or public API record.
/// `dismissed` is allowed for an uncorroborated local-NER semantic guess or a model-only
/// `custom` candidate that a reviewer has explicitly assessed as ordinary text.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub text: String,
    pub kind: String,
    pub alias: Option<String>,
    pub source: String,
    pub resolved: bool,
    pub dismissed: bool,
}

/// Byte spans produced by the replacement pass itself. `source_*` refers to the original UTF-8
/// input bytes and `output_*` refers to [`Analysis::text`] bytes. The containing analysis binds
/// these spans to immutable input and output versions through `source_sha256` and
/// `output_sha256`. This type deliberately does not implement `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Replacement {
    pub finding_id: String,
    pub source_start: usize,
    pub source_end: usize,
    pub output_start: usize,
    pub output_end: usize,
    pub alias: String,
}

/// Analysis result for one immutable material version. `text` is the derived redacted text; the
/// embedded findings retain originals and must stay inside encrypted workspace storage.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Analysis {
    pub text: String,
    pub findings: Vec<Finding>,
    /// Exact model occurrences which were range-validated against this source version. This is
    /// encrypted workspace evidence, used only to re-run a manual review after a dictionary
    /// revision. `None` means the older record did not persist model evidence; `Some(vec![])`
    /// means a current model pass was range-validated and reported no entities.
    #[serde(default)]
    pub ai_findings: Option<Vec<AiFinding>>,
    /// Actual substitutions, recorded during the replacement pass rather than reconstructed from
    /// text search. `default` keeps already-persisted pre-span analyses deserializable; callers
    /// must not treat such records as span-verified until re-analyzed.
    #[serde(default)]
    pub replacements: Vec<Replacement>,
    pub needs_review: bool,
    /// SHA-256 of the exact original UTF-8 input version that supplied `source_*` ranges.
    #[serde(default)]
    pub source_sha256: String,
    pub output_sha256: String,
}

#[derive(Clone)]
struct Candidate {
    start: usize,
    end: usize,
    kind: EntityType,
    source: &'static str,
    alias: String,
    deterministic: bool,
    automatic_allowed: bool,
}

struct Group {
    start: usize,
    end: usize,
    finding: Finding,
    replace: bool,
}

struct AliasSink<'a> {
    namespace: &'a str,
}

impl PrivateValueSinkV1 for AliasSink<'_> {
    fn store_private_values(
        &mut self,
        requests: &[StorePrivateValueRequestV1<'_>],
    ) -> Result<Vec<StoredPrivateValueBindingV1>, DeterministicDetectorError> {
        requests
            .iter()
            .map(|request| {
                let token = opaque_hash(&[
                    b"privacy-text-private-binding-v1",
                    self.namespace.as_bytes(),
                    entity_kind(request.entity_type).as_bytes(),
                    normalize_sensitive_text(request.private_value).as_bytes(),
                ]);
                let object_id = ObjectId::parse(format!("obj_{}", &token[..32]))
                    .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?;
                let fingerprint = Sha256Hex::parse(token)
                    .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?;
                Ok(StoredPrivateValueBindingV1 {
                    value_fingerprint: fingerprint.clone(),
                    private_value_ref: PrivateValueRefV1 {
                        object_id,
                        object_version: 1,
                        value_locator_hash: fingerprint,
                    },
                    proposed_replacement: stable_alias(
                        self.namespace,
                        request.entity_type,
                        request.private_value,
                    ),
                })
            })
            .collect()
    }
}

/// Strictly extract a TXT or DOCX attachment. TXT is UTF-8 unless `encoding` explicitly names
/// GB18030, UTF-16, UTF-16LE, or UTF-16BE. DOCX must not receive an encoding override.
pub fn extract(name: &str, bytes: &[u8], encoding: Option<&str>) -> Result<String, TextError> {
    file_ingest::extract_plain_text(name, bytes, encoding).map_err(|error| match error {
        file_ingest::IngestError::InvalidUtf8 | file_ingest::IngestError::InvalidTextEncoding => {
            TextError::InvalidTextEncoding
        }
        file_ingest::IngestError::UnsupportedTextEncoding => TextError::UnsupportedTextEncoding,
        file_ingest::IngestError::IncompleteDocxExtraction => TextError::IncompleteDocx,
        file_ingest::IngestError::CorruptDocx | file_ingest::IngestError::EncryptedDocx => {
            TextError::CorruptDocx
        }
        file_ingest::IngestError::UnsafeArchiveEntry
        | file_ingest::IngestError::UnsupportedDocxCompression
        | file_ingest::IngestError::DocxEntryLimitExceeded
        | file_ingest::IngestError::DocxEntryTooLarge
        | file_ingest::IngestError::DocxExpandedSizeExceeded
        | file_ingest::IngestError::DocxCompressionRatioExceeded
        | file_ingest::IngestError::ActiveContentNotAllowed
        | file_ingest::IngestError::XmlDoctypeNotAllowed => TextError::UnsafeDocx,
        _ => TextError::InputRejected,
    })
}

/// Detect, corroborate, replace, and independently validate a local text version.
///
/// Deterministic rules and dictionary matches may be replaced automatically. A local-NER match
/// alone remains unresolved; it may become automatic only when an authorized cloud finding has
/// the exact same original range and entity kind. Cloud findings never authorize a deterministic
/// field, and every cloud value must exactly occur in the supplied original text.
pub fn analyze(
    text: &str,
    namespace: &str,
    dictionary: &[DictionaryEntry],
    cloud: &[CloudFinding],
    dismissed: &[String],
) -> Result<Analysis, TextError> {
    analyze_internal(text, namespace, dictionary, cloud, &[], dismissed)
}

/// Analyze a text version with exact entity occurrences returned by the redaction model.
///
/// Model findings are primary semantic candidates, while deterministic rules and dictionary
/// matches remain local safety coverage. Every model range is checked against the exact source
/// bytes before it can be replaced. A model supplied alias or rewritten document is intentionally
/// not accepted by this API.
pub fn analyze_with_ai(
    text: &str,
    namespace: &str,
    dictionary: &[DictionaryEntry],
    ai: &[AiFinding],
    dismissed: &[String],
) -> Result<Analysis, TextError> {
    let mut analysis = analyze_internal(text, namespace, dictionary, &[], ai, dismissed)?;
    // `analyze_internal` verifies every exact span before constructing the result. Persist the
    // verified model evidence alongside the analysis so a later dictionary edit cannot make an
    // AI material silently fall back to local-only classification.
    analysis.ai_findings = Some(ai.to_vec());
    Ok(analysis)
}

fn analyze_internal(
    text: &str,
    namespace: &str,
    dictionary: &[DictionaryEntry],
    cloud: &[CloudFinding],
    ai: &[AiFinding],
    dismissed: &[String],
) -> Result<Analysis, TextError> {
    validate_inputs(text, namespace, dictionary, cloud, dismissed)?;
    validate_ai_inputs(text, ai)?;
    let mut candidates = Vec::new();
    let case_id = opaque_case_id(namespace)?;
    let material_id = opaque_material_id(text)?;
    let block_id = "privacy-text-document-v1";
    let mut sink = AliasSink { namespace };

    let deterministic = detect_finding_candidates(
        text,
        DetectionContextV1 {
            case_id: &case_id,
            material_id: &material_id,
            document_version: 1,
            page_index: 0,
            block_id,
            ocr_confidence_ppm: None,
            layout_confidence_ppm: None,
        },
        &mut sink,
    )
    .map_err(|_| TextError::AnalysisFailed)?;
    for candidate in deterministic {
        push_privacy_candidate(&mut candidates, text, candidate, "deterministic", true)?;
    }
    for (start, end) in credential_assignment_matches(text).ok_or(TextError::AnalysisFailed)? {
        let value = text.get(start..end).ok_or(TextError::AnalysisFailed)?;
        push_candidate(
            &mut candidates,
            Candidate {
                start,
                end,
                kind: EntityType::Custom,
                source: "deterministic",
                alias: stable_alias(namespace, EntityType::Custom, value),
                deterministic: true,
                automatic_allowed: true,
            },
        )?;
    }

    let pages = [LocalNerPageInputV1 {
        page_index: 0,
        block_id,
        text,
        ocr_confidence_ppm: None,
        layout_confidence_ppm: None,
    }];
    let ner = detect_local_ner_candidates(
        LocalNerDocumentInputV1 {
            case_id: &case_id,
            material_id: &material_id,
            document_version: 1,
            pages: &pages,
        },
        &mut sink,
    )
    .map_err(|_| TextError::AnalysisFailed)?;
    for candidate in ner.candidates {
        if !local_ner_candidate_is_semantically_plausible(text, &candidate)? {
            continue;
        }
        push_privacy_candidate(&mut candidates, text, candidate, "local_ner", false)?;
    }

    for entry in dictionary {
        let kind = parse_entity_kind(&entry.kind)?;
        let alias = entry
            .alias
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| stable_alias(namespace, kind, &entry.text));
        validate_alias(&alias)?;
        for (start, _) in text.match_indices(&entry.text) {
            push_candidate(
                &mut candidates,
                Candidate {
                    start,
                    end: start + entry.text.len(),
                    kind,
                    source: "dictionary",
                    alias: alias.clone(),
                    deterministic: false,
                    automatic_allowed: true,
                },
            )?;
        }
    }

    for finding in cloud {
        let kind = parse_entity_kind(&finding.kind)?;
        // Input validation above proves this iterator is non-empty. We nevertheless populate all
        // equal ranges so a cloud corroboration is bound to the precise text occurrence.
        for (start, _) in text.match_indices(&finding.text) {
            push_candidate(
                &mut candidates,
                Candidate {
                    start,
                    end: start + finding.text.len(),
                    kind,
                    source: "cloud",
                    alias: stable_alias(namespace, kind, &finding.text),
                    deterministic: false,
                    automatic_allowed: false,
                },
            )?;
        }
    }

    // An accepted model value establishes the entity spelling, but an occurrence number is only
    // a locator supplied by the provider.  Once the exact spelling has been verified against
    // this source version, cover every exact local occurrence.  The later identity-conflict gate
    // keeps equal spellings in distinct party/identity contexts out of automatic publication.
    for finding in ai {
        let kind = parse_entity_kind(&finding.kind)?;
        for (start, _) in text.match_indices(&finding.text) {
            push_candidate(
                &mut candidates,
                Candidate {
                    start,
                    end: start + finding.text.len(),
                    kind,
                    source: "ai",
                    alias: stable_alias(namespace, kind, &finding.text),
                    deterministic: false,
                    automatic_allowed: finding
                        .confidence_ppm
                        .is_some_and(|confidence| confidence >= MIN_AI_AUTOMATIC_CONFIDENCE_PPM),
                },
            )?;
        }
    }

    // A compact mixed letter/number code is locally verifiable even when vision/text extraction
    // omitted it from the model result.  Do not add a competing `custom` candidate where another
    // detector or the model already established the exact range and entity kind.
    for (start, end) in
        structured_opaque_identifier_matches(text).ok_or(TextError::AnalysisFailed)?
    {
        if candidates.iter().any(|candidate| {
            candidate.start == start
                && candidate.end == end
                && candidate.source != "local_ner"
                && candidate.kind != EntityType::Custom
        }) {
            continue;
        }
        let value = text.get(start..end).ok_or(TextError::AnalysisFailed)?;
        push_candidate(
            &mut candidates,
            Candidate {
                start,
                end,
                kind: EntityType::Custom,
                source: "deterministic",
                alias: stable_alias(namespace, EntityType::Custom, value),
                deterministic: true,
                automatic_allowed: true,
            },
        )?;
    }

    let ambiguous_organization_values =
        apply_explicit_organization_aliases(text, namespace, &mut candidates)?;
    build_analysis(
        text,
        namespace,
        candidates,
        dismissed,
        &ambiguous_organization_values,
    )
}

/// Revalidate a persisted result before reading or exporting it. It rejects unresolved findings,
/// verifies each actual replacement remains absent, and runs the independent residual scanner.
/// An accepted semantic or model-only `custom` dismissal remains meaningful: it does not require
/// removal of the reviewer-assessed ordinary text, while deterministic findings can never be
/// represented as dismissed by [`analyze`].
pub fn validate_result(text: &str, findings: &[Finding]) -> Result<(), TextError> {
    if text.len() > file_ingest::MAX_TEXT_BYTES || text.contains('\0') {
        return Err(TextError::InvalidInput);
    }
    if findings.len() > MAX_FINDINGS {
        return Err(TextError::TooManyFindings);
    }

    let mut terms = BTreeMap::<String, (EntityType, String)>::new();
    for finding in findings {
        validate_finding(finding)?;
        if !finding.resolved {
            return Err(TextError::ResultNeedsReview);
        }
        if finding.dismissed {
            continue;
        }
        if text.contains(&finding.text) {
            return Err(TextError::ResidualRisk);
        }
        let kind = parse_entity_kind(&finding.kind)?;
        let alias = finding.alias.clone().ok_or(TextError::ResultNeedsReview)?;
        match terms.get(&finding.text) {
            Some((existing_kind, existing_alias))
                if *existing_kind != kind || existing_alias != &alias =>
            {
                return Err(TextError::ResidualRisk);
            }
            Some(_) => {}
            None => {
                terms.insert(finding.text.clone(), (kind, alias));
            }
        }
    }
    // One stable alias may deliberately cover explicit name variants of the same entity, such as
    // an organization full name and its declared abbreviation. Preserve every spelling for the
    // residual dictionary scan, but give it one logical placeholder identity so the scanner does
    // not mistake that verified relationship for an alias collision.
    let mut residual_groups = BTreeMap::<(EntityType, String), Vec<String>>::new();
    for (value, (kind, alias)) in terms {
        residual_groups
            .entry((kind, alias))
            .or_default()
            .push(value);
    }
    let residual_groups = residual_groups.into_iter().collect::<Vec<_>>();
    let residual_variants = residual_groups
        .iter()
        .map(|(_, values)| {
            values
                .iter()
                .skip(1)
                .map(String::as_str)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let residual_terms = residual_groups
        .iter()
        .zip(&residual_variants)
        .map(
            |(((kind, alias), values), variants)| ResidualDictionaryTermV1 {
                entity_type: *kind,
                primary_value: values
                    .first()
                    .expect("a residual group has a primary value"),
                variants,
                expected_alias: alias,
            },
        )
        .collect::<Vec<_>>();
    let pages = [text.to_owned()];
    let report = scan_independent_residuals(IndependentResidualScanInputV1 {
        pages: &pages,
        dictionary_terms: &residual_terms,
        source_names: &[],
    })
    .map_err(|_| TextError::AnalysisFailed)?;
    let has_blocking_residual = report
        .hits
        .iter()
        .any(|hit| hit.blocking && !ignorable_residual_hit(&pages, hit))
        || has_credential_residual(text);
    if !has_blocking_residual {
        Ok(())
    } else {
        Err(TextError::ResidualRisk)
    }
}

fn ignorable_residual_hit(pages: &[String], hit: &ResidualHitV1) -> bool {
    if hit.risk_class != ResidualRiskClassV1::LongDigitSequence {
        return false;
    }
    let Ok(page_index) = usize::try_from(hit.page_index) else {
        return false;
    };
    let Some(page) = pages.get(page_index) else {
        return false;
    };
    let Ok(start) = usize::try_from(hit.start_offset) else {
        return false;
    };
    let Ok(end) = usize::try_from(hit.end_offset) else {
        return false;
    };
    let Some(candidate) = page.get(start..end) else {
        return false;
    };
    let candidate =
        candidate.trim_matches(|character: char| !character.is_ascii_digit() && character != '-');
    is_iso_date(candidate)
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    if !bytes[..4]
        .iter()
        .chain(&bytes[5..7])
        .chain(&bytes[8..])
        .all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let month = u16::from(bytes[5] - b'0') * 10 + u16::from(bytes[6] - b'0');
    let day = u16::from(bytes[8] - b'0') * 10 + u16::from(bytes[9] - b'0');
    (1..=12).contains(&month) && (1..=31).contains(&day)
}

const CREDENTIAL_ASSIGNMENT_PATTERN: &str = r"(?i)(?:\b(?:api[_-]?key|access[_-]?key|secret(?:[_-]?key)?|auth(?:entication)?[_-]?token|(?:access|refresh|id)?[_-]?token|password|passwd|pwd)\b|密钥|令牌|口令|密码)\s*[:=]\s*(?P<value>[^\s,;，；。]+)";
const ORGANIZATION_ALIAS_PATTERN: &str = r"(?P<full>[\p{Han}A-Za-z0-9·（）()\- ]{2,100}?)[（(]\s*简称\s*[:：]?\s*(?P<short>[\p{Han}A-Za-z0-9·（）()\-]{1,40}?)[）)]";
const STRUCTURED_OPAQUE_IDENTIFIER_PATTERN: &str = r"[A-Z]{2,12}(?:-[A-Z]{2,12})?-\d+(?:[-.]\d+)*";

fn has_credential_residual(text: &str) -> bool {
    credential_assignment_matches(text).is_none_or(|matches| !matches.is_empty())
}

fn credential_assignment_matches(text: &str) -> Option<Vec<(usize, usize)>> {
    static PATTERN: OnceLock<Option<Regex>> = OnceLock::new();
    let regex = PATTERN
        .get_or_init(|| Regex::new(CREDENTIAL_ASSIGNMENT_PATTERN).ok())
        .as_ref()?;
    Some(
        regex
            .captures_iter(text)
            .filter_map(|captures| {
                let full = captures.get(0)?;
                let value = captures.name("value")?;
                (!is_alias_placeholder(value.as_str())).then_some((full.start(), full.end()))
            })
            .collect(),
    )
}

fn structured_opaque_identifier_matches(text: &str) -> Option<Vec<(usize, usize)>> {
    static PATTERN: OnceLock<Option<Regex>> = OnceLock::new();
    let regex = PATTERN
        .get_or_init(|| Regex::new(STRUCTURED_OPAQUE_IDENTIFIER_PATTERN).ok())
        .as_ref()?;
    Some(
        regex
            .find_iter(text)
            .filter(|value| structured_identifier_has_boundaries(text, value.start(), value.end()))
            .map(|value| (value.start(), value.end()))
            .collect(),
    )
}

fn structured_identifier_has_boundaries(text: &str, start: usize, end: usize) -> bool {
    let before = text
        .get(..start)
        .and_then(|prefix| prefix.chars().next_back());
    let after = text.get(end..).and_then(|suffix| suffix.chars().next());
    before.is_none_or(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '_' | '[')
    }) && after.is_none_or(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '_' | ']')
    })
}

fn is_alias_placeholder(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return false;
    };
    let Some((kind, suffix)) = inner.split_once('_') else {
        return false;
    };
    !kind.is_empty()
        && kind.chars().all(|character| character.is_ascii_uppercase())
        && suffix.len() >= 8
        && suffix
            .chars()
            .all(|character| character.is_ascii_lowercase())
}

/// Apply only an explicit, unambiguous organization declaration such as
/// `全称（简称简称）`. The declaration is evidence for alias identity, not evidence that the
/// model found either occurrence: both the full and short form still need an independently
/// validated candidate before their aliases are linked. An abbreviation declared for more than
/// one full name is returned as ambiguous and remains unresolved.
fn apply_explicit_organization_aliases(
    text: &str,
    namespace: &str,
    candidates: &mut [Candidate],
) -> Result<BTreeSet<String>, TextError> {
    static PATTERN: OnceLock<Option<Regex>> = OnceLock::new();
    let Some(regex) = PATTERN
        .get_or_init(|| Regex::new(ORGANIZATION_ALIAS_PATTERN).ok())
        .as_ref()
    else {
        return Err(TextError::AnalysisFailed);
    };

    let mut declarations = BTreeMap::<String, BTreeSet<String>>::new();
    for captures in regex.captures_iter(text) {
        let Some(full) = captures.name("full").map(|value| value.as_str().trim()) else {
            continue;
        };
        let Some(short) = captures.name("short").map(|value| value.as_str().trim()) else {
            continue;
        };
        if full != short && safe_term(full) && safe_term(short) {
            declarations
                .entry(short.to_owned())
                .or_default()
                .insert(full.to_owned());
        }
    }
    if declarations.is_empty() {
        return Ok(BTreeSet::new());
    }

    let candidate_values = candidates
        .iter()
        .filter(|candidate| candidate.kind == EntityType::OrganizationName)
        .filter_map(|candidate| text.get(candidate.start..candidate.end))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut canonical_aliases = BTreeMap::<String, String>::new();
    let mut ambiguous_values = BTreeSet::new();
    for (short, full_names) in declarations {
        if full_names.len() > 1 {
            ambiguous_values.insert(short);
            continue;
        }
        let Some(full) = full_names.into_iter().next() else {
            continue;
        };
        if !candidate_values.contains(&full) || !candidate_values.contains(&short) {
            continue;
        }
        let dictionary_aliases = candidates
            .iter()
            .filter(|candidate| {
                candidate.kind == EntityType::OrganizationName
                    && candidate.source == "dictionary"
                    && text
                        .get(candidate.start..candidate.end)
                        .is_some_and(|value| value == full)
            })
            .map(|candidate| candidate.alias.clone())
            .collect::<BTreeSet<_>>();
        let canonical = if dictionary_aliases.len() == 1 {
            dictionary_aliases
                .into_iter()
                .next()
                .ok_or(TextError::AnalysisFailed)?
        } else if dictionary_aliases.is_empty() {
            stable_alias(namespace, EntityType::OrganizationName, &full)
        } else {
            // Conflicting explicit dictionary aliases are user evidence that must stay visible as
            // a review decision; do not pick one merely because a declaration was present.
            continue;
        };
        canonical_aliases.insert(full, canonical.clone());
        canonical_aliases.insert(short, canonical);
    }

    for candidate in candidates.iter_mut() {
        if candidate.kind != EntityType::OrganizationName || candidate.source == "dictionary" {
            continue;
        }
        let Some(value) = text.get(candidate.start..candidate.end) else {
            return Err(TextError::AnalysisFailed);
        };
        if let Some(alias) = canonical_aliases.get(value) {
            candidate.alias = alias.clone();
        }
    }
    Ok(ambiguous_values)
}

/// Validate a persisted, publishable analysis including its output hash and recorded replacement
/// spans. This intentionally does not accept source text, so it can run at a result-read boundary
/// without loading the original attachment. Use [`verify_analysis_source`] when the encrypted
/// original is available and exact source-range evidence must also be checked.
pub fn validate_analysis(analysis: &Analysis) -> Result<(), TextError> {
    if !valid_sha256(&analysis.output_sha256)
        || !valid_sha256(&analysis.source_sha256)
        || sha256_hex(analysis.text.as_bytes()) != analysis.output_sha256
    {
        return Err(TextError::EvidenceVerificationFailed);
    }
    verify_output_replacement_evidence(&analysis.text, &analysis.findings, &analysis.replacements)?;
    validate_result(&analysis.text, &analysis.findings)
}

/// Verify every recorded replacement against the exact original UTF-8 source version. This
/// rebuilds the derived text from the recorded byte ranges; it never uses `find` or other
/// content-based position guessing. It is suitable for the task worker before it persists an
/// immutable result, including results that still need review.
pub fn verify_analysis_source(source: &str, analysis: &Analysis) -> Result<(), TextError> {
    if !valid_sha256(&analysis.source_sha256)
        || sha256_hex(source.as_bytes()) != analysis.source_sha256
    {
        return Err(TextError::EvidenceVerificationFailed);
    }
    verify_output_replacement_evidence(&analysis.text, &analysis.findings, &analysis.replacements)?;
    verify_source_replacement_evidence(
        source,
        &analysis.text,
        &analysis.findings,
        &analysis.replacements,
    )
}

/// Export a redacted result as UTF-8 TXT, Markdown, or a minimal rebuilt DOCX.
///
/// This rejects independent residual patterns such as identifiers, contact values and local paths.
/// A caller that has findings must call [`validate_result`] first; that is what proves removal of
/// dictionary-only values and preserves an allowed local-NER dismissal's semantic decision.
pub fn export(text: &str, format: &str) -> Result<Vec<u8>, TextError> {
    validate_export_text(text)?;
    export_document(text, format, true)
}

/// Export an explicitly user-requested local template/document without treating it as a redacted
/// result. It performs format safety and DOCX text round-trip verification only; it deliberately
/// does not run privacy publication validation. Callers must keep this output outside MCP result
/// reads and other redacted-result channels.
pub fn export_local_document(text: &str, format: &str) -> Result<Vec<u8>, TextError> {
    validate_document_text(text)?;
    export_document(text, format, false)
}

fn export_document(text: &str, format: &str, redacted_result: bool) -> Result<Vec<u8>, TextError> {
    match format.trim().to_ascii_lowercase().as_str() {
        "txt" | "text" => Ok(text.as_bytes().to_vec()),
        "md" | "markdown" => Ok(text.as_bytes().to_vec()),
        "docx" => {
            let bytes = export_docx(text)?;
            let extracted = file_ingest::extract_plain_text("redacted.docx", &bytes, None)
                .map_err(|_| TextError::ExportVerificationFailed)?;
            if extracted != text {
                return Err(TextError::ExportVerificationFailed);
            }
            if redacted_result {
                validate_export_text(&extracted)?;
            } else {
                validate_document_text(&extracted)?;
            }
            Ok(bytes)
        }
        _ => Err(TextError::UnsupportedExportFormat),
    }
}

fn build_analysis(
    text: &str,
    namespace: &str,
    candidates: Vec<Candidate>,
    dismissed: &[String],
    ambiguous_organization_values: &BTreeSet<String>,
) -> Result<Analysis, TextError> {
    let candidates = suppress_redundant_local_ner(text, candidates);
    let mut grouped = BTreeMap::<(usize, usize), Vec<Candidate>>::new();
    for candidate in candidates {
        grouped
            .entry((candidate.start, candidate.end))
            .or_default()
            .push(candidate);
    }
    let dismissed = dismissed.iter().collect::<BTreeSet<_>>();
    let mut groups = Vec::with_capacity(grouped.len());

    for ((start, end), values) in grouped {
        let value = text.get(start..end).ok_or(TextError::AnalysisFailed)?;
        let kinds = values
            .iter()
            .map(|candidate| candidate.kind)
            .collect::<BTreeSet<_>>();
        let sources = values
            .iter()
            .map(|candidate| candidate.source)
            .collect::<BTreeSet<_>>();
        let aliases = values
            .iter()
            .map(|candidate| candidate.alias.as_str())
            .collect::<BTreeSet<_>>();
        let dictionary_aliases = values
            .iter()
            .filter(|candidate| candidate.source == "dictionary")
            .map(|candidate| candidate.alias.as_str())
            .collect::<BTreeSet<_>>();
        let kind = *kinds.iter().next().ok_or(TextError::AnalysisFailed)?;
        let id = finding_id(namespace, start, end, kind, value);
        let only_ner = sources.len() == 1 && sources.contains("local_ner");
        let model_only_custom =
            sources.len() == 1 && sources.contains("ai") && kind == EntityType::Custom;
        let dismissed = dismissed.contains(&id) && (only_ner || model_only_custom);
        let has_dictionary = sources.contains("dictionary");
        let has_ner = sources.contains("local_ner");
        let has_cloud = sources.contains("cloud");
        let has_automatic_ai = values
            .iter()
            .any(|candidate| candidate.source == "ai" && candidate.automatic_allowed);
        let deterministic = values.iter().any(|candidate| candidate.deterministic);
        let deterministic_automatic = values
            .iter()
            .filter(|candidate| candidate.deterministic)
            .all(|candidate| candidate.automatic_allowed);
        // A single manually-confirmed dictionary alias is authoritative over a model-derived
        // alias for the same exact value. Multiple dictionary aliases remain an explicit conflict
        // and therefore stay in review.
        let alias = if dictionary_aliases.len() == 1 {
            dictionary_aliases
                .iter()
                .next()
                .map(|value| (*value).to_owned())
        } else if dictionary_aliases.is_empty() && aliases.len() == 1 {
            aliases.iter().next().map(|value| (*value).to_owned())
        } else {
            None
        };
        let ambiguous_organization =
            kind == EntityType::OrganizationName && ambiguous_organization_values.contains(value);
        let automatic = !ambiguous_organization
            && kinds.len() == 1
            && alias.is_some()
            && (has_dictionary
                || (deterministic && deterministic_automatic)
                || (!deterministic && has_ner && (has_cloud || has_automatic_ai))
                // `custom` has no bounded semantics.  A model-only custom value may be an
                // ordinary date, amount, or other fact, so it needs local deterministic or
                // dictionary corroboration before publication can remove it.
                || (!deterministic && has_automatic_ai && kind != EntityType::Custom));
        groups.push(Group {
            start,
            end,
            finding: Finding {
                id,
                text: value.to_owned(),
                kind: entity_kind(kind).to_owned(),
                alias,
                source: sources.into_iter().collect::<Vec<_>>().join("+"),
                resolved: automatic || dismissed,
                dismissed,
            },
            replace: automatic,
        });
    }

    mark_conflicting_repeated_people(text, &mut groups);
    resolve_conflicting_replacement_overlaps(&mut groups);

    // An unresolved local-NER range may enclose a separately confirmed entity.  Preserve the
    // review finding while applying the independently verified, non-overlapping replacements;
    // only two replacement candidates that overlap make their component unsafe to apply.
    let (output, replacements) = apply_replacements(text, &groups)?;
    let mut analysis = Analysis {
        text: output,
        findings: groups.into_iter().map(|group| group.finding).collect(),
        ai_findings: None,
        replacements,
        needs_review: false,
        source_sha256: sha256_hex(text.as_bytes()),
        output_sha256: String::new(),
    };
    analysis.output_sha256 = sha256_hex(analysis.text.as_bytes());
    verify_analysis_source(text, &analysis)?;
    analysis.needs_review = analysis.findings.iter().any(|finding| !finding.resolved)
        || validate_result(&analysis.text, &analysis.findings).is_err();
    if !analysis.needs_review {
        validate_analysis(&analysis)?;
    }
    Ok(analysis)
}

fn mark_conflicting_repeated_people(text: &str, groups: &mut [Group]) {
    let mut occurrences = BTreeMap::<String, Vec<usize>>::new();
    for (index, group) in groups.iter().enumerate() {
        if group.finding.kind != entity_kind(EntityType::PersonName)
            || group.finding.dismissed
            || group
                .finding
                .source
                .split('+')
                .any(|source| source == "dictionary")
            || !group
                .finding
                .source
                .split('+')
                .any(|source| matches!(source, "ai" | "local_ner"))
        {
            continue;
        }
        occurrences
            .entry(group.finding.text.clone())
            .or_default()
            .push(index);
    }
    for indices in occurrences
        .into_values()
        .filter(|indices| indices.len() > 1)
    {
        let contexts = indices
            .iter()
            .filter_map(|index| {
                groups
                    .get(*index)
                    .and_then(|group| person_party_context(text, group.start))
            })
            .collect::<BTreeSet<_>>();
        let name = indices
            .first()
            .and_then(|index| groups.get(*index))
            .map(|group| group.finding.text.as_str())
            .unwrap_or_default();
        if contexts.len() < 2 && !same_person_name_has_explicit_identity_ambiguity(text, name) {
            continue;
        }
        for index in indices {
            if let Some(group) = groups.get_mut(index) {
                group.finding.resolved = false;
                group.replace = false;
            }
        }
    }
}

fn same_person_name_has_explicit_identity_ambiguity(text: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let paired_name_marker = ["两位", "两名", "两个", "多位", "多名"]
        .into_iter()
        .any(|count| text.contains(&format!("{count}姓名均为{name}")));
    let another_occurrence = ["另一位", "另一名", "另一个"]
        .into_iter()
        .any(|prefix| text.contains(&format!("{prefix}{name}")));
    let explicit_identity_conflict = [
        "身份不同",
        "不同身份",
        "身份不一致",
        "非同一人",
        "不是同一人",
        "并非同一人",
    ]
    .into_iter()
    .any(|marker| text.contains(marker));
    paired_name_marker
        || another_occurrence
        || (text.contains("同名") && explicit_identity_conflict)
}

fn resolve_conflicting_replacement_overlaps(groups: &mut [Group]) {
    let mut component_start = 0usize;
    while component_start < groups.len() {
        let mut component_end = component_start + 1;
        let mut farthest_end = groups[component_start].end;
        while component_end < groups.len() && groups[component_end].start < farthest_end {
            farthest_end = farthest_end.max(groups[component_end].end);
            component_end += 1;
        }
        if component_end - component_start > 1 {
            let conflicting_replacements = (component_start..component_end).any(|left| {
                groups[left].replace
                    && (left + 1..component_end).any(|right| {
                        groups[right].replace
                            && groups[right].start < groups[left].end
                            && groups[left].start < groups[right].end
                    })
            });
            if conflicting_replacements {
                for group in &mut groups[component_start..component_end] {
                    if !group.finding.dismissed {
                        group.finding.resolved = false;
                        group.replace = false;
                    }
                }
            }
        }
        component_start = component_end;
    }
}

fn person_party_context(text: &str, name_start: usize) -> Option<&'static str> {
    let before_name = text.get(..name_start)?;
    let segment_start = before_name
        .char_indices()
        .rev()
        .find(|(_, character)| matches!(character, '\n' | '。' | '；' | ';'))
        .map_or(0, |(offset, character)| offset + character.len_utf8());
    let segment = before_name.get(segment_start..)?;
    [
        ("被申请人", "respondent"),
        ("被上诉人", "appellee"),
        ("第三人", "third_party"),
        ("申请人", "applicant"),
        ("上诉人", "appellant"),
        ("委托人", "principal"),
        ("受托人", "agent"),
        ("原告", "plaintiff"),
        ("被告", "defendant"),
        ("甲方", "party_a"),
        ("乙方", "party_b"),
        ("丙方", "party_c"),
    ]
    .into_iter()
    .filter_map(|(label, identity)| segment.rfind(label).map(|offset| (offset, label, identity)))
    .max_by_key(|(offset, label, _)| (*offset, label.len()))
    .map(|(_, _, identity)| identity)
}

fn suppress_redundant_local_ner(text: &str, candidates: Vec<Candidate>) -> Vec<Candidate> {
    let ai_ranges = candidates
        .iter()
        .filter(|candidate| candidate.source == "ai")
        .map(|candidate| (candidate.start, candidate.end, candidate.kind))
        .collect::<Vec<_>>();
    candidates
        .into_iter()
        .filter(|candidate| {
            if candidate.source != "local_ner" {
                return true;
            }
            !ai_ranges.iter().any(|(ai_start, ai_end, ai_kind)| {
                if *ai_kind != candidate.kind {
                    return false;
                }
                if *ai_start <= candidate.start
                    && *ai_end >= candidate.end
                    && (*ai_start < candidate.start || *ai_end > candidate.end)
                {
                    return true;
                }
                candidate.start <= *ai_start
                    && candidate.end >= *ai_end
                    && (candidate.start < *ai_start || candidate.end > *ai_end)
                    && local_ner_wrapper_is_safe(
                        text,
                        candidate.start,
                        candidate.end,
                        *ai_start,
                        *ai_end,
                    )
            })
        })
        .collect()
}

fn local_ner_wrapper_is_safe(
    text: &str,
    local_start: usize,
    local_end: usize,
    ai_start: usize,
    ai_end: usize,
) -> bool {
    let Some(prefix) = text.get(local_start..ai_start) else {
        return false;
    };
    let Some(suffix) = text.get(ai_end..local_end) else {
        return false;
    };
    is_known_ner_context(prefix) && is_known_ner_context(suffix)
}

fn is_known_ner_context(value: &str) -> bool {
    let value = value.trim_matches(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                ':' | '：' | ',' | '，' | ';' | '；' | '、' | '(' | '（' | ')' | '）'
            )
    });
    matches!(
        value,
        "" | "与"
            | "及"
            | "和"
            | "或"
            | "简称"
            | "全称"
            | "原告"
            | "被告"
            | "甲方"
            | "乙方"
            | "申请人"
            | "被申请人"
            | "联系人"
            | "法定代表人"
    )
}

fn apply_replacements(
    text: &str,
    groups: &[Group],
) -> Result<(String, Vec<Replacement>), TextError> {
    let mut output = String::with_capacity(text.len());
    let mut replacements = Vec::new();
    let mut cursor = 0usize;
    for group in groups.iter().filter(|group| group.replace) {
        if group.start < cursor || group.end < group.start {
            return Err(TextError::AnalysisFailed);
        }
        output.push_str(
            text.get(cursor..group.start)
                .ok_or(TextError::AnalysisFailed)?,
        );
        if group.replace {
            let alias = group
                .finding
                .alias
                .as_deref()
                .ok_or(TextError::AnalysisFailed)?;
            let output_start = output.len();
            output.push_str(alias);
            let output_end = output.len();
            replacements.push(Replacement {
                finding_id: group.finding.id.clone(),
                source_start: group.start,
                source_end: group.end,
                output_start,
                output_end,
                alias: alias.to_owned(),
            });
        } else {
            output.push_str(
                text.get(group.start..group.end)
                    .ok_or(TextError::AnalysisFailed)?,
            );
        }
        cursor = group.end;
    }
    output.push_str(text.get(cursor..).ok_or(TextError::AnalysisFailed)?);
    Ok((output, replacements))
}

fn verify_output_replacement_evidence(
    output: &str,
    findings: &[Finding],
    replacements: &[Replacement],
) -> Result<(), TextError> {
    if findings.len() > MAX_FINDINGS || replacements.len() > MAX_FINDINGS {
        return Err(TextError::TooManyFindings);
    }
    let expected = findings
        .iter()
        .filter(|finding| finding.resolved && !finding.dismissed)
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != replacements.len() {
        return Err(TextError::EvidenceVerificationFailed);
    }

    let mut previous_source_end = 0usize;
    let mut previous_output_end = 0usize;
    let mut seen = BTreeSet::new();
    for replacement in replacements {
        if !seen.insert(replacement.finding_id.as_str())
            || replacement.source_start > replacement.source_end
            || replacement
                .source_end
                .saturating_sub(replacement.source_start)
                == 0
            || replacement.output_start < previous_output_end
            || replacement.source_start < previous_source_end
        {
            return Err(TextError::EvidenceVerificationFailed);
        }
        let finding = expected
            .get(replacement.finding_id.as_str())
            .ok_or(TextError::EvidenceVerificationFailed)?;
        let alias = finding
            .alias
            .as_deref()
            .ok_or(TextError::EvidenceVerificationFailed)?;
        if alias != replacement.alias
            || !matches!(
                output.get(replacement.output_start..replacement.output_end),
                Some(value) if value == replacement.alias.as_str()
            )
        {
            return Err(TextError::EvidenceVerificationFailed);
        }
        previous_source_end = replacement.source_end;
        previous_output_end = replacement.output_end;
    }
    if seen.len() != expected.len() {
        return Err(TextError::EvidenceVerificationFailed);
    }
    Ok(())
}

fn verify_source_replacement_evidence(
    source: &str,
    output: &str,
    findings: &[Finding],
    replacements: &[Replacement],
) -> Result<(), TextError> {
    let finding_by_id = findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let mut rebuilt = String::with_capacity(output.len());
    let mut cursor = 0usize;
    for replacement in replacements {
        let finding = finding_by_id
            .get(replacement.finding_id.as_str())
            .ok_or(TextError::EvidenceVerificationFailed)?;
        let source_value = source
            .get(replacement.source_start..replacement.source_end)
            .ok_or(TextError::EvidenceVerificationFailed)?;
        if source_value != finding.text {
            return Err(TextError::EvidenceVerificationFailed);
        }
        rebuilt.push_str(
            source
                .get(cursor..replacement.source_start)
                .ok_or(TextError::EvidenceVerificationFailed)?,
        );
        rebuilt.push_str(&replacement.alias);
        cursor = replacement.source_end;
    }
    rebuilt.push_str(
        source
            .get(cursor..)
            .ok_or(TextError::EvidenceVerificationFailed)?,
    );
    if rebuilt != output {
        return Err(TextError::EvidenceVerificationFailed);
    }
    Ok(())
}

fn push_privacy_candidate(
    destination: &mut Vec<Candidate>,
    text: &str,
    candidate: privacy::finding_engine::FindingCandidateV1,
    source: &'static str,
    deterministic: bool,
) -> Result<(), TextError> {
    let start = usize::try_from(candidate.start_offset).map_err(|_| TextError::AnalysisFailed)?;
    let end = usize::try_from(candidate.end_offset).map_err(|_| TextError::AnalysisFailed)?;
    let value = text.get(start..end).ok_or(TextError::AnalysisFailed)?;
    let alias = candidate
        .proposed_replacement
        .unwrap_or_else(|| stable_alias("fallback", candidate.entity_type, value));
    validate_alias(&alias)?;
    push_candidate(
        destination,
        Candidate {
            start,
            end,
            kind: candidate.entity_type,
            source,
            alias,
            deterministic,
            automatic_allowed: candidate.validation_passed
                && candidate.automatic_replacement_allowed,
        },
    )
}

fn local_ner_candidate_is_semantically_plausible(
    text: &str,
    candidate: &privacy::finding_engine::FindingCandidateV1,
) -> Result<bool, TextError> {
    let start = usize::try_from(candidate.start_offset).map_err(|_| TextError::AnalysisFailed)?;
    let end = usize::try_from(candidate.end_offset).map_err(|_| TextError::AnalysisFailed)?;
    let value = text.get(start..end).ok_or(TextError::AnalysisFailed)?;
    match candidate.entity_type {
        // A model-only address guess must carry at least one concrete Chinese location component.
        // This rejects label-value prose such as “地址已另案保管”, which contains no location at all;
        // verified dictionary, deterministic, and cloud candidates remain governed by their own
        // evidence paths and are not filtered here.
        EntityType::Address => Ok(value.chars().any(|character| {
            matches!(
                character,
                '省' | '市'
                    | '区'
                    | '县'
                    | '旗'
                    | '乡'
                    | '镇'
                    | '村'
                    | '街'
                    | '路'
                    | '巷'
                    | '弄'
                    | '号'
                    | '栋'
                    | '幢'
            )
        })),
        // These are grammatical/field-label tokens, never standalone personal names.  The local
        // model is deliberately a conservative candidate source; retaining these tokens would
        // create a review-only false positive without adding privacy coverage.
        EntityType::PersonName => Ok(!is_obvious_non_person_local_ner_token(value)),
        // Reject a local NER span only when its own text is sentence syntax rather than an
        // organization name.  We do not use a model range as proof that a broader local range is
        // an entity, so a plausible uncorroborated organization still remains reviewable.
        EntityType::OrganizationName => Ok(!has_non_organization_clause_syntax(value)),
        _ => Ok(true),
    }
}

fn is_obvious_non_person_local_ner_token(value: &str) -> bool {
    matches!(
        value,
        "电话"
            | "手机"
            | "邮箱"
            | "地址"
            | "姓名"
            | "人员"
            | "联系人"
            | "相同"
            | "均为"
            | "当成"
            | "作为"
            | "需要"
            | "应当"
            | "其中"
            | "双方"
            | "本案"
            | "材料"
    )
}

fn has_non_organization_clause_syntax(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.chars().next().is_some_and(|character| {
        matches!(
            character,
            '与' | '和' | '及' | '或' | '向' | '由' | '在' | '对'
        )
    }) {
        return true;
    }
    if [
        "原告",
        "被告",
        "申请人",
        "被申请人",
        "上诉人",
        "被上诉人",
        "承租人",
        "出租人",
        "患者",
        "联系人",
        "法定代表人",
    ]
    .into_iter()
    .any(|role| trimmed.contains(role))
    {
        return true;
    }
    if trimmed.contains('自')
        && trimmed.contains('在')
        && trimmed.chars().any(|character| character.is_ascii_digit())
    {
        return true;
    }
    trimmed
        .split_once('与')
        .is_some_and(|(left, right)| !right.is_empty() && looks_like_short_han_name(left))
}

fn looks_like_short_han_name(value: &str) -> bool {
    let characters = value.chars().collect::<Vec<_>>();
    (2..=4).contains(&characters.len())
        && characters
            .iter()
            .all(|character| ('\u{4e00}'..='\u{9fff}').contains(character))
}

fn push_candidate(destination: &mut Vec<Candidate>, candidate: Candidate) -> Result<(), TextError> {
    if destination.len() >= MAX_FINDINGS {
        return Err(TextError::TooManyFindings);
    }
    destination.push(candidate);
    Ok(())
}

fn validate_ai_inputs(text: &str, findings: &[AiFinding]) -> Result<(), TextError> {
    if findings.len() > MAX_AI_FINDINGS {
        return Err(TextError::TooManyFindings);
    }
    for finding in findings {
        if finding.text.is_empty()
            || finding.text.len() > MAX_AI_FINDING_TEXT_BYTES
            || finding.text.contains('\0')
            || finding.start >= finding.end
            || finding.end > text.len()
            || !text.is_char_boundary(finding.start)
            || !text.is_char_boundary(finding.end)
            || text.get(finding.start..finding.end) != Some(finding.text.as_str())
        {
            return Err(TextError::CloudFindingAbsent);
        }
        if finding
            .confidence_ppm
            .is_some_and(|confidence| confidence > 1_000_000)
        {
            return Err(TextError::InvalidInput);
        }
        parse_entity_kind(&finding.kind)?;
    }
    Ok(())
}

fn validate_inputs(
    text: &str,
    namespace: &str,
    dictionary: &[DictionaryEntry],
    cloud: &[CloudFinding],
    dismissed: &[String],
) -> Result<(), TextError> {
    if text.len() > file_ingest::MAX_TEXT_BYTES
        || text.len() > u32::MAX as usize
        || text.contains('\0')
    {
        return Err(TextError::InvalidInput);
    }
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || namespace.trim() != namespace
        || namespace.chars().any(char::is_control)
    {
        return Err(TextError::InvalidNamespace);
    }
    if dictionary.len() > MAX_DICTIONARY_ENTRIES
        || cloud.len() > MAX_CLOUD_FINDINGS
        || dismissed.len() > MAX_DISMISSED_FINDINGS
    {
        return Err(TextError::TooManyFindings);
    }
    for entry in dictionary {
        if !safe_term(&entry.text) {
            return Err(TextError::InvalidInput);
        }
        let _ = parse_entity_kind(&entry.kind)?;
        if let Some(alias) = &entry.alias {
            validate_alias(alias)?;
        }
    }
    for finding in cloud {
        if !safe_term(&finding.text) || !text.contains(&finding.text) {
            return Err(TextError::CloudFindingAbsent);
        }
        let _ = parse_entity_kind(&finding.kind)?;
    }
    if dismissed.iter().any(|id| !valid_finding_id(id)) {
        return Err(TextError::InvalidInput);
    }
    Ok(())
}

fn validate_finding(finding: &Finding) -> Result<(), TextError> {
    let kind = parse_entity_kind(&finding.kind)?;
    if !valid_finding_id(&finding.id)
        || !safe_term(&finding.text)
        || finding.source.is_empty()
        || finding.source.len() > 128
        || finding.source.chars().any(char::is_control)
        || finding
            .alias
            .as_deref()
            .is_some_and(|alias| validate_alias(alias).is_err())
        || (finding.dismissed
            && (!finding.resolved
                || !((finding.source == "local_ner"
                    && matches!(
                        kind,
                        EntityType::PersonName | EntityType::OrganizationName | EntityType::Address
                    ))
                    || (finding.source == "ai" && kind == EntityType::Custom))))
    {
        return Err(TextError::InvalidInput);
    }
    Ok(())
}

fn validate_export_text(text: &str) -> Result<(), TextError> {
    validate_document_text(text)?;
    let pages = [text.to_owned()];
    let report = scan_independent_residuals(IndependentResidualScanInputV1 {
        pages: &pages,
        dictionary_terms: &[],
        source_names: &[],
    })
    .map_err(|_| TextError::AnalysisFailed)?;
    let has_blocking_residual = report
        .hits
        .iter()
        .any(|hit| hit.blocking && !ignorable_residual_hit(&pages, hit))
        || has_credential_residual(text);
    if !has_blocking_residual {
        Ok(())
    } else {
        Err(TextError::ResidualRisk)
    }
}

fn validate_document_text(text: &str) -> Result<(), TextError> {
    if text.len() > file_ingest::MAX_TEXT_BYTES || text.contains('\0') || text.contains('\r') {
        return Err(TextError::InvalidInput);
    }
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(TextError::InvalidInput);
    }
    Ok(())
}

fn export_docx(text: &str) -> Result<Vec<u8>, TextError> {
    let mut body = String::with_capacity(text.len().saturating_mul(2).saturating_add(128));
    body.push_str("<w:p><w:r>");
    let mut fragments = text.split('\n').peekable();
    while let Some(fragment) = fragments.next() {
        if !fragment.is_empty() {
            body.push_str(r#"<w:t xml:space="preserve">"#);
            escape_xml_into(fragment, &mut body);
            body.push_str("</w:t>");
        }
        if fragments.peek().is_some() {
            body.push_str("<w:br/>");
        }
    }
    body.push_str("</w:r></w:p>");
    let document_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{body}<w:sectPr/></w:body></w:document>"#
    );
    let fixed_time = DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0)
        .map_err(|_| TextError::ExportVerificationFailed)?;
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .last_modified_time(fixed_time)
        .unix_permissions(0o644);
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content) in [
        ("[Content_Types].xml", CONTENT_TYPES_XML),
        ("_rels/.rels", ROOT_RELS_XML),
        ("word/document.xml", document_xml.as_str()),
    ] {
        writer
            .start_file(name, options)
            .map_err(|_| TextError::ExportVerificationFailed)?;
        writer
            .write_all(content.as_bytes())
            .map_err(|_| TextError::ExportVerificationFailed)?;
    }
    writer
        .finish()
        .map(|cursor| cursor.into_inner())
        .map_err(|_| TextError::ExportVerificationFailed)
}

fn escape_xml_into(value: &str, output: &mut String) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '\'' => output.push_str("&apos;"),
            '"' => output.push_str("&quot;"),
            _ => output.push(character),
        }
    }
}

fn opaque_case_id(namespace: &str) -> Result<CaseId, TextError> {
    CaseId::parse(format!(
        "case_{}",
        &opaque_hash(&[b"privacy-text-case-v1", namespace.as_bytes()])[..32]
    ))
    .map_err(|_| TextError::AnalysisFailed)
}

fn opaque_material_id(text: &str) -> Result<MaterialId, TextError> {
    MaterialId::parse(format!(
        "mat_{}",
        &opaque_hash(&[b"privacy-text-material-v1", text.as_bytes()])[..32]
    ))
    .map_err(|_| TextError::AnalysisFailed)
}

fn finding_id(namespace: &str, start: usize, end: usize, kind: EntityType, value: &str) -> String {
    let position = format!("{start}:{end}");
    format!(
        "fnd_{}",
        &opaque_hash(&[
            b"privacy-text-finding-v1",
            namespace.as_bytes(),
            position.as_bytes(),
            entity_kind(kind).as_bytes(),
            normalize_sensitive_text(value).as_bytes(),
        ])[..32]
    )
}

fn stable_alias(namespace: &str, kind: EntityType, value: &str) -> String {
    let digest = opaque_hash(&[
        b"privacy-text-alias-v1",
        namespace.as_bytes(),
        entity_kind(kind).as_bytes(),
        normalize_sensitive_text(value).as_bytes(),
    ]);
    // A raw hexadecimal digest can coincidentally contain an 8+ digit run. The independent
    // residual scanner must correctly block such a run in document text, so using raw hex here
    // would make publication vary with the namespace. Encode each nibble as `a` through `p`:
    // it keeps the full 40-bit stable alias token while ensuring aliases cannot mimic numbers.
    format!("[{}_{}]", entity_alias_stem(kind), alias_token(&digest))
}

fn alias_token(hex_digest: &str) -> String {
    hex_digest
        .bytes()
        .take(10)
        .map(|value| match value {
            b'0'..=b'9' => char::from(b'a' + value - b'0'),
            b'a'..=b'f' => char::from(b'k' + value - b'a'),
            _ => 'z',
        })
        .collect()
}

fn opaque_hash(parts: &[&[u8]]) -> String {
    let mut material = Vec::new();
    for part in parts {
        material.extend_from_slice(&(part.len() as u64).to_be_bytes());
        material.extend_from_slice(part);
    }
    sha256_hex(&material)
}

fn valid_finding_id(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("fnd_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_term(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .chars()
            .all(|character| !character.is_control() && character != '\0')
}

fn validate_alias(value: &str) -> Result<(), TextError> {
    if value.len() < 4
        || value.len() > 128
        || !value.starts_with('[')
        || !value.ends_with(']')
        || value.contains("..")
        || value.chars().any(char::is_control)
    {
        return Err(TextError::InvalidInput);
    }
    Ok(())
}

fn entity_kind(entity_type: EntityType) -> &'static str {
    match entity_type {
        EntityType::PersonName => "person_name",
        EntityType::OrganizationName => "organization_name",
        EntityType::CaseNumber => "case_number",
        EntityType::IdentityNumber => "identity_number",
        EntityType::PassportNumber => "passport_number",
        EntityType::PhoneNumber => "phone_number",
        EntityType::LandlineNumber => "landline_number",
        EntityType::BankAccount => "bank_account",
        EntityType::EmailAddress => "email_address",
        EntityType::Address => "address",
        EntityType::OrganizationCode => "organization_code",
        EntityType::BusinessLicenseNumber => "business_license_number",
        EntityType::VehiclePlate => "vehicle_plate",
        EntityType::IpAddress => "ip_address",
        EntityType::SocialAccount => "social_account",
        EntityType::PaymentAccount => "payment_account",
        EntityType::AccountName => "account_name",
        EntityType::ContractNumber => "contract_number",
        EntityType::TrackingNumber => "tracking_number",
        EntityType::PropertyCertificateNumber => "property_certificate_number",
        EntityType::Custom => "custom",
    }
}

fn entity_alias_stem(entity_type: EntityType) -> &'static str {
    match entity_type {
        EntityType::PersonName => "PERSON",
        EntityType::OrganizationName => "ORG",
        EntityType::CaseNumber => "CASE",
        EntityType::IdentityNumber => "ID",
        EntityType::PassportNumber => "PASSPORT",
        EntityType::PhoneNumber | EntityType::LandlineNumber => "PHONE",
        EntityType::BankAccount | EntityType::PaymentAccount => "ACCOUNT",
        EntityType::EmailAddress => "EMAIL",
        EntityType::Address => "ADDRESS",
        EntityType::OrganizationCode | EntityType::BusinessLicenseNumber => "ORGCODE",
        EntityType::VehiclePlate => "PLATE",
        EntityType::IpAddress => "IP",
        EntityType::SocialAccount => "SOCIAL",
        EntityType::AccountName => "ACCOUNTNAME",
        EntityType::ContractNumber => "CONTRACT",
        EntityType::TrackingNumber => "TRACKING",
        EntityType::PropertyCertificateNumber => "PROPERTY",
        EntityType::Custom => "CUSTOM",
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::{build_analysis, entity_kind, stable_alias, Candidate, EntityType};
    use std::collections::BTreeSet;

    #[test]
    fn unresolved_local_overlap_does_not_block_a_separate_verified_replacement() {
        let text = "甲方李明签署。";
        let person_start = text.find("李明").expect("person");
        let analysis = build_analysis(
            text,
            "overlap-component",
            vec![
                Candidate {
                    start: 0,
                    end: person_start + "李明".len(),
                    kind: EntityType::OrganizationName,
                    source: "local_ner",
                    alias: stable_alias(
                        "overlap-component",
                        EntityType::OrganizationName,
                        "甲方李明",
                    ),
                    deterministic: false,
                    automatic_allowed: false,
                },
                Candidate {
                    start: person_start,
                    end: person_start + "李明".len(),
                    kind: EntityType::PersonName,
                    source: "ai",
                    alias: stable_alias("overlap-component", EntityType::PersonName, "李明"),
                    deterministic: false,
                    automatic_allowed: true,
                },
            ],
            &[],
            &BTreeSet::new(),
        )
        .expect("overlap analysis");

        assert!(analysis.needs_review);
        assert_eq!(analysis.replacements.len(), 1);
        assert!(!analysis.text.contains("李明"));
        assert!(analysis.findings.iter().any(|finding| {
            finding.source == "local_ner"
                && finding.kind == entity_kind(EntityType::OrganizationName)
                && !finding.resolved
        }));
        assert!(analysis.findings.iter().any(|finding| {
            finding.source == "ai"
                && finding.kind == entity_kind(EntityType::PersonName)
                && finding.resolved
        }));
    }

    #[test]
    fn overlapping_verified_replacements_remain_for_review() {
        let text = "甲方李明签署。";
        let person_start = text.find("李明").expect("person");
        let analysis = build_analysis(
            text,
            "conflicting-overlap",
            vec![
                Candidate {
                    start: 0,
                    end: person_start + "李明".len(),
                    kind: EntityType::OrganizationName,
                    source: "ai",
                    alias: stable_alias(
                        "conflicting-overlap",
                        EntityType::OrganizationName,
                        "甲方李明",
                    ),
                    deterministic: false,
                    automatic_allowed: true,
                },
                Candidate {
                    start: person_start,
                    end: person_start + "李明".len(),
                    kind: EntityType::PersonName,
                    source: "ai",
                    alias: stable_alias("conflicting-overlap", EntityType::PersonName, "李明"),
                    deterministic: false,
                    automatic_allowed: true,
                },
            ],
            &[],
            &BTreeSet::new(),
        )
        .expect("conflicting overlap analysis");

        assert!(analysis.needs_review);
        assert!(analysis.replacements.is_empty());
        assert_eq!(analysis.text, text);
        assert!(analysis.findings.iter().all(|finding| !finding.resolved));
    }
}

fn parse_entity_kind(value: &str) -> Result<EntityType, TextError> {
    match value {
        "person_name" | "person" => Ok(EntityType::PersonName),
        "organization_name" | "organization" => Ok(EntityType::OrganizationName),
        "case_number" => Ok(EntityType::CaseNumber),
        "identity_number" | "id_card" => Ok(EntityType::IdentityNumber),
        "passport_number" => Ok(EntityType::PassportNumber),
        "phone_number" | "phone" => Ok(EntityType::PhoneNumber),
        "landline_number" => Ok(EntityType::LandlineNumber),
        "bank_account" => Ok(EntityType::BankAccount),
        "email_address" | "email" => Ok(EntityType::EmailAddress),
        "address" => Ok(EntityType::Address),
        "organization_code" => Ok(EntityType::OrganizationCode),
        "business_license_number" => Ok(EntityType::BusinessLicenseNumber),
        "vehicle_plate" => Ok(EntityType::VehiclePlate),
        "ip_address" => Ok(EntityType::IpAddress),
        "social_account" => Ok(EntityType::SocialAccount),
        "payment_account" => Ok(EntityType::PaymentAccount),
        "account_name" => Ok(EntityType::AccountName),
        "contract_number" => Ok(EntityType::ContractNumber),
        "tracking_number" => Ok(EntityType::TrackingNumber),
        "property_certificate_number" => Ok(EntityType::PropertyCertificateNumber),
        "custom" => Ok(EntityType::Custom),
        _ => Err(TextError::InvalidInput),
    }
}
