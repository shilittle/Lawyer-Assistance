//! Offline deterministic sensitive-field detection with a mandatory encrypted-vault boundary.
//!
//! Matched private text is borrowed only for the duration of one batch callback. Public findings
//! receive a case-keyed fingerprint and a real opaque vault reference, never the matched value.

use crate::{
    finding_engine::FindingCandidateV1,
    sha256_hex,
    vnext::{CaseId, ConfidencePpm, EntityType, MaterialId, PrivateValueRefV1, Sha256Hex},
};
use regex::{Captures, Regex};
use std::{collections::BTreeSet, error::Error, fmt};

pub const DETERMINISTIC_DETECTOR_VERSION: &str = "privacy-deterministic-cn-v2";
pub const MAX_DETERMINISTIC_MATCHES_PER_BLOCK: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeterministicDetectorError {
    InvalidContext,
    PatternUnavailable,
    MatchLimitExceeded,
    PrivateValueStoreFailed,
    InvalidPrivateBinding,
}

impl fmt::Display for DeterministicDetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidContext => "deterministic_detector_invalid_context",
            Self::PatternUnavailable => "deterministic_detector_pattern_unavailable",
            Self::MatchLimitExceeded => "deterministic_detector_match_limit_exceeded",
            Self::PrivateValueStoreFailed => "deterministic_detector_private_store_failed",
            Self::InvalidPrivateBinding => "deterministic_detector_private_binding_invalid",
        })
    }
}

impl Error for DeterministicDetectorError {}

#[derive(Clone, Copy)]
pub struct DetectionContextV1<'a> {
    pub case_id: &'a CaseId,
    pub material_id: &'a MaterialId,
    pub document_version: u64,
    pub page_index: u32,
    pub block_id: &'a str,
    pub ocr_confidence_ppm: Option<ConfidencePpm>,
    pub layout_confidence_ppm: Option<ConfidencePpm>,
}

impl fmt::Debug for DetectionContextV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DetectionContextV1")
            .field("case_id", &self.case_id)
            .field("material_id", &self.material_id)
            .field("document_version", &self.document_version)
            .field("page_index", &self.page_index)
            .field("block_id", &self.block_id)
            .field("ocr_confidence_ppm", &self.ocr_confidence_ppm)
            .field("layout_confidence_ppm", &self.layout_confidence_ppm)
            .finish()
    }
}

/// Borrowed request passed synchronously to the App-owned vault broker.
///
/// This type deliberately has no `Debug`, `Clone`, `Serialize`, or owned private string.
pub struct StorePrivateValueRequestV1<'a> {
    pub case_id: &'a CaseId,
    pub material_id: &'a MaterialId,
    pub document_version: u64,
    pub page_index: u32,
    pub block_id: &'a str,
    pub start_offset: u32,
    pub end_offset: u32,
    pub entity_type: EntityType,
    pub private_value: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPrivateValueBindingV1 {
    /// Must be keyed per case; plain SHA-256 of the value is forbidden.
    pub value_fingerprint: Sha256Hex,
    pub private_value_ref: PrivateValueRefV1,
    pub proposed_replacement: String,
}

/// Batch bridge used to seal all values in one encrypted ReviewDraft object.
pub trait PrivateValueSinkV1 {
    fn store_private_values(
        &mut self,
        requests: &[StorePrivateValueRequestV1<'_>],
    ) -> Result<Vec<StoredPrivateValueBindingV1>, DeterministicDetectorError>;
}

#[derive(Debug, Clone, Copy)]
struct Rule {
    entity_type: EntityType,
    source: &'static str,
    pattern: &'static str,
    confidence_ppm: u32,
    validator: Validator,
    replacement_verified: bool,
}

#[derive(Debug, Clone, Copy)]
enum Validator {
    None,
    ChinaIdentity,
    Mobile,
    Landline,
    BankCard,
    Email,
    CaseNumber,
    UnifiedSocialCredit,
    LegacyBusinessLicense,
    VehiclePlate,
    Ipv4,
    Passport,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Match {
    start: usize,
    end: usize,
    entity_type: EntityType,
    source: &'static str,
    confidence_ppm: u32,
    validation_passed: bool,
    replacement_verified: bool,
}

// All non-ASCII literals use regex code-point escapes so this source and its fixtures remain
// portable across Windows code pages.
const RULES: &[Rule] = &[
    Rule {
        entity_type: EntityType::IdentityNumber,
        source: "cn_identity_checksum",
        pattern: r"(?i)(?:^|[^0-9A-Z])(?P<value>[1-9][0-9]{16}[0-9X])(?:$|[^0-9A-Z])",
        confidence_ppm: 1_000_000,
        validator: Validator::ChinaIdentity,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::PhoneNumber,
        source: "cn_mobile",
        pattern: r"(?:^|[^0-9])(?P<value>1[3-9][0-9](?:[ -]?[0-9]){8})(?:$|[^0-9])",
        confidence_ppm: 995_000,
        validator: Validator::Mobile,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::LandlineNumber,
        source: "cn_landline",
        pattern: r"(?:^|[^0-9])(?P<value>0[0-9]{2,3}[ -]?[0-9]{7,8}(?:[ -](?:\x{8f6c}|ext\.?)?[0-9]{1,6})?)(?:$|[^0-9])",
        confidence_ppm: 990_000,
        validator: Validator::Landline,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::BankAccount,
        source: "bank_card_luhn",
        pattern: r"(?:^|[^0-9])(?P<value>[1-9][0-9](?:[ -]?[0-9]){10,18})(?:$|[^0-9])",
        confidence_ppm: 995_000,
        validator: Validator::BankCard,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::EmailAddress,
        source: "email_rfc_subset",
        pattern: r"(?i)(?:^|[^A-Z0-9._%+-])(?P<value>[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,190}\.[A-Z]{2,24})(?:$|[^A-Z0-9._%+-])",
        confidence_ppm: 995_000,
        validator: Validator::Email,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::CaseNumber,
        source: "cn_court_case_number",
        pattern: r"(?P<value>[\x{ff08}(][12][0-9]{3}[\x{ff09})][\x{4e00}-\x{9fff}A-Za-z0-9]{1,24}(?:\x{6c11}|\x{5211}|\x{884c}|\x{6267}|\x{8d54}|\x{77e5}|\x{7834}|\x{6e05}|\x{975e}|\x{53f8}|\x{76d1}|\x{7533}|\x{518d}|\x{6297}|\x{7ec8}|\x{521d})[\x{4e00}-\x{9fff}A-Za-z0-9]{0,12}[0-9]{1,12}\x{53f7})",
        confidence_ppm: 995_000,
        validator: Validator::CaseNumber,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::OrganizationCode,
        source: "unified_social_credit_checksum",
        pattern: r"(?i)(?:^|[^0-9A-Z])(?P<value>[159Y][1239][0-9ABCDEFGHJKLMNPQRTUWXY]{16})(?:$|[^0-9A-Z])",
        confidence_ppm: 1_000_000,
        validator: Validator::UnifiedSocialCredit,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::BusinessLicenseNumber,
        source: "legacy_business_license",
        pattern: r"(?:\x{8425}\x{4e1a}\x{6267}\x{7167}(?:\x{6ce8}\x{518c}\x{53f7}|\x{7f16}\x{53f7})?|\x{6ce8}\x{518c}\x{53f7})\s*[:\x{ff1a}]?\s*(?P<value>[0-9]{13}|[0-9]{15})",
        confidence_ppm: 980_000,
        validator: Validator::LegacyBusinessLicense,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::VehiclePlate,
        source: "cn_vehicle_plate",
        pattern: r"(?P<value>[\x{4e00}-\x{9fff}][A-HJ-NP-Z][\x{00b7} ]?[A-HJ-NP-Z0-9]{5,6})",
        confidence_ppm: 985_000,
        validator: Validator::VehiclePlate,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::IpAddress,
        source: "ipv4_octets",
        pattern: r"(?:^|[^0-9.])(?P<value>[0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:$|[^0-9.])",
        confidence_ppm: 990_000,
        validator: Validator::Ipv4,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::PassportNumber,
        source: "cn_passport",
        pattern: r"(?i)(?:(?:\x{62a4}\x{7167}(?:\x{53f7}\x{7801}|\x{53f7})?|passport)\s*[:\x{ff1a}]?\s*)?(?P<value>[EGDSP][0-9]{7,8}|[A-Z]{2}[0-9]{7})",
        confidence_ppm: 985_000,
        validator: Validator::Passport,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::Address,
        source: "labelled_address",
        pattern: r"(?:\x{4f4f}\x{5740}|\x{4f4f}\x{6240}\x{5730}|\x{6237}\x{7c4d}\x{5730}|\x{8054}\x{7cfb}\x{5730}\x{5740}|\x{9001}\x{8fbe}\x{5730}\x{5740}|\x{6ce8}\x{518c}\x{5730}\x{5740}|\x{73b0}\x{4f4f}\x{5740})\s*[:\x{ff1a}]?\s*(?P<value>[\x{4e00}-\x{9fff}A-Za-z0-9()\x{ff08}\x{ff09}\x{00b7}\-]{6,100}(?:\x{7701}|\x{5e02}|\x{533a}|\x{53bf}|\x{65d7}|\x{9547}|\x{4e61}|\x{8857}\x{9053}|\x{8def}|\x{8857}|\x{5df7}|\x{5f04}|\x{6751}|\x{7ec4}|\x{53f7}|\x{5ba4}))",
        confidence_ppm: 940_000,
        validator: Validator::None,
        replacement_verified: false,
    },
    Rule {
        entity_type: EntityType::SocialAccount,
        source: "labelled_social_account",
        pattern: r"(?:\x{5fae}\x{4fe1}\x{53f7}|QQ\x{53f7}?|\x{5fae}\x{535a}\x{8d26}\x{53f7}|\x{6296}\x{97f3}\x{53f7}|\x{793e}\x{4ea4}\x{8d26}\x{53f7})\s*[:\x{ff1a}]?\s*(?P<value>[A-Za-z0-9_.\-]{5,64})",
        confidence_ppm: 970_000,
        validator: Validator::None,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::PaymentAccount,
        source: "labelled_payment_account",
        pattern: r"(?:\x{652f}\x{4ed8}\x{5b9d}(?:\x{8d26}\x{53f7})?|\x{4ed8}\x{6b3e}\x{8d26}\x{53f7}|\x{6536}\x{6b3e}\x{8d26}\x{53f7}|\x{652f}\x{4ed8}\x{8d26}\x{53f7})\s*[:\x{ff1a}]?\s*(?P<value>[A-Za-z0-9@._+\-]{5,96})",
        confidence_ppm: 970_000,
        validator: Validator::None,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::AccountName,
        source: "labelled_account_name",
        pattern: r"(?:\x{8d26}\x{6237}\x{540d}|\x{5f00}\x{6237}\x{540d}|\x{6237}\x{540d}|\x{8d26}\x{53f7}\x{540d}\x{79f0})\s*[:\x{ff1a}]?\s*(?P<value>[\x{4e00}-\x{9fff}A-Za-z0-9\x{00b7}()\x{ff08}\x{ff09}]{2,80})",
        confidence_ppm: 950_000,
        validator: Validator::None,
        replacement_verified: false,
    },
    Rule {
        entity_type: EntityType::ContractNumber,
        source: "labelled_contract_number",
        pattern: r"(?:\x{5408}\x{540c}|\x{534f}\x{8bae})(?:\x{7f16}\x{53f7}|\x{53f7})\s*[:\x{ff1a}]?\s*(?P<value>[A-Za-z0-9\x{4e00}-\x{9fff}][A-Za-z0-9\x{4e00}-\x{9fff}/_.\-]{3,63})",
        confidence_ppm: 975_000,
        validator: Validator::None,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::TrackingNumber,
        source: "labelled_tracking_number",
        pattern: r"(?:\x{5feb}\x{9012}(?:\x{5355}\x{53f7}|\x{7f16}\x{53f7})|\x{8fd0}\x{5355}\x{53f7}|\x{7269}\x{6d41}\x{5355}\x{53f7})\s*[:\x{ff1a}]?\s*(?P<value>[A-Za-z0-9]{8,40})",
        confidence_ppm: 975_000,
        validator: Validator::None,
        replacement_verified: true,
    },
    Rule {
        entity_type: EntityType::PropertyCertificateNumber,
        source: "labelled_property_certificate",
        pattern: r"(?:\x{4e0d}\x{52a8}\x{4ea7}\x{6743}\x{8bc1}\x{53f7}|\x{623f}\x{5c4b}\x{6240}\x{6709}\x{6743}\x{8bc1}\x{53f7}|\x{623f}\x{5730}\x{4ea7}\x{6743}\x{8bc1}\x{53f7}|\x{623f}\x{4ea7}\x{8bc1}\x{53f7})\s*[:\x{ff1a}]?\s*(?P<value>[\x{4e00}-\x{9fff}A-Za-z0-9()\x{ff08}\x{ff09}\-]{5,80})",
        confidence_ppm: 980_000,
        validator: Validator::None,
        replacement_verified: true,
    },
];

pub fn detect_finding_candidates(
    text: &str,
    context: DetectionContextV1<'_>,
    sink: &mut dyn PrivateValueSinkV1,
) -> Result<Vec<FindingCandidateV1>, DeterministicDetectorError> {
    validate_context(text, context)?;
    let matches = collect_matches(text)?;
    let requests = matches
        .iter()
        .map(|matched| private_value_request(text, context, matched))
        .collect::<Result<Vec<_>, _>>()?;
    let bindings = sink.store_private_values(&requests)?;
    if bindings.len() != matches.len() {
        return Err(DeterministicDetectorError::InvalidPrivateBinding);
    }
    let mut candidates = Vec::with_capacity(matches.len());
    for (matched, binding) in matches.into_iter().zip(bindings) {
        validate_binding(&binding)?;
        let private_value = text
            .get(matched.start..matched.end)
            .ok_or(DeterministicDetectorError::InvalidContext)?;
        let confidence = ConfidencePpm::new(if matched.validation_passed {
            matched.confidence_ppm
        } else {
            matched.confidence_ppm.min(500_000)
        })
        .map_err(|_| DeterministicDetectorError::InvalidContext)?;
        let evidence = format!(
            "{DETERMINISTIC_DETECTOR_VERSION}\0{}\0{}",
            matched.source,
            if matched.validation_passed {
                "valid"
            } else {
                "invalid"
            }
        );
        candidates.push(FindingCandidateV1 {
            page_index: context.page_index,
            block_id: context.block_id.to_owned(),
            start_offset: u32::try_from(matched.start)
                .map_err(|_| DeterministicDetectorError::InvalidContext)?,
            end_offset: u32::try_from(matched.end)
                .map_err(|_| DeterministicDetectorError::InvalidContext)?,
            geometry: None,
            entity_type: matched.entity_type,
            detector_source: matched.source.to_owned(),
            detector_version: DETERMINISTIC_DETECTOR_VERSION.to_owned(),
            model_versions: Default::default(),
            raw_score_ppm: Some(confidence),
            calibrated_confidence_ppm: Some(confidence),
            ocr_confidence_ppm: context.ocr_confidence_ppm,
            layout_confidence_ppm: context.layout_confidence_ppm,
            normalization_evidence_hash: Some(parse_hash(sha256_hex(evidence.as_bytes()))?),
            confusable_evidence_hash: confusable_evidence(private_value)?,
            case_dictionary_match: false,
            value_fingerprint: binding.value_fingerprint,
            proposed_replacement: Some(binding.proposed_replacement),
            private_value_ref: binding.private_value_ref,
            validation_passed: matched.validation_passed,
            automatic_replacement_allowed: matched.validation_passed
                && matched.replacement_verified,
            replacement_verified: false,
        });
    }
    Ok(candidates)
}

/// Applies only deterministic, non-conflicting replacements and marks the exact candidates that
/// were actually emitted. Offsets are byte offsets into `text`; overlapping or conflicting groups
/// remain unresolved and are not modified.
pub fn apply_verified_replacements(
    text: &str,
    candidates: &mut [FindingCandidateV1],
) -> Result<String, DeterministicDetectorError> {
    let mut groups = std::collections::BTreeMap::<(u32, u32), Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.end_offset <= candidate.start_offset
            || usize::try_from(candidate.end_offset).map_or(true, |end| end > text.len())
        {
            return Err(DeterministicDetectorError::InvalidContext);
        }
        groups
            .entry((candidate.start_offset, candidate.end_offset))
            .or_default()
            .push(index);
    }
    let mut output = String::with_capacity(text.len());
    let mut cursor = 0_usize;
    for ((start, end), indexes) in groups {
        let start =
            usize::try_from(start).map_err(|_| DeterministicDetectorError::InvalidContext)?;
        let end = usize::try_from(end).map_err(|_| DeterministicDetectorError::InvalidContext)?;
        if start < cursor || !text.is_char_boundary(start) || !text.is_char_boundary(end) {
            continue;
        }
        let replacements = indexes
            .iter()
            .filter_map(|index| candidates[*index].proposed_replacement.as_deref())
            .collect::<BTreeSet<_>>();
        let eligible = indexes.iter().all(|index| {
            candidates[*index].validation_passed && candidates[*index].automatic_replacement_allowed
        });
        if !eligible || replacements.len() != 1 {
            continue;
        }
        let replacement = replacements
            .iter()
            .next()
            .ok_or(DeterministicDetectorError::InvalidPrivateBinding)?
            .to_string();
        output.push_str(
            text.get(cursor..start)
                .ok_or(DeterministicDetectorError::InvalidContext)?,
        );
        output.push_str(&replacement);
        cursor = end;
        for index in indexes {
            candidates[index].replacement_verified = true;
        }
    }
    output.push_str(
        text.get(cursor..)
            .ok_or(DeterministicDetectorError::InvalidContext)?,
    );
    Ok(output)
}

fn private_value_request<'a>(
    text: &'a str,
    context: DetectionContextV1<'a>,
    matched: &Match,
) -> Result<StorePrivateValueRequestV1<'a>, DeterministicDetectorError> {
    Ok(StorePrivateValueRequestV1 {
        case_id: context.case_id,
        material_id: context.material_id,
        document_version: context.document_version,
        page_index: context.page_index,
        block_id: context.block_id,
        start_offset: u32::try_from(matched.start)
            .map_err(|_| DeterministicDetectorError::InvalidContext)?,
        end_offset: u32::try_from(matched.end)
            .map_err(|_| DeterministicDetectorError::InvalidContext)?,
        entity_type: matched.entity_type,
        private_value: text
            .get(matched.start..matched.end)
            .ok_or(DeterministicDetectorError::InvalidContext)?,
    })
}

fn validate_context(
    text: &str,
    context: DetectionContextV1<'_>,
) -> Result<(), DeterministicDetectorError> {
    if text.len() > u32::MAX as usize
        || context.document_version == 0
        || context.block_id.is_empty()
        || context.block_id.len() > 256
        || context.block_id.chars().any(char::is_control)
    {
        return Err(DeterministicDetectorError::InvalidContext);
    }
    Ok(())
}

fn validate_binding(
    binding: &StoredPrivateValueBindingV1,
) -> Result<(), DeterministicDetectorError> {
    if binding.private_value_ref.object_version == 0
        || binding.proposed_replacement.is_empty()
        || binding.proposed_replacement.len() > 128
        || binding.proposed_replacement.chars().any(char::is_control)
    {
        return Err(DeterministicDetectorError::InvalidPrivateBinding);
    }
    Ok(())
}

fn collect_matches(text: &str) -> Result<Vec<Match>, DeterministicDetectorError> {
    let mut matches = BTreeSet::new();
    for rule in RULES {
        let regex =
            Regex::new(rule.pattern).map_err(|_| DeterministicDetectorError::PatternUnavailable)?;
        for captures in regex.captures_iter(text) {
            let Some(value) = capture_value(&captures) else {
                continue;
            };
            if value.start() >= value.end() || is_placeholder(value.as_str()) {
                continue;
            }
            if matches.len() >= MAX_DETERMINISTIC_MATCHES_PER_BLOCK {
                return Err(DeterministicDetectorError::MatchLimitExceeded);
            }
            if matches!(rule.validator, Validator::BankCard)
                && !validate_value(rule.validator, value.as_str())
            {
                continue;
            }
            matches.insert(Match {
                start: value.start(),
                end: value.end(),
                entity_type: rule.entity_type,
                source: rule.source,
                confidence_ppm: rule.confidence_ppm,
                validation_passed: validate_value(rule.validator, value.as_str()),
                replacement_verified: rule.replacement_verified,
            });
        }
    }
    let mut ordered = matches.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
            .then_with(|| left.entity_type.cmp(&right.entity_type))
    });
    let mut selected = Vec::with_capacity(ordered.len());
    for candidate in ordered {
        if selected
            .last()
            .is_none_or(|previous: &Match| candidate.start >= previous.end)
        {
            selected.push(candidate);
        }
    }
    Ok(selected)
}

fn capture_value<'a>(captures: &'a Captures<'a>) -> Option<regex::Match<'a>> {
    captures.name("value")
}

fn validate_value(validator: Validator, value: &str) -> bool {
    match validator {
        Validator::None => true,
        Validator::ChinaIdentity => validate_china_identity(value),
        Validator::Mobile => {
            let digits = ascii_digits(value);
            digits.len() == 11
                && digits.starts_with('1')
                && matches!(digits.as_bytes().get(1), Some(b'3'..=b'9'))
        }
        Validator::Landline => {
            let digits = ascii_digits(value);
            (10..=17).contains(&digits.len()) && digits.starts_with('0')
        }
        Validator::BankCard => validate_luhn(&ascii_digits(value)),
        Validator::Email => value.len() <= 254 && value.matches('@').count() == 1,
        Validator::CaseNumber => {
            value.ends_with('\u{53f7}') && value.chars().any(|ch| ch.is_ascii_digit())
        }
        Validator::UnifiedSocialCredit => validate_unified_social_credit(value),
        Validator::LegacyBusinessLicense => matches!(ascii_digits(value).len(), 13 | 15),
        Validator::VehiclePlate => validate_vehicle_plate(value),
        Validator::Ipv4 => validate_ipv4(value),
        Validator::Passport => (8..=10).contains(&value.len()),
    }
}

fn ascii_digits(value: &str) -> String {
    value.chars().filter(char::is_ascii_digit).collect()
}

pub fn validate_china_identity(value: &str) -> bool {
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.len() != 18 || !normalized.as_bytes()[..17].iter().all(u8::is_ascii_digit) {
        return false;
    }
    let date = normalized[6..10]
        .parse::<u32>()
        .ok()
        .zip(normalized[10..12].parse::<u32>().ok())
        .zip(normalized[12..14].parse::<u32>().ok());
    if !date.is_some_and(|((year, month), day)| valid_date(year, month, day)) {
        return false;
    }
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    const CHECKS: [u8; 11] = *b"10X98765432";
    let sum = normalized.as_bytes()[..17]
        .iter()
        .zip(WEIGHTS)
        .map(|(digit, weight)| u32::from(digit - b'0') * weight)
        .sum::<u32>();
    CHECKS[(sum % 11) as usize] == normalized.as_bytes()[17]
}

fn valid_date(year: u32, month: u32, day: u32) -> bool {
    if !(1900..=2200).contains(&year) || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let leap = year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100));
    let limit = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= limit
}

pub fn validate_luhn(value: &str) -> bool {
    if !(12..=19).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let mut sum = 0_u32;
    let parity = value.len() % 2;
    for (index, byte) in value.bytes().enumerate() {
        let mut digit = u32::from(byte - b'0');
        if index % 2 == parity {
            digit *= 2;
            if digit > 9 {
                digit -= 9;
            }
        }
        sum += digit;
    }
    sum.is_multiple_of(10)
}

pub fn validate_unified_social_credit(value: &str) -> bool {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKLMNPQRTUWXY";
    const WEIGHTS: [u32; 17] = [
        1, 3, 9, 27, 19, 26, 16, 17, 20, 29, 25, 13, 8, 24, 10, 30, 28,
    ];
    let normalized = value.trim().to_ascii_uppercase();
    if normalized.len() != 18 {
        return false;
    }
    let mut sum = 0_u32;
    for (byte, weight) in normalized.bytes().take(17).zip(WEIGHTS) {
        let Some(position) = ALPHABET.iter().position(|candidate| *candidate == byte) else {
            return false;
        };
        sum += u32::try_from(position).unwrap_or(u32::MAX) * weight;
    }
    let check = (31 - (sum % 31)) % 31;
    usize::try_from(check)
        .ok()
        .and_then(|index| ALPHABET.get(index))
        .is_some_and(|expected| Some(expected) == normalized.as_bytes().get(17))
}

fn validate_vehicle_plate(value: &str) -> bool {
    let compact = value.replace(['\u{00b7}', ' '], "");
    matches!(compact.chars().count(), 7 | 8)
        && compact
            .chars()
            .next()
            .is_some_and(|ch| ('\u{4e00}'..='\u{9fff}').contains(&ch))
        && compact
            .chars()
            .skip(2)
            .all(|ch| ch.is_ascii_digit() || (ch.is_ascii_uppercase() && !matches!(ch, 'I' | 'O')))
}

fn validate_ipv4(value: &str) -> bool {
    let octets = value.split('.').collect::<Vec<_>>();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && (octet == &"0" || !octet.starts_with('0'))
                && octet.parse::<u8>().is_ok()
        })
}

fn confusable_evidence(value: &str) -> Result<Option<Sha256Hex>, DeterministicDetectorError> {
    let has_confusable = value.chars().any(|ch| {
        matches!(
            ch,
            'O' | 'o' | 'I' | 'l' | 'S' | 'B' | '\u{ff38}' | '\u{ff58}'
        ) || ('\u{ff10}'..='\u{ff19}').contains(&ch)
    });
    has_confusable
        .then(|| parse_hash(sha256_hex(b"unicode-ocr-confusable-class-v1")))
        .transpose()
}

fn parse_hash(value: String) -> Result<Sha256Hex, DeterministicDetectorError> {
    Sha256Hex::parse(value).map_err(|_| DeterministicDetectorError::InvalidPrivateBinding)
}

fn is_placeholder(value: &str) -> bool {
    (value.starts_with('[') && value.ends_with(']'))
        || (value.starts_with('\u{3010}') && value.ends_with('\u{3011}'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vnext::ObjectId;

    struct SyntheticSink {
        next: u64,
        seen_lengths: Vec<usize>,
    }

    impl PrivateValueSinkV1 for SyntheticSink {
        fn store_private_values(
            &mut self,
            requests: &[StorePrivateValueRequestV1<'_>],
        ) -> Result<Vec<StoredPrivateValueBindingV1>, DeterministicDetectorError> {
            let object_digest = sha256_hex(format!("batch-object\0{}", self.next).as_bytes());
            self.next += 1;
            requests
                .iter()
                .enumerate()
                .map(|(index, request)| {
                    self.seen_lengths.push(request.private_value.len());
                    Ok(StoredPrivateValueBindingV1 {
                        value_fingerprint: Sha256Hex::parse(sha256_hex(
                            format!("synthetic-case-key\0{}", request.private_value).as_bytes(),
                        ))
                        .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?,
                        private_value_ref: PrivateValueRefV1 {
                            object_id: ObjectId::parse(format!("obj_{}", &object_digest[..32]))
                                .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?,
                            object_version: 1,
                            value_locator_hash: Sha256Hex::parse(sha256_hex(
                                format!("locator\0{index}").as_bytes(),
                            ))
                            .map_err(|_| DeterministicDetectorError::PrivateValueStoreFailed)?,
                        },
                        proposed_replacement: format!("[SENSITIVE_{index}]"),
                    })
                })
                .collect()
        }
    }

    fn context<'a>(case_id: &'a CaseId, material_id: &'a MaterialId) -> DetectionContextV1<'a> {
        DetectionContextV1 {
            case_id,
            material_id,
            document_version: 1,
            page_index: 0,
            block_id: "page-1",
            ocr_confidence_ppm: None,
            layout_confidence_ppm: None,
        }
    }

    #[test]
    fn validates_chinese_checksums_and_luhn() {
        assert!(validate_china_identity("11010519491231002X"));
        assert!(!validate_china_identity("110105194912310021"));
        assert!(validate_luhn("6222021001116243210"));
        assert!(!validate_luhn("6222021001116243211"));
        assert!(validate_unified_social_credit("91350211M000100Y46"));
        assert!(!validate_unified_social_credit("91350211M000100Y43"));
    }

    #[test]
    fn covers_required_deterministic_entity_matrix_without_public_raw_values() {
        let case_id = CaseId::parse("case_11111111111111111111111111111111").expect("case");
        let material_id =
            MaterialId::parse("mat_22222222222222222222222222222222").expect("material");
        let text = concat!(
            "ID 11010519491231002X mobile 13800138000 landline 010-12345678 ",
            "bank 6222021001116243210 email synthetic@example.test ",
            "case \u{ff08}2026\u{ff09}\u{4eac}0105\u{6c11}\u{521d}123\u{53f7} credit 91350211M000100Y46 ",
            "\u{8425}\u{4e1a}\u{6267}\u{7167}\u{6ce8}\u{518c}\u{53f7}:123456789012345 plate \u{4eac}A12345 IP 192.168.1.10 ",
            "passport E12345678 \u{5fae}\u{4fe1}\u{53f7}:wx_case_001 \u{652f}\u{4ed8}\u{5b9d}\u{8d26}\u{53f7}:pay_case_001 ",
            "\u{8d26}\u{6237}\u{540d}:\u{5408}\u{6210}\u{8d26}\u{6237} \u{5408}\u{540c}\u{7f16}\u{53f7}:HT-2026-0001 ",
            "\u{5feb}\u{9012}\u{5355}\u{53f7}:SF1234567890 \u{4e0d}\u{52a8}\u{4ea7}\u{6743}\u{8bc1}\u{53f7}:\u{4eac}\u{ff08}2026\u{ff09}\u{7b2c}0001\u{53f7} ",
            "\u{8054}\u{7cfb}\u{5730}\u{5740}:\u{5317}\u{4eac}\u{5e02}\u{671d}\u{9633}\u{533a}\u{5408}\u{6210}\u{8def}88\u{53f7}"
        );
        let mut sink = SyntheticSink {
            next: 0,
            seen_lengths: Vec::new(),
        };
        let candidates =
            detect_finding_candidates(text, context(&case_id, &material_id), &mut sink)
                .expect("detect");
        let types = candidates
            .iter()
            .map(|candidate| candidate.entity_type)
            .collect::<BTreeSet<_>>();
        for required in [
            EntityType::IdentityNumber,
            EntityType::PhoneNumber,
            EntityType::LandlineNumber,
            EntityType::BankAccount,
            EntityType::EmailAddress,
            EntityType::CaseNumber,
            EntityType::OrganizationCode,
            EntityType::BusinessLicenseNumber,
            EntityType::VehiclePlate,
            EntityType::IpAddress,
            EntityType::PassportNumber,
            EntityType::SocialAccount,
            EntityType::PaymentAccount,
            EntityType::AccountName,
            EntityType::ContractNumber,
            EntityType::TrackingNumber,
            EntityType::PropertyCertificateNumber,
            EntityType::Address,
        ] {
            assert!(types.contains(&required), "missing {required:?}");
        }
        let public = serde_json::to_string(
            &candidates
                .iter()
                .map(|candidate| {
                    (
                        &candidate.detector_source,
                        candidate.start_offset,
                        candidate.end_offset,
                    )
                })
                .collect::<Vec<_>>(),
        )
        .expect("public summary");
        assert!(!public.contains("11010519491231002X"));
        assert_eq!(sink.seen_lengths.len(), candidates.len());
    }

    #[test]
    fn sink_failure_is_fail_closed_without_private_echo() {
        struct Failing;
        impl PrivateValueSinkV1 for Failing {
            fn store_private_values(
                &mut self,
                _requests: &[StorePrivateValueRequestV1<'_>],
            ) -> Result<Vec<StoredPrivateValueBindingV1>, DeterministicDetectorError> {
                Err(DeterministicDetectorError::PrivateValueStoreFailed)
            }
        }
        let case_id = CaseId::parse("case_11111111111111111111111111111111").expect("case");
        let material_id =
            MaterialId::parse("mat_22222222222222222222222222222222").expect("material");
        let error = detect_finding_candidates(
            "ID 11010519491231002X",
            context(&case_id, &material_id),
            &mut Failing,
        )
        .expect_err("must fail");
        assert_eq!(
            error.to_string(),
            "deterministic_detector_private_store_failed"
        );
        assert!(!error.to_string().contains("11010519491231002X"));
    }
}
