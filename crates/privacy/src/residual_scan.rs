//! Independent post-redaction residual scanner.
//!
//! Its patterns and evidence schema are separate from the primary deterministic detector. Results
//! expose only locations, classes, counts, reason codes, and a canonical hash.

use crate::{
    sha256_hex,
    vnext::{canonical_json_v1, EntityType, Sha256Hex},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

pub const INDEPENDENT_RESIDUAL_SCAN_VERSION: &str = "independent-residual-scan-v2";
pub const MAX_RESIDUAL_HITS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndependentResidualError {
    InvalidInput,
    PatternUnavailable,
    HitLimitExceeded,
    EvidenceFailed,
}

impl fmt::Display for IndependentResidualError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "independent_residual_invalid_input",
            Self::PatternUnavailable => "independent_residual_pattern_unavailable",
            Self::HitLimitExceeded => "independent_residual_hit_limit_exceeded",
            Self::EvidenceFailed => "independent_residual_evidence_failed",
        })
    }
}
impl Error for IndependentResidualError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualRiskClassV1 {
    DictionarySubject,
    IdentityLike,
    LongDigitSequence,
    EmailLike,
    PhoneLike,
    IpLike,
    SuspectedPerson,
    SuspectedOrganization,
    AddressLike,
    SourceName,
    LocalPath,
    OcrConfusable,
    BrokenPlaceholder,
    AliasInconsistency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ResidualHitV1 {
    pub page_index: u32,
    pub start_offset: u32,
    pub end_offset: u32,
    pub risk_class: ResidualRiskClassV1,
    pub entity_type: Option<EntityType>,
    pub blocking: bool,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct IndependentResidualScanReportV1 {
    pub schema_version: String,
    pub passed: bool,
    pub hits: Vec<ResidualHitV1>,
    pub counts: BTreeMap<ResidualRiskClassV1, u32>,
    pub scanned_page_count: u32,
    pub evidence_hash: Sha256Hex,
}

impl IndependentResidualScanReportV1 {
    pub fn validate(&self) -> Result<(), IndependentResidualError> {
        if self.schema_version != INDEPENDENT_RESIDUAL_SCAN_VERSION
            || self.scanned_page_count == 0
            || self.hits.len() > MAX_RESIDUAL_HITS
            || self.hits.iter().any(|hit| {
                hit.start_offset >= hit.end_offset
                    || hit.page_index >= self.scanned_page_count
                    || hit.reason_code.is_empty()
                    || hit.reason_code.len() > 128
                    || hit.reason_code.chars().any(char::is_control)
            })
        {
            return Err(IndependentResidualError::EvidenceFailed);
        }
        let mut counts = BTreeMap::new();
        for hit in &self.hits {
            *counts.entry(hit.risk_class).or_insert(0_u32) = counts
                .get(&hit.risk_class)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
        }
        if counts != self.counts || self.passed != self.hits.iter().all(|hit| !hit.blocking) {
            return Err(IndependentResidualError::EvidenceFailed);
        }
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Claims<'a> {
            schema_version: &'a str,
            passed: bool,
            hits: &'a [ResidualHitV1],
            counts: &'a BTreeMap<ResidualRiskClassV1, u32>,
            scanned_page_count: u32,
        }
        let canonical = canonical_json_v1(&Claims {
            schema_version: &self.schema_version,
            passed: self.passed,
            hits: &self.hits,
            counts: &self.counts,
            scanned_page_count: self.scanned_page_count,
        })
        .map_err(|_| IndependentResidualError::EvidenceFailed)?;
        let expected = Sha256Hex::parse(sha256_hex(&canonical))
            .map_err(|_| IndependentResidualError::EvidenceFailed)?;
        if expected != self.evidence_hash {
            return Err(IndependentResidualError::EvidenceFailed);
        }
        Ok(())
    }
}
/// Borrowed secret dictionary term. It cannot be logged or serialized by this module.
pub struct ResidualDictionaryTermV1<'a> {
    pub entity_type: EntityType,
    pub primary_value: &'a str,
    pub variants: &'a [&'a str],
    pub expected_alias: &'a str,
}

pub struct IndependentResidualScanInputV1<'a> {
    pub pages: &'a [String],
    pub dictionary_terms: &'a [ResidualDictionaryTermV1<'a>],
    pub source_names: &'a [&'a str],
}

#[derive(Clone, Copy)]
struct Pattern {
    class: ResidualRiskClassV1,
    entity_type: Option<EntityType>,
    expression: &'static str,
    reason: &'static str,
    blocking: bool,
}

const PATTERNS: &[Pattern] = &[
    Pattern {
        class: ResidualRiskClassV1::IdentityLike,
        entity_type: Some(EntityType::IdentityNumber),
        expression: r"(?i)(?:^|[^0-9A-Z])[1-9][0-9]{16}[0-9X](?:$|[^0-9A-Z])",
        reason: "residual_identity_like",
        blocking: true,
    },
    Pattern {
        class: ResidualRiskClassV1::LongDigitSequence,
        entity_type: None,
        expression: r"(?:^|[^0-9])[0-9](?:[ -]?[0-9]){7,24}(?:$|[^0-9])",
        reason: "residual_long_digit_sequence",
        blocking: true,
    },
    Pattern {
        class: ResidualRiskClassV1::EmailLike,
        entity_type: Some(EntityType::EmailAddress),
        expression: r"(?i)[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,190}\.[A-Z]{2,24}",
        reason: "residual_email_like",
        blocking: true,
    },
    Pattern {
        class: ResidualRiskClassV1::PhoneLike,
        entity_type: Some(EntityType::PhoneNumber),
        expression: r"(?:^|[^0-9])(?:1[3-9][0-9]{9}|0[0-9]{2,3}[ -]?[0-9]{7,8})(?:$|[^0-9])",
        reason: "residual_phone_like",
        blocking: true,
    },
    Pattern {
        class: ResidualRiskClassV1::IpLike,
        entity_type: Some(EntityType::IpAddress),
        expression: r"(?:^|[^0-9.])[0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:$|[^0-9.])",
        reason: "residual_ip_like",
        blocking: true,
    },
    Pattern {
        class: ResidualRiskClassV1::LocalPath,
        entity_type: None,
        expression: r#"(?i)(?:[A-Z]:[\\/](?:[^\s<>:\"|?*]+[\\/])+|/(?:Users|home|var|tmp)/[^\s]+)"#,
        reason: "residual_local_path",
        blocking: true,
    },
    Pattern {
        class: ResidualRiskClassV1::SuspectedOrganization,
        entity_type: Some(EntityType::OrganizationName),
        expression: r"[\x{4e00}-\x{9fff}]{2,40}(?:\x{516c}\x{53f8}|\x{6cd5}\x{9662}|\x{68c0}\x{5bdf}\x{9662}|\x{5f8b}\x{5e08}\x{4e8b}\x{52a1}\x{6240}|\x{59d4}\x{5458}\x{4f1a}|\x{5c40})",
        reason: "residual_suspected_organization",
        blocking: false,
    },
    Pattern {
        class: ResidualRiskClassV1::AddressLike,
        entity_type: Some(EntityType::Address),
        expression: r"[\x{4e00}-\x{9fff}A-Za-z0-9]{6,100}(?:\x{7701}|\x{5e02}|\x{533a}|\x{53bf}|\x{8857}\x{9053}|\x{8def}|\x{8857}|\x{5df7}|\x{5f04}|\x{53f7}|\x{5ba4})",
        reason: "residual_address_like",
        blocking: false,
    },
];

pub fn scan_independent_residuals(
    input: IndependentResidualScanInputV1<'_>,
) -> Result<IndependentResidualScanReportV1, IndependentResidualError> {
    if input.pages.is_empty()
        || input.pages.len() > 100_000
        || input.dictionary_terms.len() > 4_096
        || input.source_names.len() > 256
    {
        return Err(IndependentResidualError::InvalidInput);
    }
    let compiled = PATTERNS
        .iter()
        .map(|pattern| {
            Regex::new(pattern.expression)
                .map(|regex| (*pattern, regex))
                .map_err(|_| IndependentResidualError::PatternUnavailable)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut hits = Vec::new();
    for (page_index, page) in input.pages.iter().enumerate() {
        let page_index =
            u32::try_from(page_index).map_err(|_| IndependentResidualError::InvalidInput)?;
        for (pattern, regex) in &compiled {
            for matched in regex.find_iter(page) {
                push_hit(
                    &mut hits,
                    page_index,
                    matched.start(),
                    matched.end(),
                    pattern.class,
                    pattern.entity_type,
                    pattern.blocking,
                    pattern.reason,
                )?;
            }
        }
        scan_dictionary(page, page_index, input.dictionary_terms, &mut hits)?;
        scan_source_names(page, page_index, input.source_names, &mut hits)?;
        scan_placeholders(page, page_index, input.dictionary_terms, &mut hits)?;
        scan_confusables(page, page_index, &mut hits)?;
    }
    hits.sort_by(|left, right| {
        left.page_index
            .cmp(&right.page_index)
            .then_with(|| left.start_offset.cmp(&right.start_offset))
            .then_with(|| left.end_offset.cmp(&right.end_offset))
            .then_with(|| left.risk_class.cmp(&right.risk_class))
    });
    hits.dedup();
    let mut counts = BTreeMap::new();
    for hit in &hits {
        *counts.entry(hit.risk_class).or_insert(0_u32) = counts
            .get(&hit.risk_class)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
    }
    let scanned_page_count =
        u32::try_from(input.pages.len()).map_err(|_| IndependentResidualError::InvalidInput)?;
    let passed = hits.iter().all(|hit| !hit.blocking);
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Claims<'a> {
        schema_version: &'a str,
        passed: bool,
        hits: &'a [ResidualHitV1],
        counts: &'a BTreeMap<ResidualRiskClassV1, u32>,
        scanned_page_count: u32,
    }
    let canonical = canonical_json_v1(&Claims {
        schema_version: INDEPENDENT_RESIDUAL_SCAN_VERSION,
        passed,
        hits: &hits,
        counts: &counts,
        scanned_page_count,
    })
    .map_err(|_| IndependentResidualError::EvidenceFailed)?;
    let evidence_hash = Sha256Hex::parse(sha256_hex(&canonical))
        .map_err(|_| IndependentResidualError::EvidenceFailed)?;
    Ok(IndependentResidualScanReportV1 {
        schema_version: INDEPENDENT_RESIDUAL_SCAN_VERSION.to_owned(),
        passed,
        hits,
        counts,
        scanned_page_count,
        evidence_hash,
    })
}

fn scan_dictionary(
    page: &str,
    page_index: u32,
    terms: &[ResidualDictionaryTermV1<'_>],
    hits: &mut Vec<ResidualHitV1>,
) -> Result<(), IndependentResidualError> {
    for term in terms {
        if term.primary_value.trim().is_empty()
            || term.primary_value.len() > 512
            || term.variants.len() > 32
            || term.expected_alias.trim().is_empty()
        {
            return Err(IndependentResidualError::InvalidInput);
        }
        for value in std::iter::once(term.primary_value).chain(term.variants.iter().copied()) {
            for (start, _) in page.match_indices(value) {
                push_hit(
                    hits,
                    page_index,
                    start,
                    start.saturating_add(value.len()),
                    ResidualRiskClassV1::DictionarySubject,
                    Some(term.entity_type),
                    true,
                    "residual_dictionary_subject",
                )?;
            }
        }
    }
    Ok(())
}

fn scan_source_names(
    page: &str,
    page_index: u32,
    source_names: &[&str],
    hits: &mut Vec<ResidualHitV1>,
) -> Result<(), IndependentResidualError> {
    for name in source_names {
        let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
        if leaf.len() < 3 || leaf.len() > 512 || leaf.chars().any(char::is_control) {
            continue;
        }
        for (start, _) in page.match_indices(leaf) {
            push_hit(
                hits,
                page_index,
                start,
                start.saturating_add(leaf.len()),
                ResidualRiskClassV1::SourceName,
                None,
                true,
                "residual_source_name",
            )?;
        }
    }
    Ok(())
}

fn scan_placeholders(
    page: &str,
    page_index: u32,
    terms: &[ResidualDictionaryTermV1<'_>],
    hits: &mut Vec<ResidualHitV1>,
) -> Result<(), IndependentResidualError> {
    let open_square = page.matches('[').count();
    let close_square = page.matches(']').count();
    let open_cjk = page.matches('\u{3010}').count();
    let close_cjk = page.matches('\u{3011}').count();
    if open_square != close_square || open_cjk != close_cjk {
        push_hit(
            hits,
            page_index,
            0,
            page.len().min(1),
            ResidualRiskClassV1::BrokenPlaceholder,
            None,
            true,
            "placeholder_delimiter_unbalanced",
        )?;
    }
    let aliases = terms
        .iter()
        .map(|term| term.expected_alias)
        .collect::<BTreeSet<_>>();
    if aliases.len() != terms.len() {
        push_hit(
            hits,
            page_index,
            0,
            page.len().min(1),
            ResidualRiskClassV1::AliasInconsistency,
            None,
            true,
            "dictionary_alias_not_unique",
        )?;
    }
    Ok(())
}

fn scan_confusables(
    page: &str,
    page_index: u32,
    hits: &mut Vec<ResidualHitV1>,
) -> Result<(), IndependentResidualError> {
    for (start, ch) in page.char_indices() {
        if ('\u{ff10}'..='\u{ff19}').contains(&ch) || matches!(ch, '\u{ff38}' | '\u{ff58}') {
            push_hit(
                hits,
                page_index,
                start,
                start.saturating_add(ch.len_utf8()),
                ResidualRiskClassV1::OcrConfusable,
                None,
                false,
                "ocr_confusable_requires_review",
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_hit(
    hits: &mut Vec<ResidualHitV1>,
    page_index: u32,
    start: usize,
    end: usize,
    risk_class: ResidualRiskClassV1,
    entity_type: Option<EntityType>,
    blocking: bool,
    reason_code: &str,
) -> Result<(), IndependentResidualError> {
    if hits.len() >= MAX_RESIDUAL_HITS || end <= start {
        return Err(IndependentResidualError::HitLimitExceeded);
    }
    hits.push(ResidualHitV1 {
        page_index,
        start_offset: u32::try_from(start).map_err(|_| IndependentResidualError::InvalidInput)?,
        end_offset: u32::try_from(end).map_err(|_| IndependentResidualError::InvalidInput)?,
        risk_class,
        entity_type,
        blocking,
        reason_code: reason_code.to_owned(),
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_placeholders_pass_and_report_is_stable() {
        let pages = vec!["[PERSON_A] and \u{3010}\u{516c}\u{53f8}A\u{3011}".to_owned()];
        let report = scan_independent_residuals(IndependentResidualScanInputV1 {
            pages: &pages,
            dictionary_terms: &[],
            source_names: &[],
        })
        .expect("scan");
        assert!(report.passed);
        let again = scan_independent_residuals(IndependentResidualScanInputV1 {
            pages: &pages,
            dictionary_terms: &[],
            source_names: &[],
        })
        .expect("scan again");
        assert_eq!(report.evidence_hash, again.evidence_hash);
    }

    #[test]
    fn independent_scan_finds_dictionary_id_path_filename_and_broken_aliases_without_echo() {
        let pages = vec![format!(
            "subject-one 11010519491231002X C:\\Cases\\secret.pdf secret.pdf [BROKEN"
        )];
        let variants = ["subject-1"];
        let terms = [
            ResidualDictionaryTermV1 {
                entity_type: EntityType::PersonName,
                primary_value: "subject-one",
                variants: &variants,
                expected_alias: "[PERSON_A]",
            },
            ResidualDictionaryTermV1 {
                entity_type: EntityType::PersonName,
                primary_value: "subject-two",
                variants: &[],
                expected_alias: "[PERSON_A]",
            },
        ];
        let report = scan_independent_residuals(IndependentResidualScanInputV1 {
            pages: &pages,
            dictionary_terms: &terms,
            source_names: &["secret.pdf"],
        })
        .expect("scan");
        assert!(!report.passed);
        let classes = report
            .hits
            .iter()
            .map(|hit| hit.risk_class)
            .collect::<BTreeSet<_>>();
        assert!(classes.contains(&ResidualRiskClassV1::DictionarySubject));
        assert!(classes.contains(&ResidualRiskClassV1::IdentityLike));
        assert!(classes.contains(&ResidualRiskClassV1::LocalPath));
        assert!(classes.contains(&ResidualRiskClassV1::SourceName));
        assert!(classes.contains(&ResidualRiskClassV1::BrokenPlaceholder));
        assert!(classes.contains(&ResidualRiskClassV1::AliasInconsistency));
        let wire = serde_json::to_string(&report).expect("report");
        assert!(!wire.contains("subject-one"));
        assert!(!wire.contains("11010519491231002X"));
        assert!(!wire.contains("secret.pdf"));
    }
}
