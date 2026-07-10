use crate::qa::{CitationInvalidReason, CitationStatus};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseProjectStatus {
    Active,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseProject {
    pub project_id: String,
    pub title: String,
    pub case_type: String,
    pub status: CaseProjectStatus,
    pub opened_on: Option<String>,
    pub summary: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseFile {
    pub file_id: String,
    pub project_id: String,
    pub title: String,
    pub file_type: String,
    pub storage_reference: String,
    pub summary: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartyRole {
    Plaintiff,
    Defendant,
    Claimant,
    Respondent,
    ThirdParty,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseParty {
    pub party_id: String,
    pub project_id: String,
    pub name: String,
    pub normalized_name: String,
    pub role: PartyRole,
    pub contact: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationStatus {
    ModelSuggested,
    Confirmed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseFact {
    pub fact_id: String,
    pub project_id: String,
    pub occurred_on: Option<String>,
    pub title: String,
    pub description: String,
    pub source: String,
    pub confirmation_status: ConfirmationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceItem {
    pub evidence_id: String,
    pub project_id: String,
    pub evidence_number: String,
    pub title: String,
    pub source: String,
    pub formed_on: Option<String>,
    pub summary: String,
    pub storage_reference: String,
    pub confirmation_status: ConfirmationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceLink {
    pub link_id: String,
    pub project_id: String,
    pub fact_id: String,
    pub evidence_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalIssueStatus {
    Open,
    Resolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalIssue {
    pub issue_id: String,
    pub project_id: String,
    pub title: String,
    pub description: String,
    pub claim: String,
    pub status: LegalIssueStatus,
    pub confirmation_status: ConfirmationStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyStatus {
    Open,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyRelatedEntityType {
    General,
    Party,
    Fact,
    Evidence,
    LegalIssue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseUncertainty {
    pub uncertainty_id: String,
    pub project_id: String,
    pub description: String,
    pub related_entity_type: UncertaintyRelatedEntityType,
    pub related_entity_id: Option<String>,
    pub source_file_ids: Vec<String>,
    pub status: UncertaintyStatus,
    pub resolution: String,
    pub confirmation_status: ConfirmationStatus,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalBasis {
    pub basis_id: String,
    pub project_id: String,
    pub issue_id: Option<String>,
    pub source_id: String,
    pub status: CitationStatus,
    pub invalid_reason: Option<CitationInvalidReason>,
    pub case_date: Option<String>,
    pub article_id: String,
    pub document_id: String,
    pub version_id: String,
    pub document_title: String,
    pub version_label: String,
    pub article_number: String,
    pub article_title: Option<String>,
    pub canonical_label: String,
    pub effective_from: String,
    pub effective_to: Option<String>,
    pub version_status: String,
    pub excerpt: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseWorkspace {
    pub project: CaseProject,
    pub files: Vec<CaseFile>,
    pub parties: Vec<CaseParty>,
    pub facts: Vec<CaseFact>,
    pub evidence: Vec<EvidenceItem>,
    pub evidence_links: Vec<EvidenceLink>,
    pub legal_issues: Vec<LegalIssue>,
    pub legal_basis: Vec<LegalBasis>,
    pub uncertainties: Vec<CaseUncertainty>,
    pub gaps: Vec<CaseGap>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseGapKind {
    TimelineConflict,
    PartyNameInconsistent,
    EvidenceMissingSource,
    FactMissingEvidence,
    EvidenceMissingFormedOn,
    InvalidEvidenceId,
    LegalIssueMissingBasis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseGapSeverity {
    Warning,
    Blocking,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseGap {
    pub gap_id: String,
    pub project_id: String,
    pub kind: CaseGapKind,
    pub severity: CaseGapSeverity,
    pub entity_id: String,
    pub message: String,
}

pub fn analyze_case_gaps(
    project_id: &str,
    parties: &[CaseParty],
    facts: &[CaseFact],
    evidence: &[EvidenceItem],
    evidence_links: &[EvidenceLink],
    legal_issues: &[LegalIssue],
    legal_basis: &[LegalBasis],
) -> Vec<CaseGap> {
    let mut gaps = Vec::new();
    let evidence_ids = evidence
        .iter()
        .map(|item| item.evidence_id.as_str())
        .collect::<HashSet<_>>();
    let fact_ids = facts
        .iter()
        .map(|fact| fact.fact_id.as_str())
        .collect::<HashSet<_>>();
    let linked_fact_ids = evidence_links
        .iter()
        .map(|link| link.fact_id.as_str())
        .collect::<HashSet<_>>();

    for evidence_item in evidence {
        if evidence_item.source.trim().is_empty() {
            gaps.push(CaseGap {
                gap_id: format!("gap:{}:evidence_missing_source", evidence_item.evidence_id),
                project_id: project_id.to_owned(),
                kind: CaseGapKind::EvidenceMissingSource,
                severity: CaseGapSeverity::Blocking,
                entity_id: evidence_item.evidence_id.clone(),
                message: format!(
                    "Evidence {} is missing a source.",
                    evidence_item.evidence_number
                ),
            });
        }

        if evidence_item
            .formed_on
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            gaps.push(CaseGap {
                gap_id: format!(
                    "gap:{}:evidence_missing_formed_on",
                    evidence_item.evidence_id
                ),
                project_id: project_id.to_owned(),
                kind: CaseGapKind::EvidenceMissingFormedOn,
                severity: CaseGapSeverity::Warning,
                entity_id: evidence_item.evidence_id.clone(),
                message: format!(
                    "Evidence {} is missing a formation date.",
                    evidence_item.evidence_number
                ),
            });
        }
    }

    for fact in facts {
        if !linked_fact_ids.contains(fact.fact_id.as_str()) {
            gaps.push(CaseGap {
                gap_id: format!("gap:{}:fact_missing_evidence", fact.fact_id),
                project_id: project_id.to_owned(),
                kind: CaseGapKind::FactMissingEvidence,
                severity: CaseGapSeverity::Blocking,
                entity_id: fact.fact_id.clone(),
                message: format!("Fact \"{}\" has no linked evidence.", fact.title),
            });
        }
    }

    for link in evidence_links {
        if !evidence_ids.contains(link.evidence_id.as_str())
            || !fact_ids.contains(link.fact_id.as_str())
        {
            gaps.push(CaseGap {
                gap_id: format!("gap:{}:invalid_evidence_id", link.link_id),
                project_id: project_id.to_owned(),
                kind: CaseGapKind::InvalidEvidenceId,
                severity: CaseGapSeverity::Blocking,
                entity_id: link.link_id.clone(),
                message: format!(
                    "Evidence link {} references a missing fact or evidence item.",
                    link.link_id
                ),
            });
        }
    }

    gaps.extend(timeline_conflicts(project_id, facts));
    gaps.extend(party_name_inconsistencies(project_id, parties));
    gaps.extend(legal_issue_basis_gaps(
        project_id,
        legal_issues,
        legal_basis,
    ));

    gaps
}

fn timeline_conflicts(project_id: &str, facts: &[CaseFact]) -> Vec<CaseGap> {
    let mut by_title: HashMap<String, HashSet<String>> = HashMap::new();

    for fact in facts {
        if let Some(date) = fact
            .occurred_on
            .as_deref()
            .filter(|date| !date.trim().is_empty())
        {
            by_title
                .entry(normalize_text(&fact.title))
                .or_default()
                .insert(date.to_owned());
        }
    }

    facts
        .iter()
        .filter(|fact| {
            fact.occurred_on.is_some()
                && by_title
                    .get(&normalize_text(&fact.title))
                    .is_some_and(|dates| dates.len() > 1)
        })
        .map(|fact| CaseGap {
            gap_id: format!("gap:{}:timeline_conflict", fact.fact_id),
            project_id: project_id.to_owned(),
            kind: CaseGapKind::TimelineConflict,
            severity: CaseGapSeverity::Warning,
            entity_id: fact.fact_id.clone(),
            message: format!("Fact \"{}\" appears on conflicting dates.", fact.title),
        })
        .collect()
}

fn party_name_inconsistencies(project_id: &str, parties: &[CaseParty]) -> Vec<CaseGap> {
    let mut display_names: HashMap<String, HashSet<String>> = HashMap::new();

    for party in parties {
        let normalized = if party.normalized_name.trim().is_empty() {
            normalize_text(&party.name)
        } else {
            party.normalized_name.clone()
        };
        display_names
            .entry(normalized)
            .or_default()
            .insert(party.name.clone());
    }

    parties
        .iter()
        .filter(|party| {
            let normalized = if party.normalized_name.trim().is_empty() {
                normalize_text(&party.name)
            } else {
                party.normalized_name.clone()
            };
            display_names
                .get(&normalized)
                .is_some_and(|names| names.len() > 1)
        })
        .map(|party| CaseGap {
            gap_id: format!("gap:{}:party_name_inconsistent", party.party_id),
            project_id: project_id.to_owned(),
            kind: CaseGapKind::PartyNameInconsistent,
            severity: CaseGapSeverity::Warning,
            entity_id: party.party_id.clone(),
            message: format!("Party \"{}\" has inconsistent display names.", party.name),
        })
        .collect()
}

fn legal_issue_basis_gaps(
    project_id: &str,
    legal_issues: &[LegalIssue],
    legal_basis: &[LegalBasis],
) -> Vec<CaseGap> {
    let supported_issue_ids = legal_basis
        .iter()
        .filter(|basis| basis.status == CitationStatus::Valid)
        .filter_map(|basis| basis.issue_id.as_deref())
        .collect::<HashSet<_>>();

    legal_issues
        .iter()
        .filter(|issue| issue.status == LegalIssueStatus::Open)
        .filter(|issue| !supported_issue_ids.contains(issue.issue_id.as_str()))
        .map(|issue| CaseGap {
            gap_id: format!("gap:{}:legal_issue_missing_basis", issue.issue_id),
            project_id: project_id.to_owned(),
            kind: CaseGapKind::LegalIssueMissingBasis,
            severity: CaseGapSeverity::Warning,
            entity_id: issue.issue_id.clone(),
            message: format!(
                "Legal issue \"{}\" has no validated legal basis.",
                issue.title
            ),
        })
        .collect()
}

fn normalize_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredCaseExtractionRequest {
    pub project_id: String,
    pub provider_id: String,
    pub file_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredCaseExtractionResponse {
    pub status: StructuredCaseExtractionStatus,
    pub extraction: Option<StructuredCaseExtraction>,
    pub error: Option<StructuredCaseExtractionError>,
    pub raw_output: Option<String>,
    pub repair_output: Option<String>,
    pub repair_attempted: bool,
    pub repaired: bool,
    pub review_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuredCaseExtractionStatus {
    ReviewRequired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredCaseExtractionError {
    pub error_type: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StructuredCaseExtraction {
    pub parties: Vec<ExtractedParty>,
    pub facts: Vec<ExtractedFact>,
    pub evidence: Vec<ExtractedEvidence>,
    pub legal_issues: Vec<ExtractedLegalIssue>,
    pub uncertainties: Vec<ExtractedUncertainty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtractedParty {
    pub name: String,
    pub role: PartyRole,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtractedFact {
    pub occurred_on: Option<String>,
    pub title: String,
    pub description: String,
    pub evidence_numbers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtractedEvidence {
    pub evidence_number: String,
    pub title: String,
    pub source: String,
    pub formed_on: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtractedLegalIssue {
    pub title: String,
    pub description: String,
    pub claim: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtractedUncertainty {
    pub description: String,
    pub related_entity_type: UncertaintyRelatedEntityType,
    pub related_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredExtractionParseError {
    pub message: String,
}

impl Display for StructuredExtractionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "structured extraction parse error: {}",
            self.message
        )
    }
}

pub fn parse_structured_case_extraction(
    raw_output: &str,
) -> Result<StructuredCaseExtraction, StructuredExtractionParseError> {
    let extraction =
        serde_json::from_str::<StructuredCaseExtraction>(raw_output).map_err(|error| {
            StructuredExtractionParseError {
                message: error.to_string(),
            }
        })?;
    validate_extraction_dates(&extraction)?;

    Ok(extraction)
}

fn validate_extraction_dates(
    extraction: &StructuredCaseExtraction,
) -> Result<(), StructuredExtractionParseError> {
    for (label, date) in
        extraction
            .facts
            .iter()
            .filter_map(|fact| fact.occurred_on.as_deref().map(|date| ("occurredOn", date)))
            .chain(extraction.evidence.iter().filter_map(|evidence| {
                evidence.formed_on.as_deref().map(|date| ("formedOn", date))
            }))
    {
        if !is_iso_calendar_date(date) {
            return Err(StructuredExtractionParseError {
                message: format!("{label} must be a valid YYYY-MM-DD calendar date or null"),
            });
        }
    }

    Ok(())
}

fn is_iso_calendar_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u32>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u32>() else {
        return false;
    };
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => return false,
    };

    year > 0 && (1..=days_in_month).contains(&day)
}

pub fn parse_structured_case_extraction_with_repair(
    raw_output: &str,
    repaired_output: Option<&str>,
) -> StructuredCaseExtractionResponse {
    match parse_structured_case_extraction(raw_output) {
        Ok(extraction) => StructuredCaseExtractionResponse {
            status: StructuredCaseExtractionStatus::ReviewRequired,
            extraction: Some(extraction),
            error: None,
            raw_output: None,
            repair_output: None,
            repair_attempted: false,
            repaired: false,
            review_id: None,
        },
        Err(first_error) => match repaired_output {
            Some(repaired_output) => match parse_structured_case_extraction(repaired_output) {
                Ok(extraction) => StructuredCaseExtractionResponse {
                    status: StructuredCaseExtractionStatus::ReviewRequired,
                    extraction: Some(extraction),
                    error: None,
                    raw_output: None,
                    repair_output: None,
                    repair_attempted: true,
                    repaired: true,
                    review_id: None,
                },
                Err(repair_error) => failed_extraction(
                    raw_output,
                    Some(repaired_output),
                    true,
                    format!(
                        "automatic repair failed strict validation: {}",
                        repair_error.message
                    ),
                ),
            },
            None => failed_extraction(raw_output, None, false, first_error.message),
        },
    }
}

fn failed_extraction(
    raw_output: &str,
    repair_output: Option<&str>,
    repair_attempted: bool,
    message: String,
) -> StructuredCaseExtractionResponse {
    StructuredCaseExtractionResponse {
        status: StructuredCaseExtractionStatus::Failed,
        extraction: None,
        error: Some(StructuredCaseExtractionError {
            error_type: "parse_error".to_owned(),
            message,
        }),
        raw_output: Some(raw_output.to_owned()),
        repair_output: repair_output.map(ToOwned::to_owned),
        repair_attempted,
        repaired: false,
        review_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_extraction_json() -> &'static str {
        r#"{
            "parties":[{"name":"Acme Ltd.","role":"plaintiff"}],
            "facts":[{"occurredOn":"2024-01-02","title":"Contract signed","description":"The contract was signed.","evidenceNumbers":["E-1"]}],
            "evidence":[{"evidenceNumber":"E-1","title":"Contract","source":"Client upload","formedOn":"2024-01-02","summary":"Signed contract"}],
            "legalIssues":[{"title":"Breach","description":"Late payment.","claim":"Request payment."}],
            "uncertainties":[{"description":"Payment date is unclear.","relatedEntityType":"fact","relatedReference":"Contract signed"}]
        }"#
    }

    #[test]
    fn analyzes_case_gaps_for_missing_evidence_source_dates_and_invalid_links() {
        let parties = Vec::new();
        let facts = vec![CaseFact {
            fact_id: "fact-1".to_owned(),
            project_id: "project-1".to_owned(),
            occurred_on: Some("2024-01-01".to_owned()),
            title: "Delivery".to_owned(),
            description: "Delivery occurred.".to_owned(),
            source: String::new(),
            confirmation_status: ConfirmationStatus::Confirmed,
        }];
        let evidence = vec![EvidenceItem {
            evidence_id: "ev-1".to_owned(),
            project_id: "project-1".to_owned(),
            evidence_number: "E-1".to_owned(),
            title: "Receipt".to_owned(),
            source: String::new(),
            formed_on: None,
            summary: String::new(),
            storage_reference: String::new(),
            confirmation_status: ConfirmationStatus::Confirmed,
        }];
        let links = vec![EvidenceLink {
            link_id: "link-1".to_owned(),
            project_id: "project-1".to_owned(),
            fact_id: "fact-1".to_owned(),
            evidence_id: "ev-missing".to_owned(),
        }];
        let gaps = analyze_case_gaps("project-1", &parties, &facts, &evidence, &links, &[], &[]);

        assert!(gaps
            .iter()
            .any(|gap| gap.kind == CaseGapKind::EvidenceMissingSource));
        assert!(gaps
            .iter()
            .any(|gap| gap.kind == CaseGapKind::EvidenceMissingFormedOn));
        assert!(gaps
            .iter()
            .any(|gap| gap.kind == CaseGapKind::InvalidEvidenceId));
    }

    #[test]
    fn analyzes_fact_without_evidence() {
        let fact = CaseFact {
            fact_id: "fact-1".to_owned(),
            project_id: "project-1".to_owned(),
            occurred_on: Some("2024-01-01".to_owned()),
            title: "Payment".to_owned(),
            description: "Payment was due.".to_owned(),
            source: String::new(),
            confirmation_status: ConfirmationStatus::Confirmed,
        };
        let gaps = analyze_case_gaps("project-1", &[], &[fact], &[], &[], &[], &[]);

        assert_eq!(gaps[0].kind, CaseGapKind::FactMissingEvidence);
    }

    #[test]
    fn analyzes_timeline_conflict_and_party_name_inconsistency() {
        let parties = vec![
            CaseParty {
                party_id: "party-1".to_owned(),
                project_id: "project-1".to_owned(),
                name: "Acme Ltd.".to_owned(),
                normalized_name: "acmeltd".to_owned(),
                role: PartyRole::Plaintiff,
                contact: String::new(),
                notes: String::new(),
            },
            CaseParty {
                party_id: "party-2".to_owned(),
                project_id: "project-1".to_owned(),
                name: "ACME Limited".to_owned(),
                normalized_name: "acmeltd".to_owned(),
                role: PartyRole::Plaintiff,
                contact: String::new(),
                notes: String::new(),
            },
        ];
        let facts = vec![
            CaseFact {
                fact_id: "fact-1".to_owned(),
                project_id: "project-1".to_owned(),
                occurred_on: Some("2024-01-01".to_owned()),
                title: "Payment due".to_owned(),
                description: String::new(),
                source: String::new(),
                confirmation_status: ConfirmationStatus::Confirmed,
            },
            CaseFact {
                fact_id: "fact-2".to_owned(),
                project_id: "project-1".to_owned(),
                occurred_on: Some("2024-02-01".to_owned()),
                title: "Payment due".to_owned(),
                description: String::new(),
                source: String::new(),
                confirmation_status: ConfirmationStatus::Confirmed,
            },
        ];
        let gaps = analyze_case_gaps("project-1", &parties, &facts, &[], &[], &[], &[]);

        assert!(gaps
            .iter()
            .any(|gap| gap.kind == CaseGapKind::TimelineConflict));
        assert!(gaps
            .iter()
            .any(|gap| gap.kind == CaseGapKind::PartyNameInconsistent));
    }

    #[test]
    fn analyzes_open_legal_issue_without_valid_basis() {
        let issue = LegalIssue {
            issue_id: "issue-1".to_owned(),
            project_id: "project-1".to_owned(),
            title: "Breach".to_owned(),
            description: String::new(),
            claim: String::new(),
            status: LegalIssueStatus::Open,
            confirmation_status: ConfirmationStatus::Confirmed,
        };
        let invalid_basis = LegalBasis {
            basis_id: "basis-1".to_owned(),
            project_id: "project-1".to_owned(),
            issue_id: Some("issue-1".to_owned()),
            source_id: "law:missing:version:art:1".to_owned(),
            status: CitationStatus::Invalid,
            invalid_reason: Some(CitationInvalidReason::NotFound),
            case_date: Some("2024-01-01".to_owned()),
            article_id: String::new(),
            document_id: String::new(),
            version_id: String::new(),
            document_title: String::new(),
            version_label: String::new(),
            article_number: String::new(),
            article_title: None,
            canonical_label: String::new(),
            effective_from: String::new(),
            effective_to: None,
            version_status: String::new(),
            excerpt: String::new(),
            note: String::new(),
            created_at: String::new(),
        };
        let valid_basis = LegalBasis {
            status: CitationStatus::Valid,
            invalid_reason: None,
            ..invalid_basis.clone()
        };

        let gaps = analyze_case_gaps(
            "project-1",
            &[],
            &[],
            &[],
            &[],
            std::slice::from_ref(&issue),
            std::slice::from_ref(&invalid_basis),
        );
        assert_eq!(gaps[0].kind, CaseGapKind::LegalIssueMissingBasis);

        let gaps = analyze_case_gaps("project-1", &[], &[], &[], &[], &[issue], &[valid_basis]);
        assert!(gaps.is_empty());
    }

    #[test]
    fn parses_valid_structured_extraction_json() {
        let extraction =
            parse_structured_case_extraction(valid_extraction_json()).expect("valid JSON parses");

        assert_eq!(extraction.parties[0].role, PartyRole::Plaintiff);
        assert_eq!(extraction.facts[0].evidence_numbers, vec!["E-1"]);
    }

    #[test]
    fn rejects_missing_fields_type_errors_and_extra_fields() {
        assert!(parse_structured_case_extraction(r#"{"parties":[]}"#).is_err());
        assert!(parse_structured_case_extraction(
            r#"{"parties":"bad","facts":[],"evidence":[],"legalIssues":[],"uncertainties":[]}"#
        )
        .is_err());
        assert!(parse_structured_case_extraction(
            r#"{"parties":[],"facts":[],"evidence":[],"legalIssues":[],"uncertainties":[],"extra":true}"#
        )
        .is_err());
        assert!(parse_structured_case_extraction(
            r#"{"parties":[],"facts":[],"evidence":[],"legalIssues":[],"uncertainties":[{"description":"bad type","relatedEntityType":"nonsense","relatedReference":null}]}"#
        )
        .is_err());
        assert!(parse_structured_case_extraction(
            r#"{"parties":[],"facts":[{"occurredOn":"tomorrow","title":"bad date","description":"","evidenceNumbers":[]}],"evidence":[],"legalIssues":[],"uncertainties":[]}"#
        )
        .is_err());
    }

    #[test]
    fn repair_flow_can_succeed_or_surface_raw_failure() {
        let repaired = parse_structured_case_extraction_with_repair(
            r#"{"parties":[]}"#,
            Some(valid_extraction_json()),
        );
        assert_eq!(
            repaired.status,
            StructuredCaseExtractionStatus::ReviewRequired
        );
        assert!(repaired.repaired);
        assert!(repaired.repair_attempted);
        assert!(repaired.raw_output.is_none());

        let failed = parse_structured_case_extraction_with_repair(
            r#"{"parties":[]}"#,
            Some(r#"{"still":"bad"}"#),
        );
        assert_eq!(failed.status, StructuredCaseExtractionStatus::Failed);
        assert!(failed.error.is_some());
        assert!(failed.repair_attempted);
        assert_eq!(failed.raw_output.as_deref(), Some(r#"{"parties":[]}"#));
        assert_eq!(failed.repair_output.as_deref(), Some(r#"{"still":"bad"}"#));
    }
}
