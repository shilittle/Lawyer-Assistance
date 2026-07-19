use crate::validation::{
    add_text_bytes, insert_unique, validate_count, validate_identifier, validate_nonempty_count,
    validate_optional_text, validate_required_text, validate_schema_version, validate_source_refs,
    validate_total_text,
};
use crate::{ContractError, ContractErrorType, ValidationContext};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_CASE_CHANGE_TEXT_BYTES: usize = 512 * 1024;
pub const MAX_FACT_ADDITIONS: usize = 64;
pub const MAX_EVIDENCE_ADDITIONS: usize = 64;
pub const MAX_ISSUE_ADDITIONS: usize = 32;
pub const MAX_LEGAL_BASIS_ADDITIONS: usize = 64;
pub const MAX_ATTACHMENT_TRANSFERS: usize = 2;
pub const MAX_ARTIFACT_TRANSFERS: usize = 16;
pub const MAX_ENTITY_LINKS: usize = 32;

pub const MAX_FACT_STATEMENT_BYTES: usize = 8 * 1024;
pub const MAX_DATE_TEXT_BYTES: usize = 32;
pub const MAX_EVIDENCE_TITLE_BYTES: usize = 256;
pub const MAX_EVIDENCE_SUMMARY_BYTES: usize = 8 * 1024;
pub const MAX_ISSUE_TITLE_BYTES: usize = 256;
pub const MAX_ISSUE_ANALYSIS_BYTES: usize = 8 * 1024;
pub const MAX_LEGAL_BASIS_CITATION_BYTES: usize = 2 * 1024;
pub const MAX_LEGAL_BASIS_PROPOSITION_BYTES: usize = 4 * 1024;
pub const MAX_TRANSFER_TITLE_BYTES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactAddition {
    pub id: String,
    pub statement: String,
    pub occurred_on: Option<String>,
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceAddition {
    pub id: String,
    pub title: String,
    pub summary: String,
    pub proves_fact_ids: Vec<String>,
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssueAddition {
    pub id: String,
    pub title: String,
    pub analysis: String,
    pub related_fact_ids: Vec<String>,
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalBasisAddition {
    pub id: String,
    pub issue_ids: Vec<String>,
    pub source_ref: String,
    pub marker: String,
    pub citation: String,
    pub proposition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttachmentTransfer {
    pub attachment_id: String,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactTransfer {
    pub artifact_id: String,
    pub title: String,
}

/// Model-proposed additions only. Project identifiers, SQL, paths, command
/// names, update/delete operations, and an apply flag are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseChangeSpec {
    pub schema_version: u16,
    pub facts: Vec<FactAddition>,
    pub evidence: Vec<EvidenceAddition>,
    pub issues: Vec<IssueAddition>,
    pub legal_basis: Vec<LegalBasisAddition>,
    pub attachment_transfers: Vec<AttachmentTransfer>,
    pub artifact_transfers: Vec<ArtifactTransfer>,
}

impl CaseChangeSpec {
    pub fn validate(&self, context: &ValidationContext) -> Result<(), ContractError> {
        validate_schema_version("caseChange.schemaVersion", self.schema_version)?;
        validate_count("caseChange.facts", self.facts.len(), MAX_FACT_ADDITIONS)?;
        validate_count(
            "caseChange.evidence",
            self.evidence.len(),
            MAX_EVIDENCE_ADDITIONS,
        )?;
        validate_count("caseChange.issues", self.issues.len(), MAX_ISSUE_ADDITIONS)?;
        validate_count(
            "caseChange.legalBasis",
            self.legal_basis.len(),
            MAX_LEGAL_BASIS_ADDITIONS,
        )?;
        validate_count(
            "caseChange.attachmentTransfers",
            self.attachment_transfers.len(),
            MAX_ATTACHMENT_TRANSFERS,
        )?;
        validate_count(
            "caseChange.artifactTransfers",
            self.artifact_transfers.len(),
            MAX_ARTIFACT_TRANSFERS,
        )?;
        let total_changes = self
            .facts
            .len()
            .saturating_add(self.evidence.len())
            .saturating_add(self.issues.len())
            .saturating_add(self.legal_basis.len())
            .saturating_add(self.attachment_transfers.len())
            .saturating_add(self.artifact_transfers.len());
        if total_changes == 0 {
            return Err(ContractError::new(
                ContractErrorType::MissingValue,
                "caseChange",
                "case change proposal must contain at least one bounded addition or transfer",
            ));
        }

        let mut all_new_ids = BTreeSet::new();
        let mut new_fact_ids = BTreeSet::new();
        let mut new_issue_ids = BTreeSet::new();
        let mut total_text = 0usize;

        for (index, fact) in self.facts.iter().enumerate() {
            let path = format!("caseChange.facts[{index}]");
            insert_unique(&mut all_new_ids, &format!("{path}.id"), &fact.id)?;
            new_fact_ids.insert(fact.id.clone());
            validate_required_text(
                &format!("{path}.statement"),
                &fact.statement,
                MAX_FACT_STATEMENT_BYTES,
            )?;
            validate_optional_text(
                &format!("{path}.occurredOn"),
                fact.occurred_on.as_deref(),
                MAX_DATE_TEXT_BYTES,
            )?;
            validate_nonempty_count(
                &format!("{path}.sourceRefs"),
                fact.source_refs.len(),
                crate::validation::MAX_SOURCE_REFS_PER_ITEM,
            )?;
            validate_source_refs(&format!("{path}.sourceRefs"), &fact.source_refs, context)?;
            add_text_bytes(&mut total_text, &fact.statement);
            if let Some(occurred_on) = &fact.occurred_on {
                add_text_bytes(&mut total_text, occurred_on);
            }
        }

        for (index, issue) in self.issues.iter().enumerate() {
            let path = format!("caseChange.issues[{index}]");
            insert_unique(&mut all_new_ids, &format!("{path}.id"), &issue.id)?;
            new_issue_ids.insert(issue.id.clone());
            validate_required_text(
                &format!("{path}.title"),
                &issue.title,
                MAX_ISSUE_TITLE_BYTES,
            )?;
            validate_required_text(
                &format!("{path}.analysis"),
                &issue.analysis,
                MAX_ISSUE_ANALYSIS_BYTES,
            )?;
            validate_count(
                &format!("{path}.relatedFactIds"),
                issue.related_fact_ids.len(),
                MAX_ENTITY_LINKS,
            )?;
            validate_source_refs(&format!("{path}.sourceRefs"), &issue.source_refs, context)?;
            if issue.related_fact_ids.is_empty() && issue.source_refs.is_empty() {
                return Err(ContractError::new(
                    ContractErrorType::MissingProvenance,
                    path,
                    "issue addition requires a related fact or owned source",
                ));
            }
            validate_fact_links(
                &format!("{path}.relatedFactIds"),
                &issue.related_fact_ids,
                &new_fact_ids,
                context,
            )?;
            add_text_bytes(&mut total_text, &issue.title);
            add_text_bytes(&mut total_text, &issue.analysis);
        }

        for (index, evidence) in self.evidence.iter().enumerate() {
            let path = format!("caseChange.evidence[{index}]");
            insert_unique(&mut all_new_ids, &format!("{path}.id"), &evidence.id)?;
            validate_required_text(
                &format!("{path}.title"),
                &evidence.title,
                MAX_EVIDENCE_TITLE_BYTES,
            )?;
            validate_required_text(
                &format!("{path}.summary"),
                &evidence.summary,
                MAX_EVIDENCE_SUMMARY_BYTES,
            )?;
            validate_count(
                &format!("{path}.provesFactIds"),
                evidence.proves_fact_ids.len(),
                MAX_ENTITY_LINKS,
            )?;
            validate_nonempty_count(
                &format!("{path}.sourceRefs"),
                evidence.source_refs.len(),
                crate::validation::MAX_SOURCE_REFS_PER_ITEM,
            )?;
            validate_source_refs(
                &format!("{path}.sourceRefs"),
                &evidence.source_refs,
                context,
            )?;
            validate_fact_links(
                &format!("{path}.provesFactIds"),
                &evidence.proves_fact_ids,
                &new_fact_ids,
                context,
            )?;
            add_text_bytes(&mut total_text, &evidence.title);
            add_text_bytes(&mut total_text, &evidence.summary);
        }

        for (index, basis) in self.legal_basis.iter().enumerate() {
            let path = format!("caseChange.legalBasis[{index}]");
            insert_unique(&mut all_new_ids, &format!("{path}.id"), &basis.id)?;
            validate_count(
                &format!("{path}.issueIds"),
                basis.issue_ids.len(),
                MAX_ENTITY_LINKS,
            )?;
            let mut seen_issue_ids = BTreeSet::new();
            for (issue_index, issue_id) in basis.issue_ids.iter().enumerate() {
                let issue_path = format!("{path}.issueIds[{issue_index}]");
                insert_unique(&mut seen_issue_ids, &issue_path, issue_id)?;
                if !new_issue_ids.contains(issue_id) && !context.is_case_issue_allowed(issue_id) {
                    return Err(ContractError::new(
                        ContractErrorType::InvalidEndpoint,
                        issue_path,
                        "legal basis issue does not reference a proposed or confirmed issue",
                    ));
                }
            }
            validate_identifier(&format!("{path}.sourceRef"), &basis.source_ref)?;
            if !context.is_legal_source_validated(&basis.source_ref) {
                return Err(ContractError::new(
                    ContractErrorType::UnvalidatedLegalCitation,
                    format!("{path}.sourceRef"),
                    "legal basis was not validated against the local source set",
                ));
            }
            validate_required_text(
                &format!("{path}.marker"),
                &basis.marker,
                crate::document::MAX_CITATION_MARKER_BYTES,
            )?;
            if basis.marker != format!("[SRC:{}]", basis.source_ref) {
                return Err(ContractError::new(
                    ContractErrorType::UnvalidatedLegalCitation,
                    format!("{path}.marker"),
                    "legal basis marker does not match its validated local source",
                ));
            }
            validate_required_text(
                &format!("{path}.citation"),
                &basis.citation,
                MAX_LEGAL_BASIS_CITATION_BYTES,
            )?;
            if crate::document::parse_public_citation(&basis.citation).is_none() {
                return Err(ContractError::new(
                    ContractErrorType::UnvalidatedLegalCitation,
                    format!("{path}.citation"),
                    "public citation must include the legal or case name, exact locator, and year",
                ));
            }
            validate_required_text(
                &format!("{path}.proposition"),
                &basis.proposition,
                MAX_LEGAL_BASIS_PROPOSITION_BYTES,
            )?;
            add_text_bytes(&mut total_text, &basis.marker);
            add_text_bytes(&mut total_text, &basis.citation);
            add_text_bytes(&mut total_text, &basis.proposition);
        }

        validate_transfers(self, context, &mut total_text)?;
        validate_total_text("caseChange", total_text, MAX_CASE_CHANGE_TEXT_BYTES)
    }
}

fn validate_fact_links(
    path: &str,
    fact_ids: &[String],
    new_fact_ids: &BTreeSet<String>,
    context: &ValidationContext,
) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for (index, fact_id) in fact_ids.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        insert_unique(&mut seen, &item_path, fact_id)?;
        if !new_fact_ids.contains(fact_id) && !context.is_case_fact_allowed(fact_id) {
            return Err(ContractError::new(
                ContractErrorType::InvalidEndpoint,
                item_path,
                "fact link does not reference a proposed or confirmed fact",
            ));
        }
    }
    Ok(())
}

fn validate_transfers(
    spec: &CaseChangeSpec,
    context: &ValidationContext,
    total_text: &mut usize,
) -> Result<(), ContractError> {
    let mut attachment_ids = BTreeSet::new();
    for (index, transfer) in spec.attachment_transfers.iter().enumerate() {
        let path = format!("caseChange.attachmentTransfers[{index}]");
        insert_unique(
            &mut attachment_ids,
            &format!("{path}.attachmentId"),
            &transfer.attachment_id,
        )?;
        if !context.is_attachment_allowed(&transfer.attachment_id) {
            return Err(ContractError::new(
                ContractErrorType::UnknownReference,
                format!("{path}.attachmentId"),
                "attachment is not owned by the current conversation",
            ));
        }
        validate_required_text(
            &format!("{path}.title"),
            &transfer.title,
            MAX_TRANSFER_TITLE_BYTES,
        )?;
        add_text_bytes(total_text, &transfer.title);
    }

    let mut artifact_ids = BTreeSet::new();
    for (index, transfer) in spec.artifact_transfers.iter().enumerate() {
        let path = format!("caseChange.artifactTransfers[{index}]");
        insert_unique(
            &mut artifact_ids,
            &format!("{path}.artifactId"),
            &transfer.artifact_id,
        )?;
        if !context.is_artifact_allowed(&transfer.artifact_id) {
            return Err(ContractError::new(
                ContractErrorType::UnknownReference,
                format!("{path}.artifactId"),
                "artifact is not owned by the current conversation",
            ));
        }
        validate_required_text(
            &format!("{path}.title"),
            &transfer.title,
            MAX_TRANSFER_TITLE_BYTES,
        )?;
        add_text_bytes(total_text, &transfer.title);
    }
    Ok(())
}
