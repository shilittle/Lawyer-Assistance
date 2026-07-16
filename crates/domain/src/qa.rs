use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerCandidatesRequest {
    pub question: String,
    pub law_name: Option<String>,
    pub article_number: Option<String>,
    pub keywords: Vec<String>,
    pub case_date: Option<String>,
    pub effectiveness_levels: Vec<String>,
    pub include_expired: bool,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StructuredLegalQuery {
    pub law_names: Vec<String>,
    pub article_numbers: Vec<String>,
    pub keywords: Vec<String>,
    pub legal_issue: String,
    pub case_date: Option<String>,
    pub effectiveness_levels: Vec<String>,
    pub include_expired: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalSource {
    pub source_id: String,
    pub article_id: String,
    pub document_id: String,
    pub version_id: String,
    pub document_title: String,
    pub version_label: String,
    pub article_number: String,
    pub article_title: Option<String>,
    pub canonical_label: String,
    pub content: String,
    pub snippet: String,
    pub effective_from: String,
    pub effective_to: Option<String>,
    pub version_status: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerContext {
    pub query: StructuredLegalQuery,
    pub sources: Vec<LegalSource>,
    pub prompt: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerCandidatesResponse {
    pub context: LegalAnswerContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationStatus {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CitationInvalidReason {
    InvalidSyntax,
    Duplicate,
    NotFound,
    NotInContext,
    VersionMismatch,
    DateOutOfRange,
    ParagraphNotFound,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedCitation {
    pub raw_marker: String,
    pub source_id: String,
    pub start_index: usize,
    pub end_index: usize,
    pub valid_syntax: bool,
    pub duplicate: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedCitation {
    pub raw_marker: String,
    pub source_id: String,
    pub status: CitationStatus,
    pub reason: Option<CitationInvalidReason>,
    pub source: Option<LegalSource>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CitationValidationReport {
    pub citations: Vec<ValidatedCitation>,
    pub valid_count: u32,
    pub invalid_count: u32,
    /// True when at least one legal sub-clause lacks an adjacent, valid local
    /// source marker. A false value is structural coverage, not entailment.
    pub unsupported_legal_conclusion: bool,
    /// Reserved for an explicit human or separately auditable semantic review.
    /// The current deterministic validator never claims this capability.
    #[serde(default)]
    pub semantic_support_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerRequest {
    pub request_id: String,
    pub project_id: String,
    pub provider_id: String,
    pub question: String,
    pub law_name: Option<String>,
    pub article_number: Option<String>,
    pub keywords: Vec<String>,
    pub case_date: Option<String>,
    pub effectiveness_levels: Vec<String>,
    pub include_expired: bool,
    pub limit: Option<u32>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAuditSnapshot {
    pub kind: String,
    pub model_id: String,
    pub base_url: String,
    pub capabilities: ProviderAuditCapabilities,
    pub options: ProviderAuditOptions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAuditCapabilities {
    pub chat: bool,
    pub streaming: bool,
    pub custom_model_id: bool,
    pub custom_base_url: bool,
    pub reasoning: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderAuditOptions {
    pub thinking: Option<bool>,
    pub enable_thinking: Option<bool>,
    pub thinking_budget: Option<u32>,
    pub reasoning_effort: Option<String>,
    pub endpoint_id: Option<String>,
    pub workspace_id: Option<String>,
    pub allow_private_network: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListLegalAnswerRecordsRequest {
    pub project_id: String,
    pub limit: Option<u32>,
    pub before_created_at: Option<String>,
    pub before_record_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerHistoryRecord {
    pub record_id: String,
    pub project_id: String,
    pub provider_id: String,
    pub provider_snapshot: Option<ProviderAuditSnapshot>,
    pub question: String,
    pub answer: String,
    pub case_date: Option<String>,
    pub query: StructuredLegalQuery,
    pub source_ids: Vec<String>,
    /// Complete ordered candidate set that was sent to the provider, hydrated
    /// by its immutable citation IDs when history is read.
    pub sources: Vec<LegalSource>,
    /// IDs retained for audit when an older/newer legal-core distribution can
    /// no longer hydrate a historical candidate.
    pub missing_source_ids: Vec<String>,
    pub citation_report: CitationValidationReport,
    pub created_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListLegalAnswerRecordsResponse {
    pub records: Vec<LegalAnswerHistoryRecord>,
    pub has_more: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalAnswerStreamEventType {
    Delta,
    Usage,
    Error,
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerStreamUsage {
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
    pub total_tokens: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerStreamEvent {
    pub request_id: String,
    pub event_type: LegalAnswerStreamEventType,
    pub content: Option<String>,
    pub usage: Option<LegalAnswerStreamUsage>,
    pub error_type: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerResponse {
    pub provider_id: String,
    pub answer: String,
    pub context: LegalAnswerContext,
    pub citation_report: CitationValidationReport,
    pub record_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelLegalAnswerRequest {
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelLegalAnswerResponse {
    pub request_id: String,
    pub cancelled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_answer_request_uses_camel_case_contract() {
        let request = LegalAnswerRequest {
            request_id: "answer-test-1".to_owned(),
            project_id: "case-1".to_owned(),
            provider_id: "deepseek-main".to_owned(),
            question: "合同违约责任是什么？".to_owned(),
            law_name: Some("民法典".to_owned()),
            article_number: None,
            keywords: vec!["违约责任".to_owned()],
            case_date: Some("2024-01-01".to_owned()),
            effectiveness_levels: Vec::new(),
            include_expired: false,
            limit: Some(8),
            temperature: Some(0.1),
            max_tokens: Some(512),
        };

        let serialized = serde_json::to_value(request).expect("request serializes");

        assert_eq!(serialized["providerId"], "deepseek-main");
        assert_eq!(serialized["projectId"], "case-1");
        assert_eq!(serialized["requestId"], "answer-test-1");
        assert_eq!(serialized["caseDate"], "2024-01-01");
        assert_eq!(serialized["includeExpired"], false);
        assert_eq!(serialized["maxTokens"], 512);
    }

    #[test]
    fn legal_answer_history_cursor_uses_camel_case_contract() {
        let request = ListLegalAnswerRecordsRequest {
            project_id: "case-1".to_owned(),
            limit: Some(25),
            before_created_at: Some("2026-07-14 12:00:00".to_owned()),
            before_record_id: Some("record-25".to_owned()),
        };

        let serialized = serde_json::to_value(request).expect("history request serializes");

        assert_eq!(serialized["projectId"], "case-1");
        assert_eq!(serialized["beforeCreatedAt"], "2026-07-14 12:00:00");
        assert_eq!(serialized["beforeRecordId"], "record-25");
    }
}
