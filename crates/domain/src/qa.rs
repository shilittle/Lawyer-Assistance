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
    pub unsupported_legal_conclusion: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalAnswerRequest {
    pub request_id: String,
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
        assert_eq!(serialized["requestId"], "answer-test-1");
        assert_eq!(serialized["caseDate"], "2024-01-01");
        assert_eq!(serialized["includeExpired"], false);
        assert_eq!(serialized["maxTokens"], 512);
    }
}
