use crate::{
    CaseChangeSpec, ContractError, ContractErrorType, DocumentSpec, MapSpec, ValidationContext,
    MAX_MODEL_RESPONSE_BYTES,
};
use serde::{Deserialize, Serialize};

pub const MAX_JSON_FENCE_MARKERS: usize = 2;
pub const JSON_FENCE_OPEN_LF: &str = "```json\n";
pub const JSON_FENCE_OPEN_CRLF: &str = "```json\r\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum StructuredOutput {
    DocumentSpec(DocumentSpec),
    MapSpec(MapSpec),
    CaseChangeSpec(CaseChangeSpec),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StructuredEnvelope {
    pub schema_version: u16,
    pub output: StructuredOutput,
}

impl StructuredEnvelope {
    pub fn validate(&self, context: &ValidationContext) -> Result<(), ContractError> {
        crate::validation::validate_schema_version("envelope.schemaVersion", self.schema_version)?;
        match &self.output {
            StructuredOutput::DocumentSpec(spec) => spec.validate(context),
            StructuredOutput::MapSpec(spec) => spec.validate(context),
            StructuredOutput::CaseChangeSpec(spec) => spec.validate(context),
        }
    }
}

/// Parse one bounded JSON value, optionally wrapped by exactly one outer
/// lowercase `json` Markdown fence. Any prose, a second JSON value, nested
/// fences, or a non-JSON fence fails closed.
pub fn parse_structured_envelope(input: &str) -> Result<StructuredEnvelope, ContractError> {
    if input.len() > MAX_MODEL_RESPONSE_BYTES {
        return Err(ContractError::limit(
            ContractErrorType::ResponseTooLarge,
            "response",
            "model response exceeds byte limit",
            MAX_MODEL_RESPONSE_BYTES,
            input.len(),
        ));
    }
    let json = single_json_body(input)?;
    serde_json::from_str(json).map_err(|_| {
        ContractError::new(
            ContractErrorType::InvalidJson,
            "response",
            "structured JSON does not match the closed envelope contract",
        )
    })
}

pub fn parse_and_validate_envelope(
    input: &str,
    context: &ValidationContext,
) -> Result<StructuredEnvelope, ContractError> {
    let envelope = parse_structured_envelope(input)?;
    envelope.validate(context)?;
    Ok(envelope)
}

fn single_json_body(input: &str) -> Result<&str, ContractError> {
    let trimmed = input.trim();
    if !trimmed.starts_with("```") {
        if trimmed.contains("```") {
            return Err(invalid_fence());
        }
        return Ok(trimmed);
    }

    let (after_open, line_ending) = if let Some(body) = trimmed.strip_prefix(JSON_FENCE_OPEN_LF) {
        (body, "\n")
    } else if let Some(body) = trimmed.strip_prefix(JSON_FENCE_OPEN_CRLF) {
        (body, "\r\n")
    } else {
        return Err(invalid_fence());
    };
    let close = format!("{line_ending}```");
    let body = after_open.strip_suffix(&close).ok_or_else(invalid_fence)?;
    if body.contains("```") || trimmed.matches("```").count() != MAX_JSON_FENCE_MARKERS {
        return Err(invalid_fence());
    }
    Ok(body)
}

fn invalid_fence() -> ContractError {
    ContractError::new(
        ContractErrorType::InvalidEnvelope,
        "response",
        "response must be one raw JSON value or one outer JSON fence",
    )
}
