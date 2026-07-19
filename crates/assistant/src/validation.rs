use crate::{ContractError, ContractErrorType};
use std::collections::BTreeSet;

pub const MAX_IDENTIFIER_BYTES: usize = 128;
pub const MAX_SOURCE_REFS_PER_ITEM: usize = 16;

/// Trusted ownership and citation results supplied by the application layer.
///
/// Specs may name only identifiers in this context. The assistant crate does
/// not query a database and therefore cannot establish ownership by itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationContext {
    allowed_source_refs: BTreeSet<String>,
    validated_legal_source_refs: BTreeSet<String>,
    allowed_attachment_ids: BTreeSet<String>,
    allowed_artifact_ids: BTreeSet<String>,
    allowed_case_fact_ids: BTreeSet<String>,
    allowed_case_issue_ids: BTreeSet<String>,
}

impl ValidationContext {
    pub fn allow_source_ref(&mut self, value: impl Into<String>) {
        self.allowed_source_refs.insert(value.into());
    }

    pub fn allow_validated_legal_source(&mut self, value: impl Into<String>) {
        let value = value.into();
        self.allowed_source_refs.insert(value.clone());
        self.validated_legal_source_refs.insert(value);
    }

    pub fn allow_attachment(&mut self, value: impl Into<String>) {
        self.allowed_attachment_ids.insert(value.into());
    }

    pub fn allow_artifact(&mut self, value: impl Into<String>) {
        self.allowed_artifact_ids.insert(value.into());
    }

    pub fn allow_case_fact(&mut self, value: impl Into<String>) {
        self.allowed_case_fact_ids.insert(value.into());
    }

    pub fn allow_case_issue(&mut self, value: impl Into<String>) {
        self.allowed_case_issue_ids.insert(value.into());
    }

    pub(crate) fn is_source_allowed(&self, value: &str) -> bool {
        self.allowed_source_refs.contains(value)
    }

    pub(crate) fn is_legal_source_validated(&self, value: &str) -> bool {
        self.validated_legal_source_refs.contains(value)
    }

    pub(crate) fn is_attachment_allowed(&self, value: &str) -> bool {
        self.allowed_attachment_ids.contains(value)
    }

    pub(crate) fn is_artifact_allowed(&self, value: &str) -> bool {
        self.allowed_artifact_ids.contains(value)
    }

    pub(crate) fn is_case_fact_allowed(&self, value: &str) -> bool {
        self.allowed_case_fact_ids.contains(value)
    }

    pub(crate) fn is_case_issue_allowed(&self, value: &str) -> bool {
        self.allowed_case_issue_ids.contains(value)
    }
}

pub(crate) fn validate_schema_version(path: &str, actual: u16) -> Result<(), ContractError> {
    if actual == crate::CONTRACT_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ContractError::new(
            ContractErrorType::UnsupportedSchemaVersion,
            path,
            "unsupported schema version",
        ))
    }
}

pub(crate) fn validate_required_text(
    path: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::new(
            ContractErrorType::EmptyText,
            path,
            "text must not be empty",
        ));
    }
    validate_text(path, value, max_bytes)
}

pub(crate) fn validate_optional_text(
    path: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), ContractError> {
    if let Some(value) = value {
        validate_required_text(path, value, max_bytes)?;
    }
    Ok(())
}

pub(crate) fn validate_text(
    path: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ContractError> {
    if value.len() > max_bytes {
        return Err(ContractError::limit(
            ContractErrorType::TextTooLong,
            path,
            "text exceeds byte limit",
            max_bytes,
            value.len(),
        ));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ContractError::new(
            ContractErrorType::InvalidJson,
            path,
            "text contains a disallowed control character",
        ));
    }
    Ok(())
}

pub(crate) fn validate_count(path: &str, actual: usize, max: usize) -> Result<(), ContractError> {
    if actual > max {
        Err(ContractError::limit(
            ContractErrorType::TooManyItems,
            path,
            "array exceeds item limit",
            max,
            actual,
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_nonempty_count(
    path: &str,
    actual: usize,
    max: usize,
) -> Result<(), ContractError> {
    if actual == 0 {
        return Err(ContractError::new(
            ContractErrorType::MissingValue,
            path,
            "array must contain at least one item",
        ));
    }
    validate_count(path, actual, max)
}

pub(crate) fn validate_identifier(path: &str, value: &str) -> Result<(), ContractError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
    {
        return Err(ContractError::new(
            ContractErrorType::InvalidIdentifier,
            path,
            "identifier must use bounded ASCII opaque-id characters",
        ));
    }
    Ok(())
}

pub(crate) fn insert_unique(
    seen: &mut BTreeSet<String>,
    path: &str,
    value: &str,
) -> Result<(), ContractError> {
    validate_identifier(path, value)?;
    if !seen.insert(value.to_owned()) {
        return Err(ContractError::new(
            ContractErrorType::DuplicateIdentifier,
            path,
            "identifier must be unique",
        ));
    }
    Ok(())
}

pub(crate) fn validate_source_refs(
    path: &str,
    source_refs: &[String],
    context: &ValidationContext,
) -> Result<(), ContractError> {
    validate_count(path, source_refs.len(), MAX_SOURCE_REFS_PER_ITEM)?;
    let mut seen = BTreeSet::new();
    for (index, source_ref) in source_refs.iter().enumerate() {
        let item_path = format!("{path}[{index}]");
        insert_unique(&mut seen, &item_path, source_ref)?;
        if !context.is_source_allowed(source_ref) {
            return Err(ContractError::new(
                ContractErrorType::UnknownReference,
                item_path,
                "source reference is not owned by the current run",
            ));
        }
    }
    Ok(())
}

pub(crate) fn add_text_bytes(total: &mut usize, value: &str) {
    *total = total.saturating_add(value.len());
}

pub(crate) fn validate_total_text(
    path: &str,
    total: usize,
    max: usize,
) -> Result<(), ContractError> {
    if total > max {
        Err(ContractError::limit(
            ContractErrorType::TextTooLong,
            path,
            "combined text exceeds byte limit",
            max,
            total,
        ))
    } else {
        Ok(())
    }
}
