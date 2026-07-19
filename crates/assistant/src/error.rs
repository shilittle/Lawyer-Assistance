use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

/// Stable, non-sensitive error categories suitable for IPC and audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractErrorType {
    InvalidJson,
    InvalidEnvelope,
    ResponseTooLarge,
    UnsupportedSchemaVersion,
    UnknownCapability,
    BudgetExceeded,
    MissingValue,
    EmptyText,
    TextTooLong,
    TooManyItems,
    InvalidIdentifier,
    DuplicateIdentifier,
    UnknownReference,
    UnvalidatedLegalCitation,
    InvalidProvenance,
    MissingProvenance,
    InvalidEndpoint,
    ParentCycle,
    ConfirmationRequired,
}

/// A bounded validation error. `message` is selected by this crate and never
/// includes model-produced text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractError {
    pub error_type: ContractErrorType,
    pub path: String,
    pub message: String,
    pub limit: Option<usize>,
    pub actual: Option<usize>,
}

impl ContractError {
    pub(crate) fn new(
        error_type: ContractErrorType,
        path: impl Into<String>,
        message: &'static str,
    ) -> Self {
        Self {
            error_type,
            path: path.into(),
            message: message.to_owned(),
            limit: None,
            actual: None,
        }
    }

    pub(crate) fn limit(
        error_type: ContractErrorType,
        path: impl Into<String>,
        message: &'static str,
        limit: usize,
        actual: usize,
    ) -> Self {
        Self {
            error_type,
            path: path.into(),
            message: message.to_owned(),
            limit: Some(limit),
            actual: Some(actual),
        }
    }
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.message, self.path)
    }
}

impl Error for ContractError {}
