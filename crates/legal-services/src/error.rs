use crate::SERVICE_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceError {
    pub schema_version: u16,
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub details: Value,
}

impl ServiceError {
    pub fn new(code: impl Into<String>, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            schema_version: SERVICE_SCHEMA_VERSION,
            code: code.into(),
            message: message.into(),
            retryable,
            details: Value::Object(Default::default()),
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    pub(crate) fn invalid(field: &'static str, message: &'static str) -> Self {
        Self::new("invalid_request", message, false)
            .with_details(serde_json::json!({ "field": field }))
    }

    pub(crate) fn not_found(resource: &'static str) -> Self {
        Self::new("not_found", "requested resource was not found", false)
            .with_details(serde_json::json!({ "resource": resource }))
    }

    pub(crate) fn conflict(message: &'static str) -> Self {
        Self::new("revision_conflict", message, false)
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for ServiceError {}

impl From<database::DatabaseInitError> for ServiceError {
    fn from(error: database::DatabaseInitError) -> Self {
        match error {
            database::DatabaseInitError::UnsupportedUserSchemaVersion { found, supported } => {
                Self::new(
                    "user_database_incompatible",
                    "user database schema is newer than this service supports",
                    false,
                )
                .with_details(serde_json::json!({ "found": found, "supported": supported }))
            }
            database::DatabaseInitError::InvalidUserSchemaVersion(_) => Self::new(
                "user_database_incompatible",
                "user database schema is invalid",
                false,
            ),
            database::DatabaseInitError::Io(_) | database::DatabaseInitError::Sqlite(_) => {
                Self::new(
                    "database_unavailable",
                    "configured database could not be opened or validated",
                    true,
                )
            }
        }
    }
}

impl From<rusqlite::Error> for ServiceError {
    fn from(error: rusqlite::Error) -> Self {
        let retryable = matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        );
        Self::new(
            "database_operation_failed",
            if retryable {
                "database is temporarily busy"
            } else {
                "database operation failed"
            },
            retryable,
        )
    }
}

impl From<retrieval::RetrievalError> for ServiceError {
    fn from(error: retrieval::RetrievalError) -> Self {
        match error {
            retrieval::RetrievalError::InvalidRequest(_) => {
                Self::new("invalid_request", "legal search request is invalid", false)
            }
            retrieval::RetrievalError::Sqlite(error) => error.into(),
        }
    }
}

impl From<citations::CitationError> for ServiceError {
    fn from(error: citations::CitationError) -> Self {
        match error {
            citations::CitationError::InvalidRequest(_) => {
                Self::new("invalid_request", "citation request is invalid", false)
            }
            citations::CitationError::Sqlite(error) => error.into(),
        }
    }
}

impl From<assistant::ContractError> for ServiceError {
    fn from(error: assistant::ContractError) -> Self {
        Self::new(
            "invalid_proposal",
            "case proposal failed bounded contract validation",
            false,
        )
        .with_details(serde_json::json!({
            "errorType": error.error_type,
            "path": error.path,
            "limit": error.limit,
            "actual": error.actual,
        }))
    }
}

impl From<assistant::ArtifactRenderError> for ServiceError {
    fn from(error: assistant::ArtifactRenderError) -> Self {
        Self::new("document_render_failed", error.message, false).with_details(serde_json::json!({
            "errorType": error.error_type,
            "format": error.format,
            "limit": error.limit,
            "actual": error.actual,
        }))
    }
}

impl From<file_ingest::IngestError> for ServiceError {
    fn from(error: file_ingest::IngestError) -> Self {
        Self::new(
            "material_ingest_failed",
            "source material could not be safely imported",
            false,
        )
        .with_details(serde_json::json!({ "reason": error.code() }))
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(_: serde_json::Error) -> Self {
        Self::new(
            "invalid_json",
            "structured payload is not valid canonical JSON",
            false,
        )
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(error: std::io::Error) -> Self {
        let retryable = matches!(
            error.kind(),
            std::io::ErrorKind::Interrupted
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::TimedOut
        );
        Self::new(
            "filesystem_operation_failed",
            "filesystem operation failed",
            retryable,
        )
        .with_details(serde_json::json!({ "kind": format!("{:?}", error.kind()) }))
    }
}
