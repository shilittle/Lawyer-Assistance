//! Transport-neutral application services for legal research, reviewed case
//! changes, and deterministic document generation.
//!
//! This crate deliberately has no Tauri, Windows, HTTP, or MCP dependency.
//! Callers are protocol adapters; all database, validation, revision, audit,
//! and filesystem policy decisions live here.

mod audit;
mod case;
mod config;
mod document;
mod error;
mod filesystem;
mod legal;
mod status;

pub use case::*;
pub use config::*;
pub use document::*;
pub use error::*;
pub use legal::*;
pub use status::*;

use std::path::Path;

/// Public contract version shared by all service requests, responses, and
/// errors. It is intentionally independent from either SQLite schema version.
pub const SERVICE_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Clone)]
pub struct LegalServices {
    config: ServiceConfig,
    audit_origin: ServiceOrigin,
    /// A public-law service deliberately has no user workspace.  It may only
    /// execute the read-only legal methods and reports that workspace storage
    /// is not applicable from `system_status`.
    public_law_only: bool,
}

impl LegalServices {
    pub fn new(config: ServiceConfig) -> Result<Self, ServiceError> {
        Self::new_with_origin(config, ServiceOrigin::Mcp)
    }

    pub fn new_with_origin(
        config: ServiceConfig,
        audit_origin: ServiceOrigin,
    ) -> Result<Self, ServiceError> {
        Ok(Self {
            config: config.validate()?,
            audit_origin,
            public_law_only: false,
        })
    }

    /// Construct the read-only legal service used by public MCP transports.
    ///
    /// This constructor intentionally does not require, create, or open a
    /// user/workspace database or an output directory.  The legal database is
    /// validated when a legal operation actually opens it, so a missing
    /// runtime legal database is surfaced as the ordinary legal availability
    /// error instead of preventing the MCP process from starting.
    pub fn new_public(legal_core_path: std::path::PathBuf) -> Result<Self, ServiceError> {
        if !legal_core_path.is_absolute() || legal_core_path.file_name().is_none() {
            return Err(ServiceError::new(
                "invalid_configuration",
                "legal database path must be absolute and name a file",
                false,
            ));
        }
        Ok(Self {
            config: ServiceConfig {
                legal_core_path,
                // These placeholders are never opened by a public-only
                // service.  Keeping ServiceConfig stable avoids changing the
                // existing case/document service contract.
                user_database_path: std::path::PathBuf::new(),
                allowed_file_roots: Vec::new(),
                allowed_output_root: std::path::PathBuf::new(),
            },
            audit_origin: ServiceOrigin::Mcp,
            public_law_only: true,
        })
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    pub fn is_public_law_only(&self) -> bool {
        self.public_law_only
    }

    pub(crate) fn legal_core_path(&self) -> &Path {
        &self.config.legal_core_path
    }

    pub(crate) fn user_database_path(&self) -> &Path {
        &self.config.user_database_path
    }

    pub(crate) fn output_root(&self) -> &Path {
        &self.config.allowed_output_root
    }

    pub(crate) fn audit_origin(&self) -> &'static str {
        self.audit_origin.as_str()
    }
}

pub(crate) fn require_schema_version(actual: u16) -> Result<(), ServiceError> {
    if actual == SERVICE_SCHEMA_VERSION {
        return Ok(());
    }
    Err(ServiceError::new(
        "unsupported_schema_version",
        "request schemaVersion is not supported",
        false,
    )
    .with_details(serde_json::json!({
        "supported": SERVICE_SCHEMA_VERSION,
        "actual": actual,
    })))
}

pub(crate) fn validate_identifier(field: &'static str, value: &str) -> Result<(), ServiceError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':' | b'.'))
    {
        return Err(ServiceError::invalid(
            field,
            "identifier must be a bounded opaque ASCII value",
        ));
    }
    Ok(())
}

pub(crate) fn validate_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
    allow_multiline: bool,
) -> Result<(), ServiceError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(ServiceError::invalid(
            field,
            "text must be non-empty and within its byte limit",
        ));
    }
    if value.chars().any(|character| {
        character.is_control() && !(allow_multiline && matches!(character, '\n' | '\r' | '\t'))
    }) {
        return Err(ServiceError::invalid(
            field,
            "text contains a disallowed control character",
        ));
    }
    Ok(())
}
