//! Deterministic, in-memory renderers for validated assistant artifacts.
//!
//! Renderers never access paths, databases, providers, or Tauri. The caller is
//! responsible for constructing a trusted [`ValidationContext`](crate::ValidationContext)
//! from database ownership and local citation validation results.

mod document;
mod map;

pub use document::{render_document_docx, render_document_markdown};
pub use map::{render_map_json, render_map_summary};

use crate::{ContractError, ContractErrorType};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

pub const DOCUMENT_MARKDOWN_MEDIA_TYPE: &str = "text/markdown; charset=utf-8";
pub const DOCUMENT_DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
pub const MAP_JSON_MEDIA_TYPE: &str = "application/json; charset=utf-8";
pub const MAP_SUMMARY_MEDIA_TYPE: &str = "text/markdown; charset=utf-8";

pub const MAX_DOCUMENT_MARKDOWN_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_DOCUMENT_XML_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DOCUMENT_DOCX_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MAP_JSON_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_MAP_SUMMARY_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRenderKind {
    Document,
    ModelGeneratedMap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRenderFormat {
    DocumentMarkdown,
    DocumentDocx,
    MapJson,
    MapSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRenderMetadata {
    pub artifact_kind: ArtifactRenderKind,
    pub format: ArtifactRenderFormat,
    pub media_type: String,
    pub file_extension: String,
    pub byte_len: usize,
    pub schema_version: u16,
    pub source_reference_count: usize,
    pub validated_citation_count: usize,
    pub semantic_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactRenderContent {
    Text(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedArtifact {
    pub metadata: ArtifactRenderMetadata,
    pub content: ArtifactRenderContent,
}

impl RenderedArtifact {
    pub fn as_text(&self) -> Option<&str> {
        match &self.content {
            ArtifactRenderContent::Text(value) => Some(value),
            ArtifactRenderContent::Bytes(_) => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.content {
            ArtifactRenderContent::Text(_) => None,
            ArtifactRenderContent::Bytes(value) => Some(value),
        }
    }

    pub(crate) fn text(metadata: ArtifactRenderMetadata, value: String) -> Self {
        debug_assert_eq!(metadata.byte_len, value.len());
        Self {
            metadata,
            content: ArtifactRenderContent::Text(value),
        }
    }

    pub(crate) fn bytes(metadata: ArtifactRenderMetadata, value: Vec<u8>) -> Self {
        debug_assert_eq!(metadata.byte_len, value.len());
        Self {
            metadata,
            content: ArtifactRenderContent::Bytes(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRenderErrorType {
    InvalidSpec,
    OutputTooLarge,
    SerializationFailed,
    ArchiveFailed,
}

/// Stable render failure that never includes source or generated body text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArtifactRenderError {
    pub error_type: ArtifactRenderErrorType,
    pub format: Option<ArtifactRenderFormat>,
    pub contract_error_type: Option<ContractErrorType>,
    pub message: String,
    pub limit: Option<usize>,
    pub actual: Option<usize>,
}

impl ArtifactRenderError {
    pub(crate) fn invalid_spec(format: ArtifactRenderFormat, error: &ContractError) -> Self {
        Self {
            error_type: ArtifactRenderErrorType::InvalidSpec,
            format: Some(format),
            contract_error_type: Some(error.error_type),
            message: "artifact spec failed validation before rendering".to_owned(),
            limit: None,
            actual: None,
        }
    }

    pub(crate) fn output_too_large(
        format: ArtifactRenderFormat,
        limit: usize,
        actual: usize,
    ) -> Self {
        Self {
            error_type: ArtifactRenderErrorType::OutputTooLarge,
            format: Some(format),
            contract_error_type: None,
            message: "rendered artifact exceeds output byte limit".to_owned(),
            limit: Some(limit),
            actual: Some(actual),
        }
    }

    pub(crate) fn serialization_failed(format: ArtifactRenderFormat) -> Self {
        Self {
            error_type: ArtifactRenderErrorType::SerializationFailed,
            format: Some(format),
            contract_error_type: None,
            message: "artifact serialization failed".to_owned(),
            limit: None,
            actual: None,
        }
    }

    pub(crate) fn archive_failed() -> Self {
        Self {
            error_type: ArtifactRenderErrorType::ArchiveFailed,
            format: Some(ArtifactRenderFormat::DocumentDocx),
            contract_error_type: None,
            message: "DOCX archive generation failed".to_owned(),
            limit: None,
            actual: None,
        }
    }
}

impl fmt::Display for ArtifactRenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ArtifactRenderError {}

pub(crate) fn ensure_output_limit(
    format: ArtifactRenderFormat,
    actual: usize,
    limit: usize,
) -> Result<(), ArtifactRenderError> {
    if actual > limit {
        Err(ArtifactRenderError::output_too_large(format, limit, actual))
    } else {
        Ok(())
    }
}

pub(crate) fn escape_markdown(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    for character in normalized.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '\n' => escaped.push_str("  \n"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '#' | '|' | '{' | '}' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

pub(crate) fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}
