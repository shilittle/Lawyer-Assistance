//! Content-addressed DiagramSpec validation, rendering, update, and export.
//!
//! The service owns the only filesystem boundary used by diagram MCP tools.
//! Artifact names are derived from the validated canonical spec hash; caller
//! text never participates in a filesystem path and absolute paths never leave
//! this module.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::model::{
    DiagramSpec, DisplayOptions, Edge, Group, LayoutHints, Metadata, MetadataScalar, MetadataValue,
    Node, NodeStatus, NodeType, Source, TemplateId,
};
use crate::render::render_html;
use crate::validation::{validate_spec, DiagnosticSeverity};
use crate::{canonical_json, spec_hash};

const ARTIFACT_URI_PREFIX: &str = "lawyer-assistance://diagrams/";
const ARTIFACT_DIRECTORY: &str = "diagrams";
const MAX_SPEC_BYTES: u64 = 4 * 1024 * 1024;
const MAX_HTML_BYTES: usize = 12 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagramDiagnostic {
    pub severity: String,
    pub code: String,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct DiagramStatistics {
    pub nodes: usize,
    pub edges: usize,
    pub unsupported_facts: usize,
    pub disputed_facts: usize,
    pub missing_sources: usize,
    pub invalid_legal_versions: usize,
    pub performance_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagramValidationResponse {
    pub schema_version: String,
    pub template_id: TemplateId,
    pub template_version: String,
    pub valid: bool,
    pub spec_hash: Option<String>,
    pub diagnostics: Vec<DiagramDiagnostic>,
    pub warnings: Vec<String>,
    pub statistics: DiagramStatistics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagramRenderResponse {
    pub artifact_uri: Option<String>,
    pub mime_type: String,
    pub template_id: TemplateId,
    pub template_version: String,
    pub schema_version: String,
    pub spec_hash: Option<String>,
    pub html_sha256: Option<String>,
    pub valid: bool,
    pub diagnostics: Vec<DiagramDiagnostic>,
    pub warnings: Vec<String>,
    pub statistics: DiagramStatistics,
    pub reused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiagramExportResponse {
    pub artifact_uri: String,
    pub mime_type: String,
    pub format: ExportFormat,
    pub byte_len: u64,
    pub html_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Html,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagramPatch {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub layout_hints: Option<LayoutHints>,
    #[serde(default)]
    pub display_options: Option<DisplayOptions>,
    #[serde(default)]
    pub upsert_nodes: Vec<Node>,
    #[serde(default)]
    pub remove_node_ids: Vec<String>,
    #[serde(default)]
    pub upsert_edges: Vec<Edge>,
    #[serde(default)]
    pub remove_edge_ids: Vec<String>,
    #[serde(default)]
    pub upsert_groups: Vec<Group>,
    #[serde(default)]
    pub remove_group_ids: Vec<String>,
    #[serde(default)]
    pub upsert_sources: Vec<Source>,
    #[serde(default)]
    pub remove_source_ids: Vec<String>,
    #[serde(default)]
    pub change_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagramUpdateRequest {
    #[serde(default)]
    pub artifact_uri: Option<String>,
    #[serde(default)]
    pub base_spec: Option<DiagramSpec>,
    pub expected_spec_hash: String,
    pub patch: DiagramPatch,
}

#[derive(Debug, Clone)]
pub struct DiagramService {
    output_root: PathBuf,
    diagram_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagramServiceError {
    code: &'static str,
    message: &'static str,
}

impl DiagramServiceError {
    pub const fn code(&self) -> &'static str {
        self.code
    }

    const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for DiagramServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for DiagramServiceError {}

impl DiagramService {
    pub fn new(output_root: impl AsRef<Path>) -> Result<Self, DiagramServiceError> {
        let requested = output_root.as_ref();
        if !requested.is_absolute() {
            return Err(DiagramServiceError::new(
                "invalid_output_root",
                "diagram output root must be absolute",
            ));
        }
        fs::create_dir_all(requested).map_err(|_| io_error())?;
        let output_root = fs::canonicalize(requested).map_err(|_| io_error())?;
        let diagram_directory = output_root.join(ARTIFACT_DIRECTORY);
        fs::create_dir_all(&diagram_directory).map_err(|_| io_error())?;
        let diagram_root = fs::canonicalize(&diagram_directory).map_err(|_| io_error())?;
        if !diagram_root.starts_with(&output_root) {
            return Err(DiagramServiceError::new(
                "unsafe_output_root",
                "diagram output directory is outside the configured root",
            ));
        }
        Ok(Self {
            output_root,
            diagram_root,
        })
    }

    pub fn validate(&self, spec: &DiagramSpec) -> DiagramValidationResponse {
        validation_response(spec)
    }

    pub fn render(&self, spec: &DiagramSpec) -> Result<DiagramRenderResponse, DiagramServiceError> {
        let validation = validation_response(spec);
        if !validation.valid {
            return Ok(DiagramRenderResponse {
                artifact_uri: None,
                mime_type: "text/html".to_owned(),
                template_id: spec.template_id,
                template_version: spec.provenance.template_version.clone(),
                schema_version: spec.schema_version.clone(),
                spec_hash: validation.spec_hash,
                html_sha256: None,
                valid: false,
                diagnostics: validation.diagnostics,
                warnings: validation.warnings,
                statistics: validation.statistics,
                reused: false,
            });
        }

        let hash = validation.spec_hash.clone().ok_or_else(|| {
            DiagramServiceError::new("serialization_failed", "diagram serialization failed")
        })?;
        let key = artifact_key_from_hash(&hash)?;
        let json = canonical_json(spec).map_err(|_| {
            DiagramServiceError::new("serialization_failed", "diagram serialization failed")
        })?;
        if json.len() as u64 > MAX_SPEC_BYTES {
            return Err(DiagramServiceError::new(
                "artifact_too_large",
                "diagram specification exceeds its size limit",
            ));
        }
        let html = render_html(spec);
        if html.len() > MAX_HTML_BYTES {
            return Err(DiagramServiceError::new(
                "artifact_too_large",
                "diagram artifact exceeds its size limit",
            ));
        }
        let html_path = self.safe_artifact_path(&key, "html")?;
        let spec_path = self.safe_artifact_path(&key, "diagram.json")?;
        let html_reused = atomic_install(&html_path, html.as_bytes())?;
        let spec_reused = atomic_install(&spec_path, json.as_bytes())?;
        let html_sha256 = sha256_prefixed(html.as_bytes());

        Ok(DiagramRenderResponse {
            artifact_uri: Some(format!("{ARTIFACT_URI_PREFIX}{key}")),
            mime_type: "text/html".to_owned(),
            template_id: spec.template_id,
            template_version: spec.provenance.template_version.clone(),
            schema_version: spec.schema_version.clone(),
            spec_hash: Some(hash),
            html_sha256: Some(html_sha256),
            valid: true,
            diagnostics: validation.diagnostics,
            warnings: validation.warnings,
            statistics: validation.statistics,
            reused: html_reused && spec_reused,
        })
    }

    pub fn update(
        &self,
        request: DiagramUpdateRequest,
    ) -> Result<DiagramRenderResponse, DiagramServiceError> {
        let mut spec = match (request.artifact_uri.as_deref(), request.base_spec) {
            (Some(uri), None) => self.read_spec(uri)?,
            (None, Some(spec)) => spec,
            _ => {
                return Err(DiagramServiceError::new(
                    "invalid_update_base",
                    "provide exactly one diagram update base",
                ))
            }
        };
        let actual_hash = spec_hash(&spec).map_err(|_| {
            DiagramServiceError::new("serialization_failed", "diagram serialization failed")
        })?;
        if actual_hash != request.expected_spec_hash {
            return Err(DiagramServiceError::new(
                "stale_spec",
                "diagram update base has changed",
            ));
        }
        validate_patch_shape(&request.patch)?;
        apply_patch(&mut spec, request.patch, &actual_hash)?;
        self.render(&spec)
    }

    pub fn export(
        &self,
        artifact_uri: &str,
        format: ExportFormat,
    ) -> Result<DiagramExportResponse, DiagramServiceError> {
        if format != ExportFormat::Html {
            return Err(DiagramServiceError::new(
                "unsupported_export_format",
                "diagram export format is not supported",
            ));
        }
        let key = artifact_key_from_uri(artifact_uri)?;
        let path = self.safe_artifact_path(&key, "html")?;
        ensure_regular_file(&path)?;
        let bytes = fs::read(&path).map_err(|_| io_error())?;
        if bytes.len() > MAX_HTML_BYTES {
            return Err(DiagramServiceError::new(
                "artifact_too_large",
                "diagram artifact exceeds its size limit",
            ));
        }
        Ok(DiagramExportResponse {
            artifact_uri: artifact_uri.to_owned(),
            mime_type: "text/html".to_owned(),
            format,
            byte_len: bytes.len() as u64,
            html_sha256: sha256_prefixed(&bytes),
        })
    }

    fn read_spec(&self, artifact_uri: &str) -> Result<DiagramSpec, DiagramServiceError> {
        let key = artifact_key_from_uri(artifact_uri)?;
        let path = self.safe_artifact_path(&key, "diagram.json")?;
        ensure_regular_file(&path)?;
        let metadata = fs::metadata(&path).map_err(|_| io_error())?;
        if metadata.len() > MAX_SPEC_BYTES {
            return Err(DiagramServiceError::new(
                "artifact_too_large",
                "diagram specification exceeds its size limit",
            ));
        }
        let json = fs::read_to_string(&path).map_err(|_| io_error())?;
        let spec: DiagramSpec = serde_json::from_str(&json).map_err(|_| {
            DiagramServiceError::new("invalid_artifact", "diagram artifact is invalid")
        })?;
        let actual_hash = spec_hash(&spec).map_err(|_| {
            DiagramServiceError::new("invalid_artifact", "diagram artifact is invalid")
        })?;
        if artifact_key_from_hash(&actual_hash)? != key {
            return Err(DiagramServiceError::new(
                "artifact_integrity_failed",
                "diagram artifact integrity check failed",
            ));
        }
        Ok(spec)
    }

    fn safe_artifact_path(
        &self,
        key: &str,
        extension: &str,
    ) -> Result<PathBuf, DiagramServiceError> {
        if !is_artifact_key(key)
            || !matches!(extension, "html" | "diagram.json")
            || !self.diagram_root.starts_with(&self.output_root)
        {
            return Err(DiagramServiceError::new(
                "invalid_artifact_uri",
                "diagram artifact reference is invalid",
            ));
        }
        Ok(self.diagram_root.join(format!("{key}.{extension}")))
    }
}

fn validation_response(spec: &DiagramSpec) -> DiagramValidationResponse {
    let report = validate_spec(spec);
    let valid = !report.has_errors();
    let hash = canonical_json(spec).ok().and_then(|_| spec_hash(spec).ok());
    let diagnostics = report
        .diagnostics
        .iter()
        .map(|diagnostic| DiagramDiagnostic {
            severity: diagnostic.severity.as_str().to_owned(),
            code: diagnostic.code.to_owned(),
            path: diagnostic.path.clone(),
            message: diagnostic.message.clone(),
        })
        .collect::<Vec<_>>();
    let warnings = report
        .diagnostics
        .iter()
        .filter(|item| item.severity != DiagnosticSeverity::Error)
        .map(|item| item.code.to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    DiagramValidationResponse {
        schema_version: spec.schema_version.clone(),
        template_id: spec.template_id,
        template_version: spec.provenance.template_version.clone(),
        valid,
        spec_hash: hash,
        diagnostics,
        warnings,
        statistics: diagram_statistics(spec),
    }
}

fn diagram_statistics(spec: &DiagramSpec) -> DiagramStatistics {
    let source_ids = spec
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect::<HashSet<_>>();
    let missing_sources = spec
        .nodes
        .iter()
        .filter(|node| {
            node.source_refs.is_empty()
                || node
                    .source_refs
                    .iter()
                    .any(|source| !source_ids.contains(source.as_str()))
        })
        .count()
        + spec
            .edges
            .iter()
            .filter(|edge| {
                edge.source_refs
                    .iter()
                    .any(|source| !source_ids.contains(source.as_str()))
            })
            .count();
    let invalid_legal_versions = spec
        .nodes
        .iter()
        .filter(|node| {
            node.node_type.is_legal_norm()
                && metadata_text(&node.metadata, "version").is_none()
                && !node.source_refs.iter().any(|reference| {
                    spec.sources.iter().any(|source| {
                        source.id == *reference
                            && source
                                .law_version
                                .as_deref()
                                .is_some_and(|value| !value.trim().is_empty())
                    })
                })
        })
        .count();
    DiagramStatistics {
        nodes: spec.nodes.len(),
        edges: spec.edges.len(),
        unsupported_facts: spec
            .nodes
            .iter()
            .filter(|node| {
                node.node_type == NodeType::Fact && node.status == NodeStatus::Unsupported
            })
            .count(),
        disputed_facts: spec
            .nodes
            .iter()
            .filter(|node| {
                node.node_type == NodeType::Fact
                    && matches!(node.status, NodeStatus::Disputed | NodeStatus::Contradicted)
            })
            .count(),
        missing_sources,
        invalid_legal_versions,
        performance_class: match spec.nodes.len() {
            0..=20 => "small",
            21..=100 => "medium",
            _ => "large",
        }
        .to_owned(),
    }
}

fn validate_patch_shape(patch: &DiagramPatch) -> Result<(), DiagramServiceError> {
    validate_patch_ids(&patch.upsert_nodes, &patch.remove_node_ids, |item| {
        item.id.as_str()
    })?;
    validate_patch_ids(&patch.upsert_edges, &patch.remove_edge_ids, |item| {
        item.id.as_str()
    })?;
    validate_patch_ids(&patch.upsert_groups, &patch.remove_group_ids, |item| {
        item.id.as_str()
    })?;
    validate_patch_ids(&patch.upsert_sources, &patch.remove_source_ids, |item| {
        item.id.as_str()
    })
}

fn validate_patch_ids<T, F>(
    upserts: &[T],
    removals: &[String],
    id: F,
) -> Result<(), DiagramServiceError>
where
    F: Fn(&T) -> &str,
{
    let mut upsert_ids = HashSet::new();
    for item in upserts {
        if !upsert_ids.insert(id(item)) {
            return Err(invalid_patch());
        }
    }
    let mut removal_ids = HashSet::new();
    for item in removals {
        if !removal_ids.insert(item.as_str()) || upsert_ids.contains(item.as_str()) {
            return Err(invalid_patch());
        }
    }
    Ok(())
}

fn apply_patch(
    spec: &mut DiagramSpec,
    patch: DiagramPatch,
    parent_hash: &str,
) -> Result<(), DiagramServiceError> {
    if let Some(title) = patch.title {
        spec.title = title;
    }
    if let Some(summary) = patch.summary {
        spec.summary = summary;
    }
    if let Some(layout_hints) = patch.layout_hints {
        spec.layout_hints = layout_hints;
    }
    if let Some(display_options) = patch.display_options {
        spec.display_options = display_options;
    }
    patch_vec(
        &mut spec.nodes,
        patch.upsert_nodes,
        patch.remove_node_ids,
        |item| item.id.as_str(),
    )?;
    patch_vec(
        &mut spec.edges,
        patch.upsert_edges,
        patch.remove_edge_ids,
        |item| item.id.as_str(),
    )?;
    patch_vec(
        &mut spec.groups,
        patch.upsert_groups,
        patch.remove_group_ids,
        |item| item.id.as_str(),
    )?;
    patch_vec(
        &mut spec.sources,
        patch.upsert_sources,
        patch.remove_source_ids,
        |item| item.id.as_str(),
    )?;
    spec.provenance.parent_spec_hash = Some(parent_hash.to_owned());
    spec.provenance.change_summary = patch.change_summary;
    Ok(())
}

fn patch_vec<T, F>(
    target: &mut Vec<T>,
    upserts: Vec<T>,
    removals: Vec<String>,
    id: F,
) -> Result<(), DiagramServiceError>
where
    F: Fn(&T) -> &str + Copy,
{
    let existing = target.iter().map(id).collect::<HashSet<_>>();
    if removals
        .iter()
        .any(|candidate| !existing.contains(candidate.as_str()))
    {
        return Err(invalid_patch());
    }
    let removals = removals.into_iter().collect::<HashSet<_>>();
    target.retain(|item| !removals.contains(id(item)));
    for replacement in upserts {
        let replacement_id = id(&replacement).to_owned();
        if let Some(index) = target
            .iter()
            .position(|candidate| id(candidate) == replacement_id)
        {
            target[index] = replacement;
        } else {
            target.push(replacement);
        }
    }
    Ok(())
}

fn metadata_text<'a>(metadata: &'a Metadata, key: &str) -> Option<&'a str> {
    match metadata.get(key) {
        Some(MetadataValue::Scalar(MetadataScalar::String(value))) if !value.trim().is_empty() => {
            Some(value)
        }
        _ => None,
    }
}

fn artifact_key_from_uri(uri: &str) -> Result<String, DiagramServiceError> {
    let key = uri
        .strip_prefix(ARTIFACT_URI_PREFIX)
        .filter(|value| is_artifact_key(value))
        .ok_or_else(|| {
            DiagramServiceError::new(
                "invalid_artifact_uri",
                "diagram artifact reference is invalid",
            )
        })?;
    Ok(key.to_owned())
}

fn artifact_key_from_hash(hash: &str) -> Result<String, DiagramServiceError> {
    let key = hash
        .strip_prefix("sha256:")
        .filter(|value| is_artifact_key(value));
    key.map(str::to_owned).ok_or_else(|| {
        DiagramServiceError::new("invalid_spec_hash", "diagram specification hash is invalid")
    })
}

fn is_artifact_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn ensure_regular_file(path: &Path) -> Result<(), DiagramServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        DiagramServiceError::new("artifact_not_found", "diagram artifact was not found")
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(DiagramServiceError::new(
            "invalid_artifact",
            "diagram artifact is invalid",
        ));
    }
    Ok(())
}

/// Atomically install immutable content. Returns true when identical content
/// already existed and no write was needed.
fn atomic_install(path: &Path, bytes: &[u8]) -> Result<bool, DiagramServiceError> {
    if path.exists() {
        ensure_regular_file(path)?;
        let existing = fs::read(path).map_err(|_| io_error())?;
        if existing == bytes {
            return Ok(true);
        }
        return Err(DiagramServiceError::new(
            "artifact_collision",
            "diagram artifact content does not match its key",
        ));
    }
    let parent = path.parent().ok_or_else(io_error)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".diagram-{}-{}-{}.tmp",
        std::process::id(),
        sequence,
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("artifact")
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
    })();
    match write_result {
        Ok(()) => Ok(false),
        Err(_) if path.exists() => {
            let _ = fs::remove_file(&temporary);
            ensure_regular_file(path)?;
            let existing = fs::read(path).map_err(|_| io_error())?;
            if existing == bytes {
                Ok(true)
            } else {
                Err(DiagramServiceError::new(
                    "artifact_collision",
                    "diagram artifact content does not match its key",
                ))
            }
        }
        Err(_) => {
            let _ = fs::remove_file(&temporary);
            Err(io_error())
        }
    }
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

const fn io_error() -> DiagramServiceError {
    DiagramServiceError::new("artifact_io", "diagram artifact operation failed")
}

const fn invalid_patch() -> DiagramServiceError {
    DiagramServiceError::new("invalid_patch", "diagram update patch is invalid")
}
