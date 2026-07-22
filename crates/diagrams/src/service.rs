//! Content-addressed DiagramSpec validation, rendering, update, and export.
//!
//! The service owns the only filesystem boundary used by diagram MCP tools.
//! Artifact names are derived from the validated canonical spec hash; caller
//! text never participates in a filesystem path and absolute paths never leave
//! this module.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
const ARTIFACT_SPEC_FILE: &str = "artifact.diagram.json";
const ARTIFACT_HTML_FILE: &str = "artifact.html";
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
    boundary: Arc<ArtifactBoundary>,
}

#[derive(Debug)]
struct ArtifactBoundary {
    output_root: PathBuf,
    diagram_root: PathBuf,
    output_identity: FileIdentity,
    diagram_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    first: u64,
    second: u64,
}

#[derive(Debug)]
struct DirectoryGuard {
    path: PathBuf,
    handle: fs::File,
    identity: FileIdentity,
}

#[derive(Debug)]
struct ArtifactOperation<'a> {
    boundary: &'a ArtifactBoundary,
    output: DirectoryGuard,
    diagrams: DirectoryGuard,
}

#[derive(Debug)]
struct VerifiedArtifact {
    spec: DiagramSpec,
    canonical_spec: Vec<u8>,
    html: Vec<u8>,
    _spec_lock: fs::File,
    _html_lock: fs::File,
}

#[derive(Debug)]
struct LockedArtifactFile {
    handle: fs::File,
    identity: FileIdentity,
    bytes: Vec<u8>,
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
        if !path_is_normal_absolute(requested) {
            return Err(DiagramServiceError::new(
                "invalid_output_root",
                "diagram output root must be absolute",
            ));
        }
        fs::create_dir_all(requested).map_err(|_| io_error())?;
        reject_reparse_chain(requested)?;
        let requested_guard = DirectoryGuard::open(requested, false)?;
        let output_root = fs::canonicalize(requested).map_err(|_| io_error())?;
        let output_guard = DirectoryGuard::open(&output_root, false)?;
        if requested_guard.identity != output_guard.identity {
            return Err(unsafe_output_root());
        }
        let diagram_directory = output_root.join(ARTIFACT_DIRECTORY);
        fs::create_dir_all(&diagram_directory).map_err(|_| io_error())?;
        reject_reparse_chain(&diagram_directory)?;
        let requested_diagram_guard = DirectoryGuard::open(&diagram_directory, false)?;
        let diagram_root = fs::canonicalize(&diagram_directory).map_err(|_| io_error())?;
        if diagram_root.parent() != Some(output_root.as_path()) {
            return Err(DiagramServiceError::new(
                "unsafe_output_root",
                "diagram output directory is outside the configured root",
            ));
        }
        let diagram_guard = DirectoryGuard::open(&diagram_root, false)?;
        if requested_diagram_guard.identity != diagram_guard.identity {
            return Err(unsafe_output_root());
        }
        let boundary = ArtifactBoundary {
            output_root,
            diagram_root,
            output_identity: output_guard.identity.clone(),
            diagram_identity: diagram_guard.identity.clone(),
        };
        let operation = boundary.begin_operation()?;
        operation.verify()?;
        drop(operation);
        Ok(Self {
            boundary: Arc::new(boundary),
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
        let operation = self.boundary.begin_operation()?;
        let reused =
            self.install_artifact_bundle(&operation, &key, json.as_bytes(), html.as_bytes())?;
        let installed = self.read_verified_artifact(&operation, &key)?;
        if installed.canonical_spec != json.as_bytes() || installed.html != html.as_bytes() {
            return Err(artifact_integrity_error());
        }
        operation.verify()?;
        let html_sha256 = sha256_prefixed(&installed.html);

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
            reused,
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
        let operation = self.boundary.begin_operation()?;
        let artifact = self.read_verified_artifact(&operation, &key)?;
        operation.verify()?;
        Ok(DiagramExportResponse {
            artifact_uri: artifact_uri.to_owned(),
            mime_type: "text/html".to_owned(),
            format,
            byte_len: artifact.html.len() as u64,
            html_sha256: sha256_prefixed(&artifact.html),
        })
    }

    fn read_spec(&self, artifact_uri: &str) -> Result<DiagramSpec, DiagramServiceError> {
        let key = artifact_key_from_uri(artifact_uri)?;
        let operation = self.boundary.begin_operation()?;
        let artifact = self.read_verified_artifact(&operation, &key)?;
        operation.verify()?;
        Ok(artifact.spec)
    }

    fn safe_artifact_directory(
        &self,
        operation: &ArtifactOperation<'_>,
        key: &str,
    ) -> Result<PathBuf, DiagramServiceError> {
        operation.verify()?;
        if !is_artifact_key(key) || operation.diagrams.path != self.boundary.diagram_root {
            return Err(DiagramServiceError::new(
                "invalid_artifact_uri",
                "diagram artifact reference is invalid",
            ));
        }
        let path = self.boundary.diagram_root.join(key);
        if path.parent() != Some(self.boundary.diagram_root.as_path()) {
            return Err(DiagramServiceError::new(
                "invalid_artifact_uri",
                "diagram artifact reference is invalid",
            ));
        }
        Ok(path)
    }

    fn install_artifact_bundle(
        &self,
        operation: &ArtifactOperation<'_>,
        key: &str,
        canonical_spec: &[u8],
        html: &[u8],
    ) -> Result<bool, DiagramServiceError> {
        let final_path = self.safe_artifact_directory(operation, key)?;
        match operation
            .diagrams
            .open_child_directory(OsStr::new(key), final_path.clone())
        {
            Ok(existing) => {
                let artifact = self.read_verified_artifact_from_guard(operation, key, &existing)?;
                if artifact.canonical_spec == canonical_spec && artifact.html == html {
                    return Ok(true);
                }
                return Err(DiagramServiceError::new(
                    "artifact_collision",
                    "diagram artifact content does not match its key",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(DiagramServiceError::new(
                    "artifact_collision",
                    "diagram artifact content does not match its key",
                ))
            }
        }

        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let staging_name = format!(".diagram-{}-{sequence}.tmp", std::process::id());
        let staging_path = self.boundary.diagram_root.join(&staging_name);
        operation
            .diagrams
            .create_child_directory(OsStr::new(&staging_name))
            .map_err(|_| io_error())?;
        let staging = match operation
            .diagrams
            .open_child_directory_for_commit(OsStr::new(&staging_name), staging_path.clone())
        {
            Ok(staging) => staging,
            Err(_) => {
                cleanup_staging_directory(&staging_path);
                return Err(io_error());
            }
        };
        let write_result = (|| {
            staging.write_new_child(OsStr::new(ARTIFACT_SPEC_FILE), canonical_spec)?;
            staging.write_new_child(OsStr::new(ARTIFACT_HTML_FILE), html)?;
            staging.sync_directory()?;
            let staged = self.read_verified_artifact_from_guard(operation, key, &staging)?;
            if staged.canonical_spec != canonical_spec || staged.html != html {
                return Err(artifact_integrity_error());
            }
            // Windows cannot rename a directory while child handles deny
            // delete sharing. The committed bundle is re-opened and fully
            // verified below before any successful response is returned.
            drop(staged);
            operation.verify()?;
            staging.verify()?;
            staging.verify_child_binding(&operation.diagrams)?;
            staging.commit_into(&operation.diagrams, OsStr::new(key))?;
            operation.diagrams.sync_directory()?;
            Ok(())
        })();

        if let Err(error) = write_result {
            drop(staging);
            cleanup_staging_directory(&staging_path);
            if fs::symlink_metadata(&final_path).is_ok() {
                let existing = operation
                    .diagrams
                    .open_child_directory(OsStr::new(key), final_path)
                    .map_err(|_| artifact_integrity_error())?;
                let artifact = self.read_verified_artifact_from_guard(operation, key, &existing)?;
                if artifact.canonical_spec == canonical_spec && artifact.html == html {
                    return Ok(true);
                }
            }
            return Err(error);
        }
        operation.verify()?;
        Ok(false)
    }

    fn read_verified_artifact(
        &self,
        operation: &ArtifactOperation<'_>,
        key: &str,
    ) -> Result<VerifiedArtifact, DiagramServiceError> {
        let artifact_path = self.safe_artifact_directory(operation, key)?;
        let artifact_directory = operation
            .diagrams
            .open_child_directory(OsStr::new(key), artifact_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    DiagramServiceError::new("artifact_not_found", "diagram artifact was not found")
                } else {
                    artifact_integrity_error()
                }
            })?;
        self.read_verified_artifact_from_guard(operation, key, &artifact_directory)
    }

    fn read_verified_artifact_from_guard(
        &self,
        operation: &ArtifactOperation<'_>,
        key: &str,
        artifact_directory: &DirectoryGuard,
    ) -> Result<VerifiedArtifact, DiagramServiceError> {
        operation.verify()?;
        artifact_directory.verify()?;
        artifact_directory.verify_child_binding(&operation.diagrams)?;
        let spec_file = artifact_directory
            .read_bounded_child(OsStr::new(ARTIFACT_SPEC_FILE), MAX_SPEC_BYTES as usize)
            .map_err(|_| artifact_integrity_error())?;
        let html_file = artifact_directory
            .read_bounded_child(OsStr::new(ARTIFACT_HTML_FILE), MAX_HTML_BYTES)
            .map_err(|_| artifact_integrity_error())?;
        artifact_directory.verify()?;
        artifact_directory
            .verify_regular_child_binding(OsStr::new(ARTIFACT_SPEC_FILE), &spec_file.identity)?;
        artifact_directory
            .verify_regular_child_binding(OsStr::new(ARTIFACT_HTML_FILE), &html_file.identity)?;
        artifact_directory.verify_child_binding(&operation.diagrams)?;
        operation.verify()?;

        let spec: DiagramSpec =
            serde_json::from_slice(&spec_file.bytes).map_err(|_| artifact_integrity_error())?;
        let validation = validation_response(&spec);
        if !validation.valid {
            return Err(artifact_integrity_error());
        }
        let actual_hash = validation.spec_hash.ok_or_else(artifact_integrity_error)?;
        if artifact_key_from_hash(&actual_hash)? != key {
            return Err(artifact_integrity_error());
        }
        let canonical_spec = canonical_json(&spec)
            .map_err(|_| artifact_integrity_error())?
            .into_bytes();
        if canonical_spec != spec_file.bytes {
            return Err(artifact_integrity_error());
        }
        let expected_html = render_html(&spec).into_bytes();
        if expected_html != html_file.bytes {
            return Err(artifact_integrity_error());
        }
        artifact_directory
            .verify_regular_child_binding(OsStr::new(ARTIFACT_SPEC_FILE), &spec_file.identity)?;
        artifact_directory
            .verify_regular_child_binding(OsStr::new(ARTIFACT_HTML_FILE), &html_file.identity)?;
        artifact_directory.verify_child_binding(&operation.diagrams)?;
        operation.verify()?;
        Ok(VerifiedArtifact {
            spec,
            canonical_spec,
            html: html_file.bytes,
            _spec_lock: spec_file.handle,
            _html_lock: html_file.handle,
        })
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

impl ArtifactBoundary {
    fn begin_operation(&self) -> Result<ArtifactOperation<'_>, DiagramServiceError> {
        self.verify_paths()?;
        let output = DirectoryGuard::open(&self.output_root, false)?;
        let diagrams = DirectoryGuard::open(&self.diagram_root, false)?;
        if output.identity != self.output_identity || diagrams.identity != self.diagram_identity {
            return Err(unsafe_output_root());
        }
        let operation = ArtifactOperation {
            boundary: self,
            output,
            diagrams,
        };
        operation.verify()?;
        Ok(operation)
    }

    fn verify_paths(&self) -> Result<(), DiagramServiceError> {
        reject_reparse_chain(&self.diagram_root)?;
        if !path_is_normal_absolute(&self.output_root)
            || !path_is_normal_absolute(&self.diagram_root)
            || self.diagram_root.parent() != Some(self.output_root.as_path())
        {
            return Err(unsafe_output_root());
        }
        Ok(())
    }
}

impl ArtifactOperation<'_> {
    fn verify(&self) -> Result<(), DiagramServiceError> {
        self.output.verify()?;
        self.diagrams.verify()?;
        if self.output.identity != self.boundary.output_identity
            || self.diagrams.identity != self.boundary.diagram_identity
        {
            return Err(unsafe_output_root());
        }
        self.boundary.verify_paths()
    }
}

impl DirectoryGuard {
    fn open(path: &Path, renameable: bool) -> Result<Self, DiagramServiceError> {
        let handle = open_directory_handle(path, renameable).map_err(|_| unsafe_output_root())?;
        Self::from_handle(path.to_path_buf(), handle).map_err(|_| unsafe_output_root())
    }

    fn from_handle(path: PathBuf, handle: fs::File) -> std::io::Result<Self> {
        let metadata = handle.metadata()?;
        if !metadata.is_dir() || is_reparse_or_symlink(&metadata) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory is a reparse point or link",
            ));
        }
        let identity = file_identity(&handle, &metadata)?;
        Ok(Self {
            path,
            handle,
            identity,
        })
    }

    fn verify(&self) -> Result<(), DiagramServiceError> {
        let metadata = self.handle.metadata().map_err(|_| unsafe_output_root())?;
        if !metadata.is_dir()
            || is_reparse_or_symlink(&metadata)
            || file_identity(&self.handle, &metadata).map_err(|_| unsafe_output_root())?
                != self.identity
        {
            return Err(unsafe_output_root());
        }
        Ok(())
    }

    fn verify_child_binding(&self, parent: &Self) -> Result<(), DiagramServiceError> {
        let name = self.path.file_name().ok_or_else(artifact_integrity_error)?;
        let current = parent
            .open_child_directory(name, self.path.clone())
            .map_err(|_| artifact_integrity_error())?;
        if current.identity != self.identity {
            return Err(artifact_integrity_error());
        }
        Ok(())
    }

    fn open_child_directory(&self, name: &OsStr, display_path: PathBuf) -> std::io::Result<Self> {
        require_single_component(name)?;
        let handle = open_child_directory_handle(self, name, &display_path, false)?;
        Self::from_handle(display_path, handle)
    }

    fn open_child_directory_for_commit(
        &self,
        name: &OsStr,
        display_path: PathBuf,
    ) -> std::io::Result<Self> {
        require_single_component(name)?;
        let handle = open_child_directory_handle(self, name, &display_path, true)?;
        Self::from_handle(display_path, handle)
    }

    fn create_child_directory(&self, name: &OsStr) -> std::io::Result<()> {
        require_single_component(name)?;
        create_child_directory(self, name)
    }

    fn write_new_child(&self, name: &OsStr, bytes: &[u8]) -> Result<(), DiagramServiceError> {
        require_single_component(name).map_err(|_| io_error())?;
        let mut file = create_new_child_file(self, name).map_err(|_| io_error())?;
        file.write_all(bytes).map_err(|_| io_error())?;
        file.sync_all().map_err(|_| io_error())?;
        let metadata = file.metadata().map_err(|_| io_error())?;
        if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
            return Err(io_error());
        }
        Ok(())
    }

    fn read_bounded_child(&self, name: &OsStr, max: usize) -> std::io::Result<LockedArtifactFile> {
        require_single_component(name)?;
        let mut file = open_regular_child_file(self, name)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || is_reparse_or_symlink(&metadata) || metadata.len() > max as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact child is not a bounded regular file",
            ));
        }
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(max).min(max));
        (&mut file)
            .take((max as u64).saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() > max {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact child exceeds its size limit",
            ));
        }
        let identity = file_identity(&file, &metadata)?;
        Ok(LockedArtifactFile {
            handle: file,
            identity,
            bytes,
        })
    }

    fn verify_regular_child_binding(
        &self,
        name: &OsStr,
        expected: &FileIdentity,
    ) -> Result<(), DiagramServiceError> {
        let file = open_regular_child_file(self, name).map_err(|_| artifact_integrity_error())?;
        let metadata = file.metadata().map_err(|_| artifact_integrity_error())?;
        if !metadata.is_file()
            || is_reparse_or_symlink(&metadata)
            || file_identity(&file, &metadata).map_err(|_| artifact_integrity_error())? != *expected
        {
            return Err(artifact_integrity_error());
        }
        Ok(())
    }

    fn commit_into(&self, parent: &Self, destination: &OsStr) -> Result<(), DiagramServiceError> {
        require_single_component(destination).map_err(|_| io_error())?;
        commit_directory(self, parent, destination).map_err(|_| io_error())
    }

    fn sync_directory(&self) -> Result<(), DiagramServiceError> {
        #[cfg(unix)]
        self.handle.sync_all().map_err(|_| io_error())?;
        self.verify()
    }
}

fn path_is_normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn reject_reparse_chain(path: &Path) -> Result<(), DiagramServiceError> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&cursor).map_err(|_| unsafe_output_root())?;
        if !metadata.is_dir() || is_reparse_or_symlink(&metadata) {
            return Err(unsafe_output_root());
        }
    }
    Ok(())
}

fn require_single_component(name: &OsStr) -> std::io::Result<()> {
    let mut components = Path::new(name).components();
    if matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "artifact name must be one normal path component",
        ))
    }
}

fn cleanup_staging_directory(path: &Path) {
    let Some(name) = path.file_name().and_then(OsStr::to_str) else {
        return;
    };
    if !name.starts_with(".diagram-") || !name.ends_with(".tmp") {
        return;
    }
    for child in [ARTIFACT_SPEC_FILE, ARTIFACT_HTML_FILE] {
        let candidate = path.join(child);
        if fs::symlink_metadata(&candidate)
            .is_ok_and(|metadata| metadata.is_file() && !is_reparse_or_symlink(&metadata))
        {
            let _ = fs::remove_file(candidate);
        }
    }
    let _ = fs::remove_dir(path);
}

#[cfg(windows)]
fn open_directory_handle(path: &Path, renameable: bool) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let access = FILE_READ_ATTRIBUTES | if renameable { DELETE } else { 0 };
    let mut options = OpenOptions::new();
    options
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path)
}

#[cfg(unix)]
fn open_directory_handle(path: &Path, _renameable: bool) -> std::io::Result<fs::File> {
    use rustix::fs::{open, Mode, OFlags};

    open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(Into::into)
    .map_err(Into::into)
}

#[cfg(not(any(unix, windows)))]
fn open_directory_handle(path: &Path, _renameable: bool) -> std::io::Result<fs::File> {
    fs::File::open(path)
}

#[cfg(unix)]
fn open_child_directory_handle(
    parent: &DirectoryGuard,
    name: &OsStr,
    _display_path: &Path,
    _renameable: bool,
) -> std::io::Result<fs::File> {
    use rustix::fs::{openat, Mode, OFlags};

    openat(
        &parent.handle,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(Into::into)
    .map_err(Into::into)
}

#[cfg(not(unix))]
fn open_child_directory_handle(
    _parent: &DirectoryGuard,
    _name: &OsStr,
    display_path: &Path,
    renameable: bool,
) -> std::io::Result<fs::File> {
    open_directory_handle(display_path, renameable)
}

#[cfg(unix)]
fn create_child_directory(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<()> {
    use rustix::fs::{mkdirat, Mode};

    mkdirat(&parent.handle, name, Mode::from_bits_truncate(0o700)).map_err(Into::into)
}

#[cfg(not(unix))]
fn create_child_directory(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<()> {
    fs::create_dir(parent.path.join(name))
}

#[cfg(unix)]
fn create_new_child_file(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<fs::File> {
    use rustix::fs::{openat, Mode, OFlags};

    openat(
        &parent.handle,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map(Into::into)
    .map_err(Into::into)
}

#[cfg(windows)]
fn create_new_child_file(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    let mut options = OpenOptions::new();
    options
        .create_new(true)
        .write(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(parent.path.join(name))
}

#[cfg(not(any(unix, windows)))]
fn create_new_child_file(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<fs::File> {
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(parent.path.join(name))
}

#[cfg(unix)]
fn open_regular_child_file(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<fs::File> {
    use rustix::fs::{openat, Mode, OFlags};

    openat(
        &parent.handle,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(Into::into)
    .map_err(Into::into)
}

#[cfg(windows)]
fn open_regular_child_file(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(parent.path.join(name))
}

#[cfg(not(any(unix, windows)))]
fn open_regular_child_file(parent: &DirectoryGuard, name: &OsStr) -> std::io::Result<fs::File> {
    fs::File::open(parent.path.join(name))
}

#[cfg(unix)]
fn commit_directory(
    source: &DirectoryGuard,
    parent: &DirectoryGuard,
    destination: &OsStr,
) -> std::io::Result<()> {
    use rustix::fs::renameat;

    let source_name = source
        .path
        .file_name()
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    renameat(&parent.handle, source_name, &parent.handle, destination).map_err(Into::into)
}

#[cfg(windows)]
fn commit_directory(
    source: &DirectoryGuard,
    parent: &DirectoryGuard,
    destination: &OsStr,
) -> std::io::Result<()> {
    use std::mem;
    use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfo, SetFileInformationByHandle, FILE_RENAME_INFO,
    };

    let destination_path = parent.path.join(destination);
    let wide = destination_path
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    let header_size = mem::size_of::<FILE_RENAME_INFO>() - mem::size_of::<u16>();
    let buffer_size = header_size + wide.len() * mem::size_of::<u16>();
    let mut buffer = vec![0_u64; buffer_size.div_ceil(mem::size_of::<u64>())];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `buffer` is sized for the fixed header and complete UTF-16 file
    // name. Both directory handles remain live for the entire kernel call.
    unsafe {
        (*information).Anonymous.ReplaceIfExists = false;
        (*information).RootDirectory = std::ptr::null_mut();
        (*information).FileNameLength = u32::try_from(wide.len() * 2).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "artifact name is too long",
            )
        })?;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            (*information).FileName.as_mut_ptr(),
            wide.len(),
        );
        if SetFileInformationByHandle(
            source.handle.as_raw_handle() as HANDLE,
            FileRenameInfo,
            buffer.as_ptr().cast(),
            u32::try_from(buffer_size).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "rename buffer is too large",
                )
            })?,
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn commit_directory(
    source: &DirectoryGuard,
    parent: &DirectoryGuard,
    destination: &OsStr,
) -> std::io::Result<()> {
    fs::rename(&source.path, parent.path.join(destination))
}

#[cfg(windows)]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_or_symlink(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(windows)]
fn file_identity(handle: &fs::File, _metadata: &fs::Metadata) -> std::io::Result<FileIdentity> {
    use std::mem;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    // SAFETY: the handle is live and the output structure has the expected
    // layout for `GetFileInformationByHandle`.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut information) }
        == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileIdentity {
        first: u64::from(information.dwVolumeSerialNumber),
        second: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

#[cfg(unix)]
fn file_identity(_handle: &fs::File, metadata: &fs::Metadata) -> std::io::Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Ok(FileIdentity {
        first: metadata.dev(),
        second: metadata.ino(),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_handle: &fs::File, metadata: &fs::Metadata) -> std::io::Result<FileIdentity> {
    use std::time::UNIX_EPOCH;

    let modified = metadata
        .modified()?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    Ok(FileIdentity {
        first: metadata.len(),
        second: modified,
    })
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

const fn io_error() -> DiagramServiceError {
    DiagramServiceError::new("artifact_io", "diagram artifact operation failed")
}

const fn unsafe_output_root() -> DiagramServiceError {
    DiagramServiceError::new(
        "unsafe_output_root",
        "diagram output path changed or contains a link or reparse point",
    )
}

const fn artifact_integrity_error() -> DiagramServiceError {
    DiagramServiceError::new(
        "artifact_integrity_failed",
        "diagram artifact integrity check failed",
    )
}

const fn invalid_patch() -> DiagramServiceError {
    DiagramServiceError::new("invalid_patch", "diagram update patch is invalid")
}
