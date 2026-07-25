use std::collections::{BTreeSet, HashMap, HashSet};

use serde::Serialize;

use crate::model::{
    DiagramSpec, DiagramType, Edge, Metadata, MetadataScalar, MetadataValue, Node, NodeStatus,
    NodeType, Relation, Source, SourceKind,
};
use crate::relations::relation_is_compatible;
use crate::templates::TemplateRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl DiagnosticSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

impl Diagnostic {
    pub fn new(
        severity: DiagnosticSeverity,
        code: &'static str,
        path: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            code,
            path: path.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ValidationReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        !self.has_errors()
    }

    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning)
    }

    pub fn push(&mut self, diagnostic: Diagnostic) {
        self.diagnostics.push(diagnostic);
    }

    pub fn extend(&mut self, other: Self) {
        self.diagnostics.extend(other.diagnostics);
    }
}

/// Runs the complete authoritative validation pipeline in deterministic order.
pub fn validate_spec(spec: &DiagramSpec) -> ValidationReport {
    let mut report = ValidationReport::default();
    validate_structure(spec, &mut report);
    validate_references_and_relations(spec, &mut report);
    validate_sources(spec, &mut report);
    validate_evidence(spec, &mut report);
    validate_legal_versions_and_hierarchy(spec, &mut report);
    validate_money(spec, &mut report);
    validate_timeline(spec, &mut report);
    validate_issues(spec, &mut report);
    report.extend(TemplateRegistry::new().validate(spec));
    report
}

pub fn validate(spec: &DiagramSpec) -> ValidationReport {
    validate_spec(spec)
}

fn validate_structure(spec: &DiagramSpec, report: &mut ValidationReport) {
    if spec.schema_version != "1.0" {
        error(
            report,
            "schema.unsupported_version",
            "/schema_version",
            "schema_version must be exactly 1.0",
        );
    }
    check_text(report, "/title", &spec.title, 1, 256);
    check_text(report, "/summary", &spec.summary, 0, 4096);
    check_count(report, "/nodes", spec.nodes.len(), 1, 500);
    check_count(report, "/edges", spec.edges.len(), 0, 1200);
    check_count(report, "/groups", spec.groups.len(), 0, 100);
    check_count(report, "/sources", spec.sources.len(), 0, 1000);
    if spec.nodes.len() > 100 {
        warning(
            report,
            "performance.large_graph",
            "/nodes",
            "large diagrams automatically collapse low-importance nodes and hide weak edges; use filters and focus controls to expand progressively",
        );
    }

    let mut node_ids = HashSet::new();
    for (index, node) in spec.nodes.iter().enumerate() {
        let path = format!("/nodes/{index}");
        check_identifier(report, &format!("{path}/id"), &node.id);
        if !node_ids.insert(node.id.as_str()) {
            error(
                report,
                "id.duplicate_node",
                format!("{path}/id"),
                format!("duplicate node id {}", node.id),
            );
        }
        check_optional_pattern(
            report,
            &format!("{path}/subtype"),
            node.subtype.as_deref(),
            96,
            |value| {
                value
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
            },
            "subtype may contain only lowercase ASCII letters, digits, and underscore",
        );
        check_text(report, &format!("{path}/label"), &node.label, 1, 256);
        if let Some(short_label) = &node.short_label {
            check_text(report, &format!("{path}/short_label"), short_label, 0, 80);
        }
        check_text(report, &format!("{path}/details"), &node.details, 0, 16_384);
        check_string_array(
            report,
            &format!("{path}/source_refs"),
            &node.source_refs,
            100,
            true,
        );
        check_string_array(report, &format!("{path}/tags"), &node.tags, 32, true);
        for (tag_index, tag) in node.tags.iter().enumerate() {
            check_text(report, &format!("{path}/tags/{tag_index}"), tag, 1, 64);
        }
        validate_metadata(report, &format!("{path}/metadata"), &node.metadata);
        if node.node_type == NodeType::Fact
            && !matches!(
                node.status,
                NodeStatus::Alleged
                    | NodeStatus::Admitted
                    | NodeStatus::Supported
                    | NodeStatus::Disputed
                    | NodeStatus::Contradicted
                    | NodeStatus::Established
                    | NodeStatus::Unsupported
                    | NodeStatus::Unknown
            )
        {
            error(
                report,
                "fact.invalid_status",
                format!("{path}/status"),
                "fact node uses a status reserved for another domain",
            );
        }
    }

    let mut edge_ids = HashSet::new();
    for (index, edge) in spec.edges.iter().enumerate() {
        let path = format!("/edges/{index}");
        check_identifier(report, &format!("{path}/id"), &edge.id);
        if !edge_ids.insert(edge.id.as_str()) {
            error(
                report,
                "id.duplicate_edge",
                format!("{path}/id"),
                format!("duplicate edge id {}", edge.id),
            );
        }
        if node_ids.contains(edge.id.as_str()) {
            error(
                report,
                "id.node_edge_collision",
                format!("{path}/id"),
                format!("edge id {} collides with a node id", edge.id),
            );
        }
        check_identifier(report, &format!("{path}/source"), &edge.source);
        check_identifier(report, &format!("{path}/target"), &edge.target);
        check_text(report, &format!("{path}/label"), &edge.label, 0, 256);
        check_string_array(
            report,
            &format!("{path}/source_refs"),
            &edge.source_refs,
            100,
            true,
        );
        validate_metadata(report, &format!("{path}/metadata"), &edge.metadata);
    }

    let mut group_ids = HashSet::new();
    for (index, group) in spec.groups.iter().enumerate() {
        let path = format!("/groups/{index}");
        check_identifier(report, &format!("{path}/id"), &group.id);
        if !group_ids.insert(group.id.as_str()) {
            error(
                report,
                "id.duplicate_group",
                format!("{path}/id"),
                format!("duplicate group id {}", group.id),
            );
        }
        check_text(report, &format!("{path}/label"), &group.label, 1, 128);
        check_string_array(
            report,
            &format!("{path}/node_ids"),
            &group.node_ids,
            500,
            true,
        );
        if let Some(parent) = &group.parent_group_id {
            check_identifier(report, &format!("{path}/parent_group_id"), parent);
        }
        check_string_array(
            report,
            &format!("{path}/source_refs"),
            &group.source_refs,
            100,
            true,
        );
    }

    let mut source_ids = HashSet::new();
    for (index, source) in spec.sources.iter().enumerate() {
        let path = format!("/sources/{index}");
        check_identifier(report, &format!("{path}/id"), &source.id);
        if !source_ids.insert(source.id.as_str()) {
            error(
                report,
                "id.duplicate_source",
                format!("{path}/id"),
                format!("duplicate source id {}", source.id),
            );
        }
        validate_source_shape(source, &path, report);
    }

    check_string_array(
        report,
        "/layout_hints/preferred_root_ids",
        &spec.layout_hints.preferred_root_ids,
        20,
        true,
    );
    if !(10..=500).contains(&spec.layout_hints.max_initial_nodes) {
        error(
            report,
            "schema.out_of_range",
            "/layout_hints/max_initial_nodes",
            "max_initial_nodes must be between 10 and 500",
        );
    }

    let provenance = &spec.provenance;
    if provenance.diagram_spec_version != "1.0" {
        error(
            report,
            "provenance.spec_version_mismatch",
            "/provenance/diagram_spec_version",
            "diagram_spec_version must be exactly 1.0",
        );
    }
    if provenance.template_version != "1.0.0" {
        error(
            report,
            "provenance.template_version_mismatch",
            "/provenance/template_version",
            "template_version must be exactly 1.0.0",
        );
    }
    if !looks_like_rfc3339(&provenance.generated_at) {
        error(
            report,
            "provenance.invalid_generated_at",
            "/provenance/generated_at",
            "generated_at must be an RFC 3339 date-time",
        );
    }
    check_text(
        report,
        "/provenance/generated_at",
        &provenance.generated_at,
        20,
        64,
    );
    check_string_array(
        report,
        "/provenance/source_file_ids",
        &provenance.source_file_ids,
        1000,
        true,
    );
    for (index, source_file_id) in provenance.source_file_ids.iter().enumerate() {
        check_identifier(
            report,
            &format!("/provenance/source_file_ids/{index}"),
            source_file_id,
        );
    }
    if let Some(hash) = &provenance.parent_spec_hash {
        check_sha256(report, "/provenance/parent_spec_hash", hash);
    }
    if let Some(summary) = &provenance.change_summary {
        check_text(report, "/provenance/change_summary", summary, 0, 1024);
    }
    check_text(
        report,
        "/provenance/model_content_scope",
        &provenance.model_content_scope,
        1,
        1024,
    );
    check_text(
        report,
        "/provenance/deterministic_content_scope",
        &provenance.deterministic_content_scope,
        1,
        1024,
    );
}

fn validate_source_shape(source: &Source, path: &str, report: &mut ValidationReport) {
    check_text(report, &format!("{path}/title"), &source.title, 1, 256);
    check_text(report, &format!("{path}/locator"), &source.locator, 1, 1024);
    check_optional_text(report, path, "uri", source.uri.as_deref(), 2048);
    check_optional_text(report, path, "file_name", source.file_name.as_deref(), 256);
    if let Some(file_name) = source.file_name.as_deref() {
        if !valid_source_file_name(file_name) {
            error(
                report,
                "source.file_name_not_basename",
                format!("{path}/file_name"),
                "source file_name must be a plain basename without path separators or drive prefixes",
            );
        }
    }
    for (field, value) in [
        ("locator", Some(source.locator.as_str())),
        ("attachment", source.attachment.as_deref()),
    ] {
        if value.is_some_and(contains_absolute_path) {
            error(
                report,
                "source.absolute_path_forbidden",
                format!("{path}/{field}"),
                "source display fields must use controlled locators instead of absolute local paths",
            );
        }
    }
    check_optional_text(report, path, "paragraph", source.paragraph.as_deref(), 128);
    check_optional_text(report, path, "table", source.table.as_deref(), 128);
    check_optional_text(
        report,
        path,
        "attachment",
        source.attachment.as_deref(),
        128,
    );
    check_optional_text(
        report,
        path,
        "law_document",
        source.law_document.as_deref(),
        256,
    );
    check_optional_text(
        report,
        path,
        "law_version",
        source.law_version.as_deref(),
        128,
    );
    check_optional_text(report, path, "article", source.article.as_deref(), 128);
    check_optional_text(report, path, "quote", source.quote.as_deref(), 8192);
    if let Some(artifact_id) = &source.artifact_id {
        check_identifier(report, &format!("{path}/artifact_id"), artifact_id);
    }
    if let Some(page) = source.page {
        if page == 0 || page > 1_000_000 {
            error(
                report,
                "schema.out_of_range",
                format!("{path}/page"),
                "page must be between 1 and 1000000",
            );
        }
    }
    if let Some(hash) = &source.content_hash {
        check_sha256(report, &format!("{path}/content_hash"), hash);
    }
}

fn validate_references_and_relations(spec: &DiagramSpec, report: &mut ValidationReport) {
    let nodes: HashMap<&str, &Node> = spec
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let source_ids: HashSet<&str> = spec
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    let group_ids: HashSet<&str> = spec.groups.iter().map(|group| group.id.as_str()).collect();

    for (index, node) in spec.nodes.iter().enumerate() {
        validate_source_refs(
            &node.source_refs,
            &source_ids,
            &format!("/nodes/{index}/source_refs"),
            report,
        );
    }

    let mut fallback_count = 0usize;
    for (index, edge) in spec.edges.iter().enumerate() {
        let path = format!("/edges/{index}");
        validate_source_refs(
            &edge.source_refs,
            &source_ids,
            &format!("{path}/source_refs"),
            report,
        );
        let source = nodes.get(edge.source.as_str());
        let target = nodes.get(edge.target.as_str());
        if source.is_none() {
            error(
                report,
                "edge.dangling_source",
                format!("{path}/source"),
                format!("edge source {} does not identify a node", edge.source),
            );
        }
        if target.is_none() {
            error(
                report,
                "edge.dangling_target",
                format!("{path}/target"),
                format!("edge target {} does not identify a node", edge.target),
            );
        }
        if let (Some(source), Some(target)) = (source, target) {
            if !relation_is_compatible(edge.relation, source.node_type, target.node_type) {
                error(
                    report,
                    "relation.incompatible_node_types",
                    format!("{path}/relation"),
                    format!(
                        "relation {} does not allow {} -> {}",
                        edge.relation, source.node_type, target.node_type
                    ),
                );
            }
        }
        if edge.source == edge.target {
            if edge.relation == Relation::SameEventAs {
                warning(
                    report,
                    "relation.same_event_self_loop",
                    format!("{path}/relation"),
                    "same_event_as self-loop is retained only for migration compatibility",
                );
            } else {
                error(
                    report,
                    "relation.self_loop",
                    format!("{path}/relation"),
                    format!("relation {} cannot be a self-loop", edge.relation),
                );
            }
        }
        if edge.relation == Relation::RelatedTo {
            fallback_count += 1;
            warning(
                report,
                "relation.fallback_used",
                format!("{path}/relation"),
                "related_to should be replaced by a more specific registered relation when possible",
            );
        }
    }
    if !spec.edges.is_empty() && fallback_count * 10 > spec.edges.len() {
        warning(
            report,
            "relation.excessive_fallback",
            "/edges",
            "related_to accounts for more than 10% of all edges",
        );
    }

    for (index, group) in spec.groups.iter().enumerate() {
        for (node_index, node_id) in group.node_ids.iter().enumerate() {
            if !nodes.contains_key(node_id.as_str()) {
                error(
                    report,
                    "group.dangling_node",
                    format!("/groups/{index}/node_ids/{node_index}"),
                    format!("group node {} does not exist", node_id),
                );
            }
        }
        if let Some(parent_id) = &group.parent_group_id {
            if !group_ids.contains(parent_id.as_str()) {
                error(
                    report,
                    "group.dangling_parent",
                    format!("/groups/{index}/parent_group_id"),
                    format!("parent group {} does not exist", parent_id),
                );
            }
        }
        validate_source_refs(
            &group.source_refs,
            &source_ids,
            &format!("/groups/{index}/source_refs"),
            report,
        );
    }
    validate_group_cycles(spec, report);

    for (index, root_id) in spec.layout_hints.preferred_root_ids.iter().enumerate() {
        if !nodes.contains_key(root_id.as_str()) {
            error(
                report,
                "layout.dangling_preferred_root",
                format!("/layout_hints/preferred_root_ids/{index}"),
                format!("preferred root {} does not identify a node", root_id),
            );
        }
    }

    for (index, source_file_id) in spec.provenance.source_file_ids.iter().enumerate() {
        if !source_ids.contains(source_file_id.as_str()) {
            warning(
                report,
                "provenance.unresolved_source_file_id",
                format!("/provenance/source_file_ids/{index}"),
                format!(
                    "source_file_id {} is not represented in sources",
                    source_file_id
                ),
            );
        }
    }
}

fn validate_sources(spec: &DiagramSpec, report: &mut ValidationReport) {
    for (index, source) in spec.sources.iter().enumerate() {
        let path = format!("/sources/{index}");
        if matches!(
            source.kind,
            SourceKind::File
                | SourceKind::FilePage
                | SourceKind::Paragraph
                | SourceKind::Table
                | SourceKind::Attachment
                | SourceKind::CaseRecord
        ) && source.artifact_id.is_none()
            && source.file_name.as_deref().is_none_or(str::is_empty)
        {
            error(
                report,
                "source.file_identity_missing",
                &path,
                "file-backed source must include artifact_id or file_name",
            );
        }

        if source.kind == SourceKind::Law {
            if source.law_document.as_deref().is_none_or(str::is_empty) {
                error(
                    report,
                    "source.law_document_missing",
                    format!("{path}/law_document"),
                    "law source must identify law_document",
                );
            }
            if source.law_version.as_deref().is_none_or(str::is_empty) {
                error(
                    report,
                    "source.law_version_missing",
                    format!("{path}/law_version"),
                    "law source must identify the applicable law_version",
                );
            }
            if source.article.as_deref().is_none_or(str::is_empty) {
                warning(
                    report,
                    "source.law_article_missing",
                    format!("{path}/article"),
                    "law source should identify the applicable article when available",
                );
            }
            if source.uri.is_none() && source.artifact_id.is_none() {
                error(
                    report,
                    "source.law_location_missing",
                    &path,
                    "law source must include an official uri or internal artifact_id",
                );
            }
        }

        if let Some(uri) = &source.uri {
            if !allowed_uri(uri) {
                error(
                    report,
                    "source.unsafe_uri",
                    format!("{path}/uri"),
                    "uri must use http, https, or lawyer-assistance and contain no controls",
                );
            }
        }
    }
}

fn validate_evidence(spec: &DiagramSpec, report: &mut ValidationReport) {
    let node_types: HashMap<&str, NodeType> = spec
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.node_type))
        .collect();
    let source_ids: HashSet<&str> = spec
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();

    for (index, fact) in spec
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.node_type == NodeType::Fact)
    {
        if fact.source_refs.is_empty() {
            error(
                report,
                "fact.source_missing",
                format!("/nodes/{index}/source_refs"),
                "fact nodes must cite the material that contains the allegation or fact",
            );
        }
        if matches!(fact.status, NodeStatus::Supported | NodeStatus::Established) {
            let has_supporting_evidence = spec.edges.iter().any(|edge| {
                edge.target == fact.id
                    && matches!(edge.relation, Relation::Supports | Relation::Proves)
                    && node_types.get(edge.source.as_str()) == Some(&NodeType::Evidence)
            }) || spec.nodes.iter().any(|evidence| {
                evidence.node_type == NodeType::Evidence
                    && ["supports_facts", "proves"].iter().any(|key| {
                        metadata_string_list(&evidence.metadata, key)
                            .into_iter()
                            .any(|target| target == fact.id)
                    })
            });
            if !has_supporting_evidence {
                error(
                    report,
                    "fact.supporting_evidence_missing",
                    format!("/nodes/{index}/status"),
                    "supported or established facts must be linked from supporting evidence",
                );
            }
        }
    }

    for (index, node) in spec.nodes.iter().enumerate() {
        if node.node_type != NodeType::Evidence {
            continue;
        }
        let path = format!("/nodes/{index}");
        if node.source_refs.is_empty() {
            error(
                report,
                "evidence.source_missing",
                format!("{path}/source_refs"),
                "evidence node must cite at least one source",
            );
        }
        for key in ["evidence_name", "evidence_type"] {
            if metadata_string(&node.metadata, key).is_none_or(str::is_empty) {
                warning(
                    report,
                    "evidence.metadata_incomplete",
                    format!("{path}/metadata/{key}"),
                    format!("evidence metadata should include {key}"),
                );
            }
        }
        if metadata_bool(&node.metadata, "human_confirmation").is_none() {
            warning(
                report,
                "evidence.human_confirmation_missing",
                format!("{path}/metadata/human_confirmation"),
                "evidence metadata should explicitly record human_confirmation",
            );
        }
        if let Some(source_file) = metadata_string(&node.metadata, "source_file") {
            if !source_ids.contains(source_file) {
                error(
                    report,
                    "evidence.dangling_source_file",
                    format!("{path}/metadata/source_file"),
                    format!(
                        "evidence source_file {} does not identify a source",
                        source_file
                    ),
                );
            }
        }
        for key in ["supports_facts", "contradicts_facts"] {
            for id in metadata_string_list(&node.metadata, key) {
                match node_types.get(id) {
                    Some(NodeType::Fact) => {}
                    Some(other) => error(
                        report,
                        "evidence.reference_not_fact",
                        format!("{path}/metadata/{key}"),
                        format!("{} identifies a {} node, not a fact", id, other),
                    ),
                    None => error(
                        report,
                        "evidence.dangling_fact_reference",
                        format!("{path}/metadata/{key}"),
                        format!("{} does not identify a node", id),
                    ),
                }
            }
        }
        if let Some(value) = node.metadata.get("proves") {
            let proves = match value {
                MetadataValue::Scalar(MetadataScalar::String(value)) => Some(vec![value.as_str()]),
                MetadataValue::Array(values)
                    if values
                        .iter()
                        .all(|value| matches!(value, MetadataScalar::String(_))) =>
                {
                    Some(
                        values
                            .iter()
                            .filter_map(|value| match value {
                                MetadataScalar::String(value) => Some(value.as_str()),
                                _ => None,
                            })
                            .collect(),
                    )
                }
                _ => None,
            };
            if let Some(proves) = proves {
                for id in proves {
                    match node_types.get(id) {
                        Some(NodeType::Fact | NodeType::Event | NodeType::Amount) => {}
                        Some(_) => error(
                            report,
                            "evidence.proves_invalid_target_type",
                            format!("{path}/metadata/proves"),
                            "evidence proves must target a fact, event, or amount node",
                        ),
                        None => error(
                            report,
                            "evidence.proves_dangling_target",
                            format!("{path}/metadata/proves"),
                            "evidence proves references a missing node",
                        ),
                    }
                }
            } else {
                error(
                    report,
                    "evidence.proves_invalid_shape",
                    format!("{path}/metadata/proves"),
                    "evidence proves must be a string or an array containing only strings",
                );
            }
        }

        let has_proof_edge = spec.edges.iter().any(|edge| {
            edge.source == node.id
                && matches!(
                    edge.relation,
                    Relation::Proves | Relation::Supports | Relation::Contradicts
                )
        });
        if !has_proof_edge && metadata_string_list(&node.metadata, "proves").is_empty() {
            warning(
                report,
                "evidence.proof_target_missing",
                &path,
                "evidence should identify what it proves, supports, or contradicts",
            );
        }
    }

    for (index, node) in spec.nodes.iter().enumerate() {
        if node.status != NodeStatus::Established {
            continue;
        }
        for edge in spec
            .edges
            .iter()
            .filter(|edge| edge.target == node.id && edge.relation == Relation::Contradicts)
        {
            let (code, message) = if matches!(
                edge.strength,
                crate::model::Strength::Conclusive | crate::model::Strength::Strong
            ) {
                (
                    "fact.established_with_strong_contradiction",
                    "established node has strong or conclusive contradictory evidence",
                )
            } else {
                (
                    "fact.established_with_contradiction",
                    "established node still has contradictory material",
                )
            };
            let severity = if code.ends_with("strong_contradiction") {
                DiagnosticSeverity::Error
            } else {
                DiagnosticSeverity::Warning
            };
            report.push(Diagnostic::new(
                severity,
                code,
                format!("/nodes/{index}/status"),
                message,
            ));
        }
    }
}

fn validate_legal_versions_and_hierarchy(spec: &DiagramSpec, report: &mut ValidationReport) {
    let nodes: HashMap<&str, &Node> = spec
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let sources: HashMap<&str, &Source> = spec
        .sources
        .iter()
        .map(|source| (source.id.as_str(), source))
        .collect();

    for (index, node) in spec.nodes.iter().enumerate() {
        if !node.node_type.is_legal_norm() {
            continue;
        }
        let path = format!("/nodes/{index}");
        let version = metadata_string(&node.metadata, "version");
        let official_source = metadata_string(&node.metadata, "official_source");
        let referenced_law_sources: Vec<&Source> = node
            .source_refs
            .iter()
            .filter_map(|id| sources.get(id.as_str()).copied())
            .filter(|source| source.kind == SourceKind::Law)
            .collect();
        if version.is_none_or(str::is_empty)
            && referenced_law_sources
                .iter()
                .all(|source| source.law_version.as_deref().is_none_or(str::is_empty))
        {
            error(
                report,
                "law.version_missing",
                format!("{path}/metadata/version"),
                "legal norm must identify an applicable version in metadata or a law source",
            );
        }
        if official_source.is_none_or(str::is_empty) && referenced_law_sources.is_empty() {
            warning(
                report,
                "law.official_source_missing",
                &path,
                "legal norm should cite an official source",
            );
        }
        if let Some(version) = version {
            for source in &referenced_law_sources {
                if let Some(source_version) = source.law_version.as_deref() {
                    if source_version != version {
                        warning(
                            report,
                            "law.version_mismatch",
                            format!("{path}/metadata/version"),
                            format!(
                                "node version {version} differs from cited source version {source_version}"
                            ),
                        );
                    }
                }
            }
        }
    }

    for (index, edge) in spec.edges.iter().enumerate() {
        if !matches!(
            edge.relation,
            Relation::SuperiorTo | Relation::AuthorizedBy | Relation::Implements
        ) {
            continue;
        }
        let (Some(source), Some(target)) = (
            nodes.get(edge.source.as_str()),
            nodes.get(edge.target.as_str()),
        ) else {
            continue;
        };
        let Some(source_rank) = authority_rank(source) else {
            continue;
        };
        let Some(target_rank) = authority_rank(target) else {
            continue;
        };
        let reversed = match edge.relation {
            Relation::SuperiorTo => source_rank < target_rank,
            Relation::AuthorizedBy | Relation::Implements => source_rank > target_rank,
            _ => false,
        };
        if reversed {
            error(
                report,
                "law.relation_direction_reversed",
                format!("/edges/{index}/relation"),
                format!(
                    "{} direction conflicts with recognized authority levels",
                    edge.relation
                ),
            );
        }
    }
}

fn validate_money(spec: &DiagramSpec, report: &mut ValidationReport) {
    let nodes: HashMap<&str, &Node> = spec
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect();
    let source_ids: HashSet<&str> = spec
        .sources
        .iter()
        .map(|source| source.id.as_str())
        .collect();
    let strict = spec.diagram_type == DiagramType::CaseMoneyFlow;

    for (index, node) in spec.nodes.iter().enumerate() {
        if node.node_type != NodeType::Amount {
            continue;
        }
        let path = format!("/nodes/{index}/metadata");
        validate_amount_fields(&node.metadata, &path, &source_ids, strict, report);
    }

    for (index, edge) in spec.edges.iter().enumerate() {
        if !matches!(edge.relation, Relation::PaidTo | Relation::TransferredTo) {
            continue;
        }
        let mut combined = edge.metadata.clone();
        for endpoint in [&edge.source, &edge.target] {
            if let Some(node) = nodes.get(endpoint.as_str()) {
                if node.node_type == NodeType::Amount {
                    for (key, value) in &node.metadata {
                        combined.entry(key.clone()).or_insert_with(|| value.clone());
                    }
                }
            }
        }
        if !edge.source_refs.is_empty() && !combined.contains_key("voucher_source_ref") {
            combined.insert(
                "voucher_source_ref".to_owned(),
                MetadataValue::Scalar(MetadataScalar::String(edge.source_refs[0].clone())),
            );
        }
        validate_amount_fields(
            &combined,
            &format!("/edges/{index}/metadata"),
            &source_ids,
            strict,
            report,
        );
    }
}

fn validate_amount_fields(
    metadata: &Metadata,
    path: &str,
    source_ids: &HashSet<&str>,
    strict: bool,
    report: &mut ValidationReport,
) {
    let severity = if strict {
        DiagnosticSeverity::Error
    } else {
        DiagnosticSeverity::Warning
    };
    match metadata_string(metadata, "amount") {
        Some(amount) if valid_decimal(amount) => {}
        Some(_) => report.push(Diagnostic::new(
            DiagnosticSeverity::Error,
            "money.invalid_amount",
            format!("{path}/amount"),
            "amount must be a decimal fixed-point string without exponent notation",
        )),
        None => report.push(Diagnostic::new(
            severity,
            "money.amount_missing",
            format!("{path}/amount"),
            "money flow must include amount",
        )),
    }
    match metadata_string(metadata, "currency") {
        Some(currency) if valid_currency(currency) => {}
        Some(_) => report.push(Diagnostic::new(
            DiagnosticSeverity::Error,
            "money.invalid_currency",
            format!("{path}/currency"),
            "currency must be a three-letter uppercase ISO 4217 code",
        )),
        None => report.push(Diagnostic::new(
            severity,
            "money.currency_missing",
            format!("{path}/currency"),
            "money flow must include currency",
        )),
    }
    match metadata_string(metadata, "date") {
        Some(date) if valid_date(date) => {}
        Some(_) => report.push(Diagnostic::new(
            DiagnosticSeverity::Error,
            "money.invalid_date",
            format!("{path}/date"),
            "money flow date must begin with a valid YYYY-MM-DD date",
        )),
        None => report.push(Diagnostic::new(
            severity,
            "money.date_missing",
            format!("{path}/date"),
            "money flow must include date",
        )),
    }
    match metadata_string(metadata, "voucher_source_ref") {
        Some(id) if source_ids.contains(id) => {}
        Some(id) => report.push(Diagnostic::new(
            DiagnosticSeverity::Error,
            "money.dangling_voucher_source",
            format!("{path}/voucher_source_ref"),
            format!("voucher_source_ref {} does not identify a source", id),
        )),
        None => report.push(Diagnostic::new(
            severity,
            "money.voucher_source_missing",
            format!("{path}/voucher_source_ref"),
            "money flow must cite a voucher source",
        )),
    }
}

fn validate_timeline(spec: &DiagramSpec, report: &mut ValidationReport) {
    let strict = spec.diagram_type == DiagramType::CaseTimeline;
    let severity = if strict {
        DiagnosticSeverity::Error
    } else {
        DiagnosticSeverity::Warning
    };
    let mut dates: HashMap<&str, &str> = HashMap::new();
    for (index, node) in spec.nodes.iter().enumerate() {
        if !node.node_type.is_timeline_item() {
            continue;
        }
        let path = format!("/nodes/{index}/metadata");
        let precision = match metadata_string(&node.metadata, "date_precision") {
            Some(value)
                if matches!(value, "day" | "month" | "year" | "approximate" | "unknown") =>
            {
                value
            }
            Some(_) => {
                error(
                    report,
                    "timeline.invalid_date_precision",
                    format!("{path}/date_precision"),
                    "date_precision must be day, month, year, approximate, or unknown",
                );
                "day"
            }
            None if node.metadata.contains_key("date_precision") => {
                error(
                    report,
                    "timeline.invalid_date_precision",
                    format!("{path}/date_precision"),
                    "date_precision must be a string",
                );
                "day"
            }
            None => "day",
        };
        let date = metadata_string(&node.metadata, "date")
            .or_else(|| metadata_string(&node.metadata, "date_start"));
        match date {
            Some(value) if valid_timeline_date(value, precision) => {
                if valid_date(value) {
                    dates.insert(node.id.as_str(), value);
                }
            }
            Some(_) => error(
                report,
                "timeline.invalid_date",
                format!("{path}/date"),
                "event or procedure date does not match date_precision",
            ),
            None if precision == "unknown" => warning(
                report,
                "timeline.date_unknown",
                &path,
                "timeline item explicitly records that its date is unknown",
            ),
            None => report.push(Diagnostic::new(
                severity,
                "timeline.date_missing",
                &path,
                "event or procedure should identify date or date_start",
            )),
        }
        if let (Some(start), Some(end)) = (
            metadata_string(&node.metadata, "date_start"),
            metadata_string(&node.metadata, "date_end"),
        ) {
            if !valid_date(start) || !valid_date(end) {
                error(
                    report,
                    "timeline.invalid_range",
                    &path,
                    "date_start and date_end must be valid dates",
                );
            } else if start > end {
                error(
                    report,
                    "timeline.reversed_range",
                    &path,
                    "date_start must not be later than date_end",
                );
            }
        }
        if let Some(deadline) = metadata_string(&node.metadata, "limitation_deadline") {
            if !valid_date(deadline) {
                error(
                    report,
                    "timeline.invalid_limitation_deadline",
                    format!("{path}/limitation_deadline"),
                    "limitation_deadline must begin with a valid YYYY-MM-DD date",
                );
            } else if date.is_some_and(|event_date| valid_date(event_date) && deadline < event_date)
            {
                error(
                    report,
                    "timeline.limitation_before_event",
                    format!("{path}/limitation_deadline"),
                    "limitation_deadline must not be earlier than the related event",
                );
            } else {
                warning(
                    report,
                    "timeline.limitation_review_required",
                    format!("{path}/limitation_deadline"),
                    "limitation deadline is a review prompt and must be confirmed by a lawyer",
                );
            }
        }
    }

    let mut ordering: HashMap<&str, Vec<&str>> = HashMap::new();
    for (index, edge) in spec.edges.iter().enumerate() {
        let (earlier, later) = match edge.relation {
            Relation::OccurredBefore => (edge.source.as_str(), edge.target.as_str()),
            Relation::OccurredAfter => (edge.target.as_str(), edge.source.as_str()),
            _ => continue,
        };
        ordering.entry(earlier).or_default().push(later);
        if let (Some(earlier_date), Some(later_date)) = (dates.get(earlier), dates.get(later)) {
            if earlier_date >= later_date {
                error(
                    report,
                    "timeline.order_conflict",
                    format!("/edges/{index}/relation"),
                    format!(
                        "declared ordering conflicts with dates {} and {}",
                        earlier_date, later_date
                    ),
                );
            }
        }
    }
    if directed_cycle(&ordering) {
        error(
            report,
            "timeline.order_cycle",
            "/edges",
            "occurred_before/occurred_after relations contain a cycle",
        );
    }
}

fn validate_issues(spec: &DiagramSpec, report: &mut ValidationReport) {
    for (index, issue) in spec
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.node_type == NodeType::Issue)
    {
        let incoming: Vec<&Edge> = spec
            .edges
            .iter()
            .filter(|edge| edge.target == issue.id)
            .collect();
        let has_definition = incoming.iter().any(|edge| {
            matches!(
                edge.relation,
                Relation::Raises | Relation::Disputes | Relation::Alleges
            )
        });
        let has_evidence = incoming
            .iter()
            .any(|edge| matches!(edge.relation, Relation::Supports | Relation::Contradicts));
        let has_law = incoming
            .iter()
            .any(|edge| edge.relation == Relation::AppliesTo);
        if incoming.is_empty() && spec.diagram_type == DiagramType::CaseIssueEvidenceLaw {
            error(
                report,
                "issue.isolated",
                format!("/nodes/{index}"),
                "issue is isolated from claims, evidence, and law",
            );
        } else if !has_definition {
            warning(
                report,
                "issue.origin_missing",
                format!("/nodes/{index}"),
                "issue should be raised, disputed, or alleged by a claim, defense, or party",
            );
        }
        if !has_evidence {
            warning(
                report,
                "issue.evidence_link_missing",
                format!("/nodes/{index}"),
                "issue has no direct supporting or contradictory evidence/fact link",
            );
        }
        if !has_law {
            warning(
                report,
                "issue.law_link_missing",
                format!("/nodes/{index}"),
                "issue has no direct applicable rule or legal norm link",
            );
        }
    }
}

fn validate_source_refs(
    refs: &[String],
    source_ids: &HashSet<&str>,
    path: &str,
    report: &mut ValidationReport,
) {
    for (index, reference) in refs.iter().enumerate() {
        if !source_ids.contains(reference.as_str()) {
            error(
                report,
                "source.dangling_reference",
                format!("{path}/{index}"),
                format!("source reference {} does not exist", reference),
            );
        }
    }
}

fn validate_group_cycles(spec: &DiagramSpec, report: &mut ValidationReport) {
    let parents: HashMap<&str, &str> = spec
        .groups
        .iter()
        .filter_map(|group| {
            group
                .parent_group_id
                .as_deref()
                .map(|parent| (group.id.as_str(), parent))
        })
        .collect();
    for (index, group) in spec.groups.iter().enumerate() {
        let mut seen = HashSet::new();
        let mut current = group.id.as_str();
        while let Some(parent) = parents.get(current).copied() {
            if !seen.insert(current) || parent == group.id {
                error(
                    report,
                    "group.parent_cycle",
                    format!("/groups/{index}/parent_group_id"),
                    format!("group {} participates in a parent cycle", group.id),
                );
                break;
            }
            current = parent;
        }
    }
}

fn validate_metadata(report: &mut ValidationReport, path: &str, metadata: &Metadata) {
    if metadata.len() > 100 {
        error(
            report,
            "metadata.too_many_properties",
            path,
            "metadata may contain at most 100 properties",
        );
    }
    if serde_json::to_vec(metadata).map_or(true, |bytes| bytes.len() > 65_536) {
        error(
            report,
            "metadata.too_large",
            path,
            "serialized metadata may not exceed 65536 bytes",
        );
    }
    for (key, value) in metadata {
        if !valid_metadata_key(key) {
            error(
                report,
                "metadata.invalid_key",
                format!("{path}/{}", pointer_escape(key)),
                "metadata keys must match ^[a-z][a-z0-9_]{0,63}$",
            );
        }
        let value_path = format!("{path}/{}", pointer_escape(key));
        match value {
            MetadataValue::Scalar(value) => validate_metadata_scalar(report, &value_path, value),
            MetadataValue::Array(values) => {
                if values.len() > 100 {
                    error(
                        report,
                        "metadata.array_too_long",
                        &value_path,
                        "metadata arrays may contain at most 100 scalars",
                    );
                }
                for (index, value) in values.iter().enumerate() {
                    validate_metadata_scalar(report, &format!("{value_path}/{index}"), value);
                }
            }
            MetadataValue::Object(values) => {
                if values.len() > 50 {
                    error(
                        report,
                        "metadata.object_too_large",
                        &value_path,
                        "nested metadata objects may contain at most 50 scalar properties",
                    );
                }
                for (nested_key, value) in values {
                    if !valid_metadata_key(nested_key) {
                        error(
                            report,
                            "metadata.invalid_key",
                            format!("{value_path}/{}", pointer_escape(nested_key)),
                            "metadata keys must match ^[a-z][a-z0-9_]{0,63}$",
                        );
                    }
                    validate_metadata_scalar(
                        report,
                        &format!("{value_path}/{}", pointer_escape(nested_key)),
                        value,
                    );
                }
            }
        }
    }
}

fn validate_metadata_scalar(report: &mut ValidationReport, path: &str, scalar: &MetadataScalar) {
    if let MetadataScalar::String(value) = scalar {
        check_text(report, path, value, 0, 16_384);
    }
}

fn metadata_string<'a>(metadata: &'a Metadata, key: &str) -> Option<&'a str> {
    match metadata.get(key) {
        Some(MetadataValue::Scalar(MetadataScalar::String(value))) => Some(value),
        _ => None,
    }
}

fn metadata_bool(metadata: &Metadata, key: &str) -> Option<bool> {
    match metadata.get(key) {
        Some(MetadataValue::Scalar(MetadataScalar::Bool(value))) => Some(*value),
        _ => None,
    }
}

fn metadata_string_list<'a>(metadata: &'a Metadata, key: &str) -> Vec<&'a str> {
    match metadata.get(key) {
        Some(MetadataValue::Scalar(MetadataScalar::String(value))) => vec![value],
        Some(MetadataValue::Array(values)) => values
            .iter()
            .filter_map(|value| match value {
                MetadataScalar::String(value) => Some(value.as_str()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn authority_rank(node: &Node) -> Option<u8> {
    if let Some(level) = metadata_string(&node.metadata, "authority_level") {
        let rank = match level {
            "constitution" => 100,
            "law" | "national_law" => 90,
            "administrative_regulation" => 80,
            "supervisory_regulation" | "judicial_interpretation" => 70,
            "local_regulation" => 60,
            "department_rule" => 50,
            "local_government_rule" => 40,
            "normative_document" => 20,
            _ => 0,
        };
        if rank != 0 {
            return Some(rank);
        }
    }
    Some(match node.node_type {
        NodeType::Law => 90,
        NodeType::Regulation => 80,
        NodeType::SupervisoryRegulation | NodeType::JudicialInterpretation => 70,
        NodeType::LocalRegulation => 60,
        NodeType::DepartmentRule => 50,
        NodeType::LocalGovernmentRule => 40,
        NodeType::NormativeDocument => 20,
        _ => return None,
    })
}

fn check_count(
    report: &mut ValidationReport,
    path: &str,
    count: usize,
    minimum: usize,
    maximum: usize,
) {
    if count < minimum || count > maximum {
        error(
            report,
            "schema.item_count",
            path,
            format!("item count {count} is outside {minimum}..={maximum}"),
        );
    }
}

fn check_identifier(report: &mut ValidationReport, path: &str, value: &str) {
    if !valid_identifier(value) {
        error(
            report,
            "schema.invalid_identifier",
            path,
            "identifier must match ^[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}$",
        );
    }
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 96
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.' | b':'))
}

fn check_optional_pattern(
    report: &mut ValidationReport,
    path: &str,
    value: Option<&str>,
    maximum: usize,
    predicate: impl Fn(&str) -> bool,
    message: &'static str,
) {
    if let Some(value) = value {
        if value.chars().count() > maximum || !predicate(value) {
            error(report, "schema.invalid_pattern", path, message);
        }
        if contains_unsafe_unicode(value) {
            error(
                report,
                "security.unsafe_unicode_control",
                path,
                "text contains a prohibited control or bidirectional override character",
            );
        }
    }
}

fn check_optional_text(
    report: &mut ValidationReport,
    base_path: &str,
    field: &str,
    value: Option<&str>,
    maximum: usize,
) {
    if let Some(value) = value {
        check_text(report, &format!("{base_path}/{field}"), value, 0, maximum);
    }
}

fn check_text(
    report: &mut ValidationReport,
    path: &str,
    value: &str,
    minimum: usize,
    maximum: usize,
) {
    let length = value.chars().count();
    if length < minimum || length > maximum {
        error(
            report,
            "schema.string_length",
            path,
            format!("string length {length} is outside {minimum}..={maximum}"),
        );
    }
    if contains_unsafe_unicode(value) {
        error(
            report,
            "security.unsafe_unicode_control",
            path,
            "text contains a prohibited control or bidirectional override character",
        );
    }
    if contains_absolute_path(value) {
        error(
            report,
            "security.absolute_path_forbidden",
            path,
            "absolute local filesystem paths must be replaced by controlled artifact identifiers",
        );
    }
}

fn check_string_array(
    report: &mut ValidationReport,
    path: &str,
    values: &[String],
    maximum: usize,
    unique: bool,
) {
    if values.len() > maximum {
        error(
            report,
            "schema.item_count",
            path,
            format!("array may contain at most {maximum} items"),
        );
    }
    let mut seen = HashSet::new();
    for (index, value) in values.iter().enumerate() {
        if unique && !seen.insert(value) {
            error(
                report,
                "schema.duplicate_array_item",
                format!("{path}/{index}"),
                format!("duplicate array item {value}"),
            );
        }
    }
}

fn check_sha256(report: &mut ValidationReport, path: &str, value: &str) {
    let valid = value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        error(
            report,
            "schema.invalid_sha256",
            path,
            "hash must match sha256 followed by 64 lowercase hexadecimal digits",
        );
    }
}

fn valid_metadata_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn contains_unsafe_unicode(value: &str) -> bool {
    value.chars().any(|character| {
        matches!(
            character,
            '\0'..='\u{0008}'
                | '\u{000B}'
                | '\u{000C}'
                | '\u{000E}'..='\u{001F}'
                | '\u{007F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
    })
}

fn valid_source_file_name(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value
            .chars()
            .any(|character| matches!(character, '/' | '\\' | ':'))
}

fn contains_absolute_path(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.split_whitespace().any(|token| {
        let token = token.trim_start_matches(|character: char| {
            matches!(character, '(' | '[' | '{' | '"' | '\'')
        });
        token.starts_with('/')
            || token.starts_with('\\')
            || token.starts_with("~/")
            || token.starts_with("~\\")
    }) {
        return true;
    }
    let bytes = trimmed.as_bytes();
    bytes.windows(3).enumerate().any(|(index, window)| {
        let token_boundary = index == 0
            || !bytes[index - 1].is_ascii_alphanumeric()
                && !matches!(bytes[index - 1], b'_' | b'-' | b'.');
        token_boundary
            && window[0].is_ascii_alphabetic()
            && window[1] == b':'
            && matches!(window[2], b'/' | b'\\')
    })
}

fn valid_timeline_date(value: &str, precision: &str) -> bool {
    match precision {
        "day" => valid_date(value),
        "month" => valid_year_month(value),
        "year" => valid_year(value),
        "approximate" => valid_date(value) || valid_year_month(value) || valid_year(value),
        "unknown" => false,
        _ => false,
    }
}

fn valid_year(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 4 && bytes.iter().all(u8::is_ascii_digit)
}

fn valid_year_month(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5].is_ascii_digit()
        && bytes[6].is_ascii_digit()
        && (1..=12).contains(&((bytes[5] - b'0') * 10 + (bytes[6] - b'0')))
}

fn allowed_uri(uri: &str) -> bool {
    !contains_unsafe_unicode(uri)
        && !uri.chars().any(char::is_whitespace)
        && ["https://", "http://", "lawyer-assistance://"]
            .iter()
            .any(|prefix| uri.starts_with(prefix))
}

fn valid_decimal(value: &str) -> bool {
    let value = value.strip_prefix('-').unwrap_or(value);
    if value.is_empty() {
        return false;
    }
    let mut parts = value.split('.');
    let integer = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || integer.is_empty()
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    fraction.is_none_or(|fraction| {
        !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn valid_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let Some(year) = parse_ascii_decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = parse_ascii_decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = parse_ascii_decimal(&bytes[8..10]) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) {
        return false;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum_day = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    (1..=maximum_day).contains(&day)
}

fn looks_like_rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !valid_date(value) || bytes.get(10) != Some(&b'T') {
        return false;
    }
    let time_and_zone = &bytes[11..];
    if time_and_zone.len() < 9 {
        return false;
    }
    if time_and_zone.get(2) != Some(&b':') || time_and_zone.get(5) != Some(&b':') {
        return false;
    }
    let Some(hour) = parse_ascii_decimal(&time_and_zone[0..2]) else {
        return false;
    };
    let Some(minute) = parse_ascii_decimal(&time_and_zone[3..5]) else {
        return false;
    };
    let Some(second) = parse_ascii_decimal(&time_and_zone[6..8]) else {
        return false;
    };
    if hour > 23 || minute > 59 || second > 60 {
        return false;
    }
    let zone_start = if matches!(time_and_zone.get(8), Some(b'Z' | b'+' | b'-')) {
        8
    } else if time_and_zone.get(8) == Some(&b'.') {
        let mut index = 9;
        let mut digits = 0usize;
        while time_and_zone.get(index).is_some_and(u8::is_ascii_digit) {
            digits += 1;
            index += 1;
        }
        if digits == 0 {
            return false;
        }
        index
    } else {
        return false;
    };
    let Some(zone_marker) = time_and_zone.get(zone_start) else {
        return false;
    };
    if *zone_marker == b'Z' {
        return zone_start + 1 == time_and_zone.len();
    }
    if !matches!(*zone_marker, b'+' | b'-')
        || zone_start + 6 != time_and_zone.len()
        || time_and_zone.get(zone_start + 3) != Some(&b':')
    {
        return false;
    }
    let Some(zone_hour) = parse_ascii_decimal(&time_and_zone[zone_start + 1..zone_start + 3])
    else {
        return false;
    };
    let Some(zone_minute) = parse_ascii_decimal(&time_and_zone[zone_start + 4..zone_start + 6])
    else {
        return false;
    };
    zone_hour <= 23 && zone_minute <= 59
}

fn parse_ascii_decimal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0u32, |value, byte| {
        value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))
    })
}

fn directed_cycle<'a>(graph: &HashMap<&'a str, Vec<&'a str>>) -> bool {
    fn visit<'a>(
        node: &'a str,
        graph: &HashMap<&'a str, Vec<&'a str>>,
        visiting: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
    ) -> bool {
        if visiting.contains(node) {
            return true;
        }
        if visited.contains(node) {
            return false;
        }
        visiting.insert(node);
        if graph.get(node).is_some_and(|neighbors| {
            neighbors
                .iter()
                .any(|neighbor| visit(neighbor, graph, visiting, visited))
        }) {
            return true;
        }
        visiting.remove(node);
        visited.insert(node);
        false
    }

    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    graph
        .keys()
        .copied()
        .any(|node| visit(node, graph, &mut visiting, &mut visited))
}

fn pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn error(
    report: &mut ValidationReport,
    code: &'static str,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    report.push(Diagnostic::new(
        DiagnosticSeverity::Error,
        code,
        path,
        message,
    ));
}

fn warning(
    report: &mut ValidationReport,
    code: &'static str,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    report.push(Diagnostic::new(
        DiagnosticSeverity::Warning,
        code,
        path,
        message,
    ));
}
