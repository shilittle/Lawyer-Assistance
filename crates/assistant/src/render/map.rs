use super::{
    ensure_output_limit, escape_markdown, ArtifactRenderError, ArtifactRenderFormat,
    ArtifactRenderKind, ArtifactRenderMetadata, RenderedArtifact, MAP_JSON_MEDIA_TYPE,
    MAP_SUMMARY_MEDIA_TYPE, MAX_MAP_JSON_BYTES, MAX_MAP_SUMMARY_BYTES,
};
use crate::{
    ContractError, ContractErrorType, LayoutHint, MapEdge, MapNode, MapSpec, ValidationContext,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAP_SEMANTIC_LABEL: &str = "案件要素与关系分析";
const MAP_NOTICE: &str =
    "本图用于梳理案件事实、争议焦点及其相互关系，所列内容以案件材料和法律依据为准。";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MapArtifactJson<'a> {
    schema_version: u16,
    artifact_kind: &'static str,
    display_label: &'static str,
    title: &'a str,
    layout_hint: LayoutHint,
    nodes: &'a [MapNode],
    edges: &'a [MapEdge],
}

pub fn render_map_json(
    spec: &MapSpec,
    context: &ValidationContext,
) -> Result<RenderedArtifact, ArtifactRenderError> {
    spec.validate(context).map_err(|error| {
        ArtifactRenderError::invalid_spec(ArtifactRenderFormat::MapJson, &error)
    })?;
    let payload = MapArtifactJson {
        schema_version: spec.schema_version,
        artifact_kind: "model_generated_map",
        display_label: MAP_SEMANTIC_LABEL,
        title: &spec.title,
        layout_hint: spec.layout_hint,
        nodes: &spec.nodes,
        edges: &spec.edges,
    };
    let json = serde_json::to_string(&payload)
        .map_err(|_| ArtifactRenderError::serialization_failed(ArtifactRenderFormat::MapJson))?;
    ensure_output_limit(
        ArtifactRenderFormat::MapJson,
        json.len(),
        MAX_MAP_JSON_BYTES,
    )?;
    let metadata = map_metadata(
        spec,
        ArtifactRenderFormat::MapJson,
        MAP_JSON_MEDIA_TYPE,
        "json",
        json.len(),
    );
    Ok(RenderedArtifact::text(metadata, json))
}

pub fn render_map_summary(
    spec: &MapSpec,
    context: &ValidationContext,
) -> Result<RenderedArtifact, ArtifactRenderError> {
    spec.validate(context).map_err(|error| {
        ArtifactRenderError::invalid_spec(ArtifactRenderFormat::MapSummary, &error)
    })?;
    validate_public_summary_text(spec)?;
    let mut summary = format!(
        "# {}：{}\n\n> {}\n\n分析方式：{}\n\n## 案件要点（{}）\n\n",
        MAP_SEMANTIC_LABEL,
        escape_markdown(&spec.title),
        MAP_NOTICE,
        analysis_structure_label(spec.layout_hint),
        spec.nodes.len()
    );
    let labels = spec
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.label.as_str()))
        .collect::<BTreeMap<_, _>>();
    for node in &spec.nodes {
        let parent = node
            .parent_id
            .as_deref()
            .and_then(|value| labels.get(value).copied())
            .map(|value| format!("；所属要点：{}", escape_markdown(value)))
            .unwrap_or_default();
        summary.push_str(&format!(
            "- {} — {}{}\n\n",
            escape_markdown(&node.label),
            escape_markdown(&node.summary),
            parent,
        ));
    }
    summary.push_str(&format!("## 要点关系（{}）\n\n", spec.edges.len()));
    if spec.edges.is_empty() {
        summary.push_str("- 暂无\n");
    } else {
        for edge in &spec.edges {
            let source = labels.get(edge.source.as_str()).copied().unwrap_or("前项");
            let target = labels.get(edge.target.as_str()).copied().unwrap_or("后项");
            summary.push_str(&format!(
                "- {} → {}：{}\n\n",
                escape_markdown(source),
                escape_markdown(target),
                escape_markdown(&edge.label),
            ));
        }
        summary.pop();
    }
    ensure_output_limit(
        ArtifactRenderFormat::MapSummary,
        summary.len(),
        MAX_MAP_SUMMARY_BYTES,
    )?;
    let metadata = map_metadata(
        spec,
        ArtifactRenderFormat::MapSummary,
        MAP_SUMMARY_MEDIA_TYPE,
        "md",
        summary.len(),
    );
    Ok(RenderedArtifact::text(metadata, summary))
}

fn map_metadata(
    spec: &MapSpec,
    format: ArtifactRenderFormat,
    media_type: &str,
    file_extension: &str,
    byte_len: usize,
) -> ArtifactRenderMetadata {
    let mut source_refs = BTreeSet::new();
    for node in &spec.nodes {
        source_refs.extend(node.source_refs.iter().map(String::as_str));
    }
    for edge in &spec.edges {
        source_refs.extend(edge.source_refs.iter().map(String::as_str));
    }
    ArtifactRenderMetadata {
        artifact_kind: ArtifactRenderKind::ModelGeneratedMap,
        format,
        media_type: media_type.to_owned(),
        file_extension: file_extension.to_owned(),
        byte_len,
        schema_version: spec.schema_version,
        source_reference_count: source_refs.len(),
        validated_citation_count: 0,
        semantic_label: MAP_SEMANTIC_LABEL.to_owned(),
    }
}

fn analysis_structure_label(layout_hint: LayoutHint) -> &'static str {
    match layout_hint {
        LayoutHint::Mindmap => "要点脉络",
        LayoutHint::Layered => "层次关系",
        LayoutHint::Radial => "中心与分支关系",
    }
}

/// The Markdown summary is a lawyer-facing deliverable. Structured identifiers
/// remain available in the adjacent JSON representation, but public text must
/// never reproduce them or expose implementation vocabulary.
fn validate_public_summary_text(spec: &MapSpec) -> Result<(), ArtifactRenderError> {
    let fields = std::iter::once(("map.title".to_owned(), spec.title.as_str()))
        .chain(spec.nodes.iter().enumerate().flat_map(|(index, node)| {
            [
                (format!("map.nodes[{index}].label"), node.label.as_str()),
                (format!("map.nodes[{index}].summary"), node.summary.as_str()),
            ]
        }))
        .chain(
            spec.edges
                .iter()
                .enumerate()
                .map(|(index, edge)| (format!("map.edges[{index}].label"), edge.label.as_str())),
        );

    for (path, value) in fields {
        if contains_non_deliverable_summary_text(value) {
            let error = ContractError::new(
                ContractErrorType::InvalidEnvelope,
                path,
                "public map summary contains non-deliverable content",
            );
            return Err(ArtifactRenderError::invalid_spec(
                ArtifactRenderFormat::MapSummary,
                &error,
            ));
        }
    }
    Ok(())
}

fn contains_non_deliverable_summary_text(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if [
        "模型",
        "布局",
        "内部标识",
        "内部路径",
        "系统字段",
        "工程字段",
        "技术字段",
        "无标题",
        "artifact",
        "[src:",
        "model_generated",
        "schema_version",
        "schemaversion",
        "source_ref",
        "sourceref",
        "article_id",
        "articleid",
        "proposal_hash",
        "proposalhash",
        "service_hash",
        "servicehash",
        "snippet",
        "snnipet",
        "```",
        "<script",
        "</script",
        "file://",
        "http://",
        "https://",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
    {
        return true;
    }

    contains_forbidden_public_field(&lower)
        || contains_internal_reference(&lower)
        || contains_local_path(trimmed)
        || contains_uuid(trimmed)
        || contains_hash(trimmed)
}

fn contains_forbidden_public_field(lower: &str) -> bool {
    lower
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .filter(|token| !token.is_empty())
        .any(|token| {
            matches!(
                token,
                "id" | "schema"
                    | "source_refs"
                    | "sourcerefs"
                    | "request_id"
                    | "requestid"
                    | "run_id"
                    | "runid"
                    | "artifact_id"
                    | "artifactid"
                    | "attachment_id"
                    | "attachmentid"
                    | "endpoint"
                    | "localpath"
                    | "payload"
                    | "json"
                    | "uuid"
                    | "hash"
            )
        })
}

fn contains_internal_reference(lower: &str) -> bool {
    [
        "node:",
        "edge:",
        "material:",
        "artifact:",
        "source:",
        "case:",
        "fact:",
        "evidence:",
        "citation:",
        "law:",
        "proposal:",
        "attachment:",
        "document:",
        "version:",
        "section:",
        "clause:",
        "party:",
        "service-",
    ]
    .iter()
    .any(|prefix| lower.contains(prefix))
}

fn contains_local_path(value: &str) -> bool {
    if value.contains('\\') {
        return true;
    }
    value.as_bytes().windows(3).any(|part| {
        part[0].is_ascii_alphabetic() && part[1] == b':' && matches!(part[2], b'/' | b'\\')
    })
}

fn contains_uuid(value: &str) -> bool {
    value.as_bytes().windows(36).any(|candidate| {
        [8, 13, 18, 23]
            .iter()
            .all(|index| candidate[*index] == b'-')
            && candidate
                .iter()
                .enumerate()
                .all(|(index, byte)| [8, 13, 18, 23].contains(&index) || byte.is_ascii_hexdigit())
    })
}

fn contains_hash(value: &str) -> bool {
    let mut length = 0usize;
    let mut has_digit = false;
    let mut has_hex_letter = false;
    for byte in value.bytes().chain(std::iter::once(b' ')) {
        if byte.is_ascii_hexdigit() {
            length += 1;
            has_digit |= byte.is_ascii_digit();
            has_hex_letter |= matches!(byte.to_ascii_lowercase(), b'a'..=b'f');
        } else {
            if length >= 16 && has_digit && has_hex_letter {
                return true;
            }
            length = 0;
            has_digit = false;
            has_hex_letter = false;
        }
    }
    false
}
