//! Deterministic, template-specific layout for DiagramSpec v1.
//!
//! The layout engine deliberately consumes only data from `DiagramSpec`.  It
//! does not accept coordinates, CSS, or executable layout callbacks from the
//! caller.  Sorting is always by stable identifiers so a repeated render of
//! the same specification produces identical geometry.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde_json::Value;

use crate::model::DiagramSpec;

const NODE_MIN_WIDTH: f64 = 176.0;
const NODE_MAX_WIDTH: f64 = 280.0;
const NODE_BASE_HEIGHT: f64 = 74.0;
const COLUMN_GAP: f64 = 116.0;
const ROW_GAP: f64 = 48.0;
const PAGE_MARGIN: f64 = 84.0;
const PARALLEL_EDGE_GAP: f64 = 26.0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutStrategy {
    LegalHierarchy,
    LegalApplicationChain,
    LegalConflictPriority,
    CasePartyRelationship,
    CaseIssueEvidenceLaw,
    CaseMoneyFlow,
    CaseTimeline,
}

impl LayoutStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LegalHierarchy => "legal-hierarchy",
            Self::LegalApplicationChain => "legal-application-chain",
            Self::LegalConflictPriority => "legal-conflict-priority",
            Self::CasePartyRelationship => "case-party-relationship",
            Self::CaseIssueEvidenceLaw => "case-issue-evidence-law",
            Self::CaseMoneyFlow => "case-money-flow",
            Self::CaseTimeline => "case-timeline",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LayoutNode {
    pub id: String,
    pub node_type: String,
    pub status: String,
    pub importance: String,
    pub label: String,
    pub short_label: Option<String>,
    pub details: String,
    pub source_refs: Vec<String>,
    pub tags: Vec<String>,
    pub metadata: BTreeMap<String, Value>,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    pub lane: usize,
}

impl LayoutNode {
    pub fn center_x(&self) -> f64 {
        self.x + self.width / 2.0
    }

    pub fn center_y(&self) -> f64 {
        self.y + self.height / 2.0
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct LayoutEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub relation: String,
    pub label: String,
    pub strength: String,
    pub source_refs: Vec<String>,
    pub metadata: BTreeMap<String, Value>,
    pub path: String,
    pub label_x: f64,
    pub label_y: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Layout {
    pub strategy: LayoutStrategy,
    pub width: f64,
    pub height: f64,
    pub nodes: Vec<LayoutNode>,
    pub edges: Vec<LayoutEdge>,
}

/// Compute deterministic geometry for one of the seven frozen templates.
pub fn layout(spec: &DiagramSpec) -> Layout {
    let value = serde_json::to_value(spec).unwrap_or(Value::Null);
    let diagram_type = value
        .get("diagram_type")
        .and_then(Value::as_str)
        .unwrap_or("case_issue_evidence_law");
    let strategy = strategy_for(diagram_type);
    let mut nodes = parse_nodes(&value);
    let raw_edges = parse_edges(&value);
    let preferred_roots = string_array(value.pointer("/layout_hints/preferred_root_ids"));
    let timeline_lane = value
        .pointer("/layout_hints/timeline_lane")
        .and_then(Value::as_str)
        .unwrap_or("single");

    match strategy {
        LayoutStrategy::LegalHierarchy => place_legal_hierarchy(&mut nodes),
        LayoutStrategy::LegalApplicationChain => place_application_chain(&mut nodes),
        LayoutStrategy::LegalConflictPriority => place_conflict_priority(&mut nodes, &raw_edges),
        LayoutStrategy::CasePartyRelationship => {
            place_party_relationship(&mut nodes, &raw_edges, &preferred_roots)
        }
        LayoutStrategy::CaseIssueEvidenceLaw => place_issue_evidence_law(&mut nodes),
        LayoutStrategy::CaseMoneyFlow => place_money_flow(&mut nodes, &raw_edges, &preferred_roots),
        LayoutStrategy::CaseTimeline => place_timeline(&mut nodes, timeline_lane),
    }

    normalize_geometry(&mut nodes);
    let (width, height) = canvas_size(&nodes);
    let positions: BTreeMap<&str, &LayoutNode> =
        nodes.iter().map(|node| (node.id.as_str(), node)).collect();
    let mut parallel_counts = BTreeMap::new();
    for edge in &raw_edges {
        *parallel_counts
            .entry((edge.source.clone(), edge.target.clone()))
            .or_insert(0usize) += 1;
    }
    let mut parallel_seen = BTreeMap::new();
    let edges = raw_edges
        .into_iter()
        .filter_map(|edge| {
            let key = (edge.source.clone(), edge.target.clone());
            let parallel_count = parallel_counts.get(&key).copied().unwrap_or(1);
            let parallel_index = parallel_seen.entry(key).or_insert(0usize);
            let routed = route_edge(edge, &positions, strategy, *parallel_index, parallel_count);
            *parallel_index += 1;
            routed
        })
        .collect();

    Layout {
        strategy,
        width,
        height,
        nodes,
        edges,
    }
}

fn strategy_for(diagram_type: &str) -> LayoutStrategy {
    match diagram_type {
        "legal_hierarchy" => LayoutStrategy::LegalHierarchy,
        "legal_application_chain" => LayoutStrategy::LegalApplicationChain,
        "legal_conflict_priority" => LayoutStrategy::LegalConflictPriority,
        "case_party_relationship" => LayoutStrategy::CasePartyRelationship,
        "case_money_flow" => LayoutStrategy::CaseMoneyFlow,
        "case_timeline" => LayoutStrategy::CaseTimeline,
        _ => LayoutStrategy::CaseIssueEvidenceLaw,
    }
}

fn parse_nodes(value: &Value) -> Vec<LayoutNode> {
    let mut nodes: Vec<_> = value
        .get("nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|node| {
            let id = text(node.get("id"))?;
            let label = text(node.get("label")).unwrap_or_else(|| id.clone());
            let short_label = text(node.get("short_label"));
            let shown = short_label.as_deref().unwrap_or(&label);
            let width = node_width(shown);
            let height = node_height(shown, width);
            Some(LayoutNode {
                id,
                node_type: text(node.get("type")).unwrap_or_else(|| "missing_information".into()),
                status: text(node.get("status")).unwrap_or_else(|| "unknown".into()),
                importance: text(node.get("importance")).unwrap_or_else(|| "normal".into()),
                label,
                short_label,
                details: text(node.get("details")).unwrap_or_default(),
                source_refs: string_array(node.get("source_refs")),
                tags: string_array(node.get("tags")),
                metadata: object_map(node.get("metadata")),
                x: 0.0,
                y: 0.0,
                width,
                height,
                lane: 0,
            })
        })
        .collect();
    nodes.sort_by(|a, b| a.id.cmp(&b.id));
    nodes
}

#[derive(Clone, Debug)]
struct RawEdge {
    id: String,
    source: String,
    target: String,
    relation: String,
    label: String,
    strength: String,
    source_refs: Vec<String>,
    metadata: BTreeMap<String, Value>,
}

fn parse_edges(value: &Value) -> Vec<RawEdge> {
    let mut edges: Vec<_> = value
        .get("edges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|edge| {
            Some(RawEdge {
                id: text(edge.get("id"))?,
                source: text(edge.get("source"))?,
                target: text(edge.get("target"))?,
                relation: text(edge.get("relation")).unwrap_or_else(|| "related_to".into()),
                label: text(edge.get("label")).unwrap_or_default(),
                strength: text(edge.get("strength")).unwrap_or_else(|| "unknown".into()),
                source_refs: string_array(edge.get("source_refs")),
                metadata: object_map(edge.get("metadata")),
            })
        })
        .collect();
    edges.sort_by(|a, b| a.id.cmp(&b.id));
    edges
}

fn place_legal_hierarchy(nodes: &mut [LayoutNode]) {
    place_by_columns(
        nodes,
        |node| match node.node_type.as_str() {
            "law" => 0,
            "regulation" | "judicial_interpretation" => 1,
            "supervisory_regulation" | "department_rule" => 2,
            "local_regulation" | "local_government_rule" => 3,
            "normative_document" | "guiding_case" => 4,
            "legal_principle" | "rule" | "exception_rule" => 5,
            _ => 6,
        },
        true,
    );
}

fn place_application_chain(nodes: &mut [LayoutNode]) {
    place_by_columns(
        nodes,
        |node| match node.node_type.as_str() {
            "issue" | "claim" | "defense" => 0,
            "fact" | "event" | "evidence" | "missing_information" => 1,
            "element" => 2,
            "rule" | "law" | "regulation" | "legal_principle" | "exception_rule" => 3,
            "legal_consequence" | "application_conclusion" => 4,
            _ => 2,
        },
        false,
    );
}

fn place_issue_evidence_law(nodes: &mut [LayoutNode]) {
    place_by_columns(
        nodes,
        |node| match node.node_type.as_str() {
            "evidence" | "missing_information" => 0,
            "fact" | "event" | "party" | "claim" | "defense" => 1,
            "issue" => 2,
            "rule" | "law" | "regulation" | "judicial_interpretation" | "legal_principle" => 3,
            "element" | "legal_consequence" | "application_conclusion" => 4,
            _ => 2,
        },
        false,
    );
}

fn place_by_columns<F>(nodes: &mut [LayoutNode], column: F, vertical: bool)
where
    F: Fn(&LayoutNode) -> usize,
{
    let mut buckets: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, node) in nodes.iter().enumerate() {
        buckets.entry(column(node)).or_default().push(index);
    }
    let max_width = nodes
        .iter()
        .map(|node| node.width)
        .fold(NODE_MIN_WIDTH, f64::max);
    for (bucket_index, indices) in buckets.values().enumerate() {
        for (row, index) in indices.iter().enumerate() {
            let node = &mut nodes[*index];
            if vertical {
                node.x = row as f64 * (max_width + COLUMN_GAP);
                node.y = bucket_index as f64 * (NODE_BASE_HEIGHT + ROW_GAP + 34.0);
            } else {
                node.x = bucket_index as f64 * (max_width + COLUMN_GAP);
                node.y = row as f64 * (NODE_BASE_HEIGHT + ROW_GAP);
            }
            node.lane = bucket_index;
        }
    }
}

fn place_conflict_priority(nodes: &mut [LayoutNode], edges: &[RawEdge]) {
    let mut sides: BTreeMap<String, usize> = BTreeMap::new();
    for edge in edges
        .iter()
        .filter(|edge| edge.relation == "conflicts_with")
    {
        sides.entry(edge.source.clone()).or_insert(0);
        sides.entry(edge.target.clone()).or_insert(2);
    }
    for edge in edges
        .iter()
        .filter(|edge| edge.relation == "applies_before")
    {
        sides.insert(edge.source.clone(), 1);
        sides.entry(edge.target.clone()).or_insert(2);
    }
    let max_width = nodes
        .iter()
        .map(|node| node.width)
        .fold(NODE_MIN_WIDTH, f64::max);
    let mut rows = [0usize; 3];
    for node in nodes {
        let column = sides.get(&node.id).copied().unwrap_or_else(|| {
            if matches!(
                node.node_type.as_str(),
                "application_conclusion" | "legal_consequence"
            ) {
                1
            } else {
                stable_bucket(&node.id, 2) * 2
            }
        });
        node.x = column as f64 * (max_width + COLUMN_GAP + 36.0);
        node.y = rows[column] as f64 * (NODE_BASE_HEIGHT + ROW_GAP);
        node.lane = column;
        rows[column] += 1;
    }
}

fn place_party_relationship(
    nodes: &mut [LayoutNode],
    edges: &[RawEdge],
    preferred_roots: &[String],
) {
    if nodes.is_empty() {
        return;
    }
    let mut degree: BTreeMap<&str, usize> =
        nodes.iter().map(|node| (node.id.as_str(), 0)).collect();
    for edge in edges {
        *degree.entry(edge.source.as_str()).or_default() += 1;
        *degree.entry(edge.target.as_str()).or_default() += 1;
    }
    let center_id = preferred_roots
        .iter()
        .find(|id| degree.contains_key(id.as_str()))
        .map(String::as_str)
        .or_else(|| {
            degree
                .iter()
                .max_by(|(id_a, degree_a), (id_b, degree_b)| {
                    degree_a.cmp(degree_b).then_with(|| id_b.cmp(id_a))
                })
                .map(|(id, _)| *id)
        })
        .unwrap_or(nodes[0].id.as_str())
        .to_owned();

    let max_width = nodes
        .iter()
        .map(|node| node.width)
        .fold(NODE_MIN_WIDTH, f64::max);
    let count = nodes.len().saturating_sub(1).max(1);
    let radius = (count as f64 * 46.0).max(260.0);
    let center_x = radius + max_width + PAGE_MARGIN;
    let center_y = radius + NODE_BASE_HEIGHT + PAGE_MARGIN;
    let mut ring_index = 0usize;
    for node in nodes {
        if node.id == center_id {
            node.x = center_x - node.width / 2.0;
            node.y = center_y - node.height / 2.0;
            node.lane = 0;
        } else {
            let angle = -std::f64::consts::FRAC_PI_2
                + std::f64::consts::TAU * ring_index as f64 / count as f64;
            node.x = center_x + radius * angle.cos() - node.width / 2.0;
            node.y = center_y + radius * angle.sin() - node.height / 2.0;
            node.lane = 1;
            ring_index += 1;
        }
    }
}

fn place_money_flow(nodes: &mut [LayoutNode], edges: &[RawEdge], preferred_roots: &[String]) {
    let flow_relations = ["paid_to", "transferred_to", "owes", "guarantees"];
    let ranks = topology_ranks(nodes, edges, preferred_roots, &flow_relations);
    let max_width = nodes
        .iter()
        .map(|node| node.width)
        .fold(NODE_MIN_WIDTH, f64::max);
    let mut rows: BTreeMap<usize, usize> = BTreeMap::new();
    for node in nodes {
        let rank = ranks.get(&node.id).copied().unwrap_or(0);
        let row = rows.entry(rank).or_default();
        node.x = rank as f64 * (max_width + COLUMN_GAP + 34.0);
        node.y = *row as f64 * (NODE_BASE_HEIGHT + ROW_GAP + 16.0);
        node.lane = rank;
        *row += 1;
    }
}

fn topology_ranks(
    nodes: &[LayoutNode],
    edges: &[RawEdge],
    preferred_roots: &[String],
    allowed_relations: &[&str],
) -> BTreeMap<String, usize> {
    let ids: BTreeSet<_> = nodes.iter().map(|node| node.id.clone()).collect();
    let mut incoming: BTreeMap<String, usize> = ids.iter().map(|id| (id.clone(), 0)).collect();
    let mut outgoing: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for edge in edges
        .iter()
        .filter(|edge| allowed_relations.contains(&edge.relation.as_str()))
    {
        if ids.contains(&edge.source) && ids.contains(&edge.target) && edge.source != edge.target {
            outgoing
                .entry(edge.source.clone())
                .or_default()
                .push(edge.target.clone());
            *incoming.entry(edge.target.clone()).or_default() += 1;
        }
    }
    for targets in outgoing.values_mut() {
        targets.sort();
        targets.dedup();
    }
    let mut queue = VecDeque::new();
    for root in preferred_roots {
        if ids.contains(root) {
            queue.push_back(root.clone());
        }
    }
    for (id, count) in &incoming {
        if *count == 0 && !queue.contains(id) {
            queue.push_back(id.clone());
        }
    }
    let mut rank: BTreeMap<String, usize> = ids.iter().map(|id| (id.clone(), 0)).collect();
    let mut visited = BTreeSet::new();
    while let Some(source) = queue.pop_front() {
        if !visited.insert(source.clone()) {
            continue;
        }
        let source_rank = rank.get(&source).copied().unwrap_or(0);
        if let Some(targets) = outgoing.get(&source) {
            for target in targets {
                let target_rank = rank.entry(target.clone()).or_default();
                *target_rank = (*target_rank).max(source_rank + 1);
                let count = incoming.entry(target.clone()).or_default();
                *count = count.saturating_sub(1);
                if *count == 0 {
                    queue.push_back(target.clone());
                }
            }
        }
    }
    // Cyclic leftovers retain their last deterministic rank and are offset from
    // pure roots so they remain visually distinguishable.
    for id in ids.iter().filter(|id| !visited.contains(*id)) {
        rank.insert(id.clone(), 1);
    }
    rank
}

fn place_timeline(nodes: &mut [LayoutNode], timeline_lane: &str) {
    nodes.sort_by(|a, b| {
        timeline_key(a)
            .cmp(&timeline_key(b))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut lane_names = BTreeSet::new();
    for node in nodes.iter() {
        lane_names.insert(lane_key(node, timeline_lane));
    }
    let lane_indexes: BTreeMap<_, _> = lane_names
        .into_iter()
        .enumerate()
        .map(|(index, name)| (name, index))
        .collect();
    let max_width = nodes
        .iter()
        .map(|node| node.width)
        .fold(NODE_MIN_WIDTH, f64::max);
    for (index, node) in nodes.iter_mut().enumerate() {
        let lane = lane_indexes
            .get(&lane_key(node, timeline_lane))
            .copied()
            .unwrap_or(0);
        node.x = index as f64 * (max_width + 74.0);
        node.y = lane as f64 * (NODE_BASE_HEIGHT + ROW_GAP + 72.0);
        node.lane = lane;
    }
}

fn timeline_key(node: &LayoutNode) -> String {
    for key in ["date", "date_start", "formed_on", "effective_from"] {
        if let Some(value) = node.metadata.get(key).and_then(Value::as_str) {
            return format!("0:{value}");
        }
    }
    if let Some(sequence) = node.metadata.get("sequence").and_then(Value::as_i64) {
        return format!("1:{sequence:020}");
    }
    format!("2:{}", node.id)
}

fn lane_key(node: &LayoutNode, timeline_lane: &str) -> String {
    let candidates: &[&str] = match timeline_lane {
        "by_party" => &["party", "submitted_by", "role"],
        "by_procedure" => &["procedure", "stage", "role"],
        "by_statement" => &["statement_variant", "submitted_by"],
        _ => return "single".into(),
    };
    candidates
        .iter()
        .find_map(|key| node.metadata.get(*key).and_then(Value::as_str))
        .unwrap_or("其他")
        .to_owned()
}

fn normalize_geometry(nodes: &mut [LayoutNode]) {
    if nodes.is_empty() {
        return;
    }
    let min_x = nodes
        .iter()
        .map(|node| node.x)
        .fold(f64::INFINITY, f64::min);
    let min_y = nodes
        .iter()
        .map(|node| node.y)
        .fold(f64::INFINITY, f64::min);
    for node in nodes {
        node.x = node.x - min_x + PAGE_MARGIN;
        node.y = node.y - min_y + PAGE_MARGIN;
    }
}

fn canvas_size(nodes: &[LayoutNode]) -> (f64, f64) {
    let width = nodes
        .iter()
        .map(|node| node.x + node.width)
        .fold(0.0, f64::max)
        + PAGE_MARGIN;
    let height = nodes
        .iter()
        .map(|node| node.y + node.height)
        .fold(0.0, f64::max)
        + PAGE_MARGIN;
    (width.max(720.0), height.max(460.0))
}

fn route_edge(
    edge: RawEdge,
    positions: &BTreeMap<&str, &LayoutNode>,
    strategy: LayoutStrategy,
    parallel_index: usize,
    parallel_count: usize,
) -> Option<LayoutEdge> {
    let source = positions.get(edge.source.as_str())?;
    let target = positions.get(edge.target.as_str())?;
    let (path, label_x, label_y) = if source.id == target.id {
        route_self_loop(source, parallel_index, parallel_count)
    } else if parallel_count > 1 {
        route_parallel_edge(source, target, parallel_index, parallel_count)
    } else {
        let sx = source.center_x();
        let sy = source.center_y();
        let tx = target.center_x();
        let ty = target.center_y();
        match strategy {
            LayoutStrategy::LegalHierarchy => {
                let mid_y = (sy + ty) / 2.0;
                let points = clip_orthogonal_route(
                    source,
                    target,
                    vec![(sx, sy), (sx, mid_y), (tx, mid_y), (tx, ty)],
                );
                (line_path(&points), (sx + tx) / 2.0, mid_y - 7.0)
            }
            LayoutStrategy::CasePartyRelationship => {
                let bend_x = (sx + tx) / 2.0 + (ty - sy) * 0.08;
                let bend_y = (sy + ty) / 2.0 - (tx - sx) * 0.08;
                let (start_x, start_y) = boundary_point(source, bend_x, bend_y);
                let (end_x, end_y) = boundary_point(target, bend_x, bend_y);
                (
                    format!(
                        "M {start_x:.1} {start_y:.1} Q {bend_x:.1} {bend_y:.1} {end_x:.1} {end_y:.1}"
                    ),
                    bend_x,
                    bend_y - 8.0,
                )
            }
            _ => {
                let mid_x = (sx + tx) / 2.0;
                let points = clip_orthogonal_route(
                    source,
                    target,
                    vec![(sx, sy), (mid_x, sy), (mid_x, ty), (tx, ty)],
                );
                (line_path(&points), mid_x, (sy + ty) / 2.0 - 7.0)
            }
        }
    };
    Some(LayoutEdge {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        relation: edge.relation,
        label: edge.label,
        strength: edge.strength,
        source_refs: edge.source_refs,
        metadata: edge.metadata,
        path,
        label_x,
        label_y,
    })
}

fn route_self_loop(
    node: &LayoutNode,
    parallel_index: usize,
    parallel_count: usize,
) -> (String, f64, f64) {
    let right = node.x + node.width;
    let centered_index = parallel_index as f64 - parallel_count.saturating_sub(1) as f64 / 2.0;
    let vertical_shift = centered_index * 6.0;
    let start_y =
        (node.center_y() - 16.0 + vertical_shift).clamp(node.y + 10.0, node.y + node.height - 24.0);
    let end_y =
        (node.center_y() + 16.0 + vertical_shift).clamp(node.y + 24.0, node.y + node.height - 10.0);
    let extent = 56.0 + (parallel_index % 4) as f64 * 6.0;
    let upper_y = node.y - 34.0 - parallel_index as f64 * 2.0;
    let lower_y = node.y + node.height + 34.0 + parallel_index as f64 * 2.0;
    (
        format!(
            "M {right:.1} {start_y:.1} C {:.1} {upper_y:.1}, {:.1} {lower_y:.1}, {right:.1} {end_y:.1}",
            right + extent,
            right + extent,
        ),
        right + extent,
        upper_y - 6.0,
    )
}

fn route_parallel_edge(
    source: &LayoutNode,
    target: &LayoutNode,
    parallel_index: usize,
    parallel_count: usize,
) -> (String, f64, f64) {
    let sx = source.center_x();
    let sy = source.center_y();
    let tx = target.center_x();
    let ty = target.center_y();
    let dx = tx - sx;
    let dy = ty - sy;
    let length = dx.hypot(dy).max(1.0);
    let offset =
        (parallel_index as f64 - parallel_count.saturating_sub(1) as f64 / 2.0) * PARALLEL_EDGE_GAP;
    let bend_x = (sx + tx) / 2.0 - dy / length * offset;
    let bend_y = (sy + ty) / 2.0 + dx / length * offset;
    let (start_x, start_y) = boundary_point(source, bend_x, bend_y);
    let (end_x, end_y) = boundary_point(target, bend_x, bend_y);
    (
        format!("M {start_x:.1} {start_y:.1} Q {bend_x:.1} {bend_y:.1} {end_x:.1} {end_y:.1}"),
        bend_x,
        bend_y - 8.0,
    )
}

fn clip_orthogonal_route(
    source: &LayoutNode,
    target: &LayoutNode,
    points: Vec<(f64, f64)>,
) -> Vec<(f64, f64)> {
    let mut deduplicated = Vec::with_capacity(points.len());
    for point in points {
        let is_distinct = match deduplicated.last() {
            Some(previous) => {
                let previous: &(f64, f64) = previous;
                (previous.0 - point.0).abs() > f64::EPSILON
                    || (previous.1 - point.1).abs() > f64::EPSILON
            }
            None => true,
        };
        if is_distinct {
            deduplicated.push(point);
        }
    }
    if deduplicated.len() < 2 {
        return deduplicated;
    }
    let start_toward = deduplicated[1];
    let end_toward = deduplicated[deduplicated.len() - 2];
    deduplicated[0] = boundary_point(source, start_toward.0, start_toward.1);
    let end_index = deduplicated.len() - 1;
    deduplicated[end_index] = boundary_point(target, end_toward.0, end_toward.1);
    deduplicated
}

fn boundary_point(node: &LayoutNode, toward_x: f64, toward_y: f64) -> (f64, f64) {
    let center_x = node.center_x();
    let center_y = node.center_y();
    let dx = toward_x - center_x;
    let dy = toward_y - center_y;
    if dx.abs() <= f64::EPSILON && dy.abs() <= f64::EPSILON {
        return (node.x + node.width, center_y);
    }
    let horizontal_scale = if dx.abs() <= f64::EPSILON {
        f64::INFINITY
    } else {
        node.width / 2.0 / dx.abs()
    };
    let vertical_scale = if dy.abs() <= f64::EPSILON {
        f64::INFINITY
    } else {
        node.height / 2.0 / dy.abs()
    };
    let scale = horizontal_scale.min(vertical_scale);
    (center_x + dx * scale, center_y + dy * scale)
}

fn line_path(points: &[(f64, f64)]) -> String {
    let Some((first, rest)) = points.split_first() else {
        return String::new();
    };
    let mut path = format!("M {:.1} {:.1}", first.0, first.1);
    for (x, y) in rest {
        path.push_str(&format!(" L {x:.1} {y:.1}"));
    }
    path
}

fn node_width(label: &str) -> f64 {
    let units: f64 = label
        .chars()
        .map(|ch| if ch.is_ascii() { 0.62 } else { 1.0 })
        .sum();
    (units * 13.0 + 76.0).clamp(NODE_MIN_WIDTH, NODE_MAX_WIDTH)
}

fn node_height(label: &str, width: f64) -> f64 {
    let units: f64 = label
        .chars()
        .map(|ch| if ch.is_ascii() { 0.62 } else { 1.0 })
        .sum();
    let line_units = ((width - 58.0) / 14.0).max(8.0);
    let lines = (units / line_units).ceil().clamp(1.0, 3.0);
    NODE_BASE_HEIGHT + (lines - 1.0) * 18.0
}

fn stable_bucket(value: &str, buckets: usize) -> usize {
    value.bytes().fold(0usize, |hash, byte| {
        hash.wrapping_mul(131).wrapping_add(byte as usize)
    }) % buckets.max(1)
}

fn text(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn object_map(value: Option<&Value>) -> BTreeMap<String, Value> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default()
}
