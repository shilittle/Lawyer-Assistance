use crate::validation::{
    add_text_bytes, insert_unique, validate_count, validate_identifier, validate_nonempty_count,
    validate_required_text, validate_schema_version, validate_source_refs, validate_total_text,
};
use crate::{ContractError, ContractErrorType, ValidationContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_MAP_NODES: usize = 200;
pub const MAX_MAP_EDGES: usize = 400;
pub const MAX_MAP_TEXT_BYTES: usize = 1024 * 1024;
pub const MAX_MAP_TITLE_BYTES: usize = 256;
pub const MAX_MAP_NODE_LABEL_BYTES: usize = 256;
pub const MAX_MAP_NODE_SUMMARY_BYTES: usize = 4 * 1024;
pub const MAX_MAP_EDGE_LABEL_BYTES: usize = 256;
pub const MAX_MAP_EDGE_RELATION_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutHint {
    Mindmap,
    Layered,
    Radial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MapNode {
    pub id: String,
    pub label: String,
    pub summary: String,
    pub parent_id: Option<String>,
    pub source_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MapEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub label: String,
    pub relation: String,
    pub source_refs: Vec<String>,
}

/// Pure data for a model-generated Map Artifact. There is intentionally no
/// style, class, script, HTML, CSS, or arbitrary Cytoscape configuration field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MapSpec {
    pub schema_version: u16,
    pub title: String,
    pub layout_hint: LayoutHint,
    pub nodes: Vec<MapNode>,
    pub edges: Vec<MapEdge>,
}

impl MapSpec {
    pub fn validate(&self, context: &ValidationContext) -> Result<(), ContractError> {
        validate_schema_version("map.schemaVersion", self.schema_version)?;
        validate_required_text("map.title", &self.title, MAX_MAP_TITLE_BYTES)?;
        validate_nonempty_count("map.nodes", self.nodes.len(), MAX_MAP_NODES)?;
        validate_count("map.edges", self.edges.len(), MAX_MAP_EDGES)?;

        let mut all_ids = BTreeSet::new();
        let mut node_ids = BTreeSet::new();
        let mut parents = BTreeMap::new();
        let mut total_text = self.title.len();

        for (index, node) in self.nodes.iter().enumerate() {
            let path = format!("map.nodes[{index}]");
            insert_unique(&mut all_ids, &format!("{path}.id"), &node.id)?;
            node_ids.insert(node.id.clone());
            validate_required_text(
                &format!("{path}.label"),
                &node.label,
                MAX_MAP_NODE_LABEL_BYTES,
            )?;
            validate_required_text(
                &format!("{path}.summary"),
                &node.summary,
                MAX_MAP_NODE_SUMMARY_BYTES,
            )?;
            if let Some(parent_id) = &node.parent_id {
                validate_identifier(&format!("{path}.parentId"), parent_id)?;
            }
            validate_source_refs(&format!("{path}.sourceRefs"), &node.source_refs, context)?;
            parents.insert(node.id.clone(), node.parent_id.clone());
            add_text_bytes(&mut total_text, &node.label);
            add_text_bytes(&mut total_text, &node.summary);
        }

        for (index, edge) in self.edges.iter().enumerate() {
            let path = format!("map.edges[{index}]");
            insert_unique(&mut all_ids, &format!("{path}.id"), &edge.id)?;
            validate_identifier(&format!("{path}.source"), &edge.source)?;
            validate_identifier(&format!("{path}.target"), &edge.target)?;
            if !node_ids.contains(&edge.source) {
                return Err(ContractError::new(
                    ContractErrorType::InvalidEndpoint,
                    format!("{path}.source"),
                    "edge source does not reference a map node",
                ));
            }
            if !node_ids.contains(&edge.target) {
                return Err(ContractError::new(
                    ContractErrorType::InvalidEndpoint,
                    format!("{path}.target"),
                    "edge target does not reference a map node",
                ));
            }
            validate_required_text(
                &format!("{path}.label"),
                &edge.label,
                MAX_MAP_EDGE_LABEL_BYTES,
            )?;
            validate_required_text(
                &format!("{path}.relation"),
                &edge.relation,
                MAX_MAP_EDGE_RELATION_BYTES,
            )?;
            validate_source_refs(&format!("{path}.sourceRefs"), &edge.source_refs, context)?;
            add_text_bytes(&mut total_text, &edge.label);
            add_text_bytes(&mut total_text, &edge.relation);
        }

        validate_parent_graph(&parents, &node_ids)?;
        validate_total_text("map", total_text, MAX_MAP_TEXT_BYTES)
    }
}

fn validate_parent_graph(
    parents: &BTreeMap<String, Option<String>>,
    node_ids: &BTreeSet<String>,
) -> Result<(), ContractError> {
    for (node_id, direct_parent) in parents {
        if let Some(parent_id) = direct_parent {
            if !node_ids.contains(parent_id) {
                return Err(ContractError::new(
                    ContractErrorType::InvalidEndpoint,
                    format!("map.nodes[{node_id}].parentId"),
                    "parent does not reference a map node",
                ));
            }
            if parent_id == node_id {
                return Err(ContractError::new(
                    ContractErrorType::ParentCycle,
                    format!("map.nodes[{node_id}].parentId"),
                    "node must not be its own parent",
                ));
            }
        }

        let mut visited = BTreeSet::new();
        let mut current = Some(node_id.as_str());
        while let Some(candidate) = current {
            if !visited.insert(candidate) {
                return Err(ContractError::new(
                    ContractErrorType::ParentCycle,
                    format!("map.nodes[{node_id}].parentId"),
                    "parent relationship contains a cycle",
                ));
            }
            current = parents.get(candidate).and_then(|parent| parent.as_deref());
        }
    }
    Ok(())
}
