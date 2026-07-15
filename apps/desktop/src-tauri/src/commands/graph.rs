use crate::{
    commands::case::{workspace_from_rows, IpcError},
    state::AppState,
};
use domain::{
    graph::GraphData,
    law::{GetLawRelationsRequest, RelationDirection},
};
use serde::Deserialize;
use tauri::State;

const MAX_GRAPH_SOURCE_ID_BYTES: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetCaseGraphRequest {
    pub project_id: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GetLawGraphRequest {
    pub document_id: String,
}

#[tauri::command]
pub fn get_case_graph(
    state: State<'_, AppState>,
    request: GetCaseGraphRequest,
) -> Result<GraphData, IpcError> {
    validate_source_id(&request.project_id, "projectId")?;
    let connection = database::open_user_database(state.user_database_path())?;
    let rows = database::get_case_workspace_rows(&connection, &request.project_id)?
        .ok_or_else(|| IpcError::new("not_found", "case project not found"))?;
    Ok(domain::graph::case_graph(&workspace_from_rows(rows)?))
}
#[tauri::command]
pub fn get_law_graph(
    state: State<'_, AppState>,
    request: GetLawGraphRequest,
) -> Result<GraphData, IpcError> {
    validate_source_id(&request.document_id, "documentId")?;
    let connection = database::open_legal_core_read_only(state.legal_core_path())?;
    let relations = retrieval::get_law_relations(
        &connection,
        GetLawRelationsRequest {
            document_id: request.document_id,
            direction: Some(RelationDirection::Both),
        },
    )
    .map_err(|e| IpcError::new("retrieval", e.to_string()))?;
    Ok(domain::graph::law_graph(&relations.relations))
}

fn validate_source_id(value: &str, field: &str) -> Result<(), IpcError> {
    if value.trim().is_empty() || value.len() > MAX_GRAPH_SOURCE_ID_BYTES {
        Err(IpcError::new(
            "validation",
            format!("{field} must contain 1 to {MAX_GRAPH_SOURCE_ID_BYTES} UTF-8 bytes"),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_source_identifiers_are_bounded_before_database_access() {
        assert!(validate_source_id("project-1", "projectId").is_ok());
        assert!(validate_source_id(" ", "projectId").is_err());
        assert!(validate_source_id(&"x".repeat(257), "documentId").is_err());
    }
}
