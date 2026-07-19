use crate::mcp_manager::{
    McpConfigurationSnapshot, McpManager, McpManagerError, McpServerConfig, McpServerStatus,
};
use providers::ApiSecret;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl From<McpManagerError> for IpcError {
    fn from(error: McpManagerError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerConfigResponse {
    pub config: McpServerConfig,
    pub legal_database_path: String,
    pub user_database_path: String,
    pub bearer_token_configured: bool,
    pub bearer_token_masked: Option<String>,
}

impl From<McpConfigurationSnapshot> for McpServerConfigResponse {
    fn from(snapshot: McpConfigurationSnapshot) -> Self {
        Self {
            config: snapshot.config,
            legal_database_path: snapshot.legal_database_path,
            user_database_path: snapshot.user_database_path,
            bearer_token_configured: snapshot.bearer_token_configured,
            bearer_token_masked: snapshot.bearer_token_masked,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SaveMcpServerConfigRequest {
    pub config: McpServerConfig,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WriteMcpBearerTokenRequest {
    pub token: ApiSecret,
}

impl std::fmt::Debug for WriteMcpBearerTokenRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WriteMcpBearerTokenRequest")
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteMcpBearerTokenRequest {
    pub user_confirmed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerStatusResponse {
    pub phase: String,
    pub endpoint: Option<String>,
    pub started_at: Option<String>,
    pub last_error: Option<String>,
}

impl From<McpServerStatus> for McpServerStatusResponse {
    fn from(status: McpServerStatus) -> Self {
        Self {
            phase: status.phase.to_owned(),
            endpoint: status.endpoint,
            started_at: status.started_at,
            last_error: status.last_error,
        }
    }
}

async fn configuration_response(manager: &McpManager) -> Result<McpServerConfigResponse, IpcError> {
    manager
        .configuration_snapshot()
        .await
        .map(Into::into)
        .map_err(Into::into)
}

#[tauri::command]
pub async fn get_mcp_server_config(
    manager: State<'_, McpManager>,
) -> Result<McpServerConfigResponse, IpcError> {
    configuration_response(&manager).await
}

#[tauri::command]
pub async fn save_mcp_server_config(
    manager: State<'_, McpManager>,
    request: SaveMcpServerConfigRequest,
) -> Result<McpServerConfigResponse, IpcError> {
    manager.save_config(request.config).await?;
    configuration_response(&manager).await
}

#[tauri::command]
pub fn get_mcp_server_status(
    manager: State<'_, McpManager>,
) -> Result<McpServerStatusResponse, IpcError> {
    Ok(manager.status().into())
}

#[tauri::command]
pub async fn start_mcp_server(
    manager: State<'_, McpManager>,
) -> Result<McpServerStatusResponse, IpcError> {
    manager.start().await.map(Into::into).map_err(Into::into)
}

#[tauri::command]
pub async fn stop_mcp_server(
    manager: State<'_, McpManager>,
) -> Result<McpServerStatusResponse, IpcError> {
    manager.stop().await.map(Into::into).map_err(Into::into)
}

#[tauri::command]
pub async fn write_mcp_bearer_token(
    manager: State<'_, McpManager>,
    request: WriteMcpBearerTokenRequest,
) -> Result<McpServerConfigResponse, IpcError> {
    manager.write_bearer_token(request.token).await?;
    configuration_response(&manager).await
}

#[tauri::command]
pub async fn delete_mcp_bearer_token(
    manager: State<'_, McpManager>,
    request: DeleteMcpBearerTokenRequest,
) -> Result<McpServerConfigResponse, IpcError> {
    if !request.user_confirmed {
        return Err(IpcError {
            error_type: "confirmation_required".to_owned(),
            message: "Deleting the MCP Bearer token requires explicit confirmation".to_owned(),
        });
    }
    manager.delete_bearer_token().await?;
    configuration_response(&manager).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_request_debug_output_is_redacted() {
        let request = WriteMcpBearerTokenRequest {
            token: ApiSecret::new("mcp-super-secret-token-1234567890"),
        };
        let debug = format!("{request:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("1234567890"));
    }

    #[test]
    fn status_response_uses_exact_public_shape() {
        let response = McpServerStatusResponse::from(McpServerStatus {
            phase: "running",
            endpoint: Some("http://127.0.0.1:8787/mcp".to_owned()),
            started_at: Some("2026-07-17T12:00:00Z".to_owned()),
            last_error: None,
        });
        let value = serde_json::to_value(response).expect("status serializes");
        let object = value.as_object().expect("status object");
        assert_eq!(
            object.keys().map(String::as_str).collect::<Vec<_>>(),
            ["endpoint", "lastError", "phase", "startedAt"]
        );
    }
}
