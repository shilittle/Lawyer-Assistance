use crate::{
    approved_mcp::{
        ApprovedGenerationHistory, ApprovedMcpError, ApprovedMcpQualificationStatus,
        ApprovedMcpWorkspace, PublishedApprovedGeneration,
    },
    mcp_manager::{McpManager, McpManagerError},
    privacy_workflow::{
        ApproveReviewForApprovedWorkspaceRequest, ApproveReviewForApprovedWorkspaceResponse,
        ApprovedPrivacyReviewSelection, PrivacyWorkflowError, PrivacyWorkflowManager,
    },
};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::Value;
use tauri::State;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl From<ApprovedMcpError> for IpcError {
    fn from(error: ApprovedMcpError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

impl From<McpManagerError> for IpcError {
    fn from(error: McpManagerError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

impl From<PrivacyWorkflowError> for IpcError {
    fn from(error: PrivacyWorkflowError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

fn runtime_error(message: &'static str) -> IpcError {
    IpcError {
        error_type: "runtime_failure".to_owned(),
        message: message.to_owned(),
    }
}

#[tauri::command]
pub async fn list_approved_privacy_review_selections(
    workflow: State<'_, PrivacyWorkflowManager>,
) -> Result<Vec<ApprovedPrivacyReviewSelection>, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || workflow.list_approved_review_selections())
        .await
        .map_err(|_| runtime_error("Approved review selection did not complete."))?
        .map_err(Into::into)
}
#[tauri::command]
pub async fn approve_review_for_approved_workspace(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ApproveReviewForApprovedWorkspaceRequest,
) -> Result<ApproveReviewForApprovedWorkspaceResponse, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workflow
            .approve_review_for_approved_workspace(request)
            .map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Approved MCP publication approval did not complete."))?
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishApprovedGenerationRequest {
    pub redaction_id: String,
    pub case_id: String,
    pub expected_approved_payload_sha256: String,
}

#[tauri::command]
pub async fn publish_approved_generation(
    workflow: State<'_, PrivacyWorkflowManager>,
    workspace: State<'_, ApprovedMcpWorkspace>,
    request: PublishApprovedGenerationRequest,
) -> Result<PublishedApprovedGeneration, IpcError> {
    let workflow = workflow.inner().clone();
    let workspace = workspace.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workflow
            .with_approved_generation_source_publish(
                &request.redaction_id,
                &request.expected_approved_payload_sha256,
                |source| workspace.publish(&request.case_id, source),
            )
            .map_err(IpcError::from)?
            .map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Approved generation publication did not complete."))?
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListApprovedGenerationsRequest {
    pub case_id: Option<String>,
}

#[tauri::command]
pub async fn list_approved_generations(
    workspace: State<'_, ApprovedMcpWorkspace>,
    request: ListApprovedGenerationsRequest,
) -> Result<Vec<ApprovedGenerationHistory>, IpcError> {
    let workspace = workspace.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workspace
            .list(request.case_id.as_deref())
            .map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Approved generation history could not be loaded."))?
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeApprovedGenerationRequest {
    pub case_id: String,
    pub material_id: String,
    pub document_version: u64,
    pub publication_id: String,
}

#[tauri::command]
pub async fn revoke_approved_generation(
    workspace: State<'_, ApprovedMcpWorkspace>,
    mcp: State<'_, McpManager>,
    request: RevokeApprovedGenerationRequest,
) -> Result<(), IpcError> {
    let workspace = workspace.inner().clone();
    let mcp = mcp.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workspace.revoke(
            &request.case_id,
            &request.material_id,
            request.document_version,
            &request.publication_id,
        )?;
        mcp.revoke_active_approved_tickets().map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Approved generation revocation did not complete."))?
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunApprovedMcpQualificationRequest {
    pub ttl_seconds: u64,
}

#[tauri::command]
pub async fn run_approved_mcp_qualification(
    workspace: State<'_, ApprovedMcpWorkspace>,
    request: RunApprovedMcpQualificationRequest,
) -> Result<ApprovedMcpQualificationStatus, IpcError> {
    workspace
        .inner()
        .run_qualification(request.ttl_seconds)
        .await
        .map_err(IpcError::from)
}

#[tauri::command]
pub async fn get_approved_mcp_qualification_status(
    workspace: State<'_, ApprovedMcpWorkspace>,
) -> Result<ApprovedMcpQualificationStatus, IpcError> {
    let workspace = workspace.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workspace.qualification_status().map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Approved MCP qualification status could not be loaded."))?
}

#[tauri::command]
pub async fn revoke_approved_mcp_qualification(
    workspace: State<'_, ApprovedMcpWorkspace>,
    mcp: State<'_, McpManager>,
) -> Result<ApprovedMcpQualificationStatus, IpcError> {
    let workspace = workspace.inner().clone();
    let mcp = mcp.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let status = workspace.revoke_qualification()?;
        mcp.revoke_active_approved_tickets()
            .map_err(IpcError::from)?;
        Ok(status)
    })
    .await
    .map_err(|_| runtime_error("Approved MCP qualification revocation did not complete."))?
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateStandaloneApprovedMcpSessionRequest {
    pub connector_id: String,
    pub transport: privacy::mcp_ticket::McpTransportBindingV1,
    pub grant_groups: Vec<legal_mcp::standalone_approved::ApprovedMcpGrantGroupV1>,
    pub ttl_seconds: u64,
    pub http_port: Option<u16>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[tauri::command]
pub async fn create_standalone_approved_mcp_session(
    mcp: State<'_, McpManager>,
    request: CreateStandaloneApprovedMcpSessionRequest,
) -> Result<legal_mcp::standalone_approved::ProvisionedStandaloneSessionV1, IpcError> {
    let manager = mcp.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager
            .provision_standalone_approved_session(
                request.connector_id,
                request.transport,
                request.grant_groups,
                request.ttl_seconds,
                request.http_port,
                request.allowed_origins,
            )
            .map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Standalone approved MCP session creation did not complete."))?
}

#[tauri::command]
pub async fn list_standalone_approved_mcp_sessions(
    mcp: State<'_, McpManager>,
) -> Result<Vec<legal_mcp::standalone_approved::StandaloneSessionMetadataV1>, IpcError> {
    let manager = mcp.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager
            .list_standalone_approved_sessions()
            .map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Standalone approved MCP sessions could not be loaded."))?
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevokeStandaloneApprovedMcpSessionRequest {
    pub server_instance_id: String,
}

#[tauri::command]
pub async fn revoke_standalone_approved_mcp_session(
    mcp: State<'_, McpManager>,
    request: RevokeStandaloneApprovedMcpSessionRequest,
) -> Result<(), IpcError> {
    let manager = mcp.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager
            .revoke_standalone_approved_session(&request.server_instance_id)
            .map_err(IpcError::from)
    })
    .await
    .map_err(|_| runtime_error("Standalone approved MCP session revocation did not complete."))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approved_workspace_approval_ipc_is_fixed_and_never_returns_authority() {
        let request: ApproveReviewForApprovedWorkspaceRequest =
            serde_json::from_value(serde_json::json!({
                "redactionId": "red_00000000000000000000000000000001",
                "expectedApprovedPayloadSha256": "ab".repeat(32),
                "reviewer": "reviewer-01",
                "ttlSeconds": 3600,
                "confirmed": true
            }))
            .expect("strict dedicated approval request");
        assert!(request.confirmed);
        assert_eq!(request.ttl_seconds, 3600);

        for forbidden in [
            "receiptToken",
            "destination",
            "purpose",
            "pages",
            "content",
            "path",
        ] {
            let mut value = serde_json::json!({
                "redactionId": "red_00000000000000000000000000000001",
                "expectedApprovedPayloadSha256": "ab".repeat(32),
                "reviewer": "reviewer-01",
                "ttlSeconds": 3600,
                "confirmed": true
            });
            value.as_object_mut().expect("request object").insert(
                forbidden.to_owned(),
                Value::String("must-not-cross-ipc".to_owned()),
            );
            assert!(
                serde_json::from_value::<ApproveReviewForApprovedWorkspaceRequest>(value).is_err()
            );
        }

        let response = ApproveReviewForApprovedWorkspaceResponse {
            receipt_id: "receipt_opaque".to_owned(),
            approved_payload_sha256: "ab".repeat(32),
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_003_600,
            destination_identifier: "approved_case_workspace".to_owned(),
            purpose: "mcp.case_read_approved_material.v1".to_owned(),
            mcp_publish_approved: true,
        };
        let wire = serde_json::to_string(&response).expect("serialize safe response");
        for forbidden in ["receiptToken", "redactedText", "content", "path"] {
            assert!(!wire.contains(forbidden));
        }
    }

    #[test]
    fn publish_request_rejects_paths_raw_material_and_unknown_fields() {
        for forbidden in ["path", "rawMaterial", "payload", "content", "sourceBytes"] {
            let value = serde_json::json!({
                "redactionId": "red_00000000000000000000000000000001",
                "caseId": "case_00000000000000000000000000000001",
                "expectedApprovedPayloadSha256": "00".repeat(32),
                forbidden: "must-not-cross-ipc"
            });
            assert!(serde_json::from_value::<PublishApprovedGenerationRequest>(value).is_err());
        }
    }

    #[test]
    fn standalone_session_ipc_is_strict_and_contains_only_opaque_configuration() {
        let request: CreateStandaloneApprovedMcpSessionRequest =
            serde_json::from_value(serde_json::json!({
                "connectorId":"workbuddy",
                "transport":"stdio",
                "grantGroups":["read","write"],
                "ttlSeconds":300,
                "httpPort":null,
                "allowedOrigins":[]
            }))
            .expect("strict standalone request");
        assert_eq!(request.connector_id, "workbuddy");
        for forbidden in ["descriptor", "key", "token", "content", "path"] {
            let mut value = serde_json::json!({
                "connectorId":"workbuddy",
                "transport":"stdio",
                "grantGroups":["read","write"],
                "ttlSeconds":300
            });
            value
                .as_object_mut()
                .unwrap()
                .insert(forbidden.to_owned(), Value::String("forbidden".to_owned()));
            assert!(
                serde_json::from_value::<CreateStandaloneApprovedMcpSessionRequest>(value).is_err()
            );
        }
    }
}
