use crate::{
    privacy_workflow::{
        ApproveApprovedProviderTaskRequest, ApproveApprovedProviderTaskResponse,
        ApprovedProviderOutput, ApprovedProviderOutputSummary, DispatchApprovedProviderRequest,
        DispatchApprovedProviderResponse, ListApprovedProviderOutputsRequest,
        LoadApprovedProviderOutputRequest, PrivacyWorkflowManager, ProviderQualificationRequest,
        ProviderQualificationRunRequest, ProviderQualificationStatus,
        RevokeApprovedProviderOutputRequest,
    },
    state::AppState,
};
use providers::{ApiSecret, ProviderProfile, ReqwestTransport};
use std::time::Duration;
use tauri::State;

use super::privacy_workflow::IpcError;

#[tauri::command]
pub async fn approve_approved_provider_task(
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ApproveApprovedProviderTaskRequest,
) -> Result<ApproveApprovedProviderTaskResponse, IpcError> {
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (profile, _) = provider_snapshot(&state, &request.provider_id, false)?;
        workflow
            .approve_approved_provider_task(&profile, request)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

#[tauri::command]
pub async fn dispatch_approved_provider(
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: DispatchApprovedProviderRequest,
) -> Result<DispatchApprovedProviderResponse, IpcError> {
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (profile, secret) = provider_snapshot(&state, &request.provider_id, true)?;
        let secret = secret.ok_or_else(missing_credential)?;
        let transport =
            ReqwestTransport::new(Duration::from_secs(90)).map_err(provider_ipc_error)?;
        workflow
            .dispatch_approved_provider(transport, profile, secret, request)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

#[tauri::command]
pub async fn get_provider_qualification_status(
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ProviderQualificationRequest,
) -> Result<ProviderQualificationStatus, IpcError> {
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (profile, _) = provider_snapshot(&state, &request.provider_id, false)?;
        workflow
            .provider_qualification_status(&profile)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

#[tauri::command]
pub async fn run_provider_qualification(
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ProviderQualificationRunRequest,
) -> Result<ProviderQualificationStatus, IpcError> {
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (profile, secret) = provider_snapshot(&state, &request.provider_id, true)?;
        let _secret = secret.ok_or_else(missing_credential)?;
        workflow
            .run_provider_qualification(profile, request.ttl_seconds)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

#[tauri::command]
pub async fn revoke_provider_qualification(
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ProviderQualificationRequest,
) -> Result<ProviderQualificationStatus, IpcError> {
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (profile, _) = provider_snapshot(&state, &request.provider_id, false)?;
        workflow
            .revoke_provider_qualification(&profile)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

#[tauri::command]
pub async fn list_approved_provider_outputs(
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    request: ListApprovedProviderOutputsRequest,
) -> Result<Vec<ApprovedProviderOutputSummary>, IpcError> {
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let (profile, _) = provider_snapshot(&state, &request.provider_id, false)?;
        workflow
            .list_approved_provider_outputs(&profile, request)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

#[tauri::command]
pub async fn load_approved_provider_output(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: LoadApprovedProviderOutputRequest,
) -> Result<ApprovedProviderOutput, IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workflow
            .load_approved_provider_output(request)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

#[tauri::command]
pub async fn revoke_approved_provider_output(
    workflow: State<'_, PrivacyWorkflowManager>,
    request: RevokeApprovedProviderOutputRequest,
) -> Result<(), IpcError> {
    let workflow = workflow.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        workflow
            .revoke_approved_provider_output(request)
            .map_err(IpcError::from)
    })
    .await
    .map_err(runtime_failure)?
}

fn provider_snapshot(
    state: &AppState,
    provider_id: &str,
    require_credential: bool,
) -> Result<(ProviderProfile, Option<ApiSecret>), IpcError> {
    let connection =
        database::open_user_database(state.user_database_path()).map_err(|error| IpcError {
            error_type: "database".to_owned(),
            message: providers::redact_sensitive(&error.to_string()),
        })?;
    let credentials = providers::windows_credentials::WindowsCredentialStore::new();
    let snapshot = super::provider::provider_profile_and_credential_snapshot(
        &connection,
        provider_id,
        &credentials,
    )
    .map_err(|error| IpcError {
        error_type: error.error_type,
        message: error.message,
    })?;
    if require_credential && snapshot.1.is_none() {
        return Err(missing_credential());
    }
    Ok(snapshot)
}

fn missing_credential() -> IpcError {
    IpcError {
        error_type: "missing_credential".to_owned(),
        message: "The selected Provider credential is not configured.".to_owned(),
    }
}

fn runtime_failure(_: tauri::Error) -> IpcError {
    IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "The approved Provider worker did not complete.".to_owned(),
    }
}

fn provider_ipc_error(error: providers::ProviderError) -> IpcError {
    IpcError {
        error_type: error.kind.as_str().to_owned(),
        message: providers::redact_sensitive(&error.message),
    }
}
