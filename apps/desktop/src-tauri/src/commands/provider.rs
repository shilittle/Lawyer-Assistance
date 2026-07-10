use providers::{
    ApiSecret, ConnectionTest, CredentialStore, OpenAiCompatibleAdapter, ProviderCapabilities,
    ProviderCredentialKey, ProviderError, ProviderErrorKind, ProviderKind, ProviderOptions,
    ProviderProfile, ReqwestTransport,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::State;

use crate::state::AppState;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl IpcError {
    fn new(error_type: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_type: error_type.into(),
            message: providers::redact_sensitive(&message.into()),
        }
    }
}

impl From<database::DatabaseInitError> for IpcError {
    fn from(error: database::DatabaseInitError) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<rusqlite::Error> for IpcError {
    fn from(error: rusqlite::Error) -> Self {
        Self::new("database", error.to_string())
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(error: serde_json::Error) -> Self {
        Self::new("serialization", error.to_string())
    }
}

impl From<ProviderError> for IpcError {
    fn from(error: ProviderError) -> Self {
        Self::new(error.kind.as_str(), error.message)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderProfilesResponse {
    pub profiles: Vec<ProviderProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertProviderProfileRequest {
    pub profile: ProviderProfile,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderProfileResponse {
    pub profile: ProviderProfile,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteProviderProfileRequest {
    pub provider_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteProviderProfileResponse {
    pub deleted: bool,
    pub key_deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderApiKeyStatusRequest {
    pub provider_id: String,
    pub account_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderApiKeyStatus {
    pub provider_id: String,
    pub account_id: String,
    pub configured: bool,
    pub masked_key: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderApiKeyStatusResponse {
    pub status: ProviderApiKeyStatus,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteProviderApiKeyRequest {
    pub provider_id: String,
    pub account_id: String,
    pub api_key: ApiSecret,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteProviderApiKeyRequest {
    pub provider_id: String,
    pub account_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestProviderConnectionRequest {
    pub provider_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestProviderConnectionResponse {
    pub result: ConnectionTest,
}

#[tauri::command]
pub fn list_provider_profiles(
    state: State<'_, AppState>,
) -> Result<ProviderProfilesResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let profiles = database::list_provider_profiles(&connection)?
        .into_iter()
        .map(profile_from_row)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ProviderProfilesResponse { profiles })
}

#[tauri::command]
pub fn upsert_provider_profile(
    state: State<'_, AppState>,
    request: UpsertProviderProfileRequest,
) -> Result<ProviderProfileResponse, IpcError> {
    validate_profile(&request.profile)?;
    let connection = database::open_user_database(state.user_database_path())?;
    let row = row_from_profile(&request.profile)?;
    database::upsert_provider_profile(&connection, &row)?;

    Ok(ProviderProfileResponse {
        profile: request.profile,
    })
}

#[tauri::command]
pub fn delete_provider_profile(
    state: State<'_, AppState>,
    request: DeleteProviderProfileRequest,
) -> Result<DeleteProviderProfileResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let existing = database::get_provider_profile(&connection, &request.provider_id)?;
    let key_deleted = if let Some(profile) = existing {
        let key = ProviderCredentialKey::new(profile.id, profile.credential_account_id);
        providers::windows_credentials::WindowsCredentialStore::new().delete_api_key(&key)?;
        true
    } else {
        false
    };
    let deleted = database::delete_provider_profile(&connection, &request.provider_id)?;

    Ok(DeleteProviderProfileResponse {
        deleted,
        key_deleted,
    })
}

#[tauri::command]
pub fn get_provider_api_key_status(
    request: ProviderApiKeyStatusRequest,
) -> Result<ProviderApiKeyStatusResponse, IpcError> {
    let key = ProviderCredentialKey::new(&request.provider_id, &request.account_id);
    let status = key_status(
        &providers::windows_credentials::WindowsCredentialStore::new(),
        &key,
    )?;

    Ok(ProviderApiKeyStatusResponse { status })
}

#[tauri::command]
pub fn write_provider_api_key(
    request: WriteProviderApiKeyRequest,
) -> Result<ProviderApiKeyStatusResponse, IpcError> {
    let key = ProviderCredentialKey::new(&request.provider_id, &request.account_id);
    let store = providers::windows_credentials::WindowsCredentialStore::new();
    store.write_api_key(&key, request.api_key)?;
    let status = key_status(&store, &key)?;

    Ok(ProviderApiKeyStatusResponse { status })
}

#[tauri::command]
pub fn delete_provider_api_key(
    request: DeleteProviderApiKeyRequest,
) -> Result<ProviderApiKeyStatusResponse, IpcError> {
    let key = ProviderCredentialKey::new(&request.provider_id, &request.account_id);
    let store = providers::windows_credentials::WindowsCredentialStore::new();
    store.delete_api_key(&key)?;

    Ok(ProviderApiKeyStatusResponse {
        status: ProviderApiKeyStatus {
            provider_id: request.provider_id,
            account_id: request.account_id,
            configured: false,
            masked_key: None,
        },
    })
}

#[tauri::command]
pub fn test_provider_connection(
    state: State<'_, AppState>,
    request: TestProviderConnectionRequest,
) -> Result<TestProviderConnectionResponse, IpcError> {
    let connection = database::open_user_database(state.user_database_path())?;
    let profile = database::get_provider_profile(&connection, &request.provider_id)?
        .ok_or_else(|| ProviderError::new(ProviderErrorKind::InvalidProfile, "profile not found"))
        .and_then(profile_from_row)?;

    let key = ProviderCredentialKey::new(&profile.id, &profile.credential_account_id);
    let store = providers::windows_credentials::WindowsCredentialStore::new();
    let result = match store.read_api_key(&key)? {
        Some(secret) => {
            let transport = ReqwestTransport::new(Duration::from_secs(30))?;
            OpenAiCompatibleAdapter::new(transport).test_connection(&profile, &secret)
        }
        None => ConnectionTest::failed(
            profile.id.clone(),
            None,
            None,
            0,
            &ProviderError::new(
                ProviderErrorKind::MissingCredential,
                "API key is not configured",
            ),
        ),
    };

    Ok(TestProviderConnectionResponse { result })
}

fn key_status<S>(store: &S, key: &ProviderCredentialKey) -> Result<ProviderApiKeyStatus, IpcError>
where
    S: CredentialStore<Error = ProviderError>,
{
    let secret = store.read_api_key(key)?;

    Ok(ProviderApiKeyStatus {
        provider_id: key.provider_id.clone(),
        account_id: key.account_id.clone(),
        configured: secret.is_some(),
        masked_key: secret.map(|secret| secret.masked_last_four()),
    })
}

fn validate_profile(profile: &ProviderProfile) -> Result<(), ProviderError> {
    if profile.id.trim().is_empty()
        || profile.display_name.trim().is_empty()
        || profile.model_id.trim().is_empty()
        || profile.base_url.trim().is_empty()
        || profile.credential_account_id.trim().is_empty()
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "profile fields cannot be empty",
        ));
    }

    Ok(())
}

fn row_from_profile(
    profile: &ProviderProfile,
) -> Result<database::ProviderProfileRow, serde_json::Error> {
    Ok(database::ProviderProfileRow {
        id: profile.id.clone(),
        kind: kind_to_string(profile.kind)?,
        display_name: profile.display_name.clone(),
        model_id: profile.model_id.clone(),
        base_url: profile.base_url.clone(),
        credential_account_id: profile.credential_account_id.clone(),
        capabilities_json: serde_json::to_string(&profile.capabilities)?,
        options_json: serde_json::to_string(&profile.options)?,
    })
}

pub(crate) fn profile_from_row(
    row: database::ProviderProfileRow,
) -> Result<ProviderProfile, ProviderError> {
    Ok(ProviderProfile {
        id: row.id,
        display_name: row.display_name,
        kind: serde_json::from_value::<ProviderKind>(serde_json::Value::String(row.kind)).map_err(
            |error| ProviderError::new(ProviderErrorKind::InvalidProfile, error.to_string()),
        )?,
        model_id: row.model_id,
        base_url: row.base_url,
        credential_account_id: row.credential_account_id,
        capabilities: serde_json::from_str::<ProviderCapabilities>(&row.capabilities_json)
            .map_err(|error| {
                ProviderError::new(ProviderErrorKind::InvalidProfile, error.to_string())
            })?,
        options: serde_json::from_str::<ProviderOptions>(&row.options_json).map_err(|error| {
            ProviderError::new(ProviderErrorKind::InvalidProfile, error.to_string())
        })?,
    })
}

fn kind_to_string(kind: ProviderKind) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(kind)?;

    Ok(value
        .as_str()
        .expect("provider kind serializes as a string")
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_request_debug_redacts_complete_secret() {
        let request = WriteProviderApiKeyRequest {
            provider_id: "deepseek-main".to_owned(),
            account_id: "default".to_owned(),
            api_key: ApiSecret::new("ipc-secret-4444"),
        };

        assert!(!format!("{request:?}").contains("ipc-secret-4444"));
        assert!(format!("{request:?}").contains("<redacted>"));
    }

    #[test]
    fn api_key_status_response_serializes_only_masked_key() {
        let response = ProviderApiKeyStatusResponse {
            status: ProviderApiKeyStatus {
                provider_id: "deepseek-main".to_owned(),
                account_id: "default".to_owned(),
                configured: true,
                masked_key: Some("****4444".to_owned()),
            },
        };
        let serialized = serde_json::to_string(&response).expect("status serializes");

        assert!(serialized.contains("****4444"));
        assert!(!serialized.contains("ipc-secret-4444"));
    }

    #[test]
    fn profile_roundtrip_preserves_provider_options() {
        let mut profile = ProviderProfile::new_default("qwen-main", ProviderKind::Qwen);
        profile.options.enable_thinking = Some(false);
        profile.options.thinking_budget = Some(512);

        let row = row_from_profile(&profile).expect("profile maps to row");
        let restored = profile_from_row(row).expect("row maps to profile");

        assert_eq!(restored.kind, ProviderKind::Qwen);
        assert_eq!(restored.options.enable_thinking, Some(false));
        assert_eq!(restored.options.thinking_budget, Some(512));
    }
}
