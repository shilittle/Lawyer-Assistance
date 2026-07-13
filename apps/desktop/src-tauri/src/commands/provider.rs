use providers::{
    ApiSecret, ConnectionTest, CredentialStore, OpenAiCompatibleAdapter, ProviderAdapter,
    ProviderCapabilities, ProviderCredentialKey, ProviderError, ProviderErrorKind, ProviderKind,
    ProviderOptions, ProviderProfile, ProviderStoreLock, ReqwestTransport,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tauri::State;

use crate::state::AppState;

use domain::validation::{self, TextMode};

const MAX_PROVIDER_ID_BYTES: usize = 128;
const MAX_PROVIDER_DISPLAY_NAME_BYTES: usize = 256;
const MAX_PROVIDER_MODEL_ID_BYTES: usize = 512;
const MAX_PROVIDER_BASE_URL_BYTES: usize = 2_048;
const MAX_PROVIDER_OPTION_ID_BYTES: usize = 256;
const MAX_QWEN_THINKING_BUDGET: u32 = 65_536;
const MIN_SILICONFLOW_THINKING_BUDGET: u32 = 128;
const MAX_SILICONFLOW_THINKING_BUDGET: u32 = 32_768;
// CRED_TYPE_GENERIC limits CredentialBlobSize to 5 * 512 bytes.
const WINDOWS_GENERIC_CREDENTIAL_BLOB_MAX_BYTES: usize = 5 * 512;

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
    let _provider_store_lock = ProviderStoreLock::acquire()?;
    let connection = database::open_user_database(state.user_database_path())?;
    let store = providers::windows_credentials::WindowsCredentialStore::new();
    upsert_profile_with_store(&connection, &request.profile, &store)?;

    Ok(ProviderProfileResponse {
        profile: request.profile,
    })
}

#[tauri::command]
pub fn delete_provider_profile(
    state: State<'_, AppState>,
    request: DeleteProviderProfileRequest,
) -> Result<DeleteProviderProfileResponse, IpcError> {
    validate_credential_component("providerId", &request.provider_id)?;
    let _provider_store_lock = ProviderStoreLock::acquire()?;
    let connection = database::open_user_database(state.user_database_path())?;
    let store = providers::windows_credentials::WindowsCredentialStore::new();
    let (deleted, key_deleted) =
        delete_profile_with_store(&connection, &request.provider_id, &store)?;

    Ok(DeleteProviderProfileResponse {
        deleted,
        key_deleted,
    })
}

#[tauri::command]
pub fn get_provider_api_key_status(
    state: State<'_, AppState>,
    request: ProviderApiKeyStatusRequest,
) -> Result<ProviderApiKeyStatusResponse, IpcError> {
    validate_credential_component("providerId", &request.provider_id)?;
    validate_credential_component("accountId", &request.account_id)?;
    let _provider_store_lock = ProviderStoreLock::acquire()?;
    let connection = database::open_user_database(state.user_database_path())?;
    let key =
        credential_key_for_saved_profile(&connection, &request.provider_id, &request.account_id)?;
    let status = key_status(
        &providers::windows_credentials::WindowsCredentialStore::new(),
        &key,
    )?;

    Ok(ProviderApiKeyStatusResponse { status })
}

#[tauri::command]
pub fn write_provider_api_key(
    state: State<'_, AppState>,
    request: WriteProviderApiKeyRequest,
) -> Result<ProviderApiKeyStatusResponse, IpcError> {
    validate_credential_component("providerId", &request.provider_id)?;
    validate_credential_component("accountId", &request.account_id)?;
    validate_api_secret(&request.api_key)?;

    let _provider_store_lock = ProviderStoreLock::acquire()?;
    let connection = database::open_user_database(state.user_database_path())?;
    let key = ProviderCredentialKey::new(&request.provider_id, &request.account_id);
    let store = providers::windows_credentials::WindowsCredentialStore::new();
    write_api_key_for_profile(&connection, &key, request.api_key, &store)?;
    let status = key_status(&store, &key)?;

    Ok(ProviderApiKeyStatusResponse { status })
}

#[tauri::command]
pub fn delete_provider_api_key(
    state: State<'_, AppState>,
    request: DeleteProviderApiKeyRequest,
) -> Result<ProviderApiKeyStatusResponse, IpcError> {
    validate_credential_component("providerId", &request.provider_id)?;
    validate_credential_component("accountId", &request.account_id)?;
    let _provider_store_lock = ProviderStoreLock::acquire()?;
    let connection = database::open_user_database(state.user_database_path())?;
    let key =
        credential_key_for_saved_profile(&connection, &request.provider_id, &request.account_id)?;
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
pub async fn test_provider_connection(
    state: State<'_, AppState>,
    request: TestProviderConnectionRequest,
) -> Result<TestProviderConnectionResponse, IpcError> {
    validate_credential_component("providerId", &request.provider_id)?;
    let user_database_path = state.user_database_path().to_path_buf();
    tauri::async_runtime::spawn_blocking(move || {
        let connection = database::open_user_database(user_database_path)?;
        let store = providers::windows_credentials::WindowsCredentialStore::new();
        let result = test_provider_connection_with_dependencies(
            &connection,
            &request.provider_id,
            &store,
            || {
                let transport = ReqwestTransport::new(Duration::from_secs(30))?;
                Ok(OpenAiCompatibleAdapter::new(transport))
            },
        )?;

        Ok(TestProviderConnectionResponse { result })
    })
    .await
    .map_err(|error| IpcError::new("runtime", format!("provider worker failed: {error}")))?
}

fn test_provider_connection_with_dependencies<S, A, F>(
    connection: &rusqlite::Connection,
    provider_id: &str,
    store: &S,
    adapter_factory: F,
) -> Result<ConnectionTest, IpcError>
where
    S: CredentialStore<Error = ProviderError>,
    A: ProviderAdapter,
    F: FnOnce() -> Result<A, ProviderError>,
{
    let (profile, secret) =
        provider_profile_and_credential_snapshot(connection, provider_id, store)?;

    Ok(match secret {
        Some(secret) => adapter_factory()?.test_connection(&profile, &secret),
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
    })
}

pub(crate) fn provider_profile_and_credential_snapshot<S>(
    connection: &rusqlite::Connection,
    provider_id: &str,
    store: &S,
) -> Result<(ProviderProfile, Option<ApiSecret>), IpcError>
where
    S: CredentialStore<Error = ProviderError>,
{
    validate_credential_component("providerId", provider_id)?;
    let _provider_store_lock = ProviderStoreLock::acquire()?;
    let profile = database::get_provider_profile(connection, provider_id)?
        .ok_or_else(|| ProviderError::new(ProviderErrorKind::InvalidProfile, "profile not found"))
        .and_then(profile_from_row)?;
    let key = ProviderCredentialKey::new(&profile.id, &profile.credential_account_id);
    let secret = store.read_api_key(&key)?;
    if let Some(secret) = secret.as_ref() {
        validate_api_secret(secret)?;
    }
    Ok((profile, secret))
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

fn upsert_profile_with_store<S>(
    connection: &rusqlite::Connection,
    profile: &ProviderProfile,
    store: &S,
) -> Result<(), IpcError>
where
    S: CredentialStore<Error = ProviderError>,
{
    validate_profile(profile)?;
    if let Some(existing) = database::get_provider_profile(connection, &profile.id)? {
        let existing = profile_from_row(existing)?;
        let old_key = ProviderCredentialKey::new(&existing.id, &existing.credential_account_id);
        if store.read_api_key(&old_key)?.is_some() {
            if existing.credential_account_id != profile.credential_account_id {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidProfile,
                    "delete the configured API key before changing the credential account",
                )
                .into());
            }

            let old_origin = providers::provider_endpoint_origin(&existing)?;
            let new_origin = providers::provider_endpoint_origin(profile)?;
            if existing.kind != profile.kind || old_origin != new_origin {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidProfile,
                    "delete the configured API key before changing the provider kind or endpoint origin",
                )
                .into());
            }
        }
    }

    let row = row_from_profile(profile)?;
    database::upsert_provider_profile(connection, &row)?;
    Ok(())
}

fn delete_profile_with_store<S>(
    connection: &rusqlite::Connection,
    provider_id: &str,
    store: &S,
) -> Result<(bool, bool), IpcError>
where
    S: CredentialStore<Error = ProviderError>,
{
    validate_credential_component("providerId", provider_id)?;
    let Some(profile) = database::get_provider_profile(connection, provider_id)? else {
        return Ok((false, false));
    };

    let key = ProviderCredentialKey::new(&profile.id, &profile.credential_account_id);
    let existing_secret = store.read_api_key(&key)?;
    if existing_secret.is_some() {
        store.delete_api_key(&key)?;
    }

    match database::delete_provider_profile(connection, provider_id) {
        Ok(true) => Ok((true, existing_secret.is_some())),
        Ok(false) => {
            if let Some(secret) = existing_secret {
                store.write_api_key(&key, secret)?;
            }
            Err(ProviderError::new(
                ProviderErrorKind::InvalidProfile,
                "provider profile changed while it was being deleted",
            )
            .into())
        }
        Err(database_error) => {
            if let Some(secret) = existing_secret {
                if let Err(restore_error) = store.write_api_key(&key, secret) {
                    return Err(ProviderError::new(
                        ProviderErrorKind::Credential,
                        format!(
                            "provider profile deletion failed and credential rollback failed: {database_error}; {restore_error}"
                        ),
                    )
                    .into());
                }
            }
            Err(database_error.into())
        }
    }
}

fn write_api_key_for_profile<S>(
    connection: &rusqlite::Connection,
    key: &ProviderCredentialKey,
    secret: ApiSecret,
    store: &S,
) -> Result<(), IpcError>
where
    S: CredentialStore<Error = ProviderError>,
{
    validate_credential_component("providerId", &key.provider_id)?;
    validate_credential_component("accountId", &key.account_id)?;
    validate_api_secret(&secret)?;
    let saved_key =
        credential_key_for_saved_profile(connection, &key.provider_id, &key.account_id)?;
    store.write_api_key(&saved_key, secret)?;
    Ok(())
}

fn credential_key_for_saved_profile(
    connection: &rusqlite::Connection,
    provider_id: &str,
    account_id: &str,
) -> Result<ProviderCredentialKey, IpcError> {
    validate_credential_component("providerId", provider_id)?;
    validate_credential_component("accountId", account_id)?;
    let profile = database::get_provider_profile(connection, provider_id)?.ok_or_else(|| {
        ProviderError::new(ProviderErrorKind::InvalidProfile, "profile not found")
    })?;
    if profile.credential_account_id != account_id {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "credential account does not match the saved profile",
        )
        .into());
    }

    Ok(ProviderCredentialKey::new(provider_id, account_id))
}

fn validate_profile(profile: &ProviderProfile) -> Result<(), ProviderError> {
    validate_credential_component("profile.id", &profile.id)?;
    validate_credential_component(
        "profile.credentialAccountId",
        &profile.credential_account_id,
    )?;
    validation::required_text(
        "profile.displayName",
        &profile.display_name,
        MAX_PROVIDER_DISPLAY_NAME_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_profile)?;
    validation::required_text(
        "profile.modelId",
        &profile.model_id,
        MAX_PROVIDER_MODEL_ID_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_profile)?;
    validation::required_text(
        "profile.baseUrl",
        &profile.base_url,
        MAX_PROVIDER_BASE_URL_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_profile)?;
    validation::optional_text(
        "profile.options.endpointId",
        profile.options.endpoint_id.as_deref(),
        MAX_PROVIDER_OPTION_ID_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_profile)?;
    validation::optional_text(
        "profile.options.workspaceId",
        profile.options.workspace_id.as_deref(),
        MAX_PROVIDER_OPTION_ID_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_profile)?;
    validate_thinking_budget(profile)?;

    providers::provider_endpoint_origin(profile)?;
    Ok(())
}

fn validate_thinking_budget(profile: &ProviderProfile) -> Result<(), ProviderError> {
    let Some(budget) = profile.options.thinking_budget else {
        return Ok(());
    };

    match profile.kind {
        ProviderKind::Qwen => validation::optional_positive_u32(
            "profile.options.thinkingBudget",
            Some(budget),
            MAX_QWEN_THINKING_BUDGET,
        )
        .map_err(invalid_profile),
        ProviderKind::SiliconFlow
            if (MIN_SILICONFLOW_THINKING_BUDGET..=MAX_SILICONFLOW_THINKING_BUDGET)
                .contains(&budget) =>
        {
            Ok(())
        }
        ProviderKind::SiliconFlow => Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            format!(
                "profile.options.thinkingBudget must be between {MIN_SILICONFLOW_THINKING_BUDGET} and {MAX_SILICONFLOW_THINKING_BUDGET} for SiliconFlow"
            ),
        )),
        ProviderKind::DeepSeek | ProviderKind::VolcengineArk | ProviderKind::Custom => {
            Err(ProviderError::new(
                ProviderErrorKind::InvalidProfile,
                "profile.options.thinkingBudget is supported only for Qwen and SiliconFlow profiles",
            ))
        }
    }
}

fn validate_credential_component(field: &str, value: &str) -> Result<(), ProviderError> {
    validation::identifier(field, value, MAX_PROVIDER_ID_BYTES).map_err(invalid_profile)?;
    if !is_safe_credential_component(value) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "provider and credential IDs may contain only letters, numbers, '-', '_' and '.'",
        ));
    }
    Ok(())
}

fn validate_api_secret(secret: &ApiSecret) -> Result<(), ProviderError> {
    let value = secret.expose_secret();
    validation::required_text(
        "API key",
        value,
        WINDOWS_GENERIC_CREDENTIAL_BLOB_MAX_BYTES,
        TextMode::SingleLine,
    )
    .map_err(invalid_profile)?;
    if value.chars().any(char::is_whitespace) {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "API key must not contain whitespace",
        ));
    }
    Ok(())
}

fn invalid_profile(error: validation::InputValidationError) -> ProviderError {
    ProviderError::new(ProviderErrorKind::InvalidProfile, error.to_string())
}

fn is_safe_credential_component(value: &str) -> bool {
    value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
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
    let profile = ProviderProfile {
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
    };
    validate_profile(&profile)?;
    Ok(profile)
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
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
    };

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
    fn short_api_key_status_never_serializes_the_complete_secret() {
        let store = MockCredentialStore::default();
        let key = ProviderCredentialKey::new("deepseek-main", "default");
        store
            .write_api_key(&key, ApiSecret::new("abcd"))
            .expect("short key writes");

        let status = key_status(&store, &key).expect("key status reads");
        let serialized = serde_json::to_string(&ProviderApiKeyStatusResponse { status })
            .expect("status serializes");

        assert!(serialized.contains("\"maskedKey\":\"****\""));
        assert!(!serialized.contains("abcd"));
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

    #[test]
    fn custom_profile_roundtrip_preserves_user_endpoint_and_model() {
        let mut profile = ProviderProfile::new_default("custom-main", ProviderKind::Custom);
        profile.display_name = "Private OpenAI Gateway".to_owned();
        profile.model_id = "private-chat-model".to_owned();
        profile.base_url = "https://models.example.com/openai/v1".to_owned();

        validate_profile(&profile).expect("complete custom profile is valid");
        let row = row_from_profile(&profile).expect("custom profile maps to row");
        let restored = profile_from_row(row).expect("custom row maps to profile");

        assert_eq!(restored.kind, ProviderKind::Custom);
        assert_eq!(restored.display_name, "Private OpenAI Gateway");
        assert_eq!(restored.model_id, "private-chat-model");
        assert_eq!(restored.base_url, "https://models.example.com/openai/v1");
        assert!(!restored.capabilities.reasoning);
        assert_eq!(restored.options, ProviderOptions::default());
    }

    #[test]
    fn incomplete_custom_profile_is_rejected_before_persistence() {
        let profile = ProviderProfile::new_default("custom-main", ProviderKind::Custom);

        let error = validate_profile(&profile).expect_err("blank custom fields are rejected");

        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
        assert!(error.message.contains("modelId"));
    }

    #[test]
    fn unknown_provider_kind_fails_closed_instead_of_becoming_custom() {
        let profile = ProviderProfile::new_default("future-main", ProviderKind::DeepSeek);
        let mut row = row_from_profile(&profile).expect("known profile maps to row");
        row.kind = "future_provider".to_owned();

        let error = profile_from_row(row).expect_err("unknown kind must remain invalid");

        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
    }

    #[test]
    fn existing_provider_profiles_and_custom_reopen_with_stable_credential_snapshots() {
        let (directory, connection) = test_user_database();
        let store = MockCredentialStore::default();

        let mut deep_seek =
            ProviderProfile::new_default("compat-deep-seek", ProviderKind::DeepSeek);
        deep_seek.options.reasoning_effort = Some(providers::ReasoningEffort::Max);
        let mut qwen = ProviderProfile::new_default("compat-qwen", ProviderKind::Qwen);
        qwen.options.thinking_budget = Some(512);
        let mut silicon_flow =
            ProviderProfile::new_default("compat-silicon-flow", ProviderKind::SiliconFlow);
        silicon_flow.options.thinking_budget = Some(MIN_SILICONFLOW_THINKING_BUDGET);
        let mut volcengine =
            ProviderProfile::new_default("compat-volcengine", ProviderKind::VolcengineArk);
        volcengine.options.endpoint_id = Some("compat-endpoint".to_owned());
        let mut custom = ProviderProfile::new_default("compat-custom", ProviderKind::Custom);
        custom.display_name = "Compatible Private Gateway".to_owned();
        custom.model_id = "compatible-chat-model".to_owned();
        custom.base_url = "https://compat-models.example.com/openai/v1".to_owned();

        let profiles = [deep_seek, qwen, silicon_flow, volcengine, custom];
        for (index, profile) in profiles.iter().enumerate() {
            upsert_profile_with_store(&connection, profile, &store)
                .expect("compatible profile inserts");
            write_api_key_for_profile(
                &connection,
                &ProviderCredentialKey::new(&profile.id, &profile.credential_account_id),
                ApiSecret::new(format!("mock-profile-compatibility-{index:04}")),
                &store,
            )
            .expect("compatible profile credential writes");
        }

        let schema_version_before: String = connection
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version reads before reopen");
        drop(connection);

        let reopened = database::open_user_database(database::user_database_path(directory.path()))
            .expect("existing user database reopens without a provider schema migration");
        let schema_version_after: String = reopened
            .query_row(
                "SELECT value FROM user_database_metadata WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("schema version reads after reopen");
        assert_eq!(schema_version_after, schema_version_before);
        assert_eq!(
            schema_version_after,
            database::USER_SCHEMA_VERSION.to_string()
        );

        for (index, expected) in profiles.iter().enumerate() {
            let row = database::get_provider_profile(&reopened, &expected.id)
                .expect("reopened profile row reads")
                .expect("reopened profile still exists");
            assert_eq!(
                row.kind,
                kind_to_string(expected.kind).expect("provider kind has a stable wire value")
            );

            let (profile, secret) =
                provider_profile_and_credential_snapshot(&reopened, &expected.id, &store)
                    .expect("reopened profile and original credential form one snapshot");
            assert_eq!(&profile, expected);
            assert_eq!(
                secret.as_ref().map(ApiSecret::expose_secret),
                Some(format!("mock-profile-compatibility-{index:04}").as_str())
            );
        }
    }

    #[test]
    fn profile_validation_prevents_credential_target_collisions() {
        let mut profile = ProviderProfile::new_default("deepseek/main", ProviderKind::DeepSeek);
        let error = validate_profile(&profile).expect_err("unsafe profile ID is rejected");
        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);

        profile.id = "deepseek-main".to_owned();
        profile.credential_account_id = "account/name".to_owned();
        let error = validate_profile(&profile).expect_err("unsafe account ID is rejected");
        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
    }

    #[test]
    fn profile_validation_bounds_every_user_controlled_text_field_and_accepts_chinese() {
        let mut profile = ProviderProfile::new_default("deepseek-main", ProviderKind::DeepSeek);
        profile.display_name = "中国法律问答服务".to_owned();
        profile.model_id = "法律模型/正式版".to_owned();
        profile.options.endpoint_id = Some("端点一".to_owned());
        profile.options.workspace_id = Some("工作区一".to_owned());
        validate_profile(&profile).expect("bounded Chinese profile fields are accepted");

        let mutators: [fn(&mut ProviderProfile); 5] = [
            |profile: &mut ProviderProfile| profile.display_name = "名".repeat(100),
            |profile: &mut ProviderProfile| profile.model_id = "模".repeat(200),
            |profile: &mut ProviderProfile| profile.base_url = "x".repeat(2_049),
            |profile: &mut ProviderProfile| profile.options.endpoint_id = Some("端".repeat(100)),
            |profile: &mut ProviderProfile| profile.options.workspace_id = Some("区".repeat(100)),
        ];
        for mutate in mutators {
            let mut invalid = profile.clone();
            mutate(&mut invalid);
            let error =
                validate_profile(&invalid).expect_err("oversized profile field is rejected");
            assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
        }
    }

    #[test]
    fn profile_validation_enforces_provider_specific_thinking_budget_contracts() {
        for (kind, budget) in [
            (ProviderKind::Qwen, 1),
            (ProviderKind::Qwen, MAX_QWEN_THINKING_BUDGET),
            (ProviderKind::SiliconFlow, MIN_SILICONFLOW_THINKING_BUDGET),
            (ProviderKind::SiliconFlow, MAX_SILICONFLOW_THINKING_BUDGET),
        ] {
            let mut profile = ProviderProfile::new_default("provider-valid", kind);
            profile.options.thinking_budget = Some(budget);
            validate_profile(&profile).expect("provider-specific boundary is accepted");
        }

        for (kind, budget) in [
            (ProviderKind::Qwen, 0),
            (ProviderKind::Qwen, MAX_QWEN_THINKING_BUDGET + 1),
            (
                ProviderKind::SiliconFlow,
                MIN_SILICONFLOW_THINKING_BUDGET - 1,
            ),
            (
                ProviderKind::SiliconFlow,
                MAX_SILICONFLOW_THINKING_BUDGET + 1,
            ),
            (ProviderKind::DeepSeek, 512),
            (ProviderKind::VolcengineArk, 512),
            (ProviderKind::Custom, 512),
        ] {
            let mut profile = ProviderProfile::new_default("provider-invalid", kind);
            profile.options.thinking_budget = Some(budget);
            let error = validate_profile(&profile)
                .expect_err("unsupported or out-of-range thinking budget is rejected");
            assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
        }
    }

    #[test]
    fn unusable_thinking_budget_is_not_saved_or_allowed_to_reach_an_adapter() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let mut profile =
            ProviderProfile::new_default("silicon-invalid", ProviderKind::SiliconFlow);
        profile.options.thinking_budget = Some(MIN_SILICONFLOW_THINKING_BUDGET - 1);

        let error = upsert_profile_with_store(&connection, &profile, &store)
            .expect_err("invalid profile is rejected before the database write");
        assert_eq!(error.error_type, "invalid_profile");
        assert!(database::get_provider_profile(&connection, &profile.id)
            .expect("profile reads")
            .is_none());

        database::upsert_provider_profile(
            &connection,
            &row_from_profile(&profile).expect("legacy row maps"),
        )
        .expect("test seeds a legacy invalid row directly");
        let adapter_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&adapter_calls);
        let error = test_provider_connection_with_dependencies::<
            MockCredentialStore,
            MockProviderAdapter,
            _,
        >(&connection, &profile.id, &store, move || {
            calls.fetch_add(1, Ordering::SeqCst);
            panic!("invalid stored profile must not reach the adapter factory")
        })
        .expect_err("invalid legacy profile is stopped before adapter construction");

        assert_eq!(error.error_type, "invalid_profile");
        assert_eq!(adapter_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn api_key_validation_matches_the_windows_blob_limit_without_echoing_secrets() {
        validate_api_secret(&ApiSecret::new(
            "k".repeat(WINDOWS_GENERIC_CREDENTIAL_BLOB_MAX_BYTES),
        ))
        .expect("Windows generic credential upper bound is accepted");

        let oversized = format!(
            "sensitive-prefix-{}",
            "x".repeat(WINDOWS_GENERIC_CREDENTIAL_BLOB_MAX_BYTES)
        );
        let error = validate_api_secret(&ApiSecret::new(oversized.clone()))
            .expect_err("oversized credential is rejected before Credential Manager");
        assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
        assert!(!error.message.contains("sensitive-prefix"));
        assert!(!error.message.contains(&oversized));

        for invalid in ["", "   ", "secret\nnext-line", " secret"] {
            let error = validate_api_secret(&ApiSecret::new(invalid))
                .expect_err("blank or whitespace-bearing credential is rejected");
            assert_eq!(error.kind, ProviderErrorKind::InvalidProfile);
            if invalid.contains("secret") {
                assert!(!error.message.contains("secret"));
            }
        }
    }

    #[test]
    fn api_key_helper_rejects_oversized_input_before_store_write() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("deepseek-main", ProviderKind::DeepSeek);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let key = ProviderCredentialKey::new("deepseek-main", "default");

        let error = write_api_key_for_profile(
            &connection,
            &key,
            ApiSecret::new("x".repeat(WINDOWS_GENERIC_CREDENTIAL_BLOB_MAX_BYTES + 1)),
            &store,
        )
        .expect_err("oversized secret never reaches the credential store");

        assert_eq!(error.error_type, "invalid_profile");
        assert!(store.read_api_key(&key).expect("store reads").is_none());
    }

    #[test]
    fn configured_key_blocks_account_change_until_key_is_deleted() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("qwen-main", ProviderKind::Qwen);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let old_key = ProviderCredentialKey::new("qwen-main", "default");
        write_api_key_for_profile(
            &connection,
            &old_key,
            ApiSecret::new("mock-credential-1234"),
            &store,
        )
        .expect("key writes for the saved account");

        let mut changed = profile.clone();
        changed.credential_account_id = "secondary".to_owned();
        let error = upsert_profile_with_store(&connection, &changed, &store)
            .expect_err("configured key prevents orphaning the old credential");

        assert_eq!(error.error_type, "invalid_profile");
        let saved = database::get_provider_profile(&connection, "qwen-main")
            .expect("profile reads")
            .expect("profile exists");
        assert_eq!(saved.credential_account_id, "default");
        assert!(store
            .read_api_key(&old_key)
            .expect("old key reads")
            .is_some());
    }

    #[test]
    fn configured_key_blocks_provider_kind_and_endpoint_origin_changes() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("provider-main", ProviderKind::DeepSeek);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let key = ProviderCredentialKey::new("provider-main", "default");
        store
            .write_api_key(&key, ApiSecret::new("mock-credential-1234"))
            .expect("key writes");

        let mut changed_kind = profile.clone();
        changed_kind.kind = ProviderKind::Qwen;
        let kind_error = upsert_profile_with_store(&connection, &changed_kind, &store)
            .expect_err("configured key cannot move to another provider kind");
        assert_eq!(kind_error.error_type, "invalid_profile");

        let mut changed_origin = profile.clone();
        changed_origin.base_url = "https://credentials.example.invalid/v1".to_owned();
        let origin_error = upsert_profile_with_store(&connection, &changed_origin, &store)
            .expect_err("configured key cannot move to another origin");
        assert_eq!(origin_error.error_type, "invalid_profile");

        let saved = database::get_provider_profile(&connection, "provider-main")
            .expect("profile reads")
            .expect("profile exists");
        assert_eq!(saved.kind, "deep_seek");
        assert_eq!(saved.base_url, profile.base_url);
        assert!(store.read_api_key(&key).expect("key reads").is_some());
    }

    #[test]
    fn configured_key_allows_path_change_within_the_same_https_origin() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let mut profile = ProviderProfile::new_default("deepseek-main", ProviderKind::DeepSeek);
        profile.base_url = "https://api.deepseek.com/v1".to_owned();
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let key = ProviderCredentialKey::new("deepseek-main", "default");
        store
            .write_api_key(&key, ApiSecret::new("mock-credential-1234"))
            .expect("key writes");

        profile.base_url = "https://api.deepseek.com/compatible-mode/v1".to_owned();
        upsert_profile_with_store(&connection, &profile, &store)
            .expect("same-origin path change remains allowed");

        let saved = database::get_provider_profile(&connection, "deepseek-main")
            .expect("profile reads")
            .expect("profile exists");
        assert_eq!(saved.base_url, profile.base_url);
    }

    #[test]
    fn custom_profile_key_cannot_cross_origins_and_can_move_after_key_deletion() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let mut profile = ProviderProfile::new_default("custom-main", ProviderKind::Custom);
        profile.display_name = "Private Gateway".to_owned();
        profile.model_id = "private-chat-model".to_owned();
        profile.base_url = "https://models.example.com:443/openai/v1".to_owned();
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let key = ProviderCredentialKey::new("custom-main", "default");
        write_api_key_for_profile(
            &connection,
            &key,
            ApiSecret::new("mock-custom-credential-1234"),
            &store,
        )
        .expect("key writes for custom profile");

        profile.base_url = "https://models.example.com/compatible/v1".to_owned();
        upsert_profile_with_store(&connection, &profile, &store)
            .expect("default port and same-origin path change are allowed");

        for forbidden_origin in [
            "https://other.models.example.com/compatible/v1",
            "https://models.example.com:444/compatible/v1",
        ] {
            let mut changed = profile.clone();
            changed.base_url = forbidden_origin.to_owned();
            let error = upsert_profile_with_store(&connection, &changed, &store)
                .expect_err("configured key cannot cross custom endpoint origins");
            assert_eq!(error.error_type, "invalid_profile");
        }

        let (saved, saved_secret) =
            provider_profile_and_credential_snapshot(&connection, "custom-main", &store)
                .expect("consistent custom snapshot reads");
        assert_eq!(saved.base_url, profile.base_url);
        assert_eq!(
            saved_secret.as_ref().map(ApiSecret::expose_secret),
            Some("mock-custom-credential-1234")
        );

        store.delete_api_key(&key).expect("custom key deletes");
        profile.base_url = "https://new-models.example.com/openai/v1".to_owned();
        upsert_profile_with_store(&connection, &profile, &store)
            .expect("custom origin can change after explicit key deletion");
        let (moved, moved_secret) =
            provider_profile_and_credential_snapshot(&connection, "custom-main", &store)
                .expect("moved custom snapshot reads");
        assert_eq!(moved.base_url, profile.base_url);
        assert!(moved_secret.is_none());
    }

    #[test]
    fn key_write_requires_saved_profile_and_matching_account() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let missing_key = ProviderCredentialKey::new("missing", "default");
        let missing_error = write_api_key_for_profile(
            &connection,
            &missing_key,
            ApiSecret::new("mock-credential-1234"),
            &store,
        )
        .expect_err("orphan credential is rejected");
        assert_eq!(missing_error.error_type, "invalid_profile");

        let profile = ProviderProfile::new_default("deepseek-main", ProviderKind::DeepSeek);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let wrong_account = ProviderCredentialKey::new("deepseek-main", "other");
        let mismatch_error = write_api_key_for_profile(
            &connection,
            &wrong_account,
            ApiSecret::new("mock-credential-5678"),
            &store,
        )
        .expect_err("mismatched account is rejected");

        assert_eq!(mismatch_error.error_type, "invalid_profile");
        assert!(store
            .read_api_key(&wrong_account)
            .expect("wrong account reads")
            .is_none());
    }

    #[test]
    fn credential_status_and_delete_target_require_saved_matching_account() {
        let (_directory, connection) = test_user_database();
        let profile = ProviderProfile::new_default("deepseek-main", ProviderKind::DeepSeek);
        let store = MockCredentialStore::default();
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let saved_key = ProviderCredentialKey::new("deepseek-main", "default");
        store
            .write_api_key(&saved_key, ApiSecret::new("mock-credential-2468"))
            .expect("key writes");

        let missing = credential_key_for_saved_profile(&connection, "missing", "default")
            .expect_err("missing profile cannot address a credential");
        assert_eq!(missing.error_type, "invalid_profile");

        let mismatch = credential_key_for_saved_profile(&connection, "deepseek-main", "other")
            .expect_err("wrong account cannot address a saved profile credential");
        assert_eq!(mismatch.error_type, "invalid_profile");
        assert!(store
            .read_api_key(&saved_key)
            .expect("saved key reads")
            .is_some());
    }

    #[test]
    fn deleting_profile_deletes_matching_credential_first() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("ark-main", ProviderKind::VolcengineArk);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let key = ProviderCredentialKey::new("ark-main", "default");
        write_api_key_for_profile(
            &connection,
            &key,
            ApiSecret::new("mock-credential-9012"),
            &store,
        )
        .expect("key writes");

        let result = delete_profile_with_store(&connection, "ark-main", &store)
            .expect("profile and key delete");

        assert_eq!(result, (true, true));
        assert!(store
            .read_api_key(&key)
            .expect("deleted key reads")
            .is_none());
        assert!(database::get_provider_profile(&connection, "ark-main")
            .expect("profile reads")
            .is_none());
    }

    #[test]
    fn profile_delete_restores_credential_when_database_delete_fails() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("ark-main", ProviderKind::VolcengineArk);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let key = ProviderCredentialKey::new("ark-main", "default");
        store
            .write_api_key(&key, ApiSecret::new("mock-credential-9012"))
            .expect("key writes");
        connection
            .execute_batch(
                "CREATE TRIGGER fail_provider_delete
                 BEFORE DELETE ON provider_profiles
                 BEGIN
                   SELECT RAISE(ABORT, 'simulated delete failure');
                 END;",
            )
            .expect("failure trigger installs");

        let error = delete_profile_with_store(&connection, "ark-main", &store)
            .expect_err("database deletion fails");

        assert_eq!(error.error_type, "database");
        assert!(database::get_provider_profile(&connection, "ark-main")
            .expect("profile reads")
            .is_some());
        assert!(store
            .read_api_key(&key)
            .expect("rolled back key reads")
            .is_some());
    }

    #[test]
    fn connection_command_dependency_path_uses_saved_profile_and_key() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("deepseek-main", ProviderKind::DeepSeek);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");
        let key = ProviderCredentialKey::new("deepseek-main", "default");
        store
            .write_api_key(&key, ApiSecret::new("mock-connection-secret-1234"))
            .expect("key writes");

        let calls = Arc::new(AtomicUsize::new(0));
        let seen_secret = Arc::new(Mutex::new(None));
        let expected = ConnectionTest::succeeded(
            "deepseek-main",
            200,
            Some("deepseek-test".to_owned()),
            Some(12),
            18,
            None,
        );
        let adapter = MockProviderAdapter {
            result: expected.clone(),
            calls: Arc::clone(&calls),
            seen_secret: Arc::clone(&seen_secret),
        };

        let result = test_provider_connection_with_dependencies(
            &connection,
            "deepseek-main",
            &store,
            || Ok(adapter),
        )
        .expect("connection dependency path succeeds");

        assert_eq!(result, expected);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            seen_secret.lock().expect("secret lock").as_deref(),
            Some("mock-connection-secret-1234")
        );
    }

    #[test]
    fn connection_command_dependency_path_maps_failure_and_missing_key() {
        let (_directory, connection) = test_user_database();
        let store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("qwen-main", ProviderKind::Qwen);
        upsert_profile_with_store(&connection, &profile, &store).expect("profile inserts");

        let missing = test_provider_connection_with_dependencies::<
            MockCredentialStore,
            MockProviderAdapter,
            _,
        >(&connection, "qwen-main", &store, || {
            panic!("adapter must not be created without a configured key")
        })
        .expect("missing key is a typed connection result");
        assert_eq!(missing.status, providers::ConnectionTestStatus::Failed);
        assert_eq!(missing.error_type.as_deref(), Some("missing_credential"));

        let key = ProviderCredentialKey::new("qwen-main", "default");
        store
            .write_api_key(&key, ApiSecret::new("mock-invalid-secret-9999"))
            .expect("key writes");
        let failure = ConnectionTest::failed(
            "qwen-main",
            Some(401),
            None,
            9,
            &ProviderError::with_status(ProviderErrorKind::Http, 401, "invalid credential"),
        );
        let result =
            test_provider_connection_with_dependencies(&connection, "qwen-main", &store, || {
                Ok(MockProviderAdapter::new(failure.clone()))
            })
            .expect("adapter failure is returned as a typed result");

        assert_eq!(result, failure);
        assert_eq!(result.http_status, Some(401));
        assert_eq!(result.error_type.as_deref(), Some("http"));
    }

    #[test]
    fn provider_profile_and_credential_snapshot_holds_the_cross_process_lock() {
        let (_directory, connection) = test_user_database();
        let setup_store = MockCredentialStore::default();
        let profile = ProviderProfile::new_default("deepseek-main", ProviderKind::DeepSeek);
        upsert_profile_with_store(&connection, &profile, &setup_store).expect("profile inserts");

        let observed_read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let store = ObservingCredentialStore {
            observed_read: Arc::clone(&observed_read),
            secret: ApiSecret::new("snapshot-secret-1234"),
        };
        let lock = ProviderStoreLock::acquire().expect("outer lock acquires");
        let (started_tx, started_rx) = mpsc::channel();
        let contender = thread::spawn(move || {
            started_tx.send(()).expect("start signal sends");
            provider_profile_and_credential_snapshot(&connection, "deepseek-main", &store)
                .expect("snapshot eventually reads")
        });

        started_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("contender starts");
        thread::sleep(Duration::from_millis(100));
        assert!(!observed_read.load(Ordering::SeqCst));
        drop(lock);

        let (loaded_profile, loaded_secret) = contender.join().expect("contender exits");
        assert_eq!(loaded_profile.kind, ProviderKind::DeepSeek);
        assert_eq!(
            loaded_secret.as_ref().map(ApiSecret::expose_secret),
            Some("snapshot-secret-1234")
        );
        assert!(observed_read.load(Ordering::SeqCst));
    }

    fn test_user_database() -> (tempfile::TempDir, rusqlite::Connection) {
        let directory = tempfile::tempdir().expect("tempdir exists");
        let database_path =
            database::ensure_user_database(directory.path()).expect("user database initializes");
        let connection = database::open_user_database(database_path).expect("user database opens");
        (directory, connection)
    }

    #[derive(Debug, Default)]
    struct MockCredentialStore {
        secrets: Mutex<HashMap<ProviderCredentialKey, ApiSecret>>,
    }

    #[derive(Debug)]
    struct ObservingCredentialStore {
        observed_read: Arc<std::sync::atomic::AtomicBool>,
        secret: ApiSecret,
    }

    impl CredentialStore for ObservingCredentialStore {
        type Error = ProviderError;

        fn read_api_key(
            &self,
            _key: &ProviderCredentialKey,
        ) -> Result<Option<ApiSecret>, Self::Error> {
            self.observed_read.store(true, Ordering::SeqCst);
            Ok(Some(self.secret.clone()))
        }

        fn write_api_key(
            &self,
            _key: &ProviderCredentialKey,
            _secret: ApiSecret,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn delete_api_key(&self, _key: &ProviderCredentialKey) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct MockProviderAdapter {
        result: ConnectionTest,
        calls: Arc<AtomicUsize>,
        seen_secret: Arc<Mutex<Option<String>>>,
    }

    impl MockProviderAdapter {
        fn new(result: ConnectionTest) -> Self {
            Self {
                result,
                calls: Arc::new(AtomicUsize::new(0)),
                seen_secret: Arc::new(Mutex::new(None)),
            }
        }
    }

    impl ProviderAdapter for MockProviderAdapter {
        fn send_chat(
            &self,
            _profile: &ProviderProfile,
            _secret: &ApiSecret,
            _request: &providers::ChatRequest,
        ) -> Result<providers::TransportResponse, ProviderError> {
            panic!("connection command must call the provider test boundary")
        }

        fn send_chat_with_cancellation(
            &self,
            _profile: &ProviderProfile,
            _secret: &ApiSecret,
            _request: &providers::ChatRequest,
            _cancellation: &providers::RequestCancellation,
        ) -> Result<providers::TransportResponse, ProviderError> {
            panic!("connection command must call the provider test boundary")
        }

        fn test_connection(
            &self,
            _profile: &ProviderProfile,
            secret: &ApiSecret,
        ) -> ConnectionTest {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.seen_secret.lock().expect("secret lock") =
                Some(secret.expose_secret().to_owned());
            self.result.clone()
        }
    }

    impl CredentialStore for MockCredentialStore {
        type Error = ProviderError;

        fn read_api_key(
            &self,
            key: &ProviderCredentialKey,
        ) -> Result<Option<ApiSecret>, Self::Error> {
            Ok(self.secrets.lock().expect("secrets lock").get(key).cloned())
        }

        fn write_api_key(
            &self,
            key: &ProviderCredentialKey,
            secret: ApiSecret,
        ) -> Result<(), Self::Error> {
            self.secrets
                .lock()
                .expect("secrets lock")
                .insert(key.clone(), secret);
            Ok(())
        }

        fn delete_api_key(&self, key: &ProviderCredentialKey) -> Result<(), Self::Error> {
            self.secrets.lock().expect("secrets lock").remove(key);
            Ok(())
        }
    }
}
