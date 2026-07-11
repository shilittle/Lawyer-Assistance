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
    if request.api_key.expose_secret().trim().is_empty() {
        return Err(ProviderError::new(
            ProviderErrorKind::MissingCredential,
            "API key cannot be empty",
        )
        .into());
    }

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

fn upsert_profile_with_store<S>(
    connection: &rusqlite::Connection,
    profile: &ProviderProfile,
    store: &S,
) -> Result<(), IpcError>
where
    S: CredentialStore<Error = ProviderError>,
{
    if let Some(existing) = database::get_provider_profile(connection, &profile.id)? {
        if existing.credential_account_id != profile.credential_account_id {
            let old_key = ProviderCredentialKey::new(&existing.id, &existing.credential_account_id);
            if store.read_api_key(&old_key)?.is_some() {
                return Err(ProviderError::new(
                    ProviderErrorKind::InvalidProfile,
                    "delete the configured API key before changing the credential account",
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
    let Some(profile) = database::get_provider_profile(connection, provider_id)? else {
        return Ok((false, false));
    };

    let key = ProviderCredentialKey::new(&profile.id, &profile.credential_account_id);
    store.delete_api_key(&key)?;
    let deleted = database::delete_provider_profile(connection, provider_id)?;

    Ok((deleted, true))
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
    if !is_safe_credential_component(&profile.id)
        || !is_safe_credential_component(&profile.credential_account_id)
    {
        return Err(ProviderError::new(
            ProviderErrorKind::InvalidProfile,
            "profile ID and credential account may contain only letters, numbers, '-', '_' and '.'",
        ));
    }

    Ok(())
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
    use std::{collections::HashMap, sync::Mutex};

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
