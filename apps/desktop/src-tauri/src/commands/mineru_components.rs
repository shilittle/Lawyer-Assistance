use crate::{
    mineru_components::{
        ComponentMutation, MineruComponentError, MineruComponentManager, MineruComponentStatus,
    },
    privacy_manager::{OcrMode, PrivacyConfigurationSnapshot, PrivacyManager, PrivacyManagerError},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tauri::State;
use tauri_plugin_dialog::DialogExt;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl From<MineruComponentError> for IpcError {
    fn from(error: MineruComponentError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

impl From<PrivacyManagerError> for IpcError {
    fn from(error: PrivacyManagerError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MineruComponentOperationResponse {
    cancelled: bool,
    status: MineruComponentStatus,
    privacy: Option<PrivacyConfigurationSnapshot>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackageIdRequest {
    package_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComponentVersionRequest {
    component_version: String,
}

#[tauri::command]
pub async fn get_mineru_component_status(
    components: State<'_, MineruComponentManager>,
    privacy: State<'_, PrivacyManager>,
) -> Result<MineruComponentStatus, IpcError> {
    let components = components.inner().clone();
    let privacy = privacy.inner().clone();
    tauri::async_runtime::spawn_blocking(move || checked_status(&components, &privacy))
        .await
        .map_err(|_| runtime_error())?
}

#[tauri::command]
pub async fn import_mineru_component_catalog(
    app: tauri::AppHandle,
    components: State<'_, MineruComponentManager>,
    privacy: State<'_, PrivacyManager>,
) -> Result<MineruComponentOperationResponse, IpcError> {
    let selected = app
        .dialog()
        .file()
        .set_title("导入受信 MinerU 组件目录")
        .add_filter("MinerU signed catalog", &["json"])
        .blocking_pick_file();
    let Some(selected) = selected else {
        return cancelled(&components, Some(&privacy));
    };
    let catalog = selected.into_path().map_err(|_| invalid_local_file())?;
    let signature = detached_signature_path(&catalog)?;
    let components = components.inner().clone();
    let privacy = privacy.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _mutation_guard = privacy.begin_local_mineru_component_mutation()?;
        let snapshot = privacy.revoke_local_mineru_qualification()?;
        let status = components.import_catalog(&catalog, &signature)?;
        Ok::<_, MineruOperationError>(MineruComponentOperationResponse {
            cancelled: false,
            status,
            privacy: Some(snapshot),
        })
    })
    .await
    .map_err(|_| runtime_error())?
    .map_err(Into::into)
}

#[tauri::command]
pub async fn install_mineru_offline_package(
    app: tauri::AppHandle,
    components: State<'_, MineruComponentManager>,
    privacy: State<'_, PrivacyManager>,
) -> Result<MineruComponentOperationResponse, IpcError> {
    let selected = app
        .dialog()
        .file()
        .set_title("导入离线 MinerU/OCR 组件包")
        .add_filter("Lawyer Assistance OCR package", &["laocrpkg", "laocrparts"])
        .blocking_pick_file();
    let Some(selected) = selected else {
        return cancelled(&components, Some(&privacy));
    };
    let package = selected.into_path().map_err(|_| invalid_local_file())?;
    let components = components.inner().clone();
    let privacy = privacy.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _mutation_guard = privacy.begin_local_mineru_component_mutation()?;
        privacy.revoke_local_mineru_qualification()?;
        let mutation = components.install_offline_package(&package)?;
        finish_mutation(&components, &privacy, mutation)
    })
    .await
    .map_err(|_| runtime_error())?
    .map_err(Into::into)
}

#[tauri::command]
pub async fn download_install_mineru_package(
    components: State<'_, MineruComponentManager>,
    privacy: State<'_, PrivacyManager>,
    request: PackageIdRequest,
) -> Result<MineruComponentOperationResponse, IpcError> {
    if !valid_identifier(&request.package_id) {
        return Err(IpcError {
            error_type: "catalog_package_invalid".to_owned(),
            message: "所选组件包标识无效。".to_owned(),
        });
    }
    let components = components.inner().clone();
    let privacy = privacy.inner().clone();
    let _mutation_guard = privacy
        .begin_local_mineru_component_mutation()
        .map_err(IpcError::from)?;
    let preflight_privacy = privacy.clone();
    tauri::async_runtime::spawn_blocking(move || {
        preflight_privacy.revoke_local_mineru_qualification()
    })
    .await
    .map_err(|_| runtime_error())?
    .map_err(IpcError::from)?;
    // This call downloads only the exact component bytes pinned in the local,
    // signed catalog. No case material is accepted by this command.
    let mutation = components
        .download_and_install(&request.package_id)
        .await
        .map_err(IpcError::from)?;
    tauri::async_runtime::spawn_blocking(move || finish_mutation(&components, &privacy, mutation))
        .await
        .map_err(|_| runtime_error())?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn rollback_mineru_component(
    components: State<'_, MineruComponentManager>,
    privacy: State<'_, PrivacyManager>,
    request: ComponentVersionRequest,
) -> Result<MineruComponentOperationResponse, IpcError> {
    let components = components.inner().clone();
    let privacy = privacy.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _mutation_guard = privacy.begin_local_mineru_component_mutation()?;
        privacy.revoke_local_mineru_qualification()?;
        let mutation = components.rollback(&request.component_version)?;
        finish_mutation(&components, &privacy, mutation)
    })
    .await
    .map_err(|_| runtime_error())?
    .map_err(Into::into)
}

#[tauri::command]
pub async fn uninstall_mineru_component(
    components: State<'_, MineruComponentManager>,
    privacy: State<'_, PrivacyManager>,
    request: ComponentVersionRequest,
) -> Result<MineruComponentOperationResponse, IpcError> {
    let components = components.inner().clone();
    let privacy = privacy.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _mutation_guard = privacy.begin_local_mineru_component_mutation()?;
        privacy.revoke_local_mineru_qualification()?;
        let mutation = components.uninstall(&request.component_version)?;
        finish_mutation(&components, &privacy, mutation)
    })
    .await
    .map_err(|_| runtime_error())?
    .map_err(Into::into)
}

fn checked_status(
    components: &MineruComponentManager,
    privacy: &PrivacyManager,
) -> Result<MineruComponentStatus, IpcError> {
    let status = components.status().map_err(IpcError::from)?;
    if managed_configuration_active(components, privacy) && !status.active_integrity_valid {
        privacy
            .revoke_local_mineru_qualification()
            .map_err(IpcError::from)?;
    }
    Ok(status)
}

fn finish_mutation(
    components: &MineruComponentManager,
    privacy: &PrivacyManager,
    mutation: ComponentMutation,
) -> Result<MineruComponentOperationResponse, MineruOperationError> {
    let mut config = privacy.current_config();
    if let Some(binding) = mutation.binding {
        config.ocr.mode = match config.ocr.mode {
            OcrMode::ForceLocal => OcrMode::ForceLocal,
            OcrMode::Off | OcrMode::AutoLocal => OcrMode::AutoLocal,
        };
        config.ocr.worker_path = Some(binding.worker_path);
        config.ocr.model_directory = Some(binding.model_root);
        config.ocr.tools_config_path = Some(binding.tools_config_path);
        config.ocr.runtime_executable_paths = binding.runtime_executable_paths;
    } else if mutation.removed_active_component {
        config.ocr.mode = OcrMode::Off;
        config.ocr.worker_path = None;
        config.ocr.model_directory = None;
        config.ocr.tools_config_path = None;
        config.ocr.runtime_executable_paths.clear();
    }
    privacy.save_config(config)?;
    // The command completed the revoke-first publication and qualification preflight before
    // mutating component bytes. Re-running invalidation here would create an unsafe failure point
    // after the physical mutation has already committed.
    let snapshot = privacy.configuration_snapshot()?;
    let status = components.status()?;
    Ok(MineruComponentOperationResponse {
        cancelled: false,
        status,
        privacy: Some(snapshot),
    })
}

#[derive(Debug)]
enum MineruOperationError {
    Component(MineruComponentError),
    Privacy(PrivacyManagerError),
}

impl From<MineruComponentError> for MineruOperationError {
    fn from(value: MineruComponentError) -> Self {
        Self::Component(value)
    }
}

impl From<PrivacyManagerError> for MineruOperationError {
    fn from(value: PrivacyManagerError) -> Self {
        Self::Privacy(value)
    }
}

impl From<MineruOperationError> for IpcError {
    fn from(value: MineruOperationError) -> Self {
        match value {
            MineruOperationError::Component(error) => error.into(),
            MineruOperationError::Privacy(error) => error.into(),
        }
    }
}

fn managed_configuration_active(
    components: &MineruComponentManager,
    privacy: &PrivacyManager,
) -> bool {
    privacy
        .current_config()
        .ocr
        .worker_path
        .as_deref()
        .is_some_and(|path| path.starts_with(components.managed_root()))
}

fn cancelled(
    components: &State<'_, MineruComponentManager>,
    privacy: Option<&State<'_, PrivacyManager>>,
) -> Result<MineruComponentOperationResponse, IpcError> {
    Ok(MineruComponentOperationResponse {
        cancelled: true,
        status: components.status().map_err(IpcError::from)?,
        privacy: privacy
            .map(|manager| manager.configuration_snapshot().map_err(IpcError::from))
            .transpose()?,
    })
}

fn detached_signature_path(catalog: &Path) -> Result<PathBuf, IpcError> {
    let filename = catalog
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(invalid_local_file)?;
    Ok(catalog.with_file_name(format!("{filename}.minisig")))
}

fn valid_identifier(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn invalid_local_file() -> IpcError {
    IpcError {
        error_type: "component_local_file_invalid".to_owned(),
        message: "所选组件文件不是可验证的本机普通文件。".to_owned(),
    }
}

fn runtime_error() -> IpcError {
    IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "本地 MinerU 组件管理任务未完成。".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_reject_unknown_fields_and_paths_are_not_an_ipc_input() {
        assert!(
            serde_json::from_value::<PackageIdRequest>(serde_json::json!({
                "packageId": "synthetic-package",
                "casePath": "C:\\case.pdf"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ComponentVersionRequest>(serde_json::json!({
                "componentVersion": "1.0.0",
                "removeFirewallRules": true
            }))
            .is_err()
        );
    }

    #[test]
    fn component_mutation_guard_blocks_parallel_mutation_qualification_and_ocr_config() {
        let temporary = tempfile::tempdir().unwrap();
        let manager = PrivacyManager::new(temporary.path().join("app")).unwrap();
        let guard = manager.begin_local_mineru_component_mutation().unwrap();
        assert_eq!(
            manager
                .begin_local_mineru_component_mutation()
                .unwrap_err()
                .code(),
            "component_mutation_in_progress"
        );
        assert_eq!(
            manager
                .run_local_mineru_qualification(900, true, false)
                .unwrap_err()
                .code(),
            "qualification_component_mutation_race"
        );
        assert_eq!(
            manager.install_local_mineru_trust().unwrap_err().code(),
            "qualification_component_mutation_race"
        );
        assert_eq!(
            manager
                .install_local_mineru_network_isolation()
                .unwrap_err()
                .code(),
            "qualification_component_mutation_race"
        );
        assert_eq!(
            manager.local_mineru_config().unwrap_err().code(),
            "qualification_component_mutation_race"
        );
        drop(guard);
        manager.begin_local_mineru_component_mutation().unwrap();
    }
}
