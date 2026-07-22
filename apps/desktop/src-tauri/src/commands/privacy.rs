use crate::mcp_manager::McpManager;
use crate::privacy_manager::{
    LocalMineruDiscoveryResult, LocalOcrStatus, PrivacyConfig, PrivacyConfigurationSnapshot,
    PrivacyManager, PrivacyManagerError, PrivacyVNextCapabilityMatrix,
};
use crate::privacy_qualification::TrustInstallationStatus;
use serde::{Deserialize, Serialize};
use tauri::State;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub error_type: String,
    pub message: String,
}

impl From<PrivacyManagerError> for IpcError {
    fn from(error: PrivacyManagerError) -> Self {
        Self {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SavePrivacyConfigRequest {
    pub config: PrivacyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InspectLocalMineruQualificationReportRequest {
    pub report_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunLocalMineruQualificationRequest {
    pub ttl_seconds: u64,
    pub production_case_ocr_authorized: bool,
    pub app_auto_enable_authorized: bool,
}
#[tauri::command]
pub async fn get_privacy_config(
    manager: State<'_, PrivacyManager>,
) -> Result<PrivacyConfigurationSnapshot, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.configuration_snapshot())
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "隐私配置读取任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn save_privacy_config(
    manager: State<'_, PrivacyManager>,
    request: SavePrivacyConfigRequest,
) -> Result<PrivacyConfigurationSnapshot, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.save_config(request.config))
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "隐私配置保存任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn discover_local_mineru(
    manager: State<'_, PrivacyManager>,
) -> Result<LocalMineruDiscoveryResult, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.discover_local_mineru())
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "本机 MinerU 自动发现任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn install_local_mineru_trust(
    manager: State<'_, PrivacyManager>,
) -> Result<TrustInstallationStatus, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.install_local_mineru_trust())
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "Local MinerU trust installation did not complete.".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn install_local_mineru_network_isolation(
    manager: State<'_, PrivacyManager>,
) -> Result<PrivacyConfigurationSnapshot, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.install_local_mineru_network_isolation())
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "Local MinerU network isolation installation did not complete.".to_owned(),
        })?
        .map_err(Into::into)
}

#[tauri::command]
pub async fn run_local_mineru_qualification(
    manager: State<'_, PrivacyManager>,
    request: RunLocalMineruQualificationRequest,
) -> Result<PrivacyConfigurationSnapshot, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        manager.run_local_mineru_qualification(
            request.ttl_seconds,
            request.production_case_ocr_authorized,
            request.app_auto_enable_authorized,
        )
    })
    .await
    .map_err(|_| IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "Local MinerU qualification did not complete.".to_owned(),
    })?
    .map_err(Into::into)
}

#[tauri::command]
pub async fn revoke_local_mineru_qualification(
    manager: State<'_, PrivacyManager>,
    mcp: State<'_, McpManager>,
) -> Result<PrivacyConfigurationSnapshot, IpcError> {
    let manager = manager.inner().clone();
    let mcp = mcp.inner().clone();
    let snapshot =
        tauri::async_runtime::spawn_blocking(move || manager.revoke_local_mineru_qualification())
            .await
            .map_err(|_| IpcError {
                error_type: "runtime_failure".to_owned(),
                message: "Local MinerU qualification revocation did not complete.".to_owned(),
            })?
            .map_err(IpcError::from)?;
    mcp.revoke_active_approved_tickets()
        .map_err(|error| IpcError {
            error_type: error.code().to_owned(),
            message: providers::redact_sensitive(error.message()),
        })?;
    Ok(snapshot)
}

#[tauri::command]
pub async fn inspect_local_mineru_qualification_report(
    manager: State<'_, PrivacyManager>,
    request: InspectLocalMineruQualificationReportRequest,
) -> Result<PrivacyConfigurationSnapshot, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let qualification =
            manager.inspect_local_mineru_qualification_report(&request.report_json)?;
        let mut snapshot = manager.configuration_snapshot()?;
        snapshot.qualification = qualification;
        snapshot.capabilities = PrivacyVNextCapabilityMatrix::current(
            snapshot.config_valid,
            snapshot.qualification.clone(),
        );
        Ok::<PrivacyConfigurationSnapshot, PrivacyManagerError>(snapshot)
    })
    .await
    .map_err(|_| IpcError {
        error_type: "runtime_failure".to_owned(),
        message: "local MinerU qualification report inspection did not complete".to_owned(),
    })?
    .map_err(Into::into)
}
#[tauri::command]
pub async fn get_local_ocr_status(
    manager: State<'_, PrivacyManager>,
) -> Result<LocalOcrStatus, IpcError> {
    let manager = manager.inner().clone();
    tauri::async_runtime::spawn_blocking(move || manager.local_ocr_status())
        .await
        .map_err(|_| IpcError {
            error_type: "runtime_failure".to_owned(),
            message: "本地 OCR 状态检查任务未完成。".to_owned(),
        })?
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_manager::{PrivacyVNextCapabilityMatrix, PrivacyVNextQualificationStatus};

    #[test]
    fn save_request_rejects_unknown_fields_and_cloud_fallback_is_explicit() {
        let valid = serde_json::json!({
            "config": {
                "schemaVersion": 1,
                "privacyMode": "external_redacted",
                "ocr": {
                    "mode": "off",
                    "workerPath": null,
                    "modelDirectory": null,
                    "toolsConfigPath": null,
                    "runtimeExecutablePaths": [],
                    "device": "auto",
                    "languages": ["zh", "en"],
                    "timeoutSeconds": 300,
                    "maxPages": 200,
                    "strictOffline": true,
                    "forbidCloudFallback": true,
                    "forbidRemoteUpload": true,
                    "forbidTelemetry": true
                }
            }
        });
        let request: SavePrivacyConfigRequest =
            serde_json::from_value(valid.clone()).expect("valid request parses");
        assert!(request.config.ocr.forbid_cloud_fallback);
        assert!(request.config.ocr.forbid_remote_upload);
        assert!(request.config.ocr.forbid_telemetry);

        let mut unknown = valid;
        unknown
            .as_object_mut()
            .expect("object")
            .insert("allowRawCloudUpload".to_owned(), serde_json::json!(true));
        assert!(serde_json::from_value::<SavePrivacyConfigRequest>(unknown).is_err());
    }

    #[test]
    fn snapshot_serializes_honest_enforcement_and_verification_fields() {
        let qualification = PrivacyVNextQualificationStatus::current();
        let capabilities = PrivacyVNextCapabilityMatrix::current(true, qualification.clone());
        let snapshot = PrivacyConfigurationSnapshot {
            config: PrivacyConfig::default(),
            config_valid: true,
            load_error: None,
            enforcement_state: "configuration_only",
            ocr_status: LocalOcrStatus {
                code: crate::privacy_manager::LocalOcrStatusCode::Disabled,
                message: "本地 OCR 已关闭。".to_owned(),
                worker_version: None,
                model_version: None,
                worker_sha256: None,
                model_manifest_sha256: None,
                worker_present: false,
                model_directory_present: false,
                integrity_verified: false,
                network_isolation_verified: false,
                worker_protocol_version: None,
                worker_protocol_identity_sha256: None,
                worker_health_evidence_sha256: None,
                python_version: None,
                mineru_version: None,
                pytorch_version: None,
                cuda_runtime_version: None,
                gpu_driver_version: None,
            },
            qualification,
            capabilities,
        };
        let value = serde_json::to_value(snapshot).expect("snapshot serializes");
        assert_eq!(value["enforcementState"], "configuration_only");
        assert_eq!(value["ocrStatus"]["networkIsolationVerified"], false);
        assert_eq!(value["qualification"]["networkIsolationEnforced"], false);
        assert_eq!(
            value["qualification"]["modelManifestTrustEstablished"],
            false
        );
        assert_eq!(value["qualification"]["appAutoEnableAuthorized"], false);
        assert_eq!(value["qualification"]["productionCaseOcrAuthorized"], false);
        assert_eq!(value["capabilities"]["scannedCaseOcrEnabled"], false);
        assert_eq!(value["capabilities"]["automaticApprovalEnabled"], false);
        assert_eq!(value["config"]["ocr"]["forbidCloudFallback"], true);
        assert_eq!(value["config"]["ocr"]["forbidRemoteUpload"], true);
        assert_eq!(value["config"]["ocr"]["forbidTelemetry"], true);
        assert!(value.get("allowRawCloudUpload").is_none());
    }
}
