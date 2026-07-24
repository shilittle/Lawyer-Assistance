use crate::privacy_qualification::{
    require_administrator_token, QualificationEnvironment, QualificationError,
    QualificationRepository, TrustInstallationStatus,
};
use material_processing::{
    bind_local_mineru_runtime_executable, build_local_mineru_runtime_manifest,
    measure_windows_firewall_isolation, validate_local_mineru_config, DeviceSelection,
    LocalMineruConfig as ProcessingMineruConfig, LocalMineruRuntimeExecutableRole, MineruBackend,
    NetworkIsolationEvidence, NetworkIsolationRuleEvidence, ProcessingError,
    WINDOWS_FIREWALL_ISOLATION_MECHANISM,
};
use privacy::{
    parse_local_mineru_qualification_report, risk_engine::QualificationSnapshotV1, vnext::Sha256Hex,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    fmt,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::windows::fs::MetadataExt,
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
    path::{Component, Path, PathBuf, Prefix},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetDriveTypeW, GetFileInformationByHandle, GetFinalPathNameByHandleW,
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_NAME_NORMALIZED,
        VOLUME_NAME_DOS,
    },
};

mod mineru_discovery;
pub use mineru_discovery::LocalMineruDiscoveryResult;

pub const PRIVACY_CONFIG_SCHEMA_VERSION: u16 = 1;
const CONFIG_DIRECTORY_NAME: &str = "privacy";
const CONFIG_FILE_NAME: &str = "privacy-config.json";
const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_WORKER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MODEL_MANIFEST_FILE_NAME: &str = "model-manifest.json";
const MIN_TIMEOUT_SECONDS: u64 = 10;
const MAX_TIMEOUT_SECONDS: u64 = 2 * 60 * 60;
const MAX_OCR_PAGES: u32 = 500;
const MAX_LANGUAGES: usize = 16;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyMode {
    RawNative,
    #[default]
    ExternalRedacted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OcrMode {
    #[default]
    Off,
    AutoLocal,
    ForceLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalOcrConfig {
    #[serde(default)]
    pub mode: OcrMode,
    #[serde(default)]
    pub worker_path: Option<PathBuf>,
    #[serde(default)]
    pub model_directory: Option<PathBuf>,
    #[serde(default)]
    pub tools_config_path: Option<PathBuf>,
    #[serde(default)]
    pub runtime_executable_paths: Vec<PathBuf>,
    #[serde(default = "default_device")]
    pub device: String,
    #[serde(default = "default_languages")]
    pub languages: Vec<String>,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_max_pages")]
    pub max_pages: u32,
    #[serde(default = "enabled")]
    pub strict_offline: bool,
    #[serde(default = "enabled")]
    pub forbid_cloud_fallback: bool,
    #[serde(default = "enabled")]
    pub forbid_remote_upload: bool,
    #[serde(default = "enabled")]
    pub forbid_telemetry: bool,
}

impl Default for LocalOcrConfig {
    fn default() -> Self {
        Self {
            mode: OcrMode::Off,
            worker_path: None,
            model_directory: None,
            tools_config_path: None,
            runtime_executable_paths: Vec::new(),
            device: default_device(),
            languages: default_languages(),
            timeout_seconds: default_timeout_seconds(),
            max_pages: default_max_pages(),
            strict_offline: true,
            forbid_cloud_fallback: true,
            forbid_remote_upload: true,
            forbid_telemetry: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrivacyConfig {
    #[serde(default = "current_schema_version")]
    pub schema_version: u16,
    #[serde(default)]
    pub privacy_mode: PrivacyMode,
    #[serde(default)]
    pub ocr: LocalOcrConfig,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            schema_version: PRIVACY_CONFIG_SCHEMA_VERSION,
            privacy_mode: PrivacyMode::ExternalRedacted,
            ocr: LocalOcrConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalOcrStatusCode {
    Disabled,
    NotConfigured,
    Unavailable,
    ConfiguredUnverified,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalOcrStatus {
    pub code: LocalOcrStatusCode,
    pub message: String,
    pub worker_version: Option<String>,
    pub model_version: Option<String>,
    pub worker_sha256: Option<String>,
    pub model_manifest_sha256: Option<String>,
    pub worker_present: bool,
    pub model_directory_present: bool,
    pub integrity_verified: bool,
    pub network_isolation_verified: bool,
    pub worker_protocol_version: Option<String>,
    pub worker_protocol_identity_sha256: Option<String>,
    pub worker_health_evidence_sha256: Option<String>,
    pub python_version: Option<String>,
    pub mineru_version: Option<String>,
    pub pytorch_version: Option<String>,
    pub cuda_runtime_version: Option<String>,
    pub gpu_driver_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyVNextQualificationStatus {
    pub qualification_id: Option<String>,
    pub qualification_report_id: Option<String>,
    pub qualification_report_sha256: Option<String>,
    pub synthetic_canary_qualified: bool,
    pub processing_chain_qualified: bool,
    pub exact_worker_model_match: bool,
    pub network_isolation_enforced: bool,
    pub model_manifest_trust_established: bool,
    pub app_auto_enable_authorized: bool,
    pub production_case_ocr_authorized: bool,
    pub expires_at_unix: Option<u64>,
    pub revoked: bool,
    pub reason_codes: Vec<String>,
    pub worker_protocol_version: Option<String>,
    pub worker_protocol_identity_sha256: Option<String>,
    pub worker_health_evidence_sha256: Option<String>,
    pub worker_version: Option<String>,
    pub python_version: Option<String>,
    pub mineru_version: Option<String>,
    pub pytorch_version: Option<String>,
    pub cuda_runtime_version: Option<String>,
    pub gpu_driver_version: Option<String>,
    pub model_version: Option<String>,
    pub selected_cuda_device: Option<u32>,
    pub selected_gpu_memory_mib: Option<u32>,
    pub selected_gpu_name: Option<String>,
}

impl PrivacyVNextQualificationStatus {
    pub(crate) fn current() -> Self {
        Self::blocked("qualification_not_installed")
    }

    fn blocked(reason_code: impl Into<String>) -> Self {
        Self {
            qualification_id: None,
            qualification_report_id: None,
            qualification_report_sha256: None,
            synthetic_canary_qualified: false,
            processing_chain_qualified: false,
            exact_worker_model_match: false,
            network_isolation_enforced: false,
            model_manifest_trust_established: false,
            app_auto_enable_authorized: false,
            production_case_ocr_authorized: false,
            expires_at_unix: None,
            revoked: false,
            reason_codes: vec![reason_code.into()],
            worker_protocol_version: None,
            worker_protocol_identity_sha256: None,
            worker_health_evidence_sha256: None,
            worker_version: None,
            python_version: None,
            mineru_version: None,
            pytorch_version: None,
            cuda_runtime_version: None,
            gpu_driver_version: None,
            model_version: None,
            selected_cuda_device: None,
            selected_gpu_memory_mib: None,
            selected_gpu_name: None,
        }
    }

    pub(crate) fn production_ocr_chain_authorized(&self) -> bool {
        self.processing_chain_qualified
            && self.exact_worker_model_match
            && self.network_isolation_enforced
            && self.model_manifest_trust_established
            && self.production_case_ocr_authorized
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyVNextCapabilityMatrix {
    pub local_gpu_preference_configurable: bool,
    pub scanned_case_ocr_enabled: bool,
    pub automatic_approval_enabled: bool,
    pub app_auto_ocr_enabled: bool,
    pub remote_ocr_fallback_allowed: bool,
    pub telemetry_allowed: bool,
    pub raw_material_upload_allowed: bool,
    pub blocking_reason_codes: Vec<&'static str>,
}

impl PrivacyVNextCapabilityMatrix {
    pub(crate) fn current(
        config_valid: bool,
        qualification: PrivacyVNextQualificationStatus,
    ) -> Self {
        let scanned_case_ocr_enabled =
            config_valid && qualification.production_ocr_chain_authorized();
        let mut blocking_reason_codes = Vec::new();
        if !config_valid {
            blocking_reason_codes.push("privacy_configuration_invalid");
        }
        if !qualification.network_isolation_enforced {
            blocking_reason_codes.push("network_isolation_not_enforced");
        }
        if !qualification.model_manifest_trust_established {
            blocking_reason_codes.push("model_manifest_trust_not_established");
        }
        if !qualification.app_auto_enable_authorized {
            blocking_reason_codes.push("app_auto_enable_not_authorized");
        }
        if !qualification.production_case_ocr_authorized {
            blocking_reason_codes.push("production_case_ocr_not_authorized");
        }
        Self {
            local_gpu_preference_configurable: config_valid,
            scanned_case_ocr_enabled,
            // Automatic OCR routing never means automatic redaction approval.
            automatic_approval_enabled: false,
            app_auto_ocr_enabled: scanned_case_ocr_enabled
                && qualification.app_auto_enable_authorized,
            remote_ocr_fallback_allowed: false,
            telemetry_allowed: false,
            raw_material_upload_allowed: false,
            blocking_reason_codes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyConfigurationSnapshot {
    pub config: PrivacyConfig,
    pub config_valid: bool,
    pub load_error: Option<String>,
    pub enforcement_state: &'static str,
    pub ocr_status: LocalOcrStatus,
    pub qualification: PrivacyVNextQualificationStatus,
    pub capabilities: PrivacyVNextCapabilityMatrix,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PrivacyManagerError {
    code: &'static str,
    message: String,
}

impl PrivacyManagerError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: providers::redact_sensitive(&message.into()),
        }
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for PrivacyManagerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PrivacyManagerError {}

impl From<QualificationError> for PrivacyManagerError {
    fn from(error: QualificationError) -> Self {
        Self::new(error.code(), error.message())
    }
}

impl From<ProcessingError> for PrivacyManagerError {
    fn from(error: ProcessingError) -> Self {
        Self::new(error.code(), error.message())
    }
}

/// Security boundary used by OCR qualification and component mutations. Implementations must
/// transactionally revoke only publications whose signed provenance contains local OCR evidence.
pub(crate) trait OcrQualificationInvalidator: fmt::Debug + Send + Sync {
    fn invalidate_ocr_derived(&self, reason_code: &'static str) -> Result<u64, &'static str>;
}

#[derive(Debug)]
struct ManagerState {
    config: PrivacyConfig,
    config_valid: bool,
    load_error: Option<String>,
    qualification: PrivacyVNextQualificationStatus,
    blocked_ocr_publications_secured: bool,
}

#[derive(Debug)]
struct PrivacyManagerShared {
    config_path: PathBuf,
    privacy_directory: PathBuf,
    qualification_repository: QualificationRepository,
    ocr_qualification_invalidator: Option<Arc<dyn OcrQualificationInvalidator>>,
    state: Mutex<ManagerState>,
    local_mineru_component_mutation_active: AtomicBool,
    ocr_invalidation_preflight_completed: AtomicBool,
}

#[derive(Clone, Debug)]
pub struct PrivacyManager {
    shared: Arc<PrivacyManagerShared>,
}

#[derive(Debug)]
pub(crate) struct LocalMineruComponentMutationGuard {
    shared: Arc<PrivacyManagerShared>,
}

impl Drop for LocalMineruComponentMutationGuard {
    fn drop(&mut self) {
        self.shared
            .local_mineru_component_mutation_active
            .store(false, Ordering::Release);
    }
}

impl PrivacyManager {
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(app_local_data_directory: PathBuf) -> Result<Self, PrivacyManagerError> {
        Self::new_with_optional_ocr_qualification_invalidator(app_local_data_directory, None)
    }

    pub(crate) fn new_with_ocr_qualification_invalidator(
        app_local_data_directory: PathBuf,
        invalidator: Arc<dyn OcrQualificationInvalidator>,
    ) -> Result<Self, PrivacyManagerError> {
        Self::new_with_optional_ocr_qualification_invalidator(
            app_local_data_directory,
            Some(invalidator),
        )
    }

    fn new_with_optional_ocr_qualification_invalidator(
        app_local_data_directory: PathBuf,
        ocr_qualification_invalidator: Option<Arc<dyn OcrQualificationInvalidator>>,
    ) -> Result<Self, PrivacyManagerError> {
        let privacy_directory =
            ensure_directory(&app_local_data_directory.join(CONFIG_DIRECTORY_NAME), true)?;
        let qualification_repository = QualificationRepository::new(&privacy_directory)?;
        let config_path = privacy_directory.join(CONFIG_FILE_NAME);
        let default_config = PrivacyConfig::default();
        let (config, config_valid, load_error) = match fs::symlink_metadata(&config_path) {
            Ok(_) => match read_config(&config_path) {
                Ok(config) => (config, true, None),
                Err(error) => (default_config, false, Some(error.message().to_owned())),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                persist_config(&config_path, &default_config)?;
                (default_config, true, None)
            }
            Err(_) => (
                default_config,
                false,
                Some("隐私配置文件无法检查；外发能力必须保持关闭。".to_owned()),
            ),
        };

        let manager = Self {
            shared: Arc::new(PrivacyManagerShared {
                config_path,
                privacy_directory,
                qualification_repository,
                ocr_qualification_invalidator,
                state: Mutex::new(ManagerState {
                    config,
                    config_valid,
                    load_error,
                    qualification: PrivacyVNextQualificationStatus::current(),
                    blocked_ocr_publications_secured: false,
                }),
                local_mineru_component_mutation_active: AtomicBool::new(false),
                ocr_invalidation_preflight_completed: AtomicBool::new(false),
            }),
        };
        manager.refresh_qualification_state()?;
        Ok(manager)
    }

    pub fn configuration_snapshot(
        &self,
    ) -> Result<PrivacyConfigurationSnapshot, PrivacyManagerError> {
        self.refresh_qualification_state()?;
        let (config, config_valid, load_error) = {
            let state = self.state();
            (
                state.config.clone(),
                state.config_valid,
                state.load_error.clone(),
            )
        };
        let ocr_status = self.evaluate_local_ocr_status(&config);
        let qualification = self.current_qualification();
        let capabilities =
            PrivacyVNextCapabilityMatrix::current(config_valid, qualification.clone());
        Ok(PrivacyConfigurationSnapshot {
            config,
            config_valid,
            load_error,
            enforcement_state: "local_review_safe_exports_approved_paths_qualification_gated",
            ocr_status,
            qualification,
            capabilities,
        })
    }

    pub fn local_ocr_status(&self) -> Result<LocalOcrStatus, PrivacyManagerError> {
        let config = self.state().config.clone();
        self.refresh_qualification_state()?;
        Ok(self.evaluate_local_ocr_status(&config))
    }

    pub fn current_config(&self) -> PrivacyConfig {
        self.state().config.clone()
    }

    pub(crate) fn current_qualification(&self) -> PrivacyVNextQualificationStatus {
        self.state().qualification.clone()
    }

    pub(crate) fn local_ocr_qualification_snapshot(
        &self,
    ) -> Result<QualificationSnapshotV1, PrivacyManagerError> {
        self.refresh_qualification_state()?;
        let status = self.current_qualification();
        let report_id = status.qualification_report_id.ok_or_else(|| {
            PrivacyManagerError::new(
                "qualification_state_invalid",
                "The verified local OCR qualification report id is missing.",
            )
        })?;
        let report_sha256 =
            Sha256Hex::parse(status.qualification_report_sha256.ok_or_else(|| {
                PrivacyManagerError::new(
                    "qualification_state_invalid",
                    "The verified local OCR qualification report hash is missing.",
                )
            })?)
            .map_err(|_| {
                PrivacyManagerError::new(
                    "qualification_state_invalid",
                    "The verified local OCR qualification report hash is invalid.",
                )
            })?;
        let expires_at_unix = status.expires_at_unix.ok_or_else(|| {
            PrivacyManagerError::new(
                "qualification_state_invalid",
                "The verified local OCR qualification expiry is missing.",
            )
        })?;
        Ok(QualificationSnapshotV1 {
            qualification_report_id: Some(format!("qrep_{report_id}")),
            qualification_report_sha256: Some(report_sha256),
            processing_chain_qualified: status.processing_chain_qualified,
            exact_worker_model_match: status.exact_worker_model_match,
            network_isolation_enforced: status.network_isolation_enforced,
            model_manifest_trust_established: status.model_manifest_trust_established,
            production_case_ocr_authorized: status.production_case_ocr_authorized,
            expires_at_unix: Some(expires_at_unix),
            revoked: status.revoked,
        })
    }

    pub(crate) fn install_local_mineru_trust(
        &self,
    ) -> Result<TrustInstallationStatus, PrivacyManagerError> {
        self.reject_component_mutation_race()?;
        let environment = self.qualification_environment()?;
        self.preflight_ocr_publication_invalidation("local_ocr_trust_install")?;
        let installed = match self
            .shared
            .qualification_repository
            .install_trust(&environment)
        {
            Ok(installed) => installed,
            Err(error) => {
                self.clear_ocr_invalidation_preflight();
                return Err(error.into());
            }
        };
        if self.local_mineru_component_mutation_active() {
            let revocation = self
                .shared
                .qualification_repository
                .revoke_qualification_if_present();
            self.clear_ocr_invalidation_preflight();
            revocation?;
            return Err(component_mutation_race_error());
        }
        self.refresh_qualification_state()?;
        Ok(installed)
    }

    pub(crate) fn install_local_mineru_network_isolation(
        &self,
    ) -> Result<PrivacyConfigurationSnapshot, PrivacyManagerError> {
        self.reject_component_mutation_race()?;
        require_administrator_token()?;
        let environment = self.qualification_environment()?;
        self.preflight_ocr_publication_invalidation("local_ocr_firewall_change")?;
        let trust = match self
            .shared
            .qualification_repository
            .verify_trust(&environment)
        {
            Ok(trust) => trust,
            Err(error) => {
                self.clear_ocr_invalidation_preflight();
                return Err(error.into());
            }
        };
        if let Err(error) = self
            .shared
            .qualification_repository
            .install_firewall_isolation(&environment, &trust)
        {
            self.clear_ocr_invalidation_preflight();
            return Err(error.into());
        }
        if self.local_mineru_component_mutation_active() {
            let revocation = self
                .shared
                .qualification_repository
                .revoke_qualification_if_present();
            self.clear_ocr_invalidation_preflight();
            revocation?;
            return Err(component_mutation_race_error());
        }
        self.configuration_snapshot()
    }

    pub(crate) fn run_local_mineru_qualification(
        &self,
        ttl_seconds: u64,
        production_case_ocr_authorized: bool,
        app_auto_enable_authorized: bool,
    ) -> Result<PrivacyConfigurationSnapshot, PrivacyManagerError> {
        self.reject_component_mutation_race()?;
        if !(15 * 60..=90 * 24 * 60 * 60).contains(&ttl_seconds) {
            return Err(PrivacyManagerError::new(
                "qualification_expiry_invalid",
                "Qualification lifetime must be between 15 minutes and 90 days.",
            ));
        }
        let expires_at = unix_now()?.checked_add(ttl_seconds).ok_or_else(|| {
            PrivacyManagerError::new(
                "qualification_expiry_invalid",
                "Qualification expiry overflowed.",
            )
        })?;
        let environment = self.qualification_environment()?;
        let trust = self
            .shared
            .qualification_repository
            .verify_trust(&environment)?;
        self.preflight_ocr_publication_invalidation("local_ocr_qualification_report_change")?;
        if let Err(error) = self.shared.qualification_repository.run_qualification(
            &environment,
            &trust,
            expires_at,
            production_case_ocr_authorized,
            app_auto_enable_authorized,
        ) {
            self.clear_ocr_invalidation_preflight();
            return Err(error.into());
        }
        if self.local_mineru_component_mutation_active() {
            let revocation = self
                .shared
                .qualification_repository
                .revoke_qualification_if_present();
            self.clear_ocr_invalidation_preflight();
            revocation?;
            return Err(component_mutation_race_error());
        }
        self.configuration_snapshot()
    }

    pub(crate) fn revoke_local_mineru_qualification(
        &self,
    ) -> Result<PrivacyConfigurationSnapshot, PrivacyManagerError> {
        self.preflight_ocr_publication_invalidation("local_ocr_qualification_revoked")?;
        if let Err(error) = self
            .shared
            .qualification_repository
            .revoke_qualification_if_present()
        {
            self.clear_ocr_invalidation_preflight();
            return Err(error.into());
        }
        self.configuration_snapshot()
    }

    pub(crate) fn begin_local_mineru_component_mutation(
        &self,
    ) -> Result<LocalMineruComponentMutationGuard, PrivacyManagerError> {
        self.shared
            .local_mineru_component_mutation_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                PrivacyManagerError::new(
                    "component_mutation_in_progress",
                    "Another local MinerU component mutation is already in progress.",
                )
            })?;
        Ok(LocalMineruComponentMutationGuard {
            shared: Arc::clone(&self.shared),
        })
    }

    fn local_mineru_component_mutation_active(&self) -> bool {
        self.shared
            .local_mineru_component_mutation_active
            .load(Ordering::Acquire)
    }

    fn reject_component_mutation_race(&self) -> Result<(), PrivacyManagerError> {
        if self.local_mineru_component_mutation_active() {
            Err(component_mutation_race_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn local_mineru_config(
        &self,
    ) -> Result<Option<ProcessingMineruConfig>, PrivacyManagerError> {
        self.reject_component_mutation_race()?;
        let config = self.current_config();
        if config.ocr.mode == OcrMode::Off {
            return Ok(None);
        }
        let environment = self.qualification_environment_for(&config)?;
        let trust = self
            .shared
            .qualification_repository
            .verify_trust(&environment)?;
        let qualification = self
            .shared
            .qualification_repository
            .verify_qualification(&environment, &trust)?;
        if !qualification.synthetic_canary_qualified
            || !qualification.processing_chain_qualified
            || !qualification.production_case_ocr_authorized
            || !qualification.network_isolation_enforced
            || !qualification.model_manifest_trust_established
        {
            return Err(PrivacyManagerError::new(
                "production_case_ocr_not_authorized",
                "The current local OCR environment is not authorized for production case material.",
            ));
        }
        require_local_ocr_mode_authorization(
            config.ocr.mode,
            qualification.app_auto_enable_authorized,
        )?;

        let mut runtime_bindings = Vec::new();
        let mut seen = HashSet::new();
        for (index, path) in std::iter::once(&environment.worker_path)
            .chain(environment.runtime_executable_paths.iter())
            .enumerate()
        {
            let role = if index == 0 {
                LocalMineruRuntimeExecutableRole::Launcher
            } else {
                LocalMineruRuntimeExecutableRole::Executable
            };
            let binding = bind_local_mineru_runtime_executable(path, role)?;
            let key = binding.path.to_string_lossy().to_ascii_lowercase();
            if seen.insert(key) {
                runtime_bindings.push(binding);
            }
        }
        if runtime_bindings.is_empty()
            || runtime_bindings.len() != trust.firewall_rule_names().len()
        {
            return Err(PrivacyManagerError::new(
                "trusted_runtime_changed",
                "The runtime executable set no longer matches the trusted installation.",
            ));
        }
        let manifest = build_local_mineru_runtime_manifest(
            "lawyer-assistance-mineru-runtime-v1",
            &runtime_bindings,
        )?;
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| {
            PrivacyManagerError::new(
                "runtime_manifest_invalid",
                "The local OCR runtime manifest could not be serialized.",
            )
        })?;
        let runtime_manifest_path = self
            .shared
            .privacy_directory
            .join("local-mineru-runtime-manifest.json");
        persist_bounded_bytes(&runtime_manifest_path, &manifest_bytes, MAX_MANIFEST_BYTES)?;
        let runtime_manifest_sha256 = sha256_bytes(&manifest_bytes);
        let support_manifest_path = environment
            .worker_path
            .with_file_name("mineru-worker.support-manifest.json");

        let mut rules = Vec::with_capacity(runtime_bindings.len());
        for (binding, rule_name) in runtime_bindings
            .iter()
            .zip(trust.firewall_rule_names().iter())
        {
            let measured = measure_windows_firewall_isolation(&binding.path, rule_name)?;
            rules.push(NetworkIsolationRuleEvidence {
                program_path: binding.path.clone(),
                firewall_rule_name: rule_name.clone(),
                expected_policy_sha256: measured.policy_sha256,
            });
        }
        let temporary_root =
            ensure_directory(&self.shared.privacy_directory.join("ocr-runtime"), true)?;
        let timeout_ms = config
            .ocr
            .timeout_seconds
            .checked_mul(1_000)
            .ok_or_else(|| {
                PrivacyManagerError::new("invalid_configuration", "OCR timeout overflowed.")
            })?;
        let processing = ProcessingMineruConfig {
            executable: runtime_bindings[0].path.clone(),
            expected_executable_sha256: runtime_bindings[0].expected_sha256.clone(),
            runtime_executables: runtime_bindings,
            runtime_manifest: runtime_manifest_path,
            expected_runtime_manifest_sha256: runtime_manifest_sha256,
            support_manifest: support_manifest_path,
            expected_support_manifest_sha256: trust.support_manifest_sha256().to_owned(),
            mineru_config: environment.tools_config_path,
            expected_config_sha256: trust.tools_config_sha256().to_owned(),
            model_root: environment.model_root,
            model_manifest: trust.model_manifest_path().to_path_buf(),
            expected_model_manifest_sha256: trust.model_manifest_sha256().to_owned(),
            temporary_root,
            backend: MineruBackend::Pipeline,
            device: parse_processing_device(&config.ocr.device)?,
            language: processing_language(&config.ocr.languages)?,
            timeout_ms,
            max_output_bytes: 512 * 1024 * 1024,
            strict_offline: true,
            network_isolation: NetworkIsolationEvidence {
                verified: true,
                mechanism: WINDOWS_FIREWALL_ISOLATION_MECHANISM.to_owned(),
                checked_at_unix: unix_now()?,
                rules,
            },
            qualification_report_id: format!("qrep_{}", qualification.qualification_report_id),
            expected_worker_identity_sha256: qualification.worker_protocol_identity_sha256,
        };
        if let Err(error) = validate_local_mineru_config(&processing) {
            self.preflight_ocr_publication_invalidation("local_ocr_runtime_drift")?;
            if let Err(revoke_error) = self
                .shared
                .qualification_repository
                .revoke_qualification_if_present()
            {
                self.clear_ocr_invalidation_preflight();
                return Err(revoke_error.into());
            }
            self.refresh_qualification_state()?;
            return Err(error.into());
        }
        self.reject_component_mutation_race()?;
        Ok(Some(processing))
    }

    pub(crate) fn inspect_local_mineru_qualification_report(
        &self,
        report_json: &str,
    ) -> Result<PrivacyVNextQualificationStatus, PrivacyManagerError> {
        let config = self.state().config.clone();
        let ocr_status = inspect_local_ocr(&config.ocr);
        let expected_worker = ocr_status
            .worker_sha256
            .as_deref()
            .map(Sha256Hex::parse)
            .transpose()
            .map_err(|_| {
                PrivacyManagerError::new(
                    "qualification_report_rejected",
                    "local OCR worker hash is invalid; qualification remains blocked",
                )
            })?;
        let expected_model = ocr_status
            .model_manifest_sha256
            .as_deref()
            .map(Sha256Hex::parse)
            .transpose()
            .map_err(|_| {
                PrivacyManagerError::new(
                    "qualification_report_rejected",
                    "local OCR model manifest hash is invalid; qualification remains blocked",
                )
            })?;
        let snapshot = parse_local_mineru_qualification_report(
            report_json.as_bytes(),
            expected_worker.as_ref(),
            expected_model.as_ref(),
            None,
        )
        .map_err(|error| {
            PrivacyManagerError::new(
                "qualification_report_rejected",
                format!("local MinerU qualification report rejected: {error}"),
            )
        })?;
        Ok(PrivacyVNextQualificationStatus {
            qualification_id: None,
            qualification_report_id: snapshot.qualification_report_id,
            qualification_report_sha256: snapshot
                .qualification_report_sha256
                .map(|value| value.as_str().to_owned()),
            synthetic_canary_qualified: snapshot.processing_chain_qualified,
            processing_chain_qualified: snapshot.processing_chain_qualified,
            exact_worker_model_match: snapshot.exact_worker_model_match,
            // Imported reports are diagnostic only. Production gates derive from
            // app-signed state plus current environment remeasurement.
            network_isolation_enforced: false,
            model_manifest_trust_established: false,
            app_auto_enable_authorized: false,
            production_case_ocr_authorized: false,
            expires_at_unix: None,
            revoked: false,
            reason_codes: vec!["diagnostic_report_not_trusted".to_owned()],
            worker_protocol_version: None,
            worker_protocol_identity_sha256: None,
            worker_health_evidence_sha256: None,
            worker_version: None,
            python_version: None,
            mineru_version: None,
            pytorch_version: None,
            cuda_runtime_version: None,
            gpu_driver_version: None,
            model_version: None,
            selected_cuda_device: None,
            selected_gpu_memory_mib: None,
            selected_gpu_name: None,
        })
    }

    pub fn save_config(
        &self,
        config: PrivacyConfig,
    ) -> Result<PrivacyConfigurationSnapshot, PrivacyManagerError> {
        validate_config(&config)?;
        let ocr_configuration_changed = self.current_config().ocr != config.ocr;
        if ocr_configuration_changed && !self.local_mineru_component_mutation_active() {
            self.preflight_ocr_publication_invalidation("local_ocr_configuration_changed")?;
        }
        if let Err(error) = persist_config(&self.shared.config_path, &config) {
            if ocr_configuration_changed && !self.local_mineru_component_mutation_active() {
                self.clear_ocr_invalidation_preflight();
            }
            return Err(error);
        }
        {
            let mut state = self.state();
            state.config = config;
            state.config_valid = true;
            state.load_error = None;
        }
        self.refresh_qualification_state()?;
        self.configuration_snapshot()
    }

    fn qualification_environment(&self) -> Result<QualificationEnvironment, PrivacyManagerError> {
        let config = self.current_config();
        self.qualification_environment_for(&config)
    }

    fn qualification_environment_for(
        &self,
        config: &PrivacyConfig,
    ) -> Result<QualificationEnvironment, PrivacyManagerError> {
        validate_config(config)?;
        let worker_path = config.ocr.worker_path.clone().ok_or_else(|| {
            PrivacyManagerError::new(
                "ocr_not_configured",
                "Configure a local MinerU worker first.",
            )
        })?;
        let tools_config_path = config.ocr.tools_config_path.clone().ok_or_else(|| {
            PrivacyManagerError::new("ocr_not_configured", "Configure MinerU tools JSON first.")
        })?;
        let model_root = config.ocr.model_directory.clone().ok_or_else(|| {
            PrivacyManagerError::new(
                "ocr_not_configured",
                "Configure the local MinerU model directory first.",
            )
        })?;
        let system_root = std::env::var_os("SystemRoot").ok_or_else(|| {
            PrivacyManagerError::new(
                "gpu_probe_unavailable",
                "The local Windows root is unavailable for NVIDIA GPU verification.",
            )
        })?;
        Ok(QualificationEnvironment {
            worker_path,
            tools_config_path,
            model_root,
            nvidia_smi_path: PathBuf::from(system_root)
                .join("System32")
                .join("nvidia-smi.exe"),
            runtime_executable_paths: config.ocr.runtime_executable_paths.clone(),
            timeout_seconds: config.ocr.timeout_seconds,
        })
    }

    fn refresh_qualification_state(&self) -> Result<(), PrivacyManagerError> {
        let qualification = match self.qualification_environment() {
            Ok(environment) => match self
                .shared
                .qualification_repository
                .verify_trust(&environment)
            {
                Ok(trust) => match self
                    .shared
                    .qualification_repository
                    .verify_qualification(&environment, &trust)
                {
                    Ok(value) => PrivacyVNextQualificationStatus {
                        qualification_id: Some(value.qualification_id),
                        qualification_report_id: Some(value.qualification_report_id),
                        qualification_report_sha256: Some(value.qualification_report_sha256),
                        synthetic_canary_qualified: value.synthetic_canary_qualified,
                        processing_chain_qualified: value.processing_chain_qualified,
                        exact_worker_model_match: true,
                        network_isolation_enforced: value.network_isolation_enforced,
                        model_manifest_trust_established: value.model_manifest_trust_established,
                        app_auto_enable_authorized: value.app_auto_enable_authorized,
                        production_case_ocr_authorized: value.production_case_ocr_authorized,
                        expires_at_unix: Some(value.expires_at_unix),
                        revoked: false,
                        reason_codes: Vec::new(),
                        worker_protocol_version: Some(value.worker_protocol_version),
                        worker_protocol_identity_sha256: Some(
                            value.worker_protocol_identity_sha256,
                        ),
                        worker_health_evidence_sha256: Some(value.worker_health_evidence_sha256),
                        worker_version: Some(value.worker_version),
                        python_version: Some(value.python_version),
                        mineru_version: Some(value.mineru_version),
                        pytorch_version: Some(value.pytorch_version),
                        cuda_runtime_version: Some(value.cuda_runtime_version),
                        gpu_driver_version: Some(value.gpu_driver_version),
                        model_version: Some(value.model_version),
                        selected_cuda_device: Some(value.selected_cuda_device),
                        selected_gpu_memory_mib: Some(value.selected_gpu_memory_mib),
                        selected_gpu_name: Some(value.selected_gpu_name),
                    },
                    Err(error) => PrivacyVNextQualificationStatus::blocked(error.code()),
                },
                Err(error) => PrivacyVNextQualificationStatus::blocked(error.code()),
            },
            Err(error) => PrivacyVNextQualificationStatus::blocked(error.code()),
        };
        let (previous, blocked_ocr_publications_secured) = {
            let state = self.state();
            (
                state.qualification.clone(),
                state.blocked_ocr_publications_secured,
            )
        };
        let authorized = qualification.production_ocr_chain_authorized();
        let authorized_boundary_changed =
            authorized && previous.production_ocr_chain_authorized() && previous != qualification;
        let preflight_completed = self
            .shared
            .ocr_invalidation_preflight_completed
            .load(Ordering::Acquire);
        let invalidation_required = if authorized {
            authorized_boundary_changed && !preflight_completed
        } else {
            !blocked_ocr_publications_secured && !preflight_completed
        };
        if invalidation_required {
            self.invalidate_ocr_publications("local_ocr_qualification_state_changed")?;
        }

        {
            let mut state = self.state();
            state.qualification = qualification;
            state.blocked_ocr_publications_secured = !authorized;
        }
        if preflight_completed {
            self.shared
                .ocr_invalidation_preflight_completed
                .store(false, Ordering::Release);
        }
        Ok(())
    }

    fn invalidate_ocr_publications(
        &self,
        reason_code: &'static str,
    ) -> Result<u64, PrivacyManagerError> {
        let Some(invalidator) = self.shared.ocr_qualification_invalidator.as_ref() else {
            return Ok(0);
        };
        invalidator
            .invalidate_ocr_derived(reason_code)
            .map_err(|_| {
                PrivacyManagerError::new(
                    "ocr_derived_publication_invalidation_failed",
                    "OCR-derived approved publications could not be invalidated; the qualification or component change was not applied.",
                )
            })
    }

    fn preflight_ocr_publication_invalidation(
        &self,
        reason_code: &'static str,
    ) -> Result<u64, PrivacyManagerError> {
        let invalidated = self.invalidate_ocr_publications(reason_code)?;
        self.shared
            .ocr_invalidation_preflight_completed
            .store(true, Ordering::Release);
        Ok(invalidated)
    }

    fn clear_ocr_invalidation_preflight(&self) {
        self.shared
            .ocr_invalidation_preflight_completed
            .store(false, Ordering::Release);
    }

    fn evaluate_local_ocr_status(&self, config: &PrivacyConfig) -> LocalOcrStatus {
        let mut status = inspect_local_ocr(&config.ocr);
        if config.ocr.mode == OcrMode::Off {
            return status;
        }
        if let Ok(environment) = self.qualification_environment_for(config) {
            if let Ok(trust) = self
                .shared
                .qualification_repository
                .verify_trust(&environment)
            {
                status.integrity_verified = true;
                status.worker_sha256 = Some(trust.worker_sha256().to_owned());
                status.model_manifest_sha256 = Some(trust.model_manifest_sha256().to_owned());
                status.network_isolation_verified = self
                    .shared
                    .qualification_repository
                    .verify_firewall_isolation(&environment, &trust)
                    .is_ok();
                let qualification = self.current_qualification();
                status.worker_protocol_version = qualification.worker_protocol_version.clone();
                status.worker_protocol_identity_sha256 =
                    qualification.worker_protocol_identity_sha256.clone();
                status.worker_health_evidence_sha256 =
                    qualification.worker_health_evidence_sha256.clone();
                status.worker_version = qualification.worker_version.clone();
                status.python_version = qualification.python_version.clone();
                status.mineru_version = qualification.mineru_version.clone();
                status.pytorch_version = qualification.pytorch_version.clone();
                status.cuda_runtime_version = qualification.cuda_runtime_version.clone();
                status.gpu_driver_version = qualification.gpu_driver_version.clone();
                status.model_version = qualification.model_version.clone();
                if self
                    .current_qualification()
                    .production_ocr_chain_authorized()
                {
                    status.code = LocalOcrStatusCode::Ready;
                    status.message =
                        "Local MinerU integrity and Windows network isolation are verified."
                            .to_owned();
                } else {
                    status.message =
                        "Local components are trusted; synthetic qualification and explicit authorization remain required."
                            .to_owned();
                }
            }
        }
        status
    }
    fn state(&self) -> MutexGuard<'_, ManagerState> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn component_mutation_race_error() -> PrivacyManagerError {
    PrivacyManagerError::new(
        "qualification_component_mutation_race",
        "Local OCR qualification and execution are blocked while a component mutation is active.",
    )
}

fn require_local_ocr_mode_authorization(
    mode: OcrMode,
    app_auto_enable_authorized: bool,
) -> Result<(), PrivacyManagerError> {
    if mode == OcrMode::AutoLocal && !app_auto_enable_authorized {
        return Err(PrivacyManagerError::new(
            "app_auto_ocr_not_authorized",
            "Automatic local OCR is not authorized by the current qualification.",
        ));
    }
    Ok(())
}

const fn current_schema_version() -> u16 {
    PRIVACY_CONFIG_SCHEMA_VERSION
}

const fn enabled() -> bool {
    true
}

fn default_device() -> String {
    "auto".to_owned()
}

fn default_languages() -> Vec<String> {
    vec!["zh".to_owned(), "en".to_owned()]
}

const fn default_timeout_seconds() -> u64 {
    300
}

const fn default_max_pages() -> u32 {
    200
}

fn unix_now() -> Result<u64, PrivacyManagerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| PrivacyManagerError::new("clock_invalid", "System clock is invalid."))
}
fn parse_processing_device(value: &str) -> Result<DeviceSelection, PrivacyManagerError> {
    match value {
        "auto" => Ok(DeviceSelection::Auto),
        "cpu" => Ok(DeviceSelection::Cpu),
        "cuda" => Ok(DeviceSelection::Cuda { indices: vec![0] }),
        _ => value
            .strip_prefix("cuda:")
            .and_then(|index| index.parse::<u32>().ok())
            .map(|index| DeviceSelection::Cuda {
                indices: vec![index],
            })
            .ok_or_else(|| {
                PrivacyManagerError::new("invalid_configuration", "Unsupported OCR device.")
            }),
    }
}

fn processing_language(languages: &[String]) -> Result<String, PrivacyManagerError> {
    if languages.iter().any(|language| {
        matches!(
            language.to_ascii_lowercase().as_str(),
            "zh" | "zh-cn" | "zh_cn" | "en" | "ch"
        )
    }) {
        return Ok("ch".to_owned());
    }
    let first = languages.first().map(|value| value.to_ascii_lowercase());
    match first.as_deref() {
        Some("ko" | "korean") => Ok("korean".to_owned()),
        Some(
            "ta" | "te" | "ka" | "th" | "el" | "arabic" | "east_slavic" | "cyrillic" | "devanagari"
            | "ch_server",
        ) => Ok(first.unwrap_or_default()),
        _ => Err(PrivacyManagerError::new(
            "invalid_configuration",
            "The selected OCR language is not supported by the local pipeline.",
        )),
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn persist_bounded_bytes(
    path: &Path,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<(), PrivacyManagerError> {
    if bytes.is_empty() || bytes.len() as u64 > max_bytes {
        return Err(PrivacyManagerError::new(
            "runtime_manifest_invalid",
            "The local OCR runtime manifest size is invalid.",
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.is_file() || is_reparse_point(&metadata) || !single_link_file(path) {
            return Err(PrivacyManagerError::new(
                "filesystem_rejected",
                "The local OCR runtime manifest target is not an ordinary private file.",
            ));
        }
    }
    let parent = path.parent().ok_or_else(|| {
        PrivacyManagerError::new(
            "runtime_manifest_invalid",
            "Runtime manifest has no parent.",
        )
    })?;
    let incoming = parent.join(format!(".runtime-manifest.{}.incoming", Uuid::new_v4()));
    let result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&incoming)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        crate::atomic_file::install(&incoming, path, None)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&incoming);
        return Err(PrivacyManagerError::new(
            "runtime_manifest_unavailable",
            "The local OCR runtime manifest could not be committed atomically.",
        ));
    }
    Ok(())
}

fn single_link_file(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).open(path) else {
        return false;
    };
    let handle = file.as_raw_handle() as HANDLE;
    if handle.is_null() {
        return false;
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    (unsafe { GetFileInformationByHandle(handle, &mut information) }) != 0
        && information.nNumberOfLinks == 1
}

fn validate_config(config: &PrivacyConfig) -> Result<(), PrivacyManagerError> {
    if config.schema_version != PRIVACY_CONFIG_SCHEMA_VERSION {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "隐私配置 schema 版本不受支持。",
        ));
    }
    if !config.ocr.strict_offline {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "真实案件的本地 OCR 必须启用严格离线模式。",
        ));
    }
    if !config.ocr.forbid_cloud_fallback {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "真实案件不得启用云端 OCR 回退。",
        ));
    }
    if !config.ocr.forbid_remote_upload {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "真实案件材料和 OCR 产物不得上传到远端服务。",
        ));
    }
    if !config.ocr.forbid_telemetry {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "本地 OCR 不得发送材料、正文或运行遥测。",
        ));
    }
    validate_optional_absolute_path("worker", config.ocr.worker_path.as_deref())?;
    validate_optional_absolute_path("model", config.ocr.model_directory.as_deref())?;
    validate_optional_absolute_path("tools config", config.ocr.tools_config_path.as_deref())?;
    if config.ocr.runtime_executable_paths.len() > 64 {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "OCR runtime executable count exceeds 64.",
        ));
    }
    let mut runtime_paths = HashSet::new();
    for path in &config.ocr.runtime_executable_paths {
        validate_optional_absolute_path("runtime executable", Some(path.as_path()))?;
        if !runtime_paths.insert(path.to_string_lossy().to_ascii_lowercase()) {
            return Err(PrivacyManagerError::new(
                "invalid_configuration",
                "OCR runtime executable paths must be unique.",
            ));
        }
    }
    if config.ocr.mode != OcrMode::Off
        && (config.ocr.worker_path.is_none()
            || config.ocr.model_directory.is_none()
            || config.ocr.tools_config_path.is_none())
    {
        return Err(PrivacyManagerError::new(
            "ocr_not_configured",
            "Worker, MinerU tools JSON, and model directory are required before enabling local OCR.",
        ));
    }
    if !valid_device(&config.ocr.device) {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "OCR 设备必须为 auto、cpu、cuda 或 cuda:<编号>。",
        ));
    }
    if config.ocr.languages.is_empty() || config.ocr.languages.len() > MAX_LANGUAGES {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "OCR 语言列表必须包含 1 到 16 个语言标识。",
        ));
    }
    let mut seen = HashSet::new();
    for language in &config.ocr.languages {
        if language.len() > 16
            || language.len() < 2
            || !language
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
            || !seen.insert(language.to_ascii_lowercase())
        {
            return Err(PrivacyManagerError::new(
                "invalid_configuration",
                "OCR 语言标识必须唯一，并仅包含 ASCII 字母、数字、连字符或下划线。",
            ));
        }
    }
    if !(MIN_TIMEOUT_SECONDS..=MAX_TIMEOUT_SECONDS).contains(&config.ocr.timeout_seconds) {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "OCR 超时必须在 10 到 7200 秒之间。",
        ));
    }
    if config.ocr.max_pages == 0 || config.ocr.max_pages > MAX_OCR_PAGES {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            "OCR 最大页数必须在 1 到 500 之间，以匹配安全 PDF 导出上限。",
        ));
    }
    Ok(())
}

fn valid_device(value: &str) -> bool {
    matches!(value, "auto" | "cpu" | "cuda")
        || value.strip_prefix("cuda:").is_some_and(|index| {
            !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn validate_optional_absolute_path(
    kind: &'static str,
    path: Option<&Path>,
) -> Result<(), PrivacyManagerError> {
    let Some(path) = path else {
        return Ok(());
    };
    if !is_normal_local_absolute(path) {
        return Err(PrivacyManagerError::new(
            "invalid_configuration",
            format!("OCR {kind} 路径必须位于本机非网络磁盘，且不含 . 或 .. 片段。"),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if is_reparse_point(&metadata) || has_cloud_recall_attributes(&metadata) => {
            Err(PrivacyManagerError::new(
                "filesystem_rejected",
                format!("OCR {kind} 路径不得指向链接、reparse point 或云端占位/召回对象。"),
            ))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PrivacyManagerError::new(
            "filesystem_unavailable",
            format!("OCR {kind} 路径无法检查。"),
        )),
    }
}

fn inspect_local_ocr(config: &LocalOcrConfig) -> LocalOcrStatus {
    if config.mode == OcrMode::Off {
        return status(
            LocalOcrStatusCode::Disabled,
            "本地 OCR 已关闭。",
            false,
            false,
        );
    }
    let (Some(worker_path), Some(model_directory), Some(tools_config_path)) = (
        config.worker_path.as_deref(),
        config.model_directory.as_deref(),
        config.tools_config_path.as_deref(),
    ) else {
        return status(
            LocalOcrStatusCode::NotConfigured,
            "请配置 MinerU worker 绝对路径和模型目录。",
            config.worker_path.is_some(),
            config.model_directory.is_some(),
        );
    };

    let worker_metadata = match ordinary_metadata(worker_path, false) {
        Ok(metadata) if metadata.len() <= MAX_WORKER_BYTES => metadata,
        Ok(_) => {
            return status(
                LocalOcrStatusCode::Unavailable,
                "MinerU worker 超过本地完整性检查上限。",
                true,
                model_directory.is_dir(),
            )
        }
        Err(message) => {
            return status(
                LocalOcrStatusCode::Unavailable,
                message,
                false,
                model_directory.is_dir(),
            )
        }
    };
    let model_metadata = match ordinary_metadata(model_directory, true) {
        Ok(metadata) => metadata,
        Err(message) => {
            return status(
                LocalOcrStatusCode::Unavailable,
                message,
                worker_metadata.is_file(),
                false,
            )
        }
    };
    if ordinary_metadata(tools_config_path, false).is_err() {
        return status(
            LocalOcrStatusCode::Unavailable,
            "MinerU tools JSON is missing, unavailable, or not an ordinary local file.",
            worker_metadata.is_file(),
            model_metadata.is_dir(),
        );
    }
    let worker_sha256 = match sha256_file(worker_path, MAX_WORKER_BYTES) {
        Ok(hash) => Some(hash),
        Err(_) => {
            return status(
                LocalOcrStatusCode::Unavailable,
                "MinerU worker 无法完成本地哈希检查。",
                true,
                true,
            )
        }
    };
    let worker_version = worker_manifest_path(worker_path)
        .and_then(|path| read_manifest_version(&path).ok().flatten());
    let model_manifest_path = model_directory.join(MODEL_MANIFEST_FILE_NAME);
    let (model_version, model_manifest_sha256) =
        match ordinary_metadata(&model_manifest_path, false) {
            Ok(metadata) if metadata.len() <= MAX_MANIFEST_BYTES => (
                read_manifest_version(&model_manifest_path).ok().flatten(),
                sha256_file(&model_manifest_path, MAX_MANIFEST_BYTES).ok(),
            ),
            _ => (None, None),
        };
    debug_assert!(worker_metadata.is_file());
    debug_assert!(model_metadata.is_dir());
    LocalOcrStatus {
        code: LocalOcrStatusCode::ConfiguredUnverified,
        message: "本地文件已配置并可读取；尚未执行 OCR、来源认证或网络隔离实机验证。".to_owned(),
        worker_version,
        model_version,
        worker_sha256,
        model_manifest_sha256,
        worker_present: true,
        model_directory_present: true,
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
    }
}

fn status(
    code: LocalOcrStatusCode,
    message: impl Into<String>,
    worker_present: bool,
    model_directory_present: bool,
) -> LocalOcrStatus {
    LocalOcrStatus {
        code,
        message: message.into(),
        worker_version: None,
        model_version: None,
        worker_sha256: None,
        model_manifest_sha256: None,
        worker_present,
        model_directory_present,
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
    }
}

fn ordinary_metadata(path: &Path, expect_directory: bool) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        if expect_directory {
            "MinerU 模型目录不存在或不可访问。".to_owned()
        } else {
            "MinerU worker 不存在或不可访问。".to_owned()
        }
    })?;
    let expected_type = if expect_directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if !expected_type || is_reparse_point(&metadata) || has_cloud_recall_attributes(&metadata) {
        return Err(if expect_directory {
            "MinerU 模型目录必须是普通本地目录，不能是链接、reparse point 或云端占位对象。"
                .to_owned()
        } else {
            "MinerU worker 必须是普通本地文件，不能是链接、reparse point 或云端占位对象。"
                .to_owned()
        });
    }
    Ok(metadata)
}

fn worker_manifest_path(worker_path: &Path) -> Option<PathBuf> {
    let file_name = worker_path.file_name()?.to_string_lossy();
    Some(worker_path.with_file_name(format!("{file_name}.manifest.json")))
}

fn read_manifest_version(path: &Path) -> Result<Option<String>, PrivacyManagerError> {
    let metadata = ordinary_metadata(path, false).map_err(|_| {
        PrivacyManagerError::new("manifest_unavailable", "本地组件 manifest 不可用。")
    })?;
    if metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(PrivacyManagerError::new(
            "manifest_invalid",
            "本地组件 manifest 大小无效。",
        ));
    }
    let bytes = fs::read(path).map_err(|_| {
        PrivacyManagerError::new("manifest_unavailable", "本地组件 manifest 无法读取。")
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
        PrivacyManagerError::new("manifest_invalid", "本地组件 manifest 不是有效 JSON。")
    })?;
    Ok(value
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|version| !version.trim().is_empty() && version.len() <= 128)
        .map(str::to_owned))
}

fn sha256_file(path: &Path, max_bytes: u64) -> Result<String, PrivacyManagerError> {
    let metadata = ordinary_metadata(path, false)
        .map_err(|_| PrivacyManagerError::new("hash_unavailable", "本地组件无法进行哈希检查。"))?;
    if metadata.len() > max_bytes {
        return Err(PrivacyManagerError::new(
            "hash_unavailable",
            "本地组件超过哈希检查上限。",
        ));
    }
    let mut file = fs::File::open(path)
        .map_err(|_| PrivacyManagerError::new("hash_unavailable", "本地组件无法进行哈希检查。"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|_| {
            PrivacyManagerError::new("hash_unavailable", "本地组件无法进行哈希检查。")
        })?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn ensure_directory(path: &Path, create: bool) -> Result<PathBuf, PrivacyManagerError> {
    if create {
        fs::create_dir_all(path).map_err(|_| {
            PrivacyManagerError::new("filesystem_unavailable", "隐私配置目录无法创建。")
        })?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| PrivacyManagerError::new("filesystem_unavailable", "隐私配置目录不可用。"))?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(PrivacyManagerError::new(
            "filesystem_rejected",
            "隐私配置目录必须是普通本地目录。",
        ));
    }
    Ok(path.to_path_buf())
}

fn read_config(path: &Path) -> Result<PrivacyConfig, PrivacyManagerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        PrivacyManagerError::new("configuration_unavailable", "隐私配置文件无法读取。")
    })?;
    if !metadata.is_file()
        || is_reparse_point(&metadata)
        || metadata.len() == 0
        || metadata.len() > MAX_CONFIG_BYTES
    {
        return Err(PrivacyManagerError::new(
            "configuration_invalid",
            "隐私配置必须是普通且大小受限的 JSON 文件。",
        ));
    }
    let bytes = fs::read(path).map_err(|_| {
        PrivacyManagerError::new("configuration_unavailable", "隐私配置文件无法读取。")
    })?;
    let config: PrivacyConfig = serde_json::from_slice(&bytes)
        .map_err(|_| PrivacyManagerError::new("configuration_invalid", "隐私配置 JSON 无效。"))?;
    validate_config(&config)?;
    Ok(config)
}

fn persist_config(path: &Path, config: &PrivacyConfig) -> Result<(), PrivacyManagerError> {
    validate_config(config)?;
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|_| PrivacyManagerError::new("configuration_invalid", "隐私配置无法序列化。"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(PrivacyManagerError::new(
            "configuration_invalid",
            "隐私配置超过大小上限。",
        ));
    }
    let parent = path.parent().ok_or_else(|| {
        PrivacyManagerError::new("configuration_invalid", "隐私配置路径缺少父目录。")
    })?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.is_file() || is_reparse_point(&metadata) => {
            return Err(PrivacyManagerError::new(
                "configuration_invalid",
                "隐私配置目标必须是普通文件。",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(PrivacyManagerError::new(
                "configuration_unavailable",
                "隐私配置目标无法检查。",
            ));
        }
    }
    let incoming = parent.join(format!(".{CONFIG_FILE_NAME}.{}.incoming", Uuid::new_v4()));
    let write_result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&incoming)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        crate::atomic_file::install(&incoming, path, None)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&incoming);
        return Err(PrivacyManagerError::new(
            "configuration_unavailable",
            "隐私配置无法原子保存。",
        ));
    }
    Ok(())
}

pub(crate) fn is_normal_local_absolute(path: &Path) -> bool {
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(drive) => drive,
            _ => return false,
        },
        _ => return false,
    };
    if !matches!(components.next(), Some(Component::RootDir)) {
        return false;
    }
    for component in components {
        let Component::Normal(segment) = component else {
            return false;
        };
        // A colon after the drive prefix addresses an NTFS alternate data
        // stream. It is not a distinct ordinary destination file.
        if segment.to_string_lossy().contains(':') {
            return false;
        }
    }
    let root = [u16::from(drive), u16::from(b':'), u16::from(b'\\'), 0];
    // SAFETY: root is a fixed four-element, NUL-terminated UTF-16 drive-root buffer.
    unsafe { GetDriveTypeW(root.as_ptr()) == 3 }
}

pub(crate) fn local_path_chain_is_ordinary(path: &Path) -> bool {
    if !is_normal_local_absolute(path) {
        return false;
    }
    let mut found_existing = false;
    for candidate in path.ancestors() {
        match fs::symlink_metadata(candidate) {
            Ok(metadata) => {
                found_existing = true;
                if is_reparse_point(&metadata) || has_cloud_recall_attributes(&metadata) {
                    return false;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return false,
        }
    }
    found_existing
}

pub(crate) fn opened_file_resolves_to_ordinary_local(file: &fs::File) -> bool {
    let handle = file.as_raw_handle() as HANDLE;
    // SAFETY: the file handle remains live for both calls; the second buffer is
    // sized from the first call and is writable for its full declared length.
    let required = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if required == 0 {
        return false;
    }
    let mut buffer = vec![0_u16; required as usize + 1];
    // SAFETY: see above. Windows writes at most buffer.len() UTF-16 code units.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return false;
    }
    let final_path = OsString::from_wide(&buffer[..written as usize]);
    let rendered = final_path.to_string_lossy();
    let normalized = if let Some(unc) = rendered.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{unc}"))
    } else if let Some(dos) = rendered.strip_prefix(r"\\?\") {
        PathBuf::from(dos)
    } else {
        PathBuf::from(final_path)
    };
    local_path_chain_is_ordinary(&normalized)
}

pub(crate) fn has_cloud_recall_attributes(metadata: &fs::Metadata) -> bool {
    let attributes = metadata.file_attributes();
    attributes
        & (FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
        != 0
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestOcrInvalidator {
        fail: AtomicBool,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl OcrQualificationInvalidator for TestOcrInvalidator {
        fn invalidate_ocr_derived(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            if self.fail.load(Ordering::Acquire) {
                Err("synthetic_invalidation_failure")
            } else {
                Ok(1)
            }
        }
    }

    #[test]
    fn local_absolute_path_rejects_ntfs_alternate_data_streams() {
        assert!(!is_normal_local_absolute(Path::new(
            r#"C:\privacy-export.txt:case-stream"#,
        )));
        assert!(!is_normal_local_absolute(Path::new(
            r#"C:\folder:stream\privacy-export.txt"#,
        )));
        assert!(is_normal_local_absolute(Path::new(
            r#"C:\privacy-export.txt"#,
        )));
    }

    fn configured(directory: &Path) -> PrivacyConfig {
        let worker = directory.join("mineru-worker.exe");
        let models = directory.join("models");
        let tools_config = directory.join("mineru-tools.json");
        fs::write(&worker, b"local-worker").expect("worker writes");
        fs::write(
            directory.join("mineru-worker.exe.manifest.json"),
            br#"{"version":"3.4.3-local"}"#,
        )
        .expect("worker manifest writes");
        fs::write(&tools_config, br#"{"pipeline":"local"}"#).expect("tools config writes");
        fs::create_dir_all(&models).expect("models create");
        fs::write(
            models.join(MODEL_MANIFEST_FILE_NAME),
            br#"{"version":"model-2026-07"}"#,
        )
        .expect("model manifest writes");
        PrivacyConfig {
            privacy_mode: PrivacyMode::ExternalRedacted,
            ocr: LocalOcrConfig {
                mode: OcrMode::ForceLocal,
                worker_path: Some(worker),
                model_directory: Some(models),
                tools_config_path: Some(tools_config),
                device: "cuda:0".to_owned(),
                ..LocalOcrConfig::default()
            },
            ..PrivacyConfig::default()
        }
    }

    #[test]
    fn defaults_are_strict_and_external_redacted() {
        let config = PrivacyConfig::default();
        assert_eq!(config.privacy_mode, PrivacyMode::ExternalRedacted);
        assert_eq!(config.ocr.mode, OcrMode::Off);
        assert!(config.ocr.strict_offline);
        assert!(config.ocr.forbid_cloud_fallback);
        assert!(config.ocr.forbid_remote_upload);
        assert!(config.ocr.forbid_telemetry);
    }

    #[test]
    fn auto_local_requires_explicit_app_authorization() {
        assert_eq!(
            require_local_ocr_mode_authorization(OcrMode::AutoLocal, false)
                .expect_err("AutoLocal must fail closed without explicit authorization")
                .code(),
            "app_auto_ocr_not_authorized"
        );
        require_local_ocr_mode_authorization(OcrMode::AutoLocal, true)
            .expect("explicitly authorized AutoLocal is permitted");
        require_local_ocr_mode_authorization(OcrMode::ForceLocal, false)
            .expect("manual local OCR does not inherit the AutoLocal-only gate");
    }

    #[test]
    fn invalid_configuration_blocks_hypothetically_qualified_production_capabilities() {
        let hypothetical_qualification = PrivacyVNextQualificationStatus {
            qualification_id: Some("qualification-v1".to_owned()),
            qualification_report_id: Some("qualification-report-v1".to_owned()),
            qualification_report_sha256: Some("a".repeat(64)),
            synthetic_canary_qualified: true,
            processing_chain_qualified: true,
            exact_worker_model_match: true,
            network_isolation_enforced: true,
            model_manifest_trust_established: true,
            app_auto_enable_authorized: true,
            production_case_ocr_authorized: true,
            expires_at_unix: Some(u64::MAX),
            revoked: false,
            reason_codes: Vec::new(),
            worker_protocol_version: None,
            worker_protocol_identity_sha256: None,
            worker_health_evidence_sha256: None,
            worker_version: None,
            python_version: None,
            mineru_version: None,
            pytorch_version: None,
            cuda_runtime_version: None,
            gpu_driver_version: None,
            model_version: None,
            selected_cuda_device: None,
            selected_gpu_memory_mib: None,
            selected_gpu_name: None,
        };
        let capabilities = PrivacyVNextCapabilityMatrix::current(false, hypothetical_qualification);
        assert!(!capabilities.local_gpu_preference_configurable);
        assert!(!capabilities.scanned_case_ocr_enabled);
        assert!(!capabilities.automatic_approval_enabled);
        assert!(capabilities
            .blocking_reason_codes
            .contains(&"privacy_configuration_invalid"));
    }

    #[test]
    fn schema_v1_missing_optional_fields_loads_safe_defaults() {
        let config: PrivacyConfig = serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "privacyMode": "raw_native",
            "ocr": {
                "mode": "auto_local",
                "workerPath": "C:/MinerU/mineru-worker.exe",
                "modelDirectory": "C:/MinerU/models",
                "toolsConfigPath": "C:/MinerU/mineru-tools.json"
            }
        }))
        .expect("v1 config parses");
        assert_eq!(config.privacy_mode, PrivacyMode::RawNative);
        assert_eq!(config.ocr.device, "auto");
        assert_eq!(config.ocr.languages, ["zh", "en"]);
        assert!(config.ocr.strict_offline);
        assert!(config.ocr.forbid_cloud_fallback);
        assert!(config.ocr.forbid_remote_upload);
        assert!(config.ocr.forbid_telemetry);
        validate_config(&config).expect("safe migrated defaults validate");
    }

    #[test]
    fn offline_upload_telemetry_and_path_invariants_fail_closed() {
        let mut config = PrivacyConfig::default();
        config.ocr.forbid_remote_upload = false;
        assert_eq!(
            validate_config(&config).unwrap_err().code(),
            "invalid_configuration"
        );
        config.ocr.forbid_remote_upload = true;
        config.ocr.forbid_telemetry = false;
        assert_eq!(
            validate_config(&config).unwrap_err().code(),
            "invalid_configuration"
        );
        config.ocr.forbid_telemetry = true;
        config.ocr.forbid_cloud_fallback = false;
        assert_eq!(
            validate_config(&config).unwrap_err().code(),
            "invalid_configuration"
        );

        config.ocr.forbid_cloud_fallback = true;
        config.ocr.strict_offline = false;
        assert_eq!(
            validate_config(&config).unwrap_err().code(),
            "invalid_configuration"
        );

        config.ocr.strict_offline = true;
        config.ocr.max_pages = 501;
        assert_eq!(
            validate_config(&config).unwrap_err().code(),
            "invalid_configuration"
        );

        config.ocr.max_pages = default_max_pages();
        config.ocr.worker_path = Some(PathBuf::from("relative-worker.exe"));
        assert_eq!(
            validate_config(&config).unwrap_err().code(),
            "invalid_configuration"
        );
    }

    #[test]
    fn manager_persists_config_and_reports_hashes_without_claiming_verification() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manager = PrivacyManager::new(directory.path().to_path_buf()).expect("manager");
        let config = configured(directory.path());
        let saved = manager.save_config(config.clone()).expect("config saves");
        assert_eq!(saved.config, config);
        assert!(saved.config_valid);
        assert_eq!(
            saved.enforcement_state,
            "local_review_safe_exports_approved_paths_qualification_gated"
        );
        assert_eq!(
            saved.ocr_status.code,
            LocalOcrStatusCode::ConfiguredUnverified
        );
        assert_eq!(
            saved.ocr_status.worker_version.as_deref(),
            Some("3.4.3-local")
        );
        assert_eq!(
            saved.ocr_status.model_version.as_deref(),
            Some("model-2026-07")
        );
        assert_eq!(
            saved.ocr_status.worker_sha256.as_deref().map(str::len),
            Some(64)
        );
        assert_eq!(
            saved
                .ocr_status
                .model_manifest_sha256
                .as_deref()
                .map(str::len),
            Some(64)
        );
        assert!(!saved.ocr_status.integrity_verified);
        assert!(!saved.ocr_status.network_isolation_verified);
        assert_eq!(
            saved.qualification.reason_codes,
            ["trusted_component_unavailable"]
        );
        assert!(saved.qualification.qualification_id.is_none());
        assert!(saved.qualification.qualification_report_id.is_none());
        assert!(!saved.qualification.network_isolation_enforced);
        assert!(!saved.qualification.model_manifest_trust_established);
        assert!(!saved.qualification.app_auto_enable_authorized);
        assert!(!saved.qualification.production_case_ocr_authorized);
        assert!(saved.capabilities.local_gpu_preference_configurable);
        assert!(!saved.capabilities.scanned_case_ocr_enabled);
        assert!(!saved.capabilities.automatic_approval_enabled);
        assert!(!saved.capabilities.remote_ocr_fallback_allowed);
        assert!(!saved.capabilities.telemetry_allowed);
        assert!(!saved.capabilities.raw_material_upload_allowed);

        let reopened = PrivacyManager::new(directory.path().to_path_buf()).expect("reopens");
        assert_eq!(
            reopened.configuration_snapshot().unwrap().config,
            saved.config
        );
    }

    #[test]
    fn ocr_invalidation_failure_preserves_config_and_live_qualification_state() {
        let directory = tempfile::tempdir().expect("temp directory");
        let invalidator = Arc::new(TestOcrInvalidator::default());
        let manager = PrivacyManager::new_with_ocr_qualification_invalidator(
            directory.path().to_path_buf(),
            invalidator.clone(),
        )
        .expect("manager");
        assert_eq!(invalidator.calls.load(Ordering::Acquire), 1);

        let original_config = manager.current_config();
        let original_bytes = fs::read(&manager.shared.config_path).expect("original config bytes");
        invalidator.fail.store(true, Ordering::Release);
        let error = manager
            .save_config(configured(directory.path()))
            .expect_err("OCR config mutation must stop before persistence");
        assert_eq!(error.code(), "ocr_derived_publication_invalidation_failed");
        assert_eq!(manager.current_config(), original_config);
        assert_eq!(
            fs::read(&manager.shared.config_path).expect("preserved config bytes"),
            original_bytes
        );

        let mut authorized = PrivacyVNextQualificationStatus::current();
        authorized.qualification_id = Some("qualification-before-drift".to_owned());
        authorized.processing_chain_qualified = true;
        authorized.exact_worker_model_match = true;
        authorized.network_isolation_enforced = true;
        authorized.model_manifest_trust_established = true;
        authorized.production_case_ocr_authorized = true;
        {
            let mut state = manager.state();
            state.qualification = authorized.clone();
            state.blocked_ocr_publications_secured = false;
        }
        let error = manager
            .configuration_snapshot()
            .expect_err("drift refresh must stop when selective revocation fails");
        assert_eq!(error.code(), "ocr_derived_publication_invalidation_failed");
        assert_eq!(manager.current_qualification(), authorized);
    }

    #[test]
    fn corrupt_saved_config_uses_safe_defaults_and_requires_explicit_repair() {
        let directory = tempfile::tempdir().expect("temp directory");
        let manager = PrivacyManager::new(directory.path().to_path_buf()).expect("manager");
        fs::write(&manager.shared.config_path, b"{not-json").expect("corrupt config writes");
        let reopened = PrivacyManager::new(directory.path().to_path_buf()).expect("reopens");
        let failed = reopened.configuration_snapshot().unwrap();
        assert!(!failed.config_valid);
        assert_eq!(failed.config, PrivacyConfig::default());
        assert!(failed.load_error.is_some());

        let repaired = reopened
            .save_config(PrivacyConfig::default())
            .expect("safe defaults repair config");
        assert!(repaired.config_valid);
        assert_eq!(repaired.load_error, None);
    }
    #[test]
    #[ignore = "requires a self-contained local MinerU component, RTX GPU, corpus, and administrator token"]
    fn qualifies_real_local_mineru_and_runs_full_synthetic_corpus_through_rust_host() {
        let state_directory = std::env::var_os("LA_REAL_MINERU_STATE_DIRECTORY")
            .map(PathBuf::from)
            .expect("LA_REAL_MINERU_STATE_DIRECTORY is required");
        let worker = std::env::var_os("LA_REAL_MINERU_WORKER")
            .map(PathBuf::from)
            .expect("LA_REAL_MINERU_WORKER is required");
        let model_root = std::env::var_os("LA_REAL_MINERU_MODEL_ROOT")
            .map(PathBuf::from)
            .expect("LA_REAL_MINERU_MODEL_ROOT is required");
        let corpus = std::env::var_os("LA_REAL_MINERU_CORPUS_DIRECTORY")
            .map(PathBuf::from)
            .expect("LA_REAL_MINERU_CORPUS_DIRECTORY is required");

        fs::create_dir_all(&state_directory).expect("acceptance state directory");
        let tools_config = state_directory.join("mineru-production-tools.json");
        fs::write(
            &tools_config,
            serde_json::to_vec(&serde_json::json!({
                "models-dir": {
                    "pipeline": model_root.join("pipeline"),
                    "vlm": model_root.join("vlm"),
                }
            }))
            .expect("tools config serializes"),
        )
        .expect("tools config writes");

        let manager = PrivacyManager::new(state_directory.clone()).expect("privacy manager");
        let config = PrivacyConfig {
            ocr: LocalOcrConfig {
                mode: OcrMode::ForceLocal,
                worker_path: Some(worker),
                model_directory: Some(model_root),
                tools_config_path: Some(tools_config),
                runtime_executable_paths: Vec::new(),
                device: "cuda:0".to_owned(),
                languages: vec!["zh".to_owned(), "en".to_owned()],
                timeout_seconds: 600,
                max_pages: 200,
                strict_offline: true,
                forbid_cloud_fallback: true,
                forbid_remote_upload: true,
                forbid_telemetry: true,
            },
            ..PrivacyConfig::default()
        };
        manager.save_config(config).expect("save real local config");
        let trust = manager
            .install_local_mineru_trust()
            .expect("install exact local trust");
        assert_eq!(trust.worker_sha256.len(), 64);
        assert_eq!(trust.support_manifest_sha256.len(), 64);
        assert_eq!(trust.support_tree_sha256.len(), 64);
        assert_eq!(trust.support_identity_sha256.len(), 64);
        assert!(trust.support_file_count > 10_000);
        assert_eq!(trust.model_manifest_sha256.len(), 64);
        manager
            .install_local_mineru_network_isolation()
            .expect("install and verify program firewall isolation");
        let snapshot = manager
            .run_local_mineru_qualification(24 * 60 * 60, true, true)
            .expect("run real synthetic qualification");
        assert!(snapshot.qualification.synthetic_canary_qualified);
        assert!(snapshot.qualification.processing_chain_qualified);
        assert!(snapshot.qualification.network_isolation_enforced);
        assert!(snapshot.qualification.model_manifest_trust_established);
        assert!(snapshot.qualification.production_case_ocr_authorized);
        assert!(snapshot.qualification.app_auto_enable_authorized);
        assert!(snapshot.capabilities.scanned_case_ocr_enabled);
        assert!(snapshot.capabilities.app_auto_ocr_enabled);
        assert_eq!(snapshot.ocr_status.code, LocalOcrStatusCode::Ready);

        let processing_config = manager
            .local_mineru_config()
            .expect("qualified production config reads")
            .expect("qualified production config exists");
        let limits = material_processing::ProcessingLimits {
            max_input_bytes: 8 * 1024 * 1024,
            max_pages: 10,
            max_output_bytes: 512 * 1024 * 1024,
            ..material_processing::ProcessingLimits::default()
        };
        let run = |name: &str| {
            let bytes = fs::read(corpus.join(name)).expect("synthetic corpus reads");
            material_processing::process_pdf(
                &bytes,
                material_processing::OcrMode::ForceLocal,
                Some(&processing_config),
                limits.clone(),
            )
        };

        let positive = run("privacy-vnext-ocr-positive.pdf").expect("positive corpus succeeds");
        assert_eq!(positive.page_count, 2);
        assert_eq!(
            positive
                .pages
                .iter()
                .map(|page| page.spans.len())
                .sum::<usize>(),
            13
        );
        let rotated = run("privacy-vnext-ocr-rotated.pdf").expect("rotated corpus succeeds");
        assert_eq!(rotated.page_count, 1);
        assert!(!rotated.pages[0].spans.is_empty());
        let low_resolution =
            run("privacy-vnext-ocr-low-resolution.pdf").expect("low resolution corpus succeeds");
        assert_eq!(low_resolution.page_count, 1);
        assert!(low_resolution.pages.iter().any(|page| {
            page.assessment
                .reason_codes
                .contains(&material_processing::QualityReasonCode::OcrLowResolution)
        }));
        for document in [&positive, &rotated, &low_resolution] {
            assert!(document.backend_trace.iter().any(|trace| {
                trace.backend == material_processing::ExtractionBackend::MineruLocal
                    && trace.isolation_verified
            }));
        }

        let unreadable_error = run("privacy-vnext-ocr-unreadable-handwriting.pdf")
            .expect_err("unreadable handwriting must fail closed");
        assert!(matches!(
            unreadable_error,
            material_processing::ProcessingError::OcrFailed
                | material_processing::ProcessingError::OcrOutputIncomplete
                | material_processing::ProcessingError::OcrOutputLowConfidence
        ));

        let report = serde_json::json!({
            "schemaVersion": 1,
            "syntheticOnly": true,
            "supportManifestSha256": trust.support_manifest_sha256,
            "supportTreeSha256": trust.support_tree_sha256,
            "supportIdentitySha256": trust.support_identity_sha256,
            "supportFileCount": trust.support_file_count,
            "positive": {
                "pageCount": positive.page_count,
                "spanCounts": positive.pages.iter().map(|page| page.spans.len()).collect::<Vec<_>>(),
                "qualityReasons": positive.pages.iter()
                    .map(|page| page.assessment.reason_codes.clone()).collect::<Vec<_>>(),
            },
            "rotated": {
                "pageCount": rotated.page_count,
                "spanCounts": rotated.pages.iter().map(|page| page.spans.len()).collect::<Vec<_>>(),
                "qualityReasons": rotated.pages.iter()
                    .map(|page| page.assessment.reason_codes.clone()).collect::<Vec<_>>(),
            },
            "lowResolution": {
                "pageCount": low_resolution.page_count,
                "spanCounts": low_resolution.pages.iter()
                    .map(|page| page.spans.len()).collect::<Vec<_>>(),
                "qualityReasons": low_resolution.pages.iter()
                    .map(|page| page.assessment.reason_codes.clone()).collect::<Vec<_>>(),
            },
            "unreadable": {
                "blocked": true,
                "error": format!("{unreadable_error:?}"),
            },
        });
        println!(
            "REAL_MINERU_HOST_CORPUS={}",
            serde_json::to_string(&report).expect("report serializes")
        );

        drop(processing_config);
        drop(manager);

        let reopened = PrivacyManager::new(state_directory.clone())
            .expect("qualified state reloads after manager restart");
        let reloaded = reopened
            .configuration_snapshot()
            .expect("reloaded qualification is remeasured");
        assert!(reloaded.qualification.synthetic_canary_qualified);
        assert!(reloaded.qualification.processing_chain_qualified);
        assert!(reloaded.qualification.network_isolation_enforced);
        assert!(reloaded.qualification.model_manifest_trust_established);
        assert!(reloaded.qualification.production_case_ocr_authorized);
        assert!(reloaded.qualification.app_auto_enable_authorized);
        assert!(reloaded.capabilities.scanned_case_ocr_enabled);
        assert!(reloaded.capabilities.app_auto_ocr_enabled);

        let revoked = reopened
            .revoke_local_mineru_qualification()
            .expect("qualification revocation persists");
        assert!(!revoked.qualification.production_case_ocr_authorized);
        assert!(!revoked.qualification.app_auto_enable_authorized);
        assert!(!revoked.capabilities.scanned_case_ocr_enabled);
        assert!(!revoked.capabilities.app_auto_ocr_enabled);
        drop(reopened);

        let reopened_after_revoke = PrivacyManager::new(state_directory)
            .expect("revoked state reloads after manager restart");
        let revoked_after_restart = reopened_after_revoke
            .configuration_snapshot()
            .expect("revoked state is remeasured after restart");
        assert!(
            !revoked_after_restart
                .qualification
                .production_case_ocr_authorized
        );
        assert!(
            !revoked_after_restart
                .qualification
                .app_auto_enable_authorized
        );
        assert!(!revoked_after_restart.capabilities.scanned_case_ocr_enabled);
        assert!(!revoked_after_restart.capabilities.app_auto_ocr_enabled);
    }
}
