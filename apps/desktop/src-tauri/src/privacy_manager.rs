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
    sync::{Arc, Mutex, MutexGuard},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetDriveTypeW, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    },
};

pub const PRIVACY_CONFIG_SCHEMA_VERSION: u16 = 1;
const CONFIG_DIRECTORY_NAME: &str = "privacy";
const CONFIG_FILE_NAME: &str = "privacy-config.json";
const MAX_CONFIG_BYTES: u64 = 128 * 1024;
const MAX_WORKER_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
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
}

impl Default for LocalOcrConfig {
    fn default() -> Self {
        Self {
            mode: OcrMode::Off,
            worker_path: None,
            model_directory: None,
            device: default_device(),
            languages: default_languages(),
            timeout_seconds: default_timeout_seconds(),
            max_pages: default_max_pages(),
            strict_offline: true,
            forbid_cloud_fallback: true,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalOcrStatusCode {
    Disabled,
    NotConfigured,
    Unavailable,
    ConfiguredUnverified,
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyConfigurationSnapshot {
    pub config: PrivacyConfig,
    pub config_valid: bool,
    pub load_error: Option<String>,
    pub enforcement_state: &'static str,
    pub ocr_status: LocalOcrStatus,
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

#[derive(Debug)]
struct ManagerState {
    config: PrivacyConfig,
    config_valid: bool,
    load_error: Option<String>,
}

#[derive(Debug)]
struct PrivacyManagerShared {
    config_path: PathBuf,
    state: Mutex<ManagerState>,
}

#[derive(Clone, Debug)]
pub struct PrivacyManager {
    shared: Arc<PrivacyManagerShared>,
}

impl PrivacyManager {
    pub fn new(app_local_data_directory: PathBuf) -> Result<Self, PrivacyManagerError> {
        let privacy_directory =
            ensure_directory(&app_local_data_directory.join(CONFIG_DIRECTORY_NAME), true)?;
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

        Ok(Self {
            shared: Arc::new(PrivacyManagerShared {
                config_path,
                state: Mutex::new(ManagerState {
                    config,
                    config_valid,
                    load_error,
                }),
            }),
        })
    }

    pub fn configuration_snapshot(
        &self,
    ) -> Result<PrivacyConfigurationSnapshot, PrivacyManagerError> {
        let (config, config_valid, load_error) = {
            let state = self.state();
            (
                state.config.clone(),
                state.config_valid,
                state.load_error.clone(),
            )
        };
        let ocr_status = inspect_local_ocr(&config.ocr);
        Ok(PrivacyConfigurationSnapshot {
            config,
            config_valid,
            load_error,
            // Local review and safe-PDF reconstruction are available. Case-bearing
            // Provider and production MCP forward paths remain fail closed; only
            // public legal-tool egress is open.
            enforcement_state: "local_review_safe_pdf_ready_case_provider_production_mcp_fail_closed_public_legal_tools_only",
            ocr_status,
        })
    }

    pub fn local_ocr_status(&self) -> LocalOcrStatus {
        let config = self.state().config.clone();
        inspect_local_ocr(&config.ocr)
    }

    pub fn current_config(&self) -> PrivacyConfig {
        self.state().config.clone()
    }

    pub fn save_config(
        &self,
        config: PrivacyConfig,
    ) -> Result<PrivacyConfigurationSnapshot, PrivacyManagerError> {
        validate_config(&config)?;
        persist_config(&self.shared.config_path, &config)?;
        {
            let mut state = self.state();
            state.config = config;
            state.config_valid = true;
            state.load_error = None;
        }
        self.configuration_snapshot()
    }

    fn state(&self) -> MutexGuard<'_, ManagerState> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
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
    validate_optional_absolute_path("worker", config.ocr.worker_path.as_deref())?;
    validate_optional_absolute_path("model", config.ocr.model_directory.as_deref())?;
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
    let (Some(worker_path), Some(model_directory)) = (
        config.worker_path.as_deref(),
        config.model_directory.as_deref(),
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
    if !matches!(components.next(), Some(Component::RootDir))
        || components.any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return false;
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

    fn configured(directory: &Path) -> PrivacyConfig {
        let worker = directory.join("mineru-worker.exe");
        let models = directory.join("models");
        fs::write(&worker, b"local-worker").expect("worker writes");
        fs::write(
            directory.join("mineru-worker.exe.manifest.json"),
            br#"{"version":"3.4.3-local"}"#,
        )
        .expect("worker manifest writes");
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
    }

    #[test]
    fn schema_v1_missing_optional_fields_loads_safe_defaults() {
        let config: PrivacyConfig = serde_json::from_value(serde_json::json!({
            "schemaVersion": 1,
            "privacyMode": "raw_native",
            "ocr": {"mode": "auto_local"}
        }))
        .expect("v1 config parses");
        assert_eq!(config.privacy_mode, PrivacyMode::RawNative);
        assert_eq!(config.ocr.device, "auto");
        assert_eq!(config.ocr.languages, ["zh", "en"]);
        assert!(config.ocr.strict_offline);
        assert!(config.ocr.forbid_cloud_fallback);
        validate_config(&config).expect("safe migrated defaults validate");
    }

    #[test]
    fn cloud_fallback_offline_and_path_invariants_fail_closed() {
        let mut config = PrivacyConfig::default();
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
            "local_review_safe_pdf_ready_case_provider_production_mcp_fail_closed_public_legal_tools_only"
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

        let reopened = PrivacyManager::new(directory.path().to_path_buf()).expect("reopens");
        assert_eq!(
            reopened.configuration_snapshot().unwrap().config,
            saved.config
        );
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
}
