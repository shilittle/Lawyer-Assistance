use super::{
    has_cloud_recall_attributes, is_normal_local_absolute, is_reparse_point,
    local_path_chain_is_ordinary, opened_file_resolves_to_ordinary_local, sha256_bytes,
    single_link_file, validate_config, LocalOcrConfig, OcrMode, PrivacyConfig, PrivacyManager,
    PrivacyManagerError, MAX_CONFIG_BYTES, MAX_WORKER_BYTES,
};
use material_processing::{bind_local_mineru_runtime_executable, LocalMineruRuntimeExecutableRole};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashSet,
    env,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

const MANAGED_CONFIG_PREFIX: &str = "mineru-local-offline-";
const MAX_DISCOVERY_PATH_ENTRIES: usize = 256;
const MAX_DISCOVERY_MODEL_ENTRIES: usize = 100_000;
const MAX_DISCOVERY_MODEL_BYTES: u64 = 2 * 1024 * 1024 * 1024 * 1024;
const MAX_PE_HEADER_OFFSET: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalMineruDiscoverySource {
    UvTool,
    CommonLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMineruDiscoveryResult {
    pub source: LocalMineruDiscoverySource,
    pub ocr_config: LocalOcrConfig,
    pub app_managed_tools_config: bool,
    pub requires_user_save: bool,
    pub trust_installed: bool,
    pub network_isolation_installed: bool,
    pub qualified: bool,
}

#[derive(Debug, Clone, Default)]
struct DiscoveryInputs {
    path_entries: Vec<PathBuf>,
    user_profile: Option<PathBuf>,
    roaming_app_data: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    virtual_env: Option<PathBuf>,
    conda_prefix: Option<PathBuf>,
    explicit_tools_config: Option<PathBuf>,
}

impl DiscoveryInputs {
    fn from_environment() -> Self {
        Self {
            path_entries: env::var_os("PATH")
                .map(|value| {
                    env::split_paths(&value)
                        .take(MAX_DISCOVERY_PATH_ENTRIES)
                        .collect()
                })
                .unwrap_or_default(),
            user_profile: environment_path("USERPROFILE"),
            roaming_app_data: environment_path("APPDATA"),
            local_app_data: environment_path("LOCALAPPDATA"),
            virtual_env: environment_path("VIRTUAL_ENV"),
            conda_prefix: environment_path("CONDA_PREFIX"),
            explicit_tools_config: environment_path("MINERU_TOOLS_CONFIG_JSON"),
        }
    }
}

#[derive(Debug, Clone)]
struct RuntimeCandidate {
    worker: PathBuf,
    python_candidates: Vec<PathBuf>,
    source: LocalMineruDiscoverySource,
}

#[derive(Debug, Clone)]
struct DiscoveredRuntime {
    worker: PathBuf,
    python: PathBuf,
    source: LocalMineruDiscoverySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedMineruConfig {
    #[serde(rename = "models-dir")]
    models_dir: ManagedModelsDirectory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedModelsDirectory {
    pipeline: String,
    vlm: String,
}

#[derive(Debug, Clone)]
struct ModelLayoutCandidate {
    pipeline: PathBuf,
    vlm: PathBuf,
}

#[derive(Debug, Clone)]
struct DiscoveredModels {
    model_root: PathBuf,
    pipeline: PathBuf,
    vlm: PathBuf,
}

impl PrivacyManager {
    pub fn discover_local_mineru(&self) -> Result<LocalMineruDiscoveryResult, PrivacyManagerError> {
        self.discover_local_mineru_with_inputs(&DiscoveryInputs::from_environment())
    }

    fn discover_local_mineru_with_inputs(
        &self,
        inputs: &DiscoveryInputs,
    ) -> Result<LocalMineruDiscoveryResult, PrivacyManagerError> {
        let runtime = discover_runtime(inputs)?;
        let models = discover_models(inputs)?;
        let managed_config = ManagedMineruConfig {
            models_dir: ManagedModelsDirectory {
                pipeline: models
                    .pipeline
                    .to_str()
                    .ok_or_else(|| {
                        discovery_error("本机 pipeline 模型目录不是有效 Unicode 路径。")
                    })?
                    .to_owned(),
                vlm: models
                    .vlm
                    .to_str()
                    .ok_or_else(|| discovery_error("本机 VLM 模型目录不是有效 Unicode 路径。"))?
                    .to_owned(),
            },
        };
        let managed_bytes = serde_json::to_vec(&managed_config)
            .map_err(|_| discovery_error("应用管理的 MinerU 离线配置无法序列化。"))?;
        let tools_config_path =
            persist_managed_tools_config(&self.shared.privacy_directory, &managed_bytes)?;

        let ocr_config = LocalOcrConfig {
            mode: OcrMode::AutoLocal,
            worker_path: Some(runtime.worker),
            model_directory: Some(models.model_root),
            tools_config_path: Some(tools_config_path),
            runtime_executable_paths: vec![runtime.python],
            ..LocalOcrConfig::default()
        };
        validate_config(&PrivacyConfig {
            ocr: ocr_config.clone(),
            ..PrivacyConfig::default()
        })?;
        Ok(LocalMineruDiscoveryResult {
            source: runtime.source,
            ocr_config,
            app_managed_tools_config: true,
            requires_user_save: true,
            trust_installed: false,
            network_isolation_installed: false,
            qualified: false,
        })
    }
}

fn discover_runtime(inputs: &DiscoveryInputs) -> Result<DiscoveredRuntime, PrivacyManagerError> {
    for candidate in runtime_candidates(inputs) {
        let Some(worker) = validated_pe(
            &candidate.worker,
            LocalMineruRuntimeExecutableRole::Launcher,
        ) else {
            continue;
        };
        for python_candidate in candidate.python_candidates {
            let Some(python) = validated_pe(
                &python_candidate,
                LocalMineruRuntimeExecutableRole::Executable,
            ) else {
                continue;
            };
            if !paths_equal(&worker, &python) {
                return Ok(DiscoveredRuntime {
                    worker,
                    python,
                    source: candidate.source,
                });
            }
        }
    }
    Err(PrivacyManagerError::new(
        "mineru_discovery_not_found",
        "未发现同时具有本机 MinerU PE 启动器与本机 Python PE 运行时的安全安装。",
    ))
}

fn runtime_candidates(inputs: &DiscoveryInputs) -> Vec<RuntimeCandidate> {
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    let mut global_python = Vec::new();
    let mut uv_script_directories = Vec::new();
    for root in [&inputs.roaming_app_data, &inputs.local_app_data]
        .into_iter()
        .flatten()
    {
        uv_script_directories.push(root.join("uv/tools/mineru/Scripts"));
    }
    for scripts in &uv_script_directories {
        global_python.push(scripts.join("python.exe"));
        add_installation_candidates(
            &mut values,
            &mut seen,
            scripts,
            vec![scripts.join("python.exe")],
            LocalMineruDiscoverySource::UvTool,
        );
    }
    for root in [&inputs.virtual_env, &inputs.conda_prefix]
        .into_iter()
        .flatten()
    {
        let scripts = root.join("Scripts");
        global_python.push(scripts.join("python.exe"));
        add_installation_candidates(
            &mut values,
            &mut seen,
            &scripts,
            vec![scripts.join("python.exe")],
            LocalMineruDiscoverySource::CommonLocal,
        );
    }
    for path_entry in &inputs.path_entries {
        let python = path_entry.join("python.exe");
        global_python.push(python.clone());
        add_installation_candidates(
            &mut values,
            &mut seen,
            path_entry,
            vec![python],
            LocalMineruDiscoverySource::CommonLocal,
        );
    }
    if let Some(profile) = &inputs.user_profile {
        let bin = profile.join(".local/bin");
        let mut python_candidates = vec![bin.join("python.exe")];
        python_candidates.extend(global_python.iter().cloned());
        add_installation_candidates(
            &mut values,
            &mut seen,
            &bin,
            python_candidates,
            LocalMineruDiscoverySource::UvTool,
        );
    }
    values
}

fn add_installation_candidates(
    output: &mut Vec<RuntimeCandidate>,
    seen: &mut HashSet<String>,
    directory: &Path,
    python_candidates: Vec<PathBuf>,
    source: LocalMineruDiscoverySource,
) {
    for name in ["mineru.exe", "magic-pdf.exe"] {
        let worker = directory.join(name);
        let key = normalize_path(&worker);
        if seen.insert(key) {
            output.push(RuntimeCandidate {
                worker,
                python_candidates: python_candidates.clone(),
                source,
            });
        }
    }
}

fn validated_pe(path: &Path, role: LocalMineruRuntimeExecutableRole) -> Option<PathBuf> {
    if !is_normal_local_absolute(path) || !local_path_chain_is_ordinary(path) {
        return None;
    }
    let binding = bind_local_mineru_runtime_executable(path, role).ok()?;
    if binding.expected_size_bytes > MAX_WORKER_BYTES || !full_pe_header_is_valid(&binding.path) {
        return None;
    }
    let canonical = normal_dos_path(&binding.path)?;
    local_path_chain_is_ordinary(&canonical).then_some(canonical)
}

fn normal_dos_path(path: &Path) -> Option<PathBuf> {
    let rendered = path.to_str()?;
    if rendered.starts_with(r"\\?\UNC\") {
        return None;
    }
    let normalized = rendered
        .strip_prefix(r"\\?\")
        .map_or_else(|| path.to_path_buf(), PathBuf::from);
    is_normal_local_absolute(&normalized).then_some(normalized)
}

fn canonical_ordinary_local_path(path: &Path) -> Result<PathBuf, PrivacyManagerError> {
    let canonical =
        fs::canonicalize(path).map_err(|_| discovery_error("本机路径无法解析为稳定路径。"))?;
    let normalized = normal_dos_path(&canonical)
        .ok_or_else(|| discovery_error("本机路径解析后不是固定磁盘路径。"))?;
    if !local_path_chain_is_ordinary(&normalized) {
        return Err(discovery_error("本机路径解析后包含不安全路径链。"));
    }
    Ok(normalized)
}

fn full_pe_header_is_valid(path: &Path) -> bool {
    let Ok(mut file) = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
    else {
        return false;
    };
    if !opened_file_resolves_to_ordinary_local(&file) {
        return false;
    }
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.is_file() || metadata.len() < 88 || metadata.len() > MAX_WORKER_BYTES {
        return false;
    }
    let mut dos_header = [0u8; 64];
    if file.read_exact(&mut dos_header).is_err() || &dos_header[..2] != b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes([
        dos_header[0x3c],
        dos_header[0x3d],
        dos_header[0x3e],
        dos_header[0x3f],
    ]) as u64;
    if !(64..=MAX_PE_HEADER_OFFSET).contains(&pe_offset)
        || pe_offset
            .checked_add(24)
            .is_none_or(|end| end > metadata.len())
        || file.seek(SeekFrom::Start(pe_offset)).is_err()
    {
        return false;
    }
    let mut coff = [0u8; 24];
    if file.read_exact(&mut coff).is_err() || &coff[..4] != b"PE\0\0" {
        return false;
    }
    let machine = u16::from_le_bytes([coff[4], coff[5]]);
    let section_count = u16::from_le_bytes([coff[6], coff[7]]);
    matches!(machine, 0x014c | 0x8664) && section_count > 0
}

fn discover_models(inputs: &DiscoveryInputs) -> Result<DiscoveredModels, PrivacyManagerError> {
    for candidate in model_layout_candidates(inputs) {
        let Ok(pipeline) = canonical_ordinary_model_root(&candidate.pipeline) else {
            continue;
        };
        let Ok(vlm) = canonical_ordinary_model_root(&candidate.vlm) else {
            continue;
        };
        let Ok(model_root) = common_model_root(&pipeline, &vlm) else {
            continue;
        };
        if model_tree_is_ordinary(&model_root).is_ok() {
            return Ok(DiscoveredModels {
                model_root,
                pipeline,
                vlm,
            });
        }
    }
    Err(PrivacyManagerError::new(
        "mineru_models_not_found",
        "未从本机 MinerU 配置或标准本地模型缓存同时发现安全、非空的 pipeline 与 VLM 模型目录。",
    ))
}

fn model_layout_candidates(inputs: &DiscoveryInputs) -> Vec<ModelLayoutCandidate> {
    let mut config_paths = Vec::new();
    if let Some(path) = &inputs.explicit_tools_config {
        config_paths.push(path.clone());
    }
    if let Some(profile) = &inputs.user_profile {
        config_paths.extend([
            profile.join("mineru.json"),
            profile.join("magic-pdf.json"),
            profile.join(".magic-pdf.json"),
            profile.join(".config/mineru/mineru.json"),
            profile.join(".config/magic-pdf.json"),
        ]);
    }
    for root in [&inputs.roaming_app_data, &inputs.local_app_data]
        .into_iter()
        .flatten()
    {
        config_paths.extend([
            root.join("MinerU/magic-pdf.json"),
            root.join("MinerU/mineru.json"),
        ]);
    }

    let mut layouts = Vec::new();
    let mut seen = HashSet::new();
    for config_path in config_paths {
        let Ok(bytes) = read_ordinary_local_file(&config_path, MAX_CONFIG_BYTES) else {
            continue;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let Some(models) = value.get("models-dir").and_then(Value::as_object) else {
            continue;
        };
        let (Some(pipeline), Some(vlm)) = (
            models.get("pipeline").and_then(Value::as_str),
            models.get("vlm").and_then(Value::as_str),
        ) else {
            continue;
        };
        push_unique_layout(
            &mut layouts,
            &mut seen,
            PathBuf::from(pipeline),
            PathBuf::from(vlm),
        );
    }
    if let Some(profile) = &inputs.user_profile {
        push_unique_layout(
            &mut layouts,
            &mut seen,
            profile
                .join(".cache/modelscope/models/OpenDataLab--PDF-Extract-Kit-1.0/snapshots/master"),
            profile.join(
                ".cache/modelscope/models/OpenDataLab--MinerU2.5-Pro-2605-1.2B/snapshots/master",
            ),
        );
    }
    layouts
}

fn push_unique_layout(
    output: &mut Vec<ModelLayoutCandidate>,
    seen: &mut HashSet<String>,
    pipeline: PathBuf,
    vlm: PathBuf,
) {
    let key = format!("{}\0{}", normalize_path(&pipeline), normalize_path(&vlm));
    if seen.insert(key) {
        output.push(ModelLayoutCandidate { pipeline, vlm });
    }
}

fn common_model_root(pipeline: &Path, vlm: &Path) -> Result<PathBuf, PrivacyManagerError> {
    let root = pipeline
        .ancestors()
        .find(|candidate| path_starts_with(vlm, candidate))
        .ok_or_else(|| discovery_error("pipeline 与 VLM 模型目录不在同一本机模型根目录。"))?;
    if paths_equal(root, pipeline)
        || paths_equal(root, vlm)
        || root.components().count() < 4
        || !root
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                matches!(
                    name.to_ascii_lowercase().as_str(),
                    "models" | "model-cache" | "mineru-models"
                )
            })
    {
        return Err(discovery_error(
            "pipeline 与 VLM 必须位于专用且范围受限的共同本机模型根目录。",
        ));
    }
    canonical_ordinary_model_root(root)
}

fn path_starts_with(path: &Path, root: &Path) -> bool {
    let path = normalize_path(path);
    let mut root = normalize_path(root);
    if !root.ends_with('\\') {
        root.push('\\');
    }
    path == root.trim_end_matches('\\') || path.starts_with(&root)
}
fn canonical_ordinary_model_root(path: &Path) -> Result<PathBuf, PrivacyManagerError> {
    if !is_normal_local_absolute(path) || !local_path_chain_is_ordinary(path) {
        return Err(discovery_error("模型目录不是普通本机固定磁盘路径。"));
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| discovery_error("模型目录不存在或无法检查。"))?;
    if !metadata.is_dir() || is_reparse_point(&metadata) || has_cloud_recall_attributes(&metadata) {
        return Err(discovery_error(
            "模型目录不能是链接、reparse point 或云端占位目录。",
        ));
    }
    canonical_ordinary_local_path(path)
}

fn model_tree_is_ordinary(root: &Path) -> Result<(), PrivacyManagerError> {
    let mut stack = vec![root.to_path_buf()];
    let mut file_count = 0usize;
    let mut total_bytes = 0u64;
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory).map_err(|_| discovery_error("模型目录无法枚举。"))?
        {
            let entry = entry.map_err(|_| discovery_error("模型目录项无法读取。"))?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|_| discovery_error("模型目录项无法检查。"))?;
            if is_reparse_point(&metadata) || has_cloud_recall_attributes(&metadata) {
                return Err(discovery_error(
                    "模型树包含链接、reparse point 或云端占位对象。",
                ));
            }
            let canonical = canonical_ordinary_local_path(&path)
                .map_err(|_| discovery_error("模型目录项无法解析。"))?;
            if !path_starts_with(&canonical, root) || !local_path_chain_is_ordinary(&canonical) {
                return Err(discovery_error("模型目录项越过本机模型根目录。"));
            }
            if metadata.is_dir() {
                stack.push(canonical);
            } else if metadata.is_file() {
                if !single_link_file(&canonical) {
                    return Err(discovery_error("模型树包含多硬链接文件。"));
                }
                file_count = file_count
                    .checked_add(1)
                    .ok_or_else(|| discovery_error("模型文件数量溢出。"))?;
                total_bytes = total_bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| discovery_error("模型文件大小溢出。"))?;
                if file_count > MAX_DISCOVERY_MODEL_ENTRIES
                    || total_bytes > MAX_DISCOVERY_MODEL_BYTES
                {
                    return Err(discovery_error("模型树超过本地发现安全上限。"));
                }
            } else {
                return Err(discovery_error("模型树包含不支持的对象类型。"));
            }
        }
    }
    if file_count == 0 {
        return Err(discovery_error("模型目录不能为空。"));
    }
    Ok(())
}

fn persist_managed_tools_config(
    privacy_directory: &Path,
    bytes: &[u8],
) -> Result<PathBuf, PrivacyManagerError> {
    let hash = sha256_bytes(bytes);
    let target = privacy_directory.join(format!("{MANAGED_CONFIG_PREFIX}{hash}.json"));
    if fs::symlink_metadata(&target).is_ok() {
        verify_managed_tools_config(&target, bytes)?;
        return Ok(target);
    }
    let staging = privacy_directory.join(format!(
        ".{MANAGED_CONFIG_PREFIX}{}.incoming",
        Uuid::new_v4()
    ));
    let result = (|| -> Result<(), std::io::Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&staging, &target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staging);
        if fs::symlink_metadata(&target).is_err() {
            return Err(PrivacyManagerError::new(
                "mineru_managed_config_unavailable",
                "应用管理的 MinerU 离线配置无法原子创建。",
            ));
        }
    }
    verify_managed_tools_config(&target, bytes)?;
    Ok(target)
}

fn verify_managed_tools_config(path: &Path, expected: &[u8]) -> Result<(), PrivacyManagerError> {
    let actual = read_ordinary_local_file(path, MAX_CONFIG_BYTES)?;
    if actual != expected || sha256_bytes(&actual) != sha256_bytes(expected) {
        return Err(PrivacyManagerError::new(
            "mineru_managed_config_mismatch",
            "应用管理的 MinerU 离线配置与内容哈希不一致。",
        ));
    }
    let parsed: ManagedMineruConfig = serde_json::from_slice(&actual)
        .map_err(|_| discovery_error("应用管理的 MinerU 离线配置格式无效。"))?;
    if serde_json::to_vec(&parsed).ok().as_deref() != Some(expected) {
        return Err(discovery_error(
            "应用管理的 MinerU 离线配置不是最小确定性结构。",
        ));
    }
    Ok(())
}

fn read_ordinary_local_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, PrivacyManagerError> {
    if !is_normal_local_absolute(path) || !local_path_chain_is_ordinary(path) {
        return Err(discovery_error("本机发现输入不是普通固定磁盘路径。"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| discovery_error("本机发现输入不存在或无法检查。"))?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
        || is_reparse_point(&metadata)
        || has_cloud_recall_attributes(&metadata)
        || !single_link_file(path)
    {
        return Err(discovery_error(
            "本机发现输入必须是受限大小的普通单硬链接文件。",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| discovery_error("本机发现输入无法打开。"))?;
    if !opened_file_resolves_to_ordinary_local(&file) {
        return Err(discovery_error("本机发现输入打开后解析到不安全路径。"));
    }
    let exact_len = usize::try_from(metadata.len())
        .map_err(|_| discovery_error("本机发现输入长度无法表示。"))?;
    let mut bytes = Vec::with_capacity(exact_len);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| discovery_error("本机发现输入无法读取。"))?;
    if bytes.len() != exact_len {
        return Err(discovery_error("本机发现输入读取期间发生变化。"));
    }
    Ok(bytes)
}

fn environment_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    normalize_path(left) == normalize_path(right)
}

fn discovery_error(message: &'static str) -> PrivacyManagerError {
    PrivacyManagerError::new("mineru_discovery_rejected", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_canonical(path: &Path) -> PathBuf {
        canonical_ordinary_local_path(path).expect("test path canonicalizes")
    }
    fn write_test_pe(path: &Path) {
        let mut bytes = vec![0u8; 512];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        fs::write(path, bytes).expect("test PE writes");
    }

    fn synthetic_inputs(
        root: &Path,
    ) -> (DiscoveryInputs, PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let profile = root.join("profile");
        let roaming = root.join("roaming");
        let scripts = roaming.join("uv/tools/mineru/Scripts");
        let model_root = root.join("model-cache");
        let pipeline = model_root.join("pipeline");
        let vlm = model_root.join("vlm");
        fs::create_dir_all(&scripts).expect("scripts create");
        fs::create_dir_all(&pipeline).expect("pipeline models create");
        fs::create_dir_all(&vlm).expect("VLM models create");
        let worker = scripts.join("mineru.exe");
        let python = scripts.join("python.exe");
        write_test_pe(&worker);
        write_test_pe(&python);
        fs::write(pipeline.join("weights.bin"), b"synthetic pipeline model")
            .expect("pipeline model writes");
        fs::write(vlm.join("model.safetensors"), b"synthetic VLM model").expect("VLM model writes");
        fs::create_dir_all(&profile).expect("profile create");
        fs::write(
            profile.join("mineru.json"),
            serde_json::to_vec(&serde_json::json!({
                "models-dir": {"pipeline": pipeline, "vlm": vlm},
                "server": "https://remote.invalid",
                "apiKey": "must-not-be-copied",
                "allow-download": true
            }))
            .expect("source config"),
        )
        .expect("source config writes");
        (
            DiscoveryInputs {
                user_profile: Some(profile),
                roaming_app_data: Some(roaming),
                ..DiscoveryInputs::default()
            },
            worker,
            python,
            model_root,
            pipeline,
            vlm,
        )
    }

    fn managed_config_count(manager: &PrivacyManager) -> usize {
        fs::read_dir(&manager.shared.privacy_directory)
            .expect("privacy dir")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(MANAGED_CONFIG_PREFIX)
            })
            .count()
    }

    #[test]
    fn synthetic_uv_discovery_is_minimized_but_requires_a_self_contained_component() {
        let root = tempfile::tempdir().expect("root");
        let app_data = root.path().join("app");
        let manager = PrivacyManager::new(app_data).expect("manager");
        let (inputs, worker, python, model_root, pipeline, vlm) = synthetic_inputs(root.path());
        let source_path = inputs
            .user_profile
            .as_deref()
            .expect("profile")
            .join("mineru.json");
        let source_before = fs::read(&source_path).expect("source reads before");
        let layouts = model_layout_candidates(&inputs);
        assert!(!layouts.is_empty(), "source contributes a model layout");
        let pipeline_root =
            canonical_ordinary_model_root(&layouts[0].pipeline).expect("pipeline is ordinary");
        let vlm_root = canonical_ordinary_model_root(&layouts[0].vlm).expect("VLM is ordinary");
        let common_root =
            common_model_root(&pipeline_root, &vlm_root).expect("common model root is safe");
        model_tree_is_ordinary(&common_root).expect("common model tree is ordinary");
        let result = manager
            .discover_local_mineru_with_inputs(&inputs)
            .expect("safe local installation is discovered");

        assert_eq!(result.source, LocalMineruDiscoverySource::UvTool);
        assert_eq!(result.ocr_config.mode, OcrMode::AutoLocal);
        assert_eq!(result.ocr_config.worker_path, Some(test_canonical(&worker)));
        assert_eq!(
            result.ocr_config.runtime_executable_paths,
            [test_canonical(&python)]
        );
        assert_eq!(
            result.ocr_config.model_directory,
            Some(test_canonical(&model_root))
        );
        assert!(result.app_managed_tools_config);
        assert!(result.requires_user_save);
        assert!(!result.trust_installed);
        assert!(!result.network_isolation_installed);
        assert!(!result.qualified);
        assert_eq!(manager.current_config().ocr.mode, OcrMode::Off);
        assert_eq!(
            fs::read(&source_path).expect("source reads after"),
            source_before,
            "the user's MinerU config is a read-only discovery source"
        );

        let tools_path = result
            .ocr_config
            .tools_config_path
            .as_deref()
            .expect("managed tools path");
        let value: Value = serde_json::from_slice(
            &read_ordinary_local_file(tools_path, MAX_CONFIG_BYTES).expect("managed config reads"),
        )
        .expect("managed config parses");
        assert_eq!(value.as_object().map(|object| object.len()), Some(1));
        assert_eq!(
            value["models-dir"].as_object().map(|object| object.len()),
            Some(2)
        );
        assert_eq!(
            value["models-dir"]["pipeline"],
            Value::String(test_canonical(&pipeline).to_string_lossy().into_owned())
        );
        assert_eq!(
            value["models-dir"]["vlm"],
            Value::String(test_canonical(&vlm).to_string_lossy().into_owned())
        );
        let rendered = serde_json::to_string(&value).expect("managed JSON renders");
        assert!(!rendered.contains("remote.invalid"));
        assert!(!rendered.contains("must-not-be-copied"));
        assert!(!rendered.contains("allow-download"));

        let saved = manager
            .save_config(PrivacyConfig {
                ocr: result.ocr_config,
                ..PrivacyConfig::default()
            })
            .expect("user-confirmed config saves");
        assert_eq!(saved.config.ocr.mode, OcrMode::AutoLocal);
        assert!(!saved.qualification.model_manifest_trust_established);
        let error = manager
            .install_local_mineru_trust()
            .expect_err("an external uv tool is not a self-contained production component");
        assert_eq!(error.code(), "trusted_component_unavailable");
        assert!(
            !manager
                .configuration_snapshot()
                .unwrap()
                .capabilities
                .scanned_case_ocr_enabled
        );
    }

    #[test]
    fn remote_model_directives_are_rejected_without_managed_output() {
        let root = tempfile::tempdir().expect("root");
        let manager = PrivacyManager::new(root.path().join("app")).expect("manager");
        let (mut inputs, _, _, _, _, _) = synthetic_inputs(root.path());
        fs::write(
            inputs
                .user_profile
                .as_deref()
                .expect("profile")
                .join("mineru.json"),
            br#"{"models-dir":{"pipeline":"https://remote.invalid/pipeline","vlm":"\\\\server\\share\\vlm"}}"#,
        )
        .expect("remote config writes");
        inputs.explicit_tools_config = Some(PathBuf::from(r"\\server\share\mineru.json"));

        let error = manager
            .discover_local_mineru_with_inputs(&inputs)
            .expect_err("remote model locators must be rejected");
        assert_eq!(error.code(), "mineru_models_not_found");
        assert_eq!(managed_config_count(&manager), 0);
    }

    #[test]
    fn source_with_only_legacy_pipeline_directory_is_not_sufficient() {
        let root = tempfile::tempdir().expect("root");
        let manager = PrivacyManager::new(root.path().join("app")).expect("manager");
        let (inputs, _, _, _, pipeline, _) = synthetic_inputs(root.path());
        fs::write(
            inputs
                .user_profile
                .as_deref()
                .expect("profile")
                .join("mineru.json"),
            serde_json::to_vec(&serde_json::json!({
                "models-dir": {"pipeline": pipeline}
            }))
            .expect("legacy source"),
        )
        .expect("legacy source writes");

        let error = manager
            .discover_local_mineru_with_inputs(&inputs)
            .expect_err("both pipeline and VLM are mandatory");
        assert_eq!(error.code(), "mineru_models_not_found");
        assert_eq!(managed_config_count(&manager), 0);
    }

    #[test]
    fn non_pe_and_hardlinked_workers_are_rejected_without_output() {
        let root = tempfile::tempdir().expect("root");
        let manager = PrivacyManager::new(root.path().join("app")).expect("manager");
        let (inputs, worker, _, _, _, _) = synthetic_inputs(root.path());
        fs::write(
            &worker,
            b"powershell -Command Invoke-WebRequest https://remote.invalid",
        )
        .expect("unsafe worker writes");
        let error = manager
            .discover_local_mineru_with_inputs(&inputs)
            .expect_err("non-PE worker must be rejected");
        assert_eq!(error.code(), "mineru_discovery_not_found");
        assert_eq!(managed_config_count(&manager), 0);

        write_test_pe(&worker);
        let alias = worker.with_file_name("mineru-alias.exe");
        fs::hard_link(&worker, alias).expect("hardlink creates");
        let error = manager
            .discover_local_mineru_with_inputs(&inputs)
            .expect_err("multi-link worker must be rejected");
        assert_eq!(error.code(), "mineru_discovery_not_found");
        assert_eq!(managed_config_count(&manager), 0);
    }

    #[test]
    fn installed_machine_layout_is_discoverable_when_present() {
        let inputs = DiscoveryInputs::from_environment();
        let (Some(profile), Some(roaming)) = (
            inputs.user_profile.as_deref(),
            inputs.roaming_app_data.as_deref(),
        ) else {
            return;
        };
        let source_path = profile.join("mineru.json");
        let pipeline = profile
            .join(".cache/modelscope/models/OpenDataLab--PDF-Extract-Kit-1.0/snapshots/master");
        let vlm = profile
            .join(".cache/modelscope/models/OpenDataLab--MinerU2.5-Pro-2605-1.2B/snapshots/master");
        let uv_scripts = roaming.join("uv/tools/mineru/Scripts");
        let python = uv_scripts.join("python.exe");
        let worker_present = uv_scripts.join("mineru.exe").is_file()
            || profile.join(".local/bin/mineru.exe").is_file();
        if !source_path.is_file()
            || !pipeline.is_dir()
            || !vlm.is_dir()
            || !python.is_file()
            || !worker_present
        {
            return;
        }

        let source_before = fs::read(&source_path).expect("installed source reads before");
        let app_data = tempfile::tempdir().expect("temporary app data");
        let manager = PrivacyManager::new(app_data.path().to_path_buf()).expect("manager");
        let result = manager
            .discover_local_mineru_with_inputs(&inputs)
            .expect("installed uv MinerU and ModelScope models are discovered");
        assert_eq!(result.source, LocalMineruDiscoverySource::UvTool);
        assert_eq!(result.ocr_config.mode, OcrMode::AutoLocal);
        assert_eq!(
            result.ocr_config.model_directory,
            Some(test_canonical(&profile.join(".cache/modelscope/models")))
        );
        assert_eq!(
            result.ocr_config.runtime_executable_paths,
            [test_canonical(&python)]
        );
        assert_eq!(
            fs::read(&source_path).expect("installed source reads after"),
            source_before
        );

        let managed_path = result
            .ocr_config
            .tools_config_path
            .as_deref()
            .expect("managed path");
        let value: Value = serde_json::from_slice(
            &read_ordinary_local_file(managed_path, MAX_CONFIG_BYTES)
                .expect("installed managed config reads"),
        )
        .expect("installed managed config parses");
        assert_eq!(value.as_object().map(|object| object.len()), Some(1));
        assert_eq!(
            value["models-dir"].as_object().map(|object| object.len()),
            Some(2)
        );
        assert_eq!(
            value["models-dir"]["pipeline"],
            Value::String(test_canonical(&pipeline).to_string_lossy().into_owned())
        );
        assert_eq!(
            value["models-dir"]["vlm"],
            Value::String(test_canonical(&vlm).to_string_lossy().into_owned())
        );
    }
}
