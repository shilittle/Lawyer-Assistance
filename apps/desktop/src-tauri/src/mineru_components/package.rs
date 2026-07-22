use super::{
    catalog::{ComponentCatalogEntryV1, ComponentCatalogV1},
    error, ComponentResult, ManagedMineruBinding,
};
use crate::atomic_file;
use reqwest::Url;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Component, Path, PathBuf, Prefix},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::HANDLE,
    Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
        FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ,
    },
};

pub(super) const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(super) const MAX_PROVENANCE_BYTES: u64 = 16 * 1024 * 1024;
const PACKAGE_MAGIC: &[u8; 8] = b"LAOCPK1\0";
const COMPONENT_SCHEMA_VERSION: u16 = 1;
const PROTOCOL_VERSION: &str = "la-mineru-worker-v1";
const PLATFORM: &str = "windows-x86_64";
const MANIFEST_FILE: &str = "manifest.json";
const MANAGED_CONFIG: &str = "config/lawyer-assistance-mineru.json";
const PROVENANCE_FILE: &str = "licenses/mineru-component-provenance.json";
const PROVENANCE_VERSION: &str = "lawyer-assistance-mineru-component-provenance-v1";
const MINERU_LICENSE: &str = "LicenseRef-MinerU-Open-Source-License";
pub(super) const TORCH_WHEEL: (&str, &str, &str) = (
    "torch-2.8.0+cu128-cp312-cp312-win_amd64.whl",
    "https://download-r2.pytorch.org/whl/cu128/torch-2.8.0%2Bcu128-cp312-cp312-win_amd64.whl",
    "0ad925202387f4e7314302a1b4f8860fa824357f9b1466d7992bf276370ebcff",
);
pub(super) const TORCHVISION_WHEEL: (&str, &str, &str) = (
    "torchvision-0.23.0+cu128-cp312-cp312-win_amd64.whl",
    "https://download-r2.pytorch.org/whl/cu128/torchvision-0.23.0%2Bcu128-cp312-cp312-win_amd64.whl",
    "20fa9c7362a006776630b00b8a01919fedcf504a202b81358d32c5aef39956fe",
);
pub(super) const PIPELINE_MODEL: (&str, &str, &str) = (
    "opendatalab/PDF-Extract-Kit-1.0",
    "ed6b654c018d742e65a17671e379c5e6ecc87ec9",
    "AGPL-3.0",
);
pub(super) const PIPELINE_MODEL_LICENSE_EVIDENCE_SHA256: &str =
    "96da5ddde73c3f578b9eab235ac59cbb5f512755090779a14461863767b70f34";
pub(super) const VLM_MODEL: (&str, &str, &str) = (
    "opendatalab/MinerU2.5-Pro-2605-1.2B",
    "bff20d4ae2bf202df9f45284b4d43681555a97ed",
    "Apache-2.0",
);
pub(super) const VLM_MODEL_LICENSE_EVIDENCE_SHA256: &str =
    "8f829b69be518375b02023f795b3898adec98f5ac37208239884ad88e9a21cb7";
pub(super) const PIPELINE_MODEL_FILES: &[&str] = &[
    "models/Layout/PP-DocLayoutV2/config.json",
    "models/Layout/PP-DocLayoutV2/model.safetensors",
    "models/Layout/PP-DocLayoutV2/preprocessor_config.json",
    "models/MFR/unimernet_hf_small_2503/README.md",
    "models/MFR/unimernet_hf_small_2503/config.json",
    "models/MFR/unimernet_hf_small_2503/generation_config.json",
    "models/MFR/unimernet_hf_small_2503/model.safetensors",
    "models/MFR/unimernet_hf_small_2503/special_tokens_map.json",
    "models/MFR/unimernet_hf_small_2503/tokenizer.json",
    "models/MFR/unimernet_hf_small_2503/tokenizer_config.json",
    "models/OCR/paddleocr_torch/ch_PP-OCRv6_small_det_infer.safetensors",
    "models/OCR/paddleocr_torch/ch_PP-OCRv6_small_rec_infer.safetensors",
    "models/TabCls/paddle_table_cls/PP-LCNet_x1_0_table_cls.onnx",
    "models/TabRec/SlanetPlus/slanet-plus.onnx",
    "models/TabRec/UnetStructure/unet.onnx",
];
pub(super) const VLM_MODEL_FILES: &[&str] = &[
    "added_tokens.json",
    "chat_template.jinja",
    "config.json",
    "generation_config.json",
    "merges.txt",
    "model.safetensors",
    "preprocessor_config.json",
    "special_tokens_map.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "vocab.json",
];
pub(super) const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 150_000;
const BUFFER_BYTES: usize = 1024 * 1024;
const DRIVE_FIXED_TYPE: u32 = 3;
// The embedded CPython/MinerU dependency set still contains native importers
// that are not reliable beyond the legacy Win32 MAX_PATH boundary. Count the
// final installed UTF-16 path (not the extended-length staging spelling) and
// fail closed before extraction rather than installing an unusable component.
const MAX_RUNTIME_PATH_UTF16_UNITS: usize = 259;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ComponentPackageManifestV1 {
    pub schema_version: u16,
    pub package_id: String,
    pub component_version: Version,
    pub mineru_version: String,
    pub protocol_version: String,
    pub platform: String,
    pub worker: String,
    pub runtime_executables: Vec<String>,
    pub pipeline_model_directory: String,
    pub vlm_model_directory: String,
    pub provenance_relative_path: String,
    pub provenance_size_bytes: u64,
    pub provenance_sha256: String,
    pub files: Vec<PackageFileV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PackageFileV1 {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ComponentProvenanceV1 {
    schema_version: u16,
    provenance_version: String,
    provenance_input_sha256: String,
    approval: ProvenanceApprovalV1,
    source: ProvenanceSourceV1,
    cpython: CpythonProvenanceV1,
    runtime_profile: RuntimeProfileV1,
    distributions: Vec<DistributionProvenanceV1>,
    excluded_distributions: Vec<ExcludedDistributionV1>,
    models: Vec<ModelProvenanceV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvenanceApprovalV1 {
    approved_for_redistribution: bool,
    reviewer: String,
    reviewed_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvenanceSourceV1 {
    repository_commit: String,
    build_script_sha256: String,
    worker_source_tree_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CpythonProvenanceV1 {
    version: String,
    source_url: String,
    content_sha256: String,
    license: String,
    license_file_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeProfileV1 {
    platform: String,
    root_distribution: String,
    extras: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DistributionProvenanceV1 {
    name: String,
    version: String,
    content_sha256: String,
    packaged_content_sha256: String,
    source_url: String,
    license: String,
    license_evidence_kind: String,
    license_files: Vec<ProvenanceFileV1>,
    installation_record: ProvenanceFileV1,
    upstream_artifact: UpstreamArtifactFieldV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum UpstreamArtifactFieldV1 {
    Artifact(UpstreamArtifactV1),
    None(()),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpstreamArtifactV1 {
    file_name: String,
    source_url: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExcludedDistributionV1 {
    name: String,
    version: String,
    reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ModelProvenanceV1 {
    root: String,
    name: String,
    revision: String,
    source_url: String,
    license: String,
    license_evidence_url: String,
    license_evidence_sha256: String,
    files: Vec<ProvenanceFileV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProvenanceFileV1 {
    relative_path: String,
    size_bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PartSetManifestV1 {
    pub schema_version: u16,
    pub package_id: String,
    pub component_version: Version,
    pub package_filename: String,
    pub package_size_bytes: u64,
    pub package_sha256: String,
    pub package_manifest_sha256: String,
    pub part_count: u16,
    pub parts: Vec<PartSetFileV1>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct PartSetFileV1 {
    pub number: u16,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256: String,
}

pub(super) fn read_part_set_manifest(
    path: &Path,
    catalog: &ComponentCatalogEntryV1,
) -> ComponentResult<PartSetManifestV1> {
    let expected_size = catalog
        .part_set_manifest_size_bytes
        .ok_or_else(|| error("part_manifest_untrusted"))?;
    let expected_hash = catalog
        .part_set_manifest_sha256
        .as_deref()
        .ok_or_else(|| error("part_manifest_untrusted"))?;
    let bytes = read_pinned_local_file(path, 2 * 1024 * 1024)?;
    if bytes.len() as u64 != expected_size || sha256_bytes(&bytes) != expected_hash {
        return Err(error("part_manifest_untrusted"));
    }
    let manifest: PartSetManifestV1 = privacy::vnext::strict_json_v1_from_slice(&bytes)
        .map_err(|_| error("part_manifest_invalid"))?;
    if privacy::vnext::canonical_json_v1(&manifest).map_err(|_| error("part_manifest_invalid"))?
        != bytes
    {
        return Err(error("part_manifest_not_canonical"));
    }
    let package_filename = format!(
        "lawyer-assistance-mineru-{}-windows-x86_64.laocrpkg",
        catalog.component_version
    );
    if manifest.schema_version != 1
        || manifest.package_id != catalog.package_id
        || manifest.component_version != catalog.component_version
        || manifest.package_filename != package_filename
        || manifest.package_size_bytes != catalog.package_size_bytes
        || manifest.package_sha256 != catalog.package_sha256
        || manifest.package_manifest_sha256 != catalog.package_manifest_sha256
        || usize::from(manifest.part_count) != catalog.parts.len()
        || manifest.parts.len() != catalog.parts.len()
    {
        return Err(error("part_manifest_untrusted"));
    }
    for (offset, (part, trusted)) in manifest.parts.iter().zip(&catalog.parts).enumerate() {
        let number = u16::try_from(offset + 1).map_err(|_| error("part_manifest_invalid"))?;
        if part.number != number
            || trusted.number != number
            || part.file_name != trusted.file_name
            || part.size_bytes != trusted.size_bytes
            || part.sha256 != trusted.sha256
        {
            return Err(error("part_manifest_untrusted"));
        }
    }
    Ok(manifest)
}

pub(super) fn assemble_offline_part_set(
    root: &Path,
    descriptor_path: &Path,
    catalog: &ComponentCatalogEntryV1,
) -> ComponentResult<(PathBuf, PathBuf)> {
    let manifest = read_part_set_manifest(descriptor_path, catalog)?;
    let source = descriptor_path
        .parent()
        .ok_or_else(|| error("part_source_invalid"))?;
    let mut expected = BTreeSet::from([descriptor_path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| error("part_source_invalid"))?
        .to_ascii_lowercase()]);
    expected.extend(
        manifest
            .parts
            .iter()
            .map(|part| part.file_name.to_ascii_lowercase()),
    );
    ensure_exact_source_files(source, &expected)?;
    let directory = root.join(format!(".assembly-{}", Uuid::new_v4()));
    fs::create_dir(&directory).map_err(|_| error("assembly_staging_failed"))?;
    let output = directory.join("component.laocrpkg");
    let incoming = directory.join(".component.incoming");
    let result = (|| {
        let mut target = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&incoming)
            .map_err(|_| error("assembly_write_failed"))?;
        let mut overall = Sha256::new();
        let mut total = 0u64;
        let mut buffer = vec![0u8; BUFFER_BYTES];
        for part in &manifest.parts {
            let mut source_file = open_pinned_file(&source.join(&part.file_name), part.size_bytes)?;
            let (hash, size) = measure_open_file(&mut source_file, part.size_bytes)?;
            if hash != part.sha256 || size != part.size_bytes {
                return Err(error("part_integrity_mismatch"));
            }
            loop {
                let count = source_file
                    .read(&mut buffer)
                    .map_err(|_| error("part_read_failed"))?;
                if count == 0 {
                    break;
                }
                target
                    .write_all(&buffer[..count])
                    .map_err(|_| error("assembly_write_failed"))?;
                overall.update(&buffer[..count]);
                total = total
                    .checked_add(count as u64)
                    .ok_or_else(|| error("package_size_invalid"))?;
            }
        }
        target
            .flush()
            .and_then(|_| target.sync_all())
            .map_err(|_| error("assembly_write_failed"))?;
        drop(target);
        if total != manifest.package_size_bytes
            || format!("{:x}", overall.finalize()) != manifest.package_sha256
        {
            return Err(error("package_integrity_mismatch"));
        }
        ensure_exact_source_files(source, &expected)?;
        fs::rename(&incoming, &output).map_err(|_| error("atomic_assembly_failed"))?;
        let (hash, size) = sha256_pinned_file(&output, manifest.package_size_bytes)?;
        if hash != manifest.package_sha256 || size != manifest.package_size_bytes {
            return Err(error("package_integrity_mismatch"));
        }
        Ok(())
    })();
    if let Err(failure) = result {
        let _ = fs::remove_file(&incoming);
        let _ = fs::remove_file(&output);
        let _ = fs::remove_dir(&directory);
        return Err(failure);
    }
    Ok((directory, output))
}

fn ensure_exact_source_files(directory: &Path, expected: &BTreeSet<String>) -> ComponentResult<()> {
    ensure_existing_safe_directory(directory)?;
    let mut observed = BTreeSet::new();
    collect_files(directory, directory, &mut observed)?;
    if &observed != expected {
        return Err(error("part_source_file_set_mismatch"));
    }
    Ok(())
}

pub(super) fn install_package(
    root: &Path,
    package_path: &Path,
    catalog: &ComponentCatalogEntryV1,
) -> ComponentResult<ManagedMineruBinding> {
    let mut package = open_pinned_file(package_path, MAX_PACKAGE_BYTES)?;
    let (package_hash, package_size) = measure_open_file(&mut package, MAX_PACKAGE_BYTES)?;
    if package_hash != catalog.package_sha256 || package_size != catalog.package_size_bytes {
        return Err(error("package_integrity_mismatch"));
    }
    ensure_install_capacity(root, package_size)?;
    let (manifest, manifest_bytes) = read_header(&mut package)?;
    validate_manifest(&manifest, &manifest_bytes, catalog, package_size)?;
    let manifest_hash = sha256_bytes(&manifest_bytes);
    if manifest_hash != catalog.package_manifest_sha256 {
        return Err(error("package_manifest_untrusted"));
    }
    let destination = root.join(manifest.component_version.to_string());
    ensure_runtime_path_budget(&destination, &manifest)?;
    if destination.exists() {
        let temporary_catalog = ComponentCatalogV1 {
            schema_version: 1,
            catalog_id: "existing-validation".to_owned(),
            issued_at_unix: 1,
            expires_at_unix: u64::MAX,
            entries: vec![catalog.clone()],
        };
        return validate_installed_component(root, &manifest.component_version, &temporary_catalog);
    }
    let staging = root.join(format!(".staging-{}", Uuid::new_v4()));
    fs::create_dir(&staging).map_err(|_| error("staging_create_failed"))?;
    let extraction = extract(
        &mut package,
        &staging,
        &destination,
        &manifest,
        &manifest_bytes,
    )
    .and_then(|()| validate_tree(&staging, &destination, &manifest, &manifest_hash));
    let staged_binding = match extraction {
        Ok(binding) => binding,
        Err(failure) => {
            let cleanup = cleanup_declared_tree(&staging, &expected_files(&manifest));
            return cleanup.map_or_else(|_| Err(error("cleanup_failed")), |()| Err(failure));
        }
    };
    if fs::rename(&staging, &destination).is_err() {
        let cleanup = cleanup_declared_tree(&staging, &expected_files(&manifest));
        return cleanup.map_or_else(
            |_| Err(error("cleanup_failed")),
            |()| Err(error("atomic_install_failed")),
        );
    }
    Ok(ManagedMineruBinding {
        component_version: staged_binding.component_version,
        worker_path: destination.join(validated_relative(&manifest.worker)?),
        model_root: destination.join("models"),
        tools_config_path: destination.join(MANAGED_CONFIG),
        runtime_executable_paths: manifest
            .runtime_executables
            .iter()
            .map(|value| validated_relative(value).map(|path| destination.join(path)))
            .collect::<ComponentResult<Vec<_>>>()?,
        manifest_sha256: staged_binding.manifest_sha256,
    })
}

pub(super) fn validate_installed_component(
    root: &Path,
    version: &Version,
    catalog: &ComponentCatalogV1,
) -> ComponentResult<ManagedMineruBinding> {
    let directory = root.join(version.to_string());
    let (manifest, bytes) = read_manifest(&directory)?;
    validate_manifest_shape(&manifest)?;
    if &manifest.component_version != version {
        return Err(error("installed_version_mismatch"));
    }
    let manifest_hash = sha256_bytes(&bytes);
    if !catalog.entries.iter().any(|entry| {
        !entry.revoked
            && entry.package_id == manifest.package_id
            && entry.component_version == *version
            && entry.package_manifest_sha256 == manifest_hash
            && entry.provenance_file_name == "mineru-component-provenance.json"
            && entry.provenance_size_bytes == manifest.provenance_size_bytes
            && entry.provenance_sha256 == manifest.provenance_sha256
    }) {
        return Err(error("installed_component_untrusted"));
    }
    validate_tree(&directory, &directory, &manifest, &manifest_hash)
}

fn validate_tree(
    directory: &Path,
    managed_location: &Path,
    manifest: &ComponentPackageManifestV1,
    manifest_hash: &str,
) -> ComponentResult<ManagedMineruBinding> {
    ensure_runtime_path_budget(managed_location, manifest)?;
    ensure_existing_safe_directory(directory)?;
    let mut observed = BTreeSet::new();
    collect_files(directory, directory, &mut observed)?;
    if observed != expected_files(manifest) {
        return Err(error("component_file_set_drifted"));
    }
    for entry in &manifest.files {
        let path = directory.join(validated_relative(&entry.relative_path)?);
        let (hash, size) = sha256_pinned_file(&path, entry.size_bytes)?;
        if hash != entry.sha256 || size != entry.size_bytes {
            return Err(error("component_file_drifted"));
        }
    }
    let expected_config = managed_config_bytes(managed_location, manifest)?;
    if read_pinned_local_file(&directory.join(MANAGED_CONFIG), 2 * 1024 * 1024)? != expected_config
    {
        return Err(error("managed_config_drifted"));
    }
    let manifest_bytes =
        read_pinned_local_file(&directory.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    if sha256_bytes(&manifest_bytes) != manifest_hash {
        return Err(error("installed_manifest_drifted"));
    }
    let provenance_bytes = read_pinned_local_file(
        &directory.join(validated_relative(&manifest.provenance_relative_path)?),
        MAX_PROVENANCE_BYTES,
    )?;
    if provenance_bytes.len() as u64 != manifest.provenance_size_bytes
        || sha256_bytes(&provenance_bytes) != manifest.provenance_sha256
    {
        return Err(error("component_provenance_drifted"));
    }
    validate_component_provenance(&provenance_bytes, manifest)?;
    Ok(ManagedMineruBinding {
        component_version: manifest.component_version.clone(),
        worker_path: directory.join(validated_relative(&manifest.worker)?),
        model_root: directory.join("models"),
        tools_config_path: directory.join(MANAGED_CONFIG),
        runtime_executable_paths: manifest
            .runtime_executables
            .iter()
            .map(|value| validated_relative(value).map(|path| directory.join(path)))
            .collect::<ComponentResult<Vec<_>>>()?,
        manifest_sha256: manifest_hash.to_owned(),
    })
}

fn read_header(package: &mut File) -> ComponentResult<(ComponentPackageManifestV1, Vec<u8>)> {
    package
        .seek(SeekFrom::Start(0))
        .map_err(|_| error("package_read_failed"))?;
    let mut magic = [0u8; 8];
    package
        .read_exact(&mut magic)
        .map_err(|_| error("package_format_invalid"))?;
    if &magic != PACKAGE_MAGIC {
        return Err(error("package_format_invalid"));
    }
    let mut length = [0u8; 4];
    package
        .read_exact(&mut length)
        .map_err(|_| error("package_format_invalid"))?;
    let length = u32::from_le_bytes(length) as u64;
    if length == 0 || length > MAX_MANIFEST_BYTES {
        return Err(error("package_format_invalid"));
    }
    let mut bytes = vec![0u8; length as usize];
    package
        .read_exact(&mut bytes)
        .map_err(|_| error("package_format_invalid"))?;
    let manifest = serde_json::from_slice(&bytes).map_err(|_| error("package_manifest_invalid"))?;
    Ok((manifest, bytes))
}

fn validate_manifest(
    manifest: &ComponentPackageManifestV1,
    manifest_bytes: &[u8],
    catalog: &ComponentCatalogEntryV1,
    package_size: u64,
) -> ComponentResult<()> {
    validate_manifest_shape(manifest)?;
    if manifest.package_id != catalog.package_id
        || manifest.component_version != catalog.component_version
        || manifest.mineru_version != catalog.mineru_version
        || manifest.provenance_relative_path != PROVENANCE_FILE
        || manifest.provenance_size_bytes != catalog.provenance_size_bytes
        || manifest.provenance_sha256 != catalog.provenance_sha256
        || catalog.provenance_file_name != "mineru-component-provenance.json"
    {
        return Err(error("package_manifest_untrusted"));
    }
    let payload_size = manifest.files.iter().try_fold(0u64, |total, file| {
        total
            .checked_add(file.size_bytes)
            .ok_or_else(|| error("package_size_invalid"))
    })?;
    if 12u64
        .checked_add(manifest_bytes.len() as u64)
        .and_then(|header| header.checked_add(payload_size))
        != Some(package_size)
    {
        return Err(error("package_size_invalid"));
    }
    Ok(())
}

fn validate_manifest_shape(manifest: &ComponentPackageManifestV1) -> ComponentResult<()> {
    if manifest.schema_version != COMPONENT_SCHEMA_VERSION
        || manifest.protocol_version != PROTOCOL_VERSION
        || manifest.platform != PLATFORM
        || manifest.package_id.len() < 3
        || manifest.package_id.len() > 64
        || manifest.mineru_version.is_empty()
        || manifest.mineru_version.len() > 64
        || manifest.files.is_empty()
        || manifest.files.len() > MAX_FILES
        || manifest.runtime_executables.len() > 32
        || manifest.provenance_relative_path != PROVENANCE_FILE
        || manifest.provenance_size_bytes == 0
        || manifest.provenance_size_bytes > MAX_PROVENANCE_BYTES
        || !valid_hash(&manifest.provenance_sha256)
    {
        return Err(error("package_manifest_invalid"));
    }
    let mut paths = BTreeSet::new();
    for file in &manifest.files {
        validated_relative(&file.relative_path)?;
        if !paths.insert(file.relative_path.to_ascii_lowercase())
            || file.relative_path.eq_ignore_ascii_case(MANIFEST_FILE)
            || file.relative_path.eq_ignore_ascii_case(MANAGED_CONFIG)
            || file.size_bytes == 0
            || !valid_hash(&file.sha256)
        {
            return Err(error("package_manifest_invalid"));
        }
    }
    for executable in std::iter::once(&manifest.worker).chain(manifest.runtime_executables.iter()) {
        let path = validated_relative(executable)?;
        if path.extension().and_then(OsStr::to_str) != Some("exe")
            || !paths.contains(&executable.to_ascii_lowercase())
        {
            return Err(error("package_manifest_invalid"));
        }
    }
    for file in &manifest.files {
        let is_executable = relative_path(&file.relative_path).is_some_and(|path| {
            path.extension()
                .and_then(OsStr::to_str)
                .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
        });
        let declared = std::iter::once(&manifest.worker)
            .chain(manifest.runtime_executables.iter())
            .any(|executable| executable.eq_ignore_ascii_case(&file.relative_path));
        if is_executable && !declared {
            return Err(error("package_manifest_invalid"));
        }
    }
    for model in [
        &manifest.pipeline_model_directory,
        &manifest.vlm_model_directory,
    ] {
        let model_path = validated_relative(model)?;
        if !model_path.starts_with("models")
            || !manifest.files.iter().any(|file| {
                relative_path(&file.relative_path).is_some_and(|path| path.starts_with(&model_path))
            })
        {
            return Err(error("package_manifest_invalid"));
        }
    }
    let provenance_entries = manifest
        .files
        .iter()
        .filter(|file| file.relative_path.eq_ignore_ascii_case(PROVENANCE_FILE))
        .collect::<Vec<_>>();
    if provenance_entries.len() != 1
        || provenance_entries[0].relative_path != PROVENANCE_FILE
        || provenance_entries[0].size_bytes != manifest.provenance_size_bytes
        || provenance_entries[0].sha256 != manifest.provenance_sha256
    {
        return Err(error("package_manifest_invalid"));
    }
    Ok(())
}

pub(super) fn validate_component_provenance(
    bytes: &[u8],
    manifest: &ComponentPackageManifestV1,
) -> ComponentResult<()> {
    let provenance: ComponentProvenanceV1 = privacy::vnext::strict_json_v1_from_slice(bytes)
        .map_err(|_| error("component_provenance_invalid"))?;
    if privacy::vnext::canonical_json_v1(&provenance)
        .map_err(|_| error("component_provenance_invalid"))?
        != bytes
    {
        return Err(error("component_provenance_not_canonical"));
    }
    if provenance.schema_version != 1
        || provenance.provenance_version != PROVENANCE_VERSION
        || !valid_hash(&provenance.provenance_input_sha256)
        || !provenance.approval.approved_for_redistribution
        || provenance.approval.reviewer.trim().is_empty()
        || provenance.approval.reviewer.len() > 128
        || provenance.approval.reviewed_at_unix == 0
        || !valid_revision(&provenance.source.repository_commit)
        || !valid_hash(&provenance.source.build_script_sha256)
        || !valid_hash(&provenance.source.worker_source_tree_sha256)
        || provenance.cpython.version != "3.12.13"
        || !valid_official_source_url(&provenance.cpython.source_url)
        || !valid_hash(&provenance.cpython.content_sha256)
        || unknown_license(&provenance.cpython.license)
        || !valid_hash(&provenance.cpython.license_file_sha256)
        || provenance.runtime_profile.platform != PLATFORM
        || provenance.runtime_profile.root_distribution != "mineru==3.4.3"
        || provenance.runtime_profile.extras != ["pipeline", "vlm"]
        || provenance.distributions.is_empty()
        || provenance.distributions.len() > 512
        || provenance.models.len() != 2
    {
        return Err(error("component_provenance_invalid"));
    }
    if !manifest_file_matches(
        manifest,
        "licenses/cpython/LICENSE.txt",
        None,
        Some(&provenance.cpython.license_file_sha256),
    ) {
        return Err(error("component_provenance_unbound"));
    }

    let mut distribution_names = BTreeSet::new();
    let mut previous_name: Option<&str> = None;
    let mut mineru_seen = false;
    let mut torch_seen = false;
    let mut torchvision_seen = false;
    for distribution in &provenance.distributions {
        if previous_name.is_some_and(|previous| previous >= distribution.name.as_str())
            || !distribution_names.insert(distribution.name.as_str())
            || distribution.name.is_empty()
            || distribution.name.len() > 128
            || distribution.version.is_empty()
            || distribution.version.len() > 128
            || !valid_hash(&distribution.content_sha256)
            || !valid_hash(&distribution.packaged_content_sha256)
            || !valid_official_source_url(&distribution.source_url)
            || unknown_license(&distribution.license)
            || !matches!(
                distribution.license_evidence_kind.as_str(),
                "metadata-license-expression" | "metadata-license" | "metadata-license-classifier"
            )
            || !valid_provenance_file(&distribution.installation_record, false)
            || !distribution
                .installation_record
                .relative_path
                .ends_with(".dist-info/RECORD")
        {
            return Err(error("component_provenance_invalid"));
        }
        previous_name = Some(&distribution.name);
        if !manifest_file_matches(
            manifest,
            &format!(
                "runtime/site-packages/{}",
                distribution.installation_record.relative_path
            ),
            Some(distribution.installation_record.size_bytes),
            Some(&distribution.installation_record.sha256),
        ) {
            return Err(error("component_provenance_unbound"));
        }
        validate_provenance_files(&distribution.license_files)?;
        for license_file in &distribution.license_files {
            if !manifest_file_matches(
                manifest,
                &format!("runtime/site-packages/{}", license_file.relative_path),
                Some(license_file.size_bytes),
                Some(&license_file.sha256),
            ) {
                return Err(error("component_provenance_unbound"));
            }
        }
        match distribution.name.as_str() {
            "mineru" => {
                mineru_seen = true;
                if distribution.version != "3.4.3"
                    || distribution.license != MINERU_LICENSE
                    || !distribution.license_files.iter().any(|file| {
                        file.relative_path.ends_with("/LICENSE.md")
                            || file.relative_path == "LICENSE.md"
                    })
                    || !matches!(
                        &distribution.upstream_artifact,
                        UpstreamArtifactFieldV1::None(())
                    )
                {
                    return Err(error("component_provenance_invalid"));
                }
            }
            "torch" => {
                torch_seen = true;
                validate_pytorch_artifact(distribution, "2.8.0+cu128", TORCH_WHEEL)?;
                let names = distribution
                    .license_files
                    .iter()
                    .filter_map(|file| Path::new(&file.relative_path).file_name())
                    .filter_map(OsStr::to_str)
                    .collect::<BTreeSet<_>>();
                if !names.contains("LICENSE") || !names.contains("NOTICE") {
                    return Err(error("component_provenance_invalid"));
                }
            }
            "torchvision" => {
                torchvision_seen = true;
                validate_pytorch_artifact(distribution, "0.23.0+cu128", TORCHVISION_WHEEL)?;
            }
            _ if !matches!(
                &distribution.upstream_artifact,
                UpstreamArtifactFieldV1::None(())
            ) =>
            {
                return Err(error("component_provenance_invalid"));
            }
            _ => {}
        }
    }
    if !mineru_seen || !torch_seen || !torchvision_seen {
        return Err(error("component_provenance_invalid"));
    }

    let mut excluded_names = BTreeSet::new();
    let mut previous_excluded: Option<&str> = None;
    for excluded in &provenance.excluded_distributions {
        if excluded.name.is_empty()
            || excluded.version.is_empty()
            || excluded.reason != "outside-mineru-pipeline-vlm-dependency-closure"
            || previous_excluded.is_some_and(|previous| previous >= excluded.name.as_str())
            || !excluded_names.insert(excluded.name.as_str())
            || distribution_names.contains(excluded.name.as_str())
        {
            return Err(error("component_provenance_invalid"));
        }
        previous_excluded = Some(&excluded.name);
    }

    for (index, model) in provenance.models.iter().enumerate() {
        let (root, profile, evidence_sha256, expected_files) = if index == 0 {
            (
                "pipeline",
                PIPELINE_MODEL,
                PIPELINE_MODEL_LICENSE_EVIDENCE_SHA256,
                PIPELINE_MODEL_FILES,
            )
        } else {
            (
                "vlm",
                VLM_MODEL,
                VLM_MODEL_LICENSE_EVIDENCE_SHA256,
                VLM_MODEL_FILES,
            )
        };
        validate_model_provenance(
            manifest,
            model,
            root,
            profile,
            evidence_sha256,
            expected_files,
        )?;
    }
    Ok(())
}

fn validate_pytorch_artifact(
    distribution: &DistributionProvenanceV1,
    version: &str,
    expected: (&str, &str, &str),
) -> ComponentResult<()> {
    let UpstreamArtifactFieldV1::Artifact(artifact) = &distribution.upstream_artifact else {
        return Err(error("component_provenance_invalid"));
    };
    if distribution.version != version
        || artifact.file_name != expected.0
        || artifact.source_url != expected.1
        || artifact.sha256 != expected.2
        || !valid_official_source_url(&artifact.source_url)
    {
        return Err(error("component_provenance_invalid"));
    }
    Ok(())
}

fn validate_model_provenance(
    manifest: &ComponentPackageManifestV1,
    model: &ModelProvenanceV1,
    root: &str,
    profile: (&str, &str, &str),
    evidence_sha256: &str,
    expected_files: &[&str],
) -> ComponentResult<()> {
    let expected_source = format!("https://huggingface.co/{}/tree/{}", profile.0, profile.1);
    let expected_evidence = format!(
        "https://huggingface.co/{}/blob/{}/README.md",
        profile.0, profile.1
    );
    if model.root != root
        || model.name != profile.0
        || model.revision != profile.1
        || model.license != profile.2
        || model.source_url != expected_source
        || model.license_evidence_url != expected_evidence
        || model.license_evidence_sha256 != evidence_sha256
        || !valid_hash(&model.license_evidence_sha256)
        || !valid_official_source_url(&model.source_url)
        || !valid_official_source_url(&model.license_evidence_url)
    {
        return Err(error("component_provenance_invalid"));
    }
    validate_provenance_files(&model.files)?;
    if model
        .files
        .iter()
        .map(|file| file.relative_path.as_str())
        .ne(expected_files.iter().copied())
    {
        return Err(error("component_provenance_invalid"));
    }
    let prefix = format!("models/{root}/");
    let observed = manifest
        .files
        .iter()
        .filter_map(|file| file.relative_path.strip_prefix(&prefix))
        .collect::<BTreeSet<_>>();
    if observed != expected_files.iter().copied().collect::<BTreeSet<_>>() {
        return Err(error("component_provenance_unbound"));
    }
    for file in &model.files {
        if !manifest_file_matches(
            manifest,
            &format!("{prefix}{}", file.relative_path),
            Some(file.size_bytes),
            Some(&file.sha256),
        ) {
            return Err(error("component_provenance_unbound"));
        }
    }
    Ok(())
}

fn validate_provenance_files(files: &[ProvenanceFileV1]) -> ComponentResult<()> {
    let mut previous: Option<&str> = None;
    for file in files {
        if previous.is_some_and(|value| value >= file.relative_path.as_str())
            || !valid_provenance_file(file, true)
        {
            return Err(error("component_provenance_invalid"));
        }
        previous = Some(&file.relative_path);
    }
    Ok(())
}

fn valid_provenance_file(file: &ProvenanceFileV1, allow_zero: bool) -> bool {
    file.relative_path.len() <= 240
        && validated_relative(&file.relative_path).is_ok()
        && (allow_zero || file.size_bytes > 0)
        && valid_hash(&file.sha256)
}

fn manifest_file_matches(
    manifest: &ComponentPackageManifestV1,
    relative_path: &str,
    size: Option<u64>,
    hash: Option<&str>,
) -> bool {
    manifest.files.iter().any(|file| {
        file.relative_path == relative_path
            && size.is_none_or(|value| file.size_bytes == value)
            && hash.is_none_or(|value| file.sha256 == value)
    })
}

fn valid_revision(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unknown_license(value: &str) -> bool {
    value.trim().is_empty()
        || matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "noassertion" | "none" | "unknown" | "n/a" | "not specified"
        )
}

fn valid_official_source_url(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    let official = matches!(
        url.host_str(),
        Some(
            "download-r2.pytorch.org"
                | "download.pytorch.org"
                | "pypi.org"
                | "files.pythonhosted.org"
                | "python.org"
                | "www.python.org"
                | "huggingface.co"
                | "github.com"
                | "raw.githubusercontent.com"
        )
    );
    url.scheme() == "https"
        && official
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn extract(
    package: &mut File,
    staging: &Path,
    managed_location: &Path,
    manifest: &ComponentPackageManifestV1,
    manifest_bytes: &[u8],
) -> ComponentResult<()> {
    let mut buffer = vec![0u8; BUFFER_BYTES];
    for entry in &manifest.files {
        let destination = staging.join(validated_relative(&entry.relative_path)?);
        create_parents(staging, destination.parent().unwrap_or(staging))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|_| error("extract_failed"))?;
        let mut remaining = entry.size_bytes;
        let mut hasher = Sha256::new();
        let mut prefix = [0u8; 2];
        let mut prefix_len = 0usize;
        while remaining > 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            package
                .read_exact(&mut buffer[..count])
                .map_err(|_| error("package_truncated"))?;
            if prefix_len < 2 {
                let take = (2 - prefix_len).min(count);
                prefix[prefix_len..prefix_len + take].copy_from_slice(&buffer[..take]);
                prefix_len += take;
            }
            output
                .write_all(&buffer[..count])
                .map_err(|_| error("extract_failed"))?;
            hasher.update(&buffer[..count]);
            remaining -= count as u64;
        }
        output
            .flush()
            .and_then(|_| output.sync_all())
            .map_err(|_| error("extract_failed"))?;
        drop(output);
        if format!("{:x}", hasher.finalize()) != entry.sha256 {
            return Err(error("package_payload_hash_mismatch"));
        }
        if std::iter::once(&manifest.worker)
            .chain(manifest.runtime_executables.iter())
            .any(|path| path == &entry.relative_path)
            && prefix != *b"MZ"
        {
            return Err(error("component_executable_invalid"));
        }
    }
    if package
        .stream_position()
        .map_err(|_| error("package_read_failed"))?
        != package
            .metadata()
            .map_err(|_| error("package_read_failed"))?
            .len()
    {
        return Err(error("package_trailing_data"));
    }
    write_new_file(&staging.join(MANIFEST_FILE), manifest_bytes)?;
    let config = managed_config_bytes(managed_location, manifest)?;
    let config_path = staging.join(MANAGED_CONFIG);
    create_parents(staging, config_path.parent().unwrap_or(staging))?;
    write_new_file(&config_path, &config)
}

fn managed_config_bytes(
    component: &Path,
    manifest: &ComponentPackageManifestV1,
) -> ComponentResult<Vec<u8>> {
    let root = normalized_managed_location(component)?;
    let pipeline = root.join(validated_relative(&manifest.pipeline_model_directory)?);
    let vlm = root.join(validated_relative(&manifest.vlm_model_directory)?);
    if component.exists() {
        ensure_existing_safe_directory(&pipeline)?;
        ensure_existing_safe_directory(&vlm)?;
    }
    let pipeline = mineru_compatible_path(&pipeline)?;
    let vlm = mineru_compatible_path(&vlm)?;
    serde_json::to_vec(&serde_json::json!({
        "models-dir": {"pipeline": pipeline, "vlm": vlm}
    }))
    .map_err(|_| error("managed_config_invalid"))
}

fn normalized_managed_location(component: &Path) -> ComponentResult<PathBuf> {
    let root = if component.exists() {
        fs::canonicalize(component).map_err(|_| error("component_directory_invalid"))?
    } else {
        let parent = component
            .parent()
            .ok_or_else(|| error("component_directory_invalid"))?;
        let name = component
            .file_name()
            .ok_or_else(|| error("component_directory_invalid"))?;
        fs::canonicalize(parent)
            .map_err(|_| error("component_directory_invalid"))?
            .join(name)
    };
    Ok(PathBuf::from(mineru_compatible_path(&root)?))
}

pub(super) fn ensure_runtime_path_budget(
    managed_location: &Path,
    manifest: &ComponentPackageManifestV1,
) -> ComponentResult<()> {
    let root = normalized_managed_location(managed_location)?;
    for relative in manifest
        .files
        .iter()
        .map(|entry| entry.relative_path.as_str())
        .chain([MANIFEST_FILE, MANAGED_CONFIG])
    {
        let path = root.join(validated_relative(relative)?);
        if path.as_os_str().encode_wide().count() > MAX_RUNTIME_PATH_UTF16_UNITS {
            return Err(error("component_runtime_path_too_long"));
        }
    }
    Ok(())
}

fn mineru_compatible_path(path: &Path) -> ComponentResult<String> {
    let value = path
        .to_str()
        .ok_or_else(|| error("component_path_not_unicode"))?;
    #[cfg(windows)]
    let value = if let Some(unc) = value.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else if let Some(local) = value.strip_prefix(r"\\?\") {
        local.to_owned()
    } else {
        value.to_owned()
    };
    #[cfg(not(windows))]
    let value = value.to_owned();
    Ok(value)
}

pub(super) fn read_manifest(
    directory: &Path,
) -> ComponentResult<(ComponentPackageManifestV1, Vec<u8>)> {
    let bytes = read_pinned_local_file(&directory.join(MANIFEST_FILE), MAX_MANIFEST_BYTES)?;
    let manifest =
        serde_json::from_slice(&bytes).map_err(|_| error("installed_manifest_invalid"))?;
    Ok((manifest, bytes))
}

pub(super) fn installed_versions(root: &Path, limit: usize) -> ComponentResult<Vec<Version>> {
    let mut versions = Vec::new();
    for entry in fs::read_dir(root).map_err(|_| error("component_root_unavailable"))? {
        let entry = entry.map_err(|_| error("component_root_unavailable"))?;
        let Ok(version) = Version::parse(&entry.file_name().to_string_lossy()) else {
            continue;
        };
        ensure_existing_safe_directory(&entry.path())?;
        versions.push(version);
        if versions.len() > limit {
            return Err(error("too_many_component_versions"));
        }
    }
    Ok(versions)
}

pub(super) fn remove_installed_component(directory: &Path) -> ComponentResult<()> {
    let (manifest, _) = read_manifest(directory)?;
    cleanup_declared_tree(directory, &expected_files(&manifest))
}

fn cleanup_declared_tree(directory: &Path, expected: &BTreeSet<String>) -> ComponentResult<()> {
    ensure_existing_safe_directory(directory)?;
    let mut observed = BTreeSet::new();
    collect_files(directory, directory, &mut observed)?;
    if &observed != expected {
        return Err(error("uninstall_file_set_mismatch"));
    }
    let mut files: Vec<_> = expected
        .iter()
        .map(|value| directory.join(relative_path(value).unwrap_or_default()))
        .collect();
    files.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for file in files {
        fs::remove_file(file).map_err(|_| error("uninstall_incomplete"))?;
    }
    remove_empty_directories(directory)?;
    fs::remove_dir(directory).map_err(|_| error("uninstall_incomplete"))
}

fn remove_empty_directories(root: &Path) -> ComponentResult<()> {
    let mut directories = Vec::new();
    collect_directories(root, &mut directories)?;
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        fs::remove_dir(directory).map_err(|_| error("uninstall_incomplete"))?;
    }
    Ok(())
}

fn collect_directories(directory: &Path, output: &mut Vec<PathBuf>) -> ComponentResult<()> {
    for entry in fs::read_dir(directory).map_err(|_| error("filesystem_rejected"))? {
        let entry = entry.map_err(|_| error("filesystem_rejected"))?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| error("filesystem_rejected"))?;
        if unsafe_attributes(&metadata) {
            return Err(error("filesystem_rejected"));
        }
        if metadata.is_dir() {
            collect_directories(&entry.path(), output)?;
            output.push(entry.path());
        } else if metadata.is_file() {
            return Err(error("uninstall_incomplete"));
        }
    }
    Ok(())
}

fn expected_files(manifest: &ComponentPackageManifestV1) -> BTreeSet<String> {
    manifest
        .files
        .iter()
        .map(|entry| entry.relative_path.to_ascii_lowercase())
        .chain([MANIFEST_FILE.to_owned(), MANAGED_CONFIG.to_owned()])
        .collect()
}

fn collect_files(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
) -> ComponentResult<()> {
    for entry in fs::read_dir(directory).map_err(|_| error("filesystem_rejected"))? {
        let entry = entry.map_err(|_| error("filesystem_rejected"))?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| error("filesystem_rejected"))?;
        if unsafe_attributes(&metadata) {
            return Err(error("filesystem_rejected"));
        }
        if metadata.is_dir() {
            collect_files(root, &entry.path(), output)?;
        } else if metadata.is_file() && single_link(&entry.path()) {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|_| error("filesystem_rejected"))?
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/")
                .to_ascii_lowercase();
            if !output.insert(relative) {
                return Err(error("filesystem_rejected"));
            }
        } else {
            return Err(error("filesystem_rejected"));
        }
    }
    Ok(())
}

pub(super) fn cleanup_exact_transient(directory: &Path, files: &[PathBuf]) -> ComponentResult<()> {
    for file in files {
        match fs::remove_file(file) {
            Ok(()) => {}
            Err(failure) if failure.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error("cleanup_failed")),
        }
    }
    fs::remove_dir(directory).map_err(|_| error("cleanup_failed"))
}

pub(super) fn cleanup_safe_transient(directory: &Path) -> ComponentResult<()> {
    ensure_existing_safe_directory(directory)?;
    let mut files = Vec::new();
    let mut directories = Vec::new();
    collect_cleanup_entries(directory, &mut files, &mut directories)?;
    for file in files {
        fs::remove_file(file).map_err(|_| error("cleanup_failed"))?;
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for child in directories {
        fs::remove_dir(child).map_err(|_| error("cleanup_failed"))?;
    }
    fs::remove_dir(directory).map_err(|_| error("cleanup_failed"))
}

fn collect_cleanup_entries(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    directories: &mut Vec<PathBuf>,
) -> ComponentResult<()> {
    for entry in fs::read_dir(directory).map_err(|_| error("cleanup_failed"))? {
        let entry = entry.map_err(|_| error("cleanup_failed"))?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|_| error("cleanup_failed"))?;
        if unsafe_attributes(&metadata) {
            return Err(error("cleanup_failed"));
        }
        if metadata.is_file() && single_link(&entry.path()) {
            files.push(entry.path());
        } else if metadata.is_dir() {
            collect_cleanup_entries(&entry.path(), files, directories)?;
            directories.push(entry.path());
        } else {
            return Err(error("cleanup_failed"));
        }
    }
    Ok(())
}

fn create_parents(root: &Path, parent: &Path) -> ComponentResult<()> {
    let relative = parent
        .strip_prefix(root)
        .map_err(|_| error("filesystem_rejected"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(error("filesystem_rejected"));
        };
        current.push(name);
        match fs::create_dir(&current) {
            Ok(()) => {}
            Err(failure) if failure.kind() == std::io::ErrorKind::AlreadyExists => {
                ensure_existing_safe_directory(&current)?;
            }
            Err(_) => return Err(error("extract_failed")),
        }
    }
    Ok(())
}

pub(super) fn write_new_file(path: &Path, bytes: &[u8]) -> ComponentResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| error("component_write_failed"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| error("component_write_failed"))
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> ComponentResult<()> {
    let parent = path.parent().ok_or_else(|| error("filesystem_rejected"))?;
    ensure_existing_safe_directory(parent)?;
    let incoming = parent.join(format!(".incoming-{}", Uuid::new_v4()));
    write_new_file(&incoming, bytes)?;
    if atomic_file::install(&incoming, path, None).is_err() {
        let _ = fs::remove_file(&incoming);
        return Err(error("atomic_write_failed"));
    }
    Ok(())
}

pub(super) fn append_file(path: &Path, bytes: &[u8]) -> ComponentResult<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|_| error("audit_failed"))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_data())
        .map_err(|_| error("audit_failed"))
}

pub(super) fn read_pinned_local_file(path: &Path, max: u64) -> ComponentResult<Vec<u8>> {
    let mut file = open_pinned_file(path, max)?;
    let size = file
        .metadata()
        .map_err(|_| error("component_file_unavailable"))?
        .len();
    let mut bytes = Vec::with_capacity(size.min(16 * 1024 * 1024) as usize);
    file.read_to_end(&mut bytes)
        .map_err(|_| error("component_file_unavailable"))?;
    if bytes.len() as u64 != size {
        return Err(error("component_file_changed"));
    }
    Ok(bytes)
}

pub(super) fn sha256_pinned_file(path: &Path, max: u64) -> ComponentResult<(String, u64)> {
    let mut file = open_pinned_file(path, max)?;
    measure_open_file(&mut file, max)
}

fn measure_open_file(file: &mut File, max: u64) -> ComponentResult<(String, u64)> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| error("component_file_unavailable"))?;
    let size = file
        .metadata()
        .map_err(|_| error("component_file_unavailable"))?
        .len();
    if size == 0 || size > max {
        return Err(error("component_file_size_invalid"));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; BUFFER_BYTES];
    let mut total = 0u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| error("component_file_unavailable"))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| error("component_file_changed"))?;
        hasher.update(&buffer[..count]);
    }
    if total != size || link_count(file)? != 1 {
        return Err(error("component_file_changed"));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| error("component_file_unavailable"))?;
    Ok((format!("{:x}", hasher.finalize()), size))
}

pub(super) fn ensure_download_capacity(root: &Path, package_size: u64) -> ComponentResult<()> {
    let required = package_size
        .checked_mul(2)
        .and_then(|value| value.checked_add(2 * 1024 * 1024 * 1024))
        .ok_or_else(|| error("package_size_invalid"))?;
    ensure_free_space(root, required)
}

fn ensure_install_capacity(root: &Path, package_size: u64) -> ComponentResult<()> {
    let required = package_size
        .checked_add(2 * 1024 * 1024 * 1024)
        .ok_or_else(|| error("package_size_invalid"))?;
    ensure_free_space(root, required)
}

fn ensure_free_space(root: &Path, required: u64) -> ComponentResult<()> {
    let wide: Vec<u16> = root.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut available = 0u64;
    if unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
        || available < required
    {
        return Err(error("insufficient_component_disk_space"));
    }
    Ok(())
}

fn open_pinned_file(path: &Path, max: u64) -> ComponentResult<File> {
    if !is_normal_fixed_absolute(path) {
        return Err(error("filesystem_rejected"));
    }
    ensure_safe_chain(path.parent().ok_or_else(|| error("filesystem_rejected"))?)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .map_err(|failure| {
            if failure.kind() == std::io::ErrorKind::NotFound {
                error("component_file_missing")
            } else {
                error("component_file_unavailable")
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| error("component_file_unavailable"))?;
    if !metadata.is_file()
        || unsafe_attributes(&metadata)
        || metadata.len() == 0
        || metadata.len() > max
        || link_count(&file)? != 1
    {
        return Err(error("filesystem_rejected"));
    }
    Ok(file)
}

pub(super) fn ordinary_file(path: &Path, max: u64) -> ComponentResult<()> {
    open_pinned_file(path, max).map(|_| ())
}

fn single_link(path: &Path) -> bool {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
        .ok()
        .and_then(|file| link_count(&file).ok())
        == Some(1)
}

fn link_count(file: &File) -> ComponentResult<u32> {
    let handle = file.as_raw_handle() as HANDLE;
    if handle.is_null() {
        return Err(error("filesystem_rejected"));
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut information) } == 0 {
        return Err(error("filesystem_rejected"));
    }
    Ok(information.nNumberOfLinks)
}

pub(super) fn ensure_private_fixed_directory(path: &Path) -> ComponentResult<PathBuf> {
    fs::create_dir_all(path).map_err(|_| error("component_root_unavailable"))?;
    ensure_existing_safe_directory(path)?;
    fs::canonicalize(path).map_err(|_| error("component_root_unavailable"))
}

fn ensure_existing_safe_directory(path: &Path) -> ComponentResult<()> {
    if !is_normal_fixed_absolute(path) {
        return Err(error("filesystem_rejected"));
    }
    ensure_safe_chain(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| error("filesystem_rejected"))?;
    if !metadata.is_dir() || unsafe_attributes(&metadata) {
        return Err(error("filesystem_rejected"));
    }
    Ok(())
}

fn ensure_safe_chain(path: &Path) -> ComponentResult<()> {
    let canonical = fs::canonicalize(path).map_err(|_| error("filesystem_rejected"))?;
    if !is_normal_fixed_absolute(&canonical) {
        return Err(error("filesystem_rejected"));
    }
    let mut current = PathBuf::new();
    for component in canonical.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| error("filesystem_rejected"))?;
        if unsafe_attributes(&metadata) {
            return Err(error("filesystem_rejected"));
        }
    }
    Ok(())
}

fn is_normal_fixed_absolute(path: &Path) -> bool {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(component, Component::CurDir | Component::ParentDir)
                || matches!(component, Component::Normal(value) if value.to_string_lossy().contains(':'))
        })
    {
        return false;
    }
    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return false;
    };
    if !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        return false;
    }
    let mut wide = prefix.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(u16::from(b'\\'));
    wide.push(0);
    (unsafe { GetDriveTypeW(wide.as_ptr()) }) == DRIVE_FIXED_TYPE
}

fn unsafe_attributes(metadata: &fs::Metadata) -> bool {
    metadata.file_attributes()
        & (FILE_ATTRIBUTE_REPARSE_POINT
            | FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
            | FILE_ATTRIBUTE_RECALL_ON_OPEN)
        != 0
}

pub(super) fn validated_relative(value: &str) -> ComponentResult<PathBuf> {
    let path = relative_path(value).ok_or_else(|| error("package_path_invalid"))?;
    if path.components().count() > 32 || value.len() > 240 {
        return Err(error("package_path_invalid"));
    }
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(error("package_path_invalid"));
        };
        let name = name.to_string_lossy();
        let stem = name
            .split('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if name.is_empty()
            || name.ends_with(['.', ' '])
            || name.contains(':')
            || matches!(
                stem.as_str(),
                "CON"
                    | "PRN"
                    | "AUX"
                    | "NUL"
                    | "COM1"
                    | "COM2"
                    | "COM3"
                    | "COM4"
                    | "COM5"
                    | "COM6"
                    | "COM7"
                    | "COM8"
                    | "COM9"
                    | "LPT1"
                    | "LPT2"
                    | "LPT3"
                    | "LPT4"
                    | "LPT5"
                    | "LPT6"
                    | "LPT7"
                    | "LPT8"
                    | "LPT9"
            )
        {
            return Err(error("package_path_invalid"));
        }
    }
    Ok(path)
}

fn relative_path(value: &str) -> Option<PathBuf> {
    if value.is_empty()
        || value.contains('\\')
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
    {
        return None;
    }
    let path = PathBuf::from(value);
    (!path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_))))
    .then_some(path)
}

pub(super) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn valid_reason_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub(super) fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(super) fn unix_now() -> ComponentResult<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| error("clock_invalid"))
}
