#![allow(unsafe_code)]

//! Canonical archive of encrypted Vault state.
//!
//! Export never decrypts an object. It pins and copies only the SQLite state image, DPAPI-wrapped
//! case-key records, authenticated object envelopes/commits, and AES-GCM ciphertext. Staging uses
//! a fixed local root with the Vault ACL/no-index controls, then opens the reconstructed Vault and
//! decrypts every committed object solely to authenticate the restore before it can be advanced.

use crate::{
    sha256_hex,
    vault_store::{
        validate_fixed_local_directory, FixedLocalStorageRoot, VaultStore, VaultStoreError,
    },
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, CaseId, ObjectId, Sha256Hex,
        WorkspaceInstanceId,
    },
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{compiler_fence, Ordering},
};

pub const ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION: &str = "encrypted-vault-backup-v1";
pub const MAX_ENCRYPTED_VAULT_BACKUP_FILES: usize = 200_000;
pub const MAX_ENCRYPTED_VAULT_BACKUP_CONTENT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_ENCRYPTED_VAULT_BACKUP_BYTES: usize = 720 * 1024 * 1024;
const DATABASE_FILE: &str = "vault-state.sqlite";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultBackupError {
    InvalidInput,
    TooLarge,
    Tampered,
    WorkspaceMismatch,
    UnsafeFilesystem,
    Store(VaultStoreError),
    IoFailed,
    CleanupFailed,
}

impl VaultBackupError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "vault_backup_invalid_input",
            Self::TooLarge => "vault_backup_too_large",
            Self::Tampered => "vault_backup_tampered",
            Self::WorkspaceMismatch => "vault_backup_workspace_mismatch",
            Self::UnsafeFilesystem => "vault_backup_unsafe_filesystem",
            Self::Store(error) => error.code(),
            Self::IoFailed => "vault_backup_io_failed",
            Self::CleanupFailed => "vault_backup_cleanup_failed",
        }
    }
}

impl fmt::Display for VaultBackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for VaultBackupError {}

impl From<VaultStoreError> for VaultBackupError {
    fn from(error: VaultStoreError) -> Self {
        match error {
            VaultStoreError::UnsafeFilesystem | VaultStoreError::InvalidRoot => {
                Self::UnsafeFilesystem
            }
            other => Self::Store(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultBackupSummaryV1 {
    pub schema_version: String,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub file_count: u64,
    pub encrypted_file_bytes: u64,
    pub manifest_sha256: Sha256Hex,
    pub archive_sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultBackupFileManifestV1 {
    relative_path: String,
    bytes: u64,
    sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultBackupManifestV1 {
    schema_version: String,
    workspace_instance_id: WorkspaceInstanceId,
    file_count: u64,
    encrypted_file_bytes: u64,
    files: Vec<VaultBackupFileManifestV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VaultBackupFileV1 {
    relative_path: String,
    bytes: u64,
    sha256: Sha256Hex,
    content_base64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedVaultBackupEnvelopeV1 {
    schema_version: String,
    workspace_instance_id: WorkspaceInstanceId,
    file_count: u64,
    encrypted_file_bytes: u64,
    manifest_sha256: Sha256Hex,
    files: Vec<VaultBackupFileV1>,
}

struct ZeroizingBytes(Vec<u8>);

impl ZeroizingBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

/// Copy only encrypted Vault files into a canonical archive. The returned archive is intended to
/// be encrypted once more by the application-level .lavbackup envelope.
pub fn export_encrypted_vault_backup(
    store: &VaultStore,
) -> Result<(Vec<u8>, VaultBackupSummaryV1), VaultBackupError> {
    let database = store.begin_encrypted_backup_snapshot()?;
    let result = export_with_snapshot(store, &database);
    let rollback = database
        .execute_batch("ROLLBACK")
        .map_err(|_| VaultBackupError::Store(VaultStoreError::DatabaseFailed));
    rollback?;
    result
}

fn export_with_snapshot(
    store: &VaultStore,
    database: &Connection,
) -> Result<(Vec<u8>, VaultBackupSummaryV1), VaultBackupError> {
    let relative_paths = expected_backup_paths(store, database)?;
    if relative_paths.is_empty() || relative_paths.len() > MAX_ENCRYPTED_VAULT_BACKUP_FILES {
        return Err(VaultBackupError::TooLarge);
    }

    let mut files = Vec::with_capacity(relative_paths.len());
    let mut manifests = Vec::with_capacity(relative_paths.len());
    let mut total = 0_u64;
    for relative_path in relative_paths {
        let path = store
            .encrypted_backup_root()
            .join(path_from_archive(&relative_path)?);
        let bytes = read_pinned_regular_file(&path, MAX_ENCRYPTED_VAULT_BACKUP_CONTENT_BYTES)?;
        if bytes.is_empty() {
            return Err(VaultBackupError::Tampered);
        }
        total = total
            .checked_add(u64::try_from(bytes.len()).map_err(|_| VaultBackupError::TooLarge)?)
            .ok_or(VaultBackupError::TooLarge)?;
        if total
            > u64::try_from(MAX_ENCRYPTED_VAULT_BACKUP_CONTENT_BYTES)
                .map_err(|_| VaultBackupError::TooLarge)?
        {
            return Err(VaultBackupError::TooLarge);
        }
        let digest =
            Sha256Hex::parse(sha256_hex(&bytes)).map_err(|_| VaultBackupError::Tampered)?;
        manifests.push(VaultBackupFileManifestV1 {
            relative_path: relative_path.clone(),
            bytes: bytes.len() as u64,
            sha256: digest.clone(),
        });
        files.push(VaultBackupFileV1 {
            relative_path,
            bytes: bytes.len() as u64,
            sha256: digest,
            content_base64: BASE64_STANDARD.encode(&bytes),
        });
    }
    let file_count = u64::try_from(files.len()).map_err(|_| VaultBackupError::TooLarge)?;
    let manifest = VaultBackupManifestV1 {
        schema_version: ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION.to_owned(),
        workspace_instance_id: store.workspace_instance_id().clone(),
        file_count,
        encrypted_file_bytes: total,
        files: manifests,
    };
    let manifest_bytes =
        canonical_json_v1(&manifest).map_err(|_| VaultBackupError::InvalidInput)?;
    let manifest_sha256 =
        Sha256Hex::parse(sha256_hex(&manifest_bytes)).map_err(|_| VaultBackupError::Tampered)?;
    let envelope = EncryptedVaultBackupEnvelopeV1 {
        schema_version: ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION.to_owned(),
        workspace_instance_id: store.workspace_instance_id().clone(),
        file_count,
        encrypted_file_bytes: total,
        manifest_sha256: manifest_sha256.clone(),
        files,
    };
    let archive = canonical_json_v1(&envelope).map_err(|_| VaultBackupError::InvalidInput)?;
    if archive.is_empty() || archive.len() > MAX_ENCRYPTED_VAULT_BACKUP_BYTES {
        return Err(VaultBackupError::TooLarge);
    }
    let archive_sha256 =
        Sha256Hex::parse(sha256_hex(&archive)).map_err(|_| VaultBackupError::Tampered)?;
    Ok((
        archive,
        VaultBackupSummaryV1 {
            schema_version: ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION.to_owned(),
            workspace_instance_id: store.workspace_instance_id().clone(),
            file_count,
            encrypted_file_bytes: total,
            manifest_sha256,
            archive_sha256,
        },
    ))
}

/// Reconstruct an encrypted Vault at an unused fixed local path and authenticate every object.
/// On every failure after directory creation, removal of the sensitive staging tree is mandatory;
/// a cleanup failure replaces the original error.
pub fn stage_encrypted_vault_backup(
    archive: &[u8],
    expected_workspace_instance_id: &WorkspaceInstanceId,
    destination: impl AsRef<Path>,
) -> Result<VaultBackupSummaryV1, VaultBackupError> {
    if archive.is_empty() || archive.len() > MAX_ENCRYPTED_VAULT_BACKUP_BYTES {
        return Err(VaultBackupError::TooLarge);
    }
    let envelope: EncryptedVaultBackupEnvelopeV1 =
        strict_json_v1_from_slice(archive).map_err(|_| VaultBackupError::Tampered)?;
    let canonical = canonical_json_v1(&envelope).map_err(|_| VaultBackupError::Tampered)?;
    if canonical != archive {
        return Err(VaultBackupError::Tampered);
    }
    validate_archive_envelope(&envelope, expected_workspace_instance_id)?;

    let destination = destination.as_ref();
    if !destination.is_absolute() || destination.exists() {
        return Err(VaultBackupError::InvalidInput);
    }
    let parent = destination.parent().ok_or(VaultBackupError::InvalidInput)?;
    validate_fixed_local_directory(parent)?;
    let archive_sha256 =
        Sha256Hex::parse(sha256_hex(archive)).map_err(|_| VaultBackupError::Tampered)?;
    let result = stage_archive_entries(
        &envelope,
        expected_workspace_instance_id,
        destination,
        archive_sha256,
    );
    if result.is_err() && destination.exists() && fs::remove_dir_all(destination).is_err() {
        return Err(VaultBackupError::CleanupFailed);
    }
    result
}

fn stage_archive_entries(
    envelope: &EncryptedVaultBackupEnvelopeV1,
    expected_workspace_instance_id: &WorkspaceInstanceId,
    destination: &Path,
    archive_sha256: Sha256Hex,
) -> Result<VaultBackupSummaryV1, VaultBackupError> {
    let fixed = FixedLocalStorageRoot::initialize(destination)?;
    for relative in ["objects", "keys", ".staging", ".quarantine"] {
        fixed.ensure_directory(Path::new(relative))?;
    }
    for entry in &envelope.files {
        let relative = path_from_archive(&entry.relative_path)?;
        if let Some(parent) = relative
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fixed.ensure_directory(parent)?;
        }
        let path = fixed.validate_new_path(&relative)?;
        let decoded = ZeroizingBytes(
            BASE64_STANDARD
                .decode(entry.content_base64.as_bytes())
                .map_err(|_| VaultBackupError::Tampered)?,
        );
        if decoded.0.len() as u64 != entry.bytes
            || decoded.0.is_empty()
            || sha256_hex(decoded.as_slice()) != entry.sha256.as_str()
        {
            return Err(VaultBackupError::Tampered);
        }
        write_new_synced_file(&path, decoded.as_slice())?;
    }

    let (store, _schema_upgrade_required) = VaultStore::open_for_application_startup(
        destination,
        expected_workspace_instance_id.clone(),
    )?;
    let isolation = store.isolation_status()?;
    if !isolation.private_acl_enforced
        || !isolation.content_indexing_disabled
        || !isolation.encrypted_at_rest
    {
        return Err(VaultBackupError::UnsafeFilesystem);
    }
    store.verify_all_committed_objects()?;
    let database = store.begin_encrypted_backup_snapshot()?;
    let expected = expected_backup_paths(&store, &database)?;
    let actual = envelope
        .files
        .iter()
        .map(|entry| entry.relative_path.clone())
        .collect::<BTreeSet<_>>();
    let rollback = database
        .execute_batch("ROLLBACK")
        .map_err(|_| VaultBackupError::Store(VaultStoreError::DatabaseFailed));
    rollback?;
    if expected != actual {
        return Err(VaultBackupError::Tampered);
    }
    Ok(VaultBackupSummaryV1 {
        schema_version: ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION.to_owned(),
        workspace_instance_id: expected_workspace_instance_id.clone(),
        file_count: envelope.file_count,
        encrypted_file_bytes: envelope.encrypted_file_bytes,
        manifest_sha256: envelope.manifest_sha256.clone(),
        archive_sha256,
    })
}

fn validate_archive_envelope(
    envelope: &EncryptedVaultBackupEnvelopeV1,
    expected_workspace_instance_id: &WorkspaceInstanceId,
) -> Result<(), VaultBackupError> {
    if envelope.schema_version != ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION {
        return Err(VaultBackupError::InvalidInput);
    }
    if envelope.workspace_instance_id != *expected_workspace_instance_id {
        return Err(VaultBackupError::WorkspaceMismatch);
    }
    if envelope.files.is_empty()
        || envelope.files.len() > MAX_ENCRYPTED_VAULT_BACKUP_FILES
        || u64::try_from(envelope.files.len()).ok() != Some(envelope.file_count)
        || envelope.encrypted_file_bytes == 0
        || envelope.encrypted_file_bytes
            > u64::try_from(MAX_ENCRYPTED_VAULT_BACKUP_CONTENT_BYTES)
                .map_err(|_| VaultBackupError::TooLarge)?
    {
        return Err(VaultBackupError::TooLarge);
    }
    let mut previous: Option<&str> = None;
    let mut total = 0_u64;
    let mut manifests = Vec::with_capacity(envelope.files.len());
    for entry in &envelope.files {
        validate_archive_path(&entry.relative_path)?;
        if previous.is_some_and(|value| value >= entry.relative_path.as_str())
            || entry.bytes == 0
            || entry.bytes
                > u64::try_from(MAX_ENCRYPTED_VAULT_BACKUP_CONTENT_BYTES)
                    .map_err(|_| VaultBackupError::TooLarge)?
            || entry.content_base64.len() > MAX_ENCRYPTED_VAULT_BACKUP_BYTES
        {
            return Err(VaultBackupError::Tampered);
        }
        previous = Some(&entry.relative_path);
        total = total
            .checked_add(entry.bytes)
            .ok_or(VaultBackupError::TooLarge)?;
        manifests.push(VaultBackupFileManifestV1 {
            relative_path: entry.relative_path.clone(),
            bytes: entry.bytes,
            sha256: entry.sha256.clone(),
        });
    }
    if total != envelope.encrypted_file_bytes {
        return Err(VaultBackupError::Tampered);
    }
    let manifest = VaultBackupManifestV1 {
        schema_version: ENCRYPTED_VAULT_BACKUP_SCHEMA_VERSION.to_owned(),
        workspace_instance_id: envelope.workspace_instance_id.clone(),
        file_count: envelope.file_count,
        encrypted_file_bytes: envelope.encrypted_file_bytes,
        files: manifests,
    };
    let canonical = canonical_json_v1(&manifest).map_err(|_| VaultBackupError::Tampered)?;
    if sha256_hex(&canonical) != envelope.manifest_sha256.as_str() {
        return Err(VaultBackupError::Tampered);
    }
    Ok(())
}

fn expected_backup_paths(
    store: &VaultStore,
    database: &Connection,
) -> Result<BTreeSet<String>, VaultBackupError> {
    validate_root_layout(store.encrypted_backup_root())?;
    let mut expected = BTreeSet::new();
    expected.insert(DATABASE_FILE.to_owned());

    let mut statement = database
        .prepare(
            "SELECT case_id,object_id,version,chunk_count FROM object_journal
             WHERE state='committed' ORDER BY case_id,object_id,version",
        )
        .map_err(|_| VaultBackupError::Store(VaultStoreError::DatabaseFailed))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .map_err(|_| VaultBackupError::Store(VaultStoreError::DatabaseFailed))?;
    let mut committed = Vec::new();
    for row in rows {
        committed.push(row.map_err(|_| VaultBackupError::Store(VaultStoreError::DatabaseFailed))?);
    }
    drop(statement);

    let mut committed_cases = BTreeSet::new();
    for (case, object, version, chunk_count) in committed {
        let case = CaseId::parse(case).map_err(|_| VaultBackupError::Tampered)?;
        let object = ObjectId::parse(object).map_err(|_| VaultBackupError::Tampered)?;
        let version = u64::try_from(version).map_err(|_| VaultBackupError::Tampered)?;
        let chunk_count = u32::try_from(chunk_count).map_err(|_| VaultBackupError::Tampered)?;
        if version == 0 || chunk_count == 0 {
            return Err(VaultBackupError::Tampered);
        }
        committed_cases.insert(case.as_str().to_owned());
        let prefix = format!(
            "objects/{}/{}/v{version:020}",
            case.as_str(),
            object.as_str()
        );
        for file in ["commit.json", "envelope.json", "private-metadata.bin"] {
            expected.insert(format!("{prefix}/{file}"));
        }
        for index in 0..chunk_count {
            expected.insert(format!("{prefix}/chunk-{index:08}.bin"));
        }
    }

    let keys = store.encrypted_backup_root().join("keys");
    for entry in fs::read_dir(&keys).map_err(|_| VaultBackupError::IoFailed)? {
        let entry = entry.map_err(|_| VaultBackupError::IoFailed)?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| VaultBackupError::IoFailed)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(VaultBackupError::UnsafeFilesystem);
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| VaultBackupError::UnsafeFilesystem)?;
        let case_text = name
            .strip_suffix(".key.json")
            .ok_or(VaultBackupError::UnsafeFilesystem)?;
        CaseId::parse(case_text.to_owned()).map_err(|_| VaultBackupError::Tampered)?;
        expected.insert(format!("keys/{name}"));
    }
    for case in committed_cases {
        if !expected.contains(&format!("keys/{case}.key.json")) {
            return Err(VaultBackupError::Tampered);
        }
    }

    let actual_objects = collect_actual_object_files(store.encrypted_backup_root())?;
    let expected_objects = expected
        .iter()
        .filter(|path| path.starts_with("objects/"))
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_objects != expected_objects {
        return Err(VaultBackupError::Tampered);
    }
    if expected.len() > MAX_ENCRYPTED_VAULT_BACKUP_FILES {
        return Err(VaultBackupError::TooLarge);
    }
    Ok(expected)
}

fn validate_root_layout(root: &Path) -> Result<(), VaultBackupError> {
    for entry in fs::read_dir(root).map_err(|_| VaultBackupError::IoFailed)? {
        let entry = entry.map_err(|_| VaultBackupError::IoFailed)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| VaultBackupError::UnsafeFilesystem)?;
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| VaultBackupError::IoFailed)?;
        if metadata.file_type().is_symlink() {
            return Err(VaultBackupError::UnsafeFilesystem);
        }
        match name.as_str() {
            "objects" | "keys" | ".staging" | ".quarantine" if metadata.is_dir() => {}
            DATABASE_FILE | "vault-state.sqlite-wal" | "vault-state.sqlite-shm"
                if metadata.is_file() => {}
            _ => return Err(VaultBackupError::UnsafeFilesystem),
        }
    }
    Ok(())
}

fn collect_actual_object_files(root: &Path) -> Result<BTreeSet<String>, VaultBackupError> {
    let objects = root.join("objects");
    let mut output = BTreeSet::new();
    collect_object_files_recursive(root, &objects, &mut output)?;
    Ok(output)
}

fn collect_object_files_recursive(
    root: &Path,
    directory: &Path,
    output: &mut BTreeSet<String>,
) -> Result<(), VaultBackupError> {
    for entry in fs::read_dir(directory).map_err(|_| VaultBackupError::IoFailed)? {
        let entry = entry.map_err(|_| VaultBackupError::IoFailed)?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|_| VaultBackupError::IoFailed)?;
        if metadata.file_type().is_symlink() {
            return Err(VaultBackupError::UnsafeFilesystem);
        }
        if metadata.is_dir() {
            collect_object_files_recursive(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| VaultBackupError::UnsafeFilesystem)?;
            let archive_path = relative_path_to_archive(relative)?;
            validate_archive_path(&archive_path)?;
            if !output.insert(archive_path) {
                return Err(VaultBackupError::Tampered);
            }
        } else {
            return Err(VaultBackupError::UnsafeFilesystem);
        }
    }
    Ok(())
}

fn validate_archive_path(value: &str) -> Result<(), VaultBackupError> {
    let parts = value.split('/').collect::<Vec<_>>();
    if value.is_empty()
        || value.len() > 512
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
        || parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(VaultBackupError::UnsafeFilesystem);
    }
    if parts.as_slice() == [DATABASE_FILE] {
        return Ok(());
    }
    if parts.len() == 2 && parts[0] == "keys" {
        let case = parts[1]
            .strip_suffix(".key.json")
            .ok_or(VaultBackupError::UnsafeFilesystem)?;
        CaseId::parse(case.to_owned()).map_err(|_| VaultBackupError::UnsafeFilesystem)?;
        return Ok(());
    }
    if parts.len() != 5 || parts[0] != "objects" {
        return Err(VaultBackupError::UnsafeFilesystem);
    }
    CaseId::parse(parts[1].to_owned()).map_err(|_| VaultBackupError::UnsafeFilesystem)?;
    ObjectId::parse(parts[2].to_owned()).map_err(|_| VaultBackupError::UnsafeFilesystem)?;
    let version = parts[3]
        .strip_prefix('v')
        .filter(|value| value.len() == 20 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(VaultBackupError::UnsafeFilesystem)?;
    let _ = version;
    let file = parts[4];
    if matches!(
        file,
        "envelope.json" | "commit.json" | "private-metadata.bin"
    ) || file
        .strip_prefix("chunk-")
        .and_then(|value| value.strip_suffix(".bin"))
        .is_some_and(|value| value.len() == 8 && value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        Ok(())
    } else {
        Err(VaultBackupError::UnsafeFilesystem)
    }
}

fn path_from_archive(value: &str) -> Result<PathBuf, VaultBackupError> {
    validate_archive_path(value)?;
    let mut path = PathBuf::new();
    for component in value.split('/') {
        path.push(component);
    }
    Ok(path)
}

fn relative_path_to_archive(path: &Path) -> Result<String, VaultBackupError> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(value) = component else {
            return Err(VaultBackupError::UnsafeFilesystem);
        };
        parts.push(
            value
                .to_str()
                .ok_or(VaultBackupError::UnsafeFilesystem)?
                .to_owned(),
        );
    }
    Ok(parts.join("/"))
}

fn write_new_synced_file(path: &Path, bytes: &[u8]) -> Result<(), VaultBackupError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| VaultBackupError::IoFailed)?;
    file.write_all(bytes)
        .map_err(|_| VaultBackupError::IoFailed)?;
    file.sync_all().map_err(|_| VaultBackupError::IoFailed)
}

#[cfg(windows)]
fn read_pinned_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, VaultBackupError> {
    use std::{
        mem::zeroed,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| VaultBackupError::IoFailed)?;
    let information = |file: &File| -> Result<BY_HANDLE_FILE_INFORMATION, VaultBackupError> {
        let mut value: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        let success = unsafe {
            GetFileInformationByHandle(
                file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
                &mut value,
            )
        };
        if success == 0
            || value.nNumberOfLinks != 1
            || value.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                != 0
        {
            return Err(VaultBackupError::UnsafeFilesystem);
        }
        Ok(value)
    };
    let before = information(&file)?;
    let expected = (u64::from(before.nFileSizeHigh) << 32) | u64::from(before.nFileSizeLow);
    if expected == 0 || expected > max_bytes as u64 {
        return Err(VaultBackupError::TooLarge);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(expected).map_err(|_| VaultBackupError::TooLarge)?);
    (&mut file)
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultBackupError::IoFailed)?;
    let after = information(&file)?;
    if bytes.len() as u64 != expected
        || before.dwVolumeSerialNumber != after.dwVolumeSerialNumber
        || before.nFileIndexHigh != after.nFileIndexHigh
        || before.nFileIndexLow != after.nFileIndexLow
        || before.nFileSizeHigh != after.nFileSizeHigh
        || before.nFileSizeLow != after.nFileSizeLow
    {
        return Err(VaultBackupError::UnsafeFilesystem);
    }
    Ok(bytes)
}

#[cfg(not(windows))]
fn read_pinned_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, VaultBackupError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultBackupError::IoFailed)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        return Err(VaultBackupError::UnsafeFilesystem);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(VaultBackupError::UnsafeFilesystem);
        }
    }
    if metadata.len() > max_bytes as u64 {
        return Err(VaultBackupError::TooLarge);
    }
    let mut file = File::open(path).map_err(|_| VaultBackupError::IoFailed)?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| VaultBackupError::IoFailed)?;
    if bytes.len() as u64 != metadata.len() {
        return Err(VaultBackupError::UnsafeFilesystem);
    }
    Ok(bytes)
}

fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::vault_store::VaultPrivateMetadataInputV1;

    fn workspace() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse("ws_0123456789abcdef0123456789abcdef").expect("workspace")
    }

    fn create_synthetic_vault(root: &Path) -> (VaultStore, CaseId, ObjectId) {
        let store = VaultStore::initialize(root, workspace()).expect("initialize synthetic vault");
        let case = CaseId::parse("case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("synthetic case");
        let summary = store
            .create_source_object(
                &case,
                VaultPrivateMetadataInputV1 {
                    original_file_name: "synthetic-confidential.pdf".to_owned(),
                    original_source_path: Some(
                        r"C:\synthetic-only\synthetic-confidential.pdf".to_owned(),
                    ),
                    original_media_type: "application/pdf".to_owned(),
                    imported_at_unix: 10,
                },
                b"SYNTHETIC_VAULT_PRIVATE_CANARY_001",
                10,
            )
            .expect("create synthetic object");
        (store, case, summary.object_id)
    }

    #[test]
    fn encrypted_archive_round_trip_contains_no_source_plaintext() {
        let directory = tempfile::tempdir().expect("temp");
        let source = directory.path().join("source-vault");
        let destination = directory.path().join("restored-vault");
        let (store, case, object) = create_synthetic_vault(&source);
        fs::write(
            source.join(".staging/uncommitted.bin"),
            b"SYNTHETIC_STAGING_CANARY",
        )
        .expect("staging residue");
        fs::write(
            source.join(".quarantine/rejected.bin"),
            b"SYNTHETIC_QUARANTINE_CANARY",
        )
        .expect("quarantine residue");
        let (archive, summary) =
            export_encrypted_vault_backup(&store).expect("export encrypted vault");
        for needle in [
            b"SYNTHETIC_VAULT_PRIVATE_CANARY_001".as_slice(),
            b"synthetic-confidential.pdf".as_slice(),
            b"synthetic-only".as_slice(),
            b"SYNTHETIC_STAGING_CANARY".as_slice(),
            b"SYNTHETIC_QUARANTINE_CANARY".as_slice(),
        ] {
            assert!(!archive.windows(needle.len()).any(|window| window == needle));
        }
        let envelope: EncryptedVaultBackupEnvelopeV1 =
            strict_json_v1_from_slice(&archive).expect("strict exported archive");
        assert!(envelope.files.iter().all(|entry| {
            !entry.relative_path.starts_with(".staging/")
                && !entry.relative_path.starts_with(".quarantine/")
        }));
        let staged =
            stage_encrypted_vault_backup(&archive, &workspace(), &destination).expect("stage");
        assert_eq!(staged.manifest_sha256, summary.manifest_sha256);
        let restored = VaultStore::open(&destination, workspace()).expect("open restored");
        let decrypted = restored
            .read_object(&case, &object, 1)
            .expect("read restored object");
        assert_eq!(decrypted.content, b"SYNTHETIC_VAULT_PRIVATE_CANARY_001");
        assert_eq!(
            decrypted.private_metadata.original_file_name,
            "synthetic-confidential.pdf"
        );
        let (restored_archive, restored_summary) =
            export_encrypted_vault_backup(&restored).expect("re-export restored Vault");
        assert_eq!(restored_archive, archive);
        assert_eq!(restored_summary.archive_sha256, summary.archive_sha256);
        assert_eq!(restored_summary.manifest_sha256, summary.manifest_sha256);
        assert_eq!(restored_summary.file_count, summary.file_count);
    }

    #[test]
    fn tamper_and_traversal_fail_and_remove_staging_tree() {
        let directory = tempfile::tempdir().expect("temp");
        let source = directory.path().join("source-vault");
        let (store, _, _) = create_synthetic_vault(&source);
        let (archive, _) = export_encrypted_vault_backup(&store).expect("export");
        let mut envelope: EncryptedVaultBackupEnvelopeV1 =
            strict_json_v1_from_slice(&archive).expect("strict archive");
        let mut decoded = BASE64_STANDARD
            .decode(envelope.files[0].content_base64.as_bytes())
            .expect("decode");
        decoded[0] ^= 1;
        envelope.files[0].content_base64 = BASE64_STANDARD.encode(decoded);
        let tampered = canonical_json_v1(&envelope).expect("canonical tamper");
        let tamper_destination = directory.path().join("tamper-destination");
        assert_eq!(
            stage_encrypted_vault_backup(&tampered, &workspace(), &tamper_destination),
            Err(VaultBackupError::Tampered)
        );
        assert!(!tamper_destination.exists());

        let mut traversal: EncryptedVaultBackupEnvelopeV1 =
            strict_json_v1_from_slice(&archive).expect("strict archive");
        traversal.files[0].relative_path = "../vault-state.sqlite".to_owned();
        let traversal = canonical_json_v1(&traversal).expect("canonical traversal");
        let traversal_destination = directory.path().join("traversal-destination");
        assert_eq!(
            stage_encrypted_vault_backup(&traversal, &workspace(), &traversal_destination),
            Err(VaultBackupError::UnsafeFilesystem)
        );
        assert!(!traversal_destination.exists());
    }

    #[test]
    fn export_never_decrypts_but_staging_authenticates_every_object() {
        let directory = tempfile::tempdir().expect("temp");
        let source = directory.path().join("source-vault");
        let destination = directory.path().join("restored-vault");
        let (store, case, object) = create_synthetic_vault(&source);
        let chunk = source
            .join("objects")
            .join(case.as_str())
            .join(object.as_str())
            .join("v00000000000000000001/chunk-00000000.bin");
        let mut ciphertext = fs::read(&chunk).expect("ciphertext chunk");
        ciphertext[0] ^= 0x40;
        fs::write(&chunk, ciphertext).expect("tamper source ciphertext");

        let (archive, _) = export_encrypted_vault_backup(&store)
            .expect("ciphertext-only export does not open case plaintext");
        assert!(matches!(
            stage_encrypted_vault_backup(&archive, &workspace(), &destination),
            Err(VaultBackupError::Store(_)) | Err(VaultBackupError::Tampered)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn hardlinked_encrypted_source_file_is_rejected() {
        let directory = tempfile::tempdir().expect("temp");
        let source = directory.path().join("source-vault");
        let (store, case, _) = create_synthetic_vault(&source);
        let key = source
            .join("keys")
            .join(format!("{}.key.json", case.as_str()));
        let second_link = directory.path().join("synthetic-second-link.key.json");
        fs::hard_link(&key, &second_link).expect("create synthetic hard link");
        assert_eq!(
            export_encrypted_vault_backup(&store),
            Err(VaultBackupError::UnsafeFilesystem)
        );
    }
}
