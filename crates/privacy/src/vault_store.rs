#![allow(unsafe_code)]

//! Local encrypted object store for original case materials.
//!
//! Every case has an independently generated AES-256 key. The key is wrapped with Windows
//! DPAPI CurrentUser, while object content and private source metadata are sealed with Windows
//! CNG AES-256-GCM. Public manifests, database rows and filesystem names contain opaque IDs only;
//! original filenames, source paths and plaintext hashes exist exclusively inside the encrypted
//! private-metadata object.

use crate::{
    sha256_hex,
    vault_crypto::{
        open, seal, unwrap_case_key, wrap_case_key, AeadSealedV1, SecretKey32, VaultCryptoError,
        GCM_NONCE_BYTES, GCM_TAG_BYTES, VAULT_CRYPTO_SUITE, VAULT_KEY_WRAP_PROVIDER,
    },
    vnext::{
        canonical_json_v1, strict_json_v1_from_slice, CaseId, ObjectId, Sha256Hex,
        WorkspaceInstanceId,
    },
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
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

pub const VAULT_STORE_SCHEMA_VERSION: u32 = 1;
pub const VAULT_OBJECT_ENVELOPE_VERSION: &str = "vault-object-envelope-v1";
pub const VAULT_OBJECT_COMMIT_VERSION: &str = "vault-object-commit-v1";
pub const VAULT_PRIVATE_METADATA_VERSION: &str = "vault-private-metadata-v1";
pub const VAULT_CASE_KEY_RECORD_VERSION: &str = "vault-case-key-record-v1";
pub const MAX_VAULT_CONTENT_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_VAULT_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_VAULT_PRIVATE_METADATA_BYTES: usize = 128 * 1024;
pub const MAX_VAULT_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_VAULT_KEY_RECORD_BYTES: usize = 64 * 1024;
const MAX_ORIGINAL_FILE_NAME_BYTES: usize = 1024;
const MAX_ORIGINAL_SOURCE_PATH_BYTES: usize = 32 * 1024;
const MAX_MEDIA_TYPE_BYTES: usize = 255;
const MAX_WRAPPED_CASE_KEY_BYTES: usize = 16 * 1024;
const NONCE_RESERVATION_ATTEMPTS: usize = 32;
const OBJECT_ALLOCATION_ATTEMPTS: usize = 32;
const CONTENT_COMPONENT: &str = "content";
const PRIVATE_METADATA_COMPONENT: &str = "private_metadata";
const PRIVATE_METADATA_CHUNK_INDEX: i64 = -1;
const AAD_DOMAIN: &[u8] = b"LawyerAssistance/vault-object-aad/v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultStoreError {
    PlatformUnavailable,
    InvalidRoot,
    UnsafeFilesystem,
    InvalidInput,
    ObjectTooLarge,
    PrivateMetadataTooLarge,
    ObjectNotAvailable,
    CaseKeyUnavailable,
    KeyRecordInvalid,
    EnvelopeInvalid,
    ContentCorrupt,
    AuthenticationFailed,
    NonceReservationFailed,
    ObjectAllocationFailed,
    AlreadyExists,
    DatabaseFailed,
    IoFailed,
}

impl VaultStoreError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::PlatformUnavailable => "vault_store_platform_unavailable",
            Self::InvalidRoot => "vault_store_invalid_root",
            Self::UnsafeFilesystem => "vault_store_unsafe_filesystem",
            Self::InvalidInput => "vault_store_invalid_input",
            Self::ObjectTooLarge => "vault_store_object_too_large",
            Self::PrivateMetadataTooLarge => "vault_store_private_metadata_too_large",
            Self::ObjectNotAvailable => "vault_store_object_not_available",
            Self::CaseKeyUnavailable => "vault_store_case_key_unavailable",
            Self::KeyRecordInvalid => "vault_store_key_record_invalid",
            Self::EnvelopeInvalid => "vault_store_envelope_invalid",
            Self::ContentCorrupt => "vault_store_content_corrupt",
            Self::AuthenticationFailed => "vault_store_authentication_failed",
            Self::NonceReservationFailed => "vault_store_nonce_reservation_failed",
            Self::ObjectAllocationFailed => "vault_store_object_allocation_failed",
            Self::AlreadyExists => "vault_store_object_already_exists",
            Self::DatabaseFailed => "vault_store_database_failed",
            Self::IoFailed => "vault_store_io_failed",
        }
    }
}

impl fmt::Display for VaultStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for VaultStoreError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultObjectKind {
    SourceMaterial,
    LocalOcrArtifact,
    RenderedPage,
    ReviewDraft,
}

impl VaultObjectKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceMaterial => "source_material",
            Self::LocalOcrArtifact => "local_ocr_artifact",
            Self::RenderedPage => "rendered_page",
            Self::ReviewDraft => "review_draft",
        }
    }

    fn parse(value: &str) -> Result<Self, VaultStoreError> {
        match value {
            "source_material" => Ok(Self::SourceMaterial),
            "local_ocr_artifact" => Ok(Self::LocalOcrArtifact),
            "rendered_page" => Ok(Self::RenderedPage),
            "review_draft" => Ok(Self::ReviewDraft),
            _ => Err(VaultStoreError::EnvelopeInvalid),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct VaultPrivateMetadataInputV1 {
    pub original_file_name: String,
    pub original_source_path: Option<String>,
    pub original_media_type: String,
    pub imported_at_unix: u64,
}

impl fmt::Debug for VaultPrivateMetadataInputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultPrivateMetadataInputV1")
            .field("original_file_name", &"[ENCRYPTED_PRIVATE_METADATA]")
            .field(
                "original_source_path",
                &self
                    .original_source_path
                    .as_ref()
                    .map(|_| "[ENCRYPTED_PRIVATE_METADATA]"),
            )
            .field("original_media_type", &self.original_media_type)
            .field("imported_at_unix", &self.imported_at_unix)
            .finish()
    }
}

impl VaultPrivateMetadataInputV1 {
    fn validate(&self) -> Result<(), VaultStoreError> {
        validate_private_string(
            &self.original_file_name,
            MAX_ORIGINAL_FILE_NAME_BYTES,
            false,
        )?;
        if self.original_source_path.as_ref().is_some_and(|path| {
            validate_private_string(path, MAX_ORIGINAL_SOURCE_PATH_BYTES, false).is_err()
        }) {
            return Err(VaultStoreError::InvalidInput);
        }
        validate_private_string(&self.original_media_type, MAX_MEDIA_TYPE_BYTES, true)?;
        if self.imported_at_unix == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VaultPrivateMetadataV1 {
    pub schema_version: String,
    pub original_file_name: String,
    pub original_source_path: Option<String>,
    pub original_media_type: String,
    pub source_sha256: Sha256Hex,
    pub source_bytes: u64,
    pub imported_at_unix: u64,
}

impl fmt::Debug for VaultPrivateMetadataV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultPrivateMetadataV1")
            .field("schema_version", &self.schema_version)
            .field("original_file_name", &"[DECRYPTED_PRIVATE_METADATA]")
            .field(
                "original_source_path",
                &self
                    .original_source_path
                    .as_ref()
                    .map(|_| "[DECRYPTED_PRIVATE_METADATA]"),
            )
            .field("original_media_type", &self.original_media_type)
            .field("source_sha256", &"[DECRYPTED_PRIVATE_METADATA]")
            .field("source_bytes", &self.source_bytes)
            .field("imported_at_unix", &self.imported_at_unix)
            .finish()
    }
}

impl Drop for VaultPrivateMetadataV1 {
    fn drop(&mut self) {
        zeroize_string(&mut self.original_file_name);
        if let Some(path) = &mut self.original_source_path {
            zeroize_string(path);
        }
        zeroize_string(&mut self.original_media_type);
    }
}

impl VaultPrivateMetadataV1 {
    fn validate(&self) -> Result<(), VaultStoreError> {
        if self.schema_version != VAULT_PRIVATE_METADATA_VERSION || self.source_bytes == 0 {
            return Err(VaultStoreError::EnvelopeInvalid);
        }
        validate_private_string(
            &self.original_file_name,
            MAX_ORIGINAL_FILE_NAME_BYTES,
            false,
        )?;
        if self.original_source_path.as_ref().is_some_and(|path| {
            validate_private_string(path, MAX_ORIGINAL_SOURCE_PATH_BYTES, false).is_err()
        }) {
            return Err(VaultStoreError::EnvelopeInvalid);
        }
        validate_private_string(&self.original_media_type, MAX_MEDIA_TYPE_BYTES, true)?;
        if self.imported_at_unix == 0 {
            return Err(VaultStoreError::EnvelopeInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VaultSealedChunkV1 {
    pub chunk_index: u32,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub nonce_hex: String,
    pub tag_hex: String,
    pub ciphertext_sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VaultSealedPrivateMetadataV1 {
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    pub nonce_hex: String,
    pub tag_hex: String,
    pub ciphertext_sha256: Sha256Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VaultObjectEnvelopeV1 {
    pub schema_version: String,
    pub crypto_suite: String,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub case_id: CaseId,
    pub object_id: ObjectId,
    pub object_kind: VaultObjectKind,
    pub version: u64,
    pub content_bytes: u64,
    pub chunk_size_bytes: u64,
    pub chunks: Vec<VaultSealedChunkV1>,
    pub private_metadata: VaultSealedPrivateMetadataV1,
    pub created_at_unix: u64,
}

impl VaultObjectEnvelopeV1 {
    pub fn validate(&self) -> Result<(), VaultStoreError> {
        let max_content =
            u64::try_from(MAX_VAULT_CONTENT_BYTES).map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        let expected_chunk_size =
            u64::try_from(MAX_VAULT_CHUNK_BYTES).map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        if self.schema_version != VAULT_OBJECT_ENVELOPE_VERSION
            || self.crypto_suite != VAULT_CRYPTO_SUITE
            || self.version == 0
            || self.content_bytes == 0
            || self.content_bytes > max_content
            || self.chunk_size_bytes != expected_chunk_size
            || self.created_at_unix == 0
            || self.chunks.is_empty()
        {
            return Err(VaultStoreError::EnvelopeInvalid);
        }

        let expected_count_u64 = self.content_bytes.div_ceil(self.chunk_size_bytes);
        let expected_count =
            usize::try_from(expected_count_u64).map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        if self.chunks.len() != expected_count {
            return Err(VaultStoreError::EnvelopeInvalid);
        }

        let mut nonces = BTreeSet::new();
        for (position, chunk) in self.chunks.iter().enumerate() {
            let chunk_index =
                u32::try_from(position).map_err(|_| VaultStoreError::EnvelopeInvalid)?;
            let position_u64 =
                u64::try_from(position).map_err(|_| VaultStoreError::EnvelopeInvalid)?;
            let consumed = position_u64
                .checked_mul(self.chunk_size_bytes)
                .ok_or(VaultStoreError::EnvelopeInvalid)?;
            let expected_bytes = self
                .content_bytes
                .checked_sub(consumed)
                .ok_or(VaultStoreError::EnvelopeInvalid)?
                .min(self.chunk_size_bytes);
            if chunk.chunk_index != chunk_index
                || chunk.plaintext_bytes != expected_bytes
                || chunk.ciphertext_bytes != expected_bytes
                || decode_fixed_hex::<GCM_TAG_BYTES>(&chunk.tag_hex).is_err()
                || !nonces.insert(decode_fixed_hex::<GCM_NONCE_BYTES>(&chunk.nonce_hex)?)
            {
                return Err(VaultStoreError::EnvelopeInvalid);
            }
        }

        let metadata_max = u64::try_from(MAX_VAULT_PRIVATE_METADATA_BYTES)
            .map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        if self.private_metadata.plaintext_bytes == 0
            || self.private_metadata.plaintext_bytes > metadata_max
            || self.private_metadata.ciphertext_bytes != self.private_metadata.plaintext_bytes
            || decode_fixed_hex::<GCM_TAG_BYTES>(&self.private_metadata.tag_hex).is_err()
            || !nonces.insert(decode_fixed_hex::<GCM_NONCE_BYTES>(
                &self.private_metadata.nonce_hex,
            )?)
        {
            return Err(VaultStoreError::EnvelopeInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DecryptedVaultObjectV1 {
    pub workspace_instance_id: WorkspaceInstanceId,
    pub case_id: CaseId,
    pub object_id: ObjectId,
    pub object_kind: VaultObjectKind,
    pub version: u64,
    pub content: Vec<u8>,
    pub private_metadata: VaultPrivateMetadataV1,
}

impl fmt::Debug for DecryptedVaultObjectV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecryptedVaultObjectV1")
            .field("workspace_instance_id", &self.workspace_instance_id)
            .field("case_id", &self.case_id)
            .field("object_id", &self.object_id)
            .field("object_kind", &self.object_kind)
            .field("version", &self.version)
            .field(
                "content",
                &format_args!("[DECRYPTED {} BYTES]", self.content.len()),
            )
            .field("private_metadata", &self.private_metadata)
            .finish()
    }
}

impl Drop for DecryptedVaultObjectV1 {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.content);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultObjectSummaryV1 {
    pub workspace_instance_id: WorkspaceInstanceId,
    pub case_id: CaseId,
    pub object_id: ObjectId,
    pub object_kind: VaultObjectKind,
    pub version: u64,
    pub content_bytes: u64,
    pub chunk_count: u32,
    pub envelope_sha256: Sha256Hex,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WrappedCaseKeyRecordV1 {
    schema_version: String,
    wrap_provider: String,
    workspace_instance_id: WorkspaceInstanceId,
    case_id: CaseId,
    wrapped_key_base64: String,
    wrapped_key_sha256: Sha256Hex,
    created_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct VaultObjectCommitV1 {
    schema_version: String,
    workspace_instance_id: WorkspaceInstanceId,
    case_id: CaseId,
    object_id: ObjectId,
    version: u64,
    envelope_sha256: Sha256Hex,
    chunk_count: u32,
}

pub struct VaultStore {
    root: ValidatedVaultRoot,
    workspace_instance_id: WorkspaceInstanceId,
}

impl VaultStore {
    pub fn initialize(
        root: impl AsRef<Path>,
        workspace_instance_id: WorkspaceInstanceId,
    ) -> Result<Self, VaultStoreError> {
        let root = ValidatedVaultRoot::initialize(root.as_ref())?;
        initialize_database(&root, &workspace_instance_id)?;
        Ok(Self {
            root,
            workspace_instance_id,
        })
    }

    pub fn open(
        root: impl AsRef<Path>,
        workspace_instance_id: WorkspaceInstanceId,
    ) -> Result<Self, VaultStoreError> {
        let root = ValidatedVaultRoot::open(root.as_ref())?;
        validate_database(&root, &workspace_instance_id)?;
        Ok(Self {
            root,
            workspace_instance_id,
        })
    }

    pub fn create_source_object(
        &self,
        case_id: &CaseId,
        private_metadata: VaultPrivateMetadataInputV1,
        content: &[u8],
        created_at_unix: u64,
    ) -> Result<VaultObjectSummaryV1, VaultStoreError> {
        self.create_object(
            case_id,
            VaultObjectKind::SourceMaterial,
            private_metadata,
            content,
            created_at_unix,
        )
    }

    pub fn create_object(
        &self,
        case_id: &CaseId,
        object_kind: VaultObjectKind,
        private_metadata: VaultPrivateMetadataInputV1,
        content: &[u8],
        created_at_unix: u64,
    ) -> Result<VaultObjectSummaryV1, VaultStoreError> {
        if content.is_empty() || created_at_unix == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        if content.len() > MAX_VAULT_CONTENT_BYTES {
            return Err(VaultStoreError::ObjectTooLarge);
        }
        private_metadata.validate()?;

        let content_bytes =
            u64::try_from(content.len()).map_err(|_| VaultStoreError::ObjectTooLarge)?;
        let private_metadata = VaultPrivateMetadataV1 {
            schema_version: VAULT_PRIVATE_METADATA_VERSION.to_owned(),
            original_file_name: private_metadata.original_file_name,
            original_source_path: private_metadata.original_source_path,
            original_media_type: private_metadata.original_media_type,
            source_sha256: Sha256Hex::parse(sha256_hex(content))
                .map_err(|_| VaultStoreError::InvalidInput)?,
            source_bytes: content_bytes,
            imported_at_unix: private_metadata.imported_at_unix,
        };
        private_metadata.validate()?;
        let private_metadata_bytes = ZeroizingBytes::new(
            canonical_json_v1(&private_metadata).map_err(|_| VaultStoreError::InvalidInput)?,
        );
        if private_metadata_bytes.len() > MAX_VAULT_PRIVATE_METADATA_BYTES {
            return Err(VaultStoreError::PrivateMetadataTooLarge);
        }

        let key = self.load_or_create_case_key(case_id, created_at_unix)?;
        let db = open_database(&self.root)?;
        let object_id = self.allocate_object(&db, case_id, object_kind, created_at_unix)?;
        let version = 1_u64;

        let mut sealed_chunks = Vec::new();
        let mut chunk_records = Vec::new();
        for (position, plaintext) in content.chunks(MAX_VAULT_CHUNK_BYTES).enumerate() {
            let chunk_index =
                u32::try_from(position).map_err(|_| VaultStoreError::ObjectTooLarge)?;
            let aad = build_aad(
                &self.workspace_instance_id,
                case_id,
                &object_id,
                object_kind,
                version,
                content_bytes,
                created_at_unix,
                CONTENT_COMPONENT,
                i64::from(chunk_index),
            )?;
            let sealed = self.seal_and_reserve_nonce(
                &db,
                &key,
                plaintext,
                &aad,
                case_id,
                &object_id,
                version,
                CONTENT_COMPONENT,
                i64::from(chunk_index),
                created_at_unix,
            )?;
            chunk_records.push(VaultSealedChunkV1 {
                chunk_index,
                plaintext_bytes: u64::try_from(plaintext.len())
                    .map_err(|_| VaultStoreError::ObjectTooLarge)?,
                ciphertext_bytes: u64::try_from(sealed.ciphertext().len())
                    .map_err(|_| VaultStoreError::ObjectTooLarge)?,
                nonce_hex: hex_lower(sealed.nonce()),
                tag_hex: hex_lower(sealed.tag()),
                ciphertext_sha256: Sha256Hex::parse(sha256_hex(sealed.ciphertext()))
                    .map_err(|_| VaultStoreError::EnvelopeInvalid)?,
            });
            sealed_chunks.push(sealed);
        }

        let metadata_aad = build_aad(
            &self.workspace_instance_id,
            case_id,
            &object_id,
            object_kind,
            version,
            content_bytes,
            created_at_unix,
            PRIVATE_METADATA_COMPONENT,
            PRIVATE_METADATA_CHUNK_INDEX,
        )?;
        let sealed_metadata = self.seal_and_reserve_nonce(
            &db,
            &key,
            &private_metadata_bytes,
            &metadata_aad,
            case_id,
            &object_id,
            version,
            PRIVATE_METADATA_COMPONENT,
            PRIVATE_METADATA_CHUNK_INDEX,
            created_at_unix,
        )?;
        let metadata_record = VaultSealedPrivateMetadataV1 {
            plaintext_bytes: u64::try_from(private_metadata_bytes.len())
                .map_err(|_| VaultStoreError::PrivateMetadataTooLarge)?,
            ciphertext_bytes: u64::try_from(sealed_metadata.ciphertext().len())
                .map_err(|_| VaultStoreError::PrivateMetadataTooLarge)?,
            nonce_hex: hex_lower(sealed_metadata.nonce()),
            tag_hex: hex_lower(sealed_metadata.tag()),
            ciphertext_sha256: Sha256Hex::parse(sha256_hex(sealed_metadata.ciphertext()))
                .map_err(|_| VaultStoreError::EnvelopeInvalid)?,
        };

        let envelope = VaultObjectEnvelopeV1 {
            schema_version: VAULT_OBJECT_ENVELOPE_VERSION.to_owned(),
            crypto_suite: VAULT_CRYPTO_SUITE.to_owned(),
            workspace_instance_id: self.workspace_instance_id.clone(),
            case_id: case_id.clone(),
            object_id: object_id.clone(),
            object_kind,
            version,
            content_bytes,
            chunk_size_bytes: u64::try_from(MAX_VAULT_CHUNK_BYTES)
                .map_err(|_| VaultStoreError::EnvelopeInvalid)?,
            chunks: chunk_records,
            private_metadata: metadata_record,
            created_at_unix,
        };
        envelope.validate()?;
        let envelope_bytes =
            canonical_json_v1(&envelope).map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        if envelope_bytes.len() > MAX_VAULT_ENVELOPE_BYTES {
            return Err(VaultStoreError::EnvelopeInvalid);
        }
        let envelope_sha256 = Sha256Hex::parse(sha256_hex(&envelope_bytes))
            .map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        let chunk_count =
            u32::try_from(envelope.chunks.len()).map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        let commit = VaultObjectCommitV1 {
            schema_version: VAULT_OBJECT_COMMIT_VERSION.to_owned(),
            workspace_instance_id: self.workspace_instance_id.clone(),
            case_id: case_id.clone(),
            object_id: object_id.clone(),
            version,
            envelope_sha256: envelope_sha256.clone(),
            chunk_count,
        };
        let commit_bytes =
            canonical_json_v1(&commit).map_err(|_| VaultStoreError::EnvelopeInvalid)?;

        let version_sql = sql_i64(version)?;
        let content_bytes_sql = sql_i64(content_bytes)?;
        let chunk_count_sql = i64::from(chunk_count);
        let changed = db
            .execute(
                "UPDATE object_journal
                 SET state='prepared',envelope_sha256=?3,content_bytes=?4,chunk_count=?5
                 WHERE object_id=?1 AND version=?2 AND state='allocated'",
                params![
                    object_id.as_str(),
                    version_sql,
                    envelope_sha256.as_str(),
                    content_bytes_sql,
                    chunk_count_sql
                ],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if changed != 1 {
            return Err(VaultStoreError::ObjectAllocationFailed);
        }

        let staging = self.root.staging.join(format!(
            "{}-v{:020}-{}",
            object_id.as_str(),
            version,
            random_hex(8)?
        ));
        validate_new_controlled_path(&self.root, &staging)?;
        fs::create_dir(&staging).map_err(|_| VaultStoreError::IoFailed)?;
        platform::mark_not_content_indexed(&staging)?;

        let write_result = (|| {
            for (record, sealed) in envelope.chunks.iter().zip(&sealed_chunks) {
                let path = staging.join(chunk_file_name(record.chunk_index));
                write_new_file(&path, sealed.ciphertext())?;
            }
            write_new_file(
                &staging.join("private-metadata.bin"),
                sealed_metadata.ciphertext(),
            )?;
            write_new_file(&staging.join("envelope.json"), &envelope_bytes)?;
            write_new_file(&staging.join("commit.json"), &commit_bytes)?;

            let object_parent = self
                .root
                .objects
                .join(case_id.as_str())
                .join(object_id.as_str());
            ensure_controlled_directory(&self.root, &object_parent)?;
            let final_directory = object_parent.join(version_directory_name(version));
            if final_directory.exists() {
                return Err(VaultStoreError::AlreadyExists);
            }
            validate_new_controlled_path(&self.root, &final_directory)?;
            fs::rename(&staging, &final_directory).map_err(|_| VaultStoreError::IoFailed)?;
            Ok::<PathBuf, VaultStoreError>(final_directory)
        })();

        let final_directory = match write_result {
            Ok(directory) => directory,
            Err(error) => {
                let _ = quarantine_path(&self.root, &staging);
                let _ = db.execute(
                    "UPDATE object_journal SET state='quarantined'
                     WHERE object_id=?1 AND version=?2 AND state!='committed'",
                    params![object_id.as_str(), version_sql],
                );
                return Err(error);
            }
        };

        let changed = db
            .execute(
                "UPDATE object_journal SET state='committed',committed_at_unix=?3
                 WHERE object_id=?1 AND version=?2 AND state='prepared'",
                params![object_id.as_str(), version_sql, sql_i64(created_at_unix)?],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if changed != 1 {
            let _ = quarantine_path(&self.root, &final_directory);
            return Err(VaultStoreError::DatabaseFailed);
        }

        Ok(VaultObjectSummaryV1 {
            workspace_instance_id: self.workspace_instance_id.clone(),
            case_id: case_id.clone(),
            object_id,
            object_kind,
            version,
            content_bytes,
            chunk_count,
            envelope_sha256,
        })
    }

    pub fn read_object(
        &self,
        case_id: &CaseId,
        object_id: &ObjectId,
        version: u64,
    ) -> Result<DecryptedVaultObjectV1, VaultStoreError> {
        if version == 0 {
            return Err(VaultStoreError::InvalidInput);
        }
        let db = open_database(&self.root)?;
        let version_sql = sql_i64(version)?;
        let row: Option<(String, String, String, String, Option<String>)> = db
            .query_row(
                "SELECT workspace_instance_id,case_id,object_kind,state,envelope_sha256
                 FROM object_journal WHERE object_id=?1 AND version=?2",
                params![object_id.as_str(), version_sql],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        let Some((workspace, stored_case, stored_kind, state, expected_envelope_hash)) = row else {
            return Err(VaultStoreError::ObjectNotAvailable);
        };
        if state != "committed"
            || workspace != self.workspace_instance_id.as_str()
            || stored_case != case_id.as_str()
        {
            return Err(VaultStoreError::ObjectNotAvailable);
        }
        let expected_envelope_hash =
            expected_envelope_hash.ok_or(VaultStoreError::ObjectNotAvailable)?;
        let object_kind = VaultObjectKind::parse(&stored_kind)?;
        let directory = self.object_directory(case_id, object_id, version);
        validate_controlled_path(&self.root, &directory, false)?;
        let envelope_path = directory.join("envelope.json");
        let commit_path = directory.join("commit.json");
        validate_controlled_path(&self.root, &envelope_path, true)?;
        validate_controlled_path(&self.root, &commit_path, true)?;
        let envelope_bytes = read_bounded(&envelope_path, MAX_VAULT_ENVELOPE_BYTES)?;
        if sha256_hex(&envelope_bytes) != expected_envelope_hash {
            return Err(VaultStoreError::EnvelopeInvalid);
        }
        let envelope: VaultObjectEnvelopeV1 = strict_json_v1_from_slice(&envelope_bytes)
            .map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        envelope.validate()?;
        if envelope.workspace_instance_id != self.workspace_instance_id
            || envelope.case_id != *case_id
            || envelope.object_id != *object_id
            || envelope.object_kind != object_kind
            || envelope.version != version
        {
            return Err(VaultStoreError::EnvelopeInvalid);
        }
        let commit_bytes = read_bounded(&commit_path, MAX_VAULT_ENVELOPE_BYTES)?;
        let commit: VaultObjectCommitV1 = strict_json_v1_from_slice(&commit_bytes)
            .map_err(|_| VaultStoreError::EnvelopeInvalid)?;
        if commit.schema_version != VAULT_OBJECT_COMMIT_VERSION
            || commit.workspace_instance_id != self.workspace_instance_id
            || commit.case_id != *case_id
            || commit.object_id != *object_id
            || commit.version != version
            || commit.envelope_sha256.as_str() != expected_envelope_hash
            || usize::try_from(commit.chunk_count).ok() != Some(envelope.chunks.len())
        {
            return Err(VaultStoreError::EnvelopeInvalid);
        }

        let key = self.load_case_key(case_id)?;
        let capacity =
            usize::try_from(envelope.content_bytes).map_err(|_| VaultStoreError::ObjectTooLarge)?;
        let mut content = ZeroizingBytes::with_capacity(capacity);
        for record in &envelope.chunks {
            let path = directory.join(chunk_file_name(record.chunk_index));
            validate_controlled_path(&self.root, &path, true)?;
            let ciphertext = read_exact_bytes(&path, record.ciphertext_bytes)?;
            if sha256_hex(&ciphertext) != record.ciphertext_sha256.as_str() {
                return Err(VaultStoreError::ContentCorrupt);
            }
            let nonce = decode_fixed_hex::<GCM_NONCE_BYTES>(&record.nonce_hex)?;
            let tag = decode_fixed_hex::<GCM_TAG_BYTES>(&record.tag_hex)?;
            let sealed = AeadSealedV1::from_parts(&nonce, ciphertext, &tag)
                .map_err(|_| VaultStoreError::ContentCorrupt)?;
            let aad = build_aad(
                &self.workspace_instance_id,
                case_id,
                object_id,
                object_kind,
                version,
                envelope.content_bytes,
                envelope.created_at_unix,
                CONTENT_COMPONENT,
                i64::from(record.chunk_index),
            )?;
            let plaintext = ZeroizingBytes::new(open(&key, &sealed, &aad).map_err(map_open_error)?);
            if u64::try_from(plaintext.len()).ok() != Some(record.plaintext_bytes) {
                return Err(VaultStoreError::ContentCorrupt);
            }
            content.extend_from_slice(&plaintext);
        }
        if u64::try_from(content.len()).ok() != Some(envelope.content_bytes) {
            return Err(VaultStoreError::ContentCorrupt);
        }

        let metadata_path = directory.join("private-metadata.bin");
        validate_controlled_path(&self.root, &metadata_path, true)?;
        let metadata_ciphertext =
            read_exact_bytes(&metadata_path, envelope.private_metadata.ciphertext_bytes)?;
        if sha256_hex(&metadata_ciphertext) != envelope.private_metadata.ciphertext_sha256.as_str()
        {
            return Err(VaultStoreError::ContentCorrupt);
        }
        let metadata_nonce =
            decode_fixed_hex::<GCM_NONCE_BYTES>(&envelope.private_metadata.nonce_hex)?;
        let metadata_tag = decode_fixed_hex::<GCM_TAG_BYTES>(&envelope.private_metadata.tag_hex)?;
        let sealed_metadata =
            AeadSealedV1::from_parts(&metadata_nonce, metadata_ciphertext, &metadata_tag)
                .map_err(|_| VaultStoreError::ContentCorrupt)?;
        let metadata_aad = build_aad(
            &self.workspace_instance_id,
            case_id,
            object_id,
            object_kind,
            version,
            envelope.content_bytes,
            envelope.created_at_unix,
            PRIVATE_METADATA_COMPONENT,
            PRIVATE_METADATA_CHUNK_INDEX,
        )?;
        let metadata_bytes = ZeroizingBytes::new(
            open(&key, &sealed_metadata, &metadata_aad).map_err(map_open_error)?,
        );
        if u64::try_from(metadata_bytes.len()).ok()
            != Some(envelope.private_metadata.plaintext_bytes)
        {
            return Err(VaultStoreError::ContentCorrupt);
        }
        let private_metadata: VaultPrivateMetadataV1 =
            strict_json_v1_from_slice(&metadata_bytes)
                .map_err(|_| VaultStoreError::ContentCorrupt)?;
        private_metadata
            .validate()
            .map_err(|_| VaultStoreError::ContentCorrupt)?;
        if private_metadata.source_bytes != envelope.content_bytes
            || private_metadata.source_sha256.as_str() != sha256_hex(&content)
        {
            return Err(VaultStoreError::ContentCorrupt);
        }

        Ok(DecryptedVaultObjectV1 {
            workspace_instance_id: self.workspace_instance_id.clone(),
            case_id: case_id.clone(),
            object_id: object_id.clone(),
            object_kind,
            version,
            content: content.into_inner(),
            private_metadata,
        })
    }

    fn allocate_object(
        &self,
        db: &Connection,
        case_id: &CaseId,
        object_kind: VaultObjectKind,
        created_at_unix: u64,
    ) -> Result<ObjectId, VaultStoreError> {
        for _ in 0..OBJECT_ALLOCATION_ATTEMPTS {
            let object_id = random_object_id()?;
            let inserted = db
                .execute(
                    "INSERT OR IGNORE INTO object_journal(
                         object_id,version,workspace_instance_id,case_id,object_kind,state,created_at_unix
                     ) VALUES(?1,1,?2,?3,?4,'allocated',?5)",
                    params![
                        object_id.as_str(),
                        self.workspace_instance_id.as_str(),
                        case_id.as_str(),
                        object_kind.as_str(),
                        sql_i64(created_at_unix)?
                    ],
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            if inserted == 1 {
                return Ok(object_id);
            }
        }
        Err(VaultStoreError::ObjectAllocationFailed)
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_and_reserve_nonce(
        &self,
        db: &Connection,
        key: &SecretKey32,
        plaintext: &[u8],
        aad: &[u8],
        case_id: &CaseId,
        object_id: &ObjectId,
        version: u64,
        component: &str,
        chunk_index: i64,
        reserved_at_unix: u64,
    ) -> Result<AeadSealedV1, VaultStoreError> {
        for _ in 0..NONCE_RESERVATION_ATTEMPTS {
            let sealed = seal(key, plaintext, aad).map_err(map_seal_error)?;
            let inserted = db
                .execute(
                    "INSERT OR IGNORE INTO nonce_reservations(
                         case_id,nonce_hex,object_id,version,component,chunk_index,reserved_at_unix
                     ) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![
                        case_id.as_str(),
                        hex_lower(sealed.nonce()),
                        object_id.as_str(),
                        sql_i64(version)?,
                        component,
                        chunk_index,
                        sql_i64(reserved_at_unix)?
                    ],
                )
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            if inserted == 1 {
                return Ok(sealed);
            }
        }
        Err(VaultStoreError::NonceReservationFailed)
    }

    fn load_or_create_case_key(
        &self,
        case_id: &CaseId,
        created_at_unix: u64,
    ) -> Result<SecretKey32, VaultStoreError> {
        let final_path = self.case_key_path(case_id);
        if final_path.exists() {
            return self.load_case_key(case_id);
        }

        // A missing key is never interpreted as an invitation to rotate it silently. If any
        // journal record exists for the case, replacement would make prior ciphertext
        // permanently unreadable and could hide key-loss incidents.
        let db = open_database(&self.root)?;
        let object_count: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM object_journal WHERE case_id=?1",
                params![case_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        if object_count != 0 {
            return Err(VaultStoreError::CaseKeyUnavailable);
        }

        validate_new_controlled_path(&self.root, &final_path)?;
        let key = SecretKey32::generate().map_err(map_key_generation_error)?;
        let wrapped = wrap_case_key(&key).map_err(|_| VaultStoreError::CaseKeyUnavailable)?;
        if wrapped.is_empty() || wrapped.len() > MAX_WRAPPED_CASE_KEY_BYTES {
            return Err(VaultStoreError::KeyRecordInvalid);
        }
        let record = WrappedCaseKeyRecordV1 {
            schema_version: VAULT_CASE_KEY_RECORD_VERSION.to_owned(),
            wrap_provider: VAULT_KEY_WRAP_PROVIDER.to_owned(),
            workspace_instance_id: self.workspace_instance_id.clone(),
            case_id: case_id.clone(),
            wrapped_key_base64: BASE64_STANDARD.encode(&wrapped),
            wrapped_key_sha256: Sha256Hex::parse(sha256_hex(&wrapped))
                .map_err(|_| VaultStoreError::KeyRecordInvalid)?,
            created_at_unix,
        };
        let bytes = canonical_json_v1(&record).map_err(|_| VaultStoreError::KeyRecordInvalid)?;
        if bytes.len() > MAX_VAULT_KEY_RECORD_BYTES {
            return Err(VaultStoreError::KeyRecordInvalid);
        }
        let temporary = self.root.staging.join(format!(
            "{}-case-key-{}.tmp",
            case_id.as_str(),
            random_hex(8)?
        ));
        validate_new_controlled_path(&self.root, &temporary)?;
        write_new_file(&temporary, &bytes)?;
        match fs::rename(&temporary, &final_path) {
            Ok(()) => Ok(key),
            Err(_) if final_path.exists() => {
                let _ = fs::remove_file(&temporary);
                self.load_case_key(case_id)
            }
            Err(_) => {
                let _ = fs::remove_file(&temporary);
                Err(VaultStoreError::IoFailed)
            }
        }
    }

    fn load_case_key(&self, case_id: &CaseId) -> Result<SecretKey32, VaultStoreError> {
        let path = self.case_key_path(case_id);
        if !path.exists() {
            return Err(VaultStoreError::CaseKeyUnavailable);
        }
        validate_controlled_path(&self.root, &path, true)?;
        let bytes =
            read_bounded(&path, MAX_VAULT_KEY_RECORD_BYTES).map_err(|error| match error {
                VaultStoreError::ObjectNotAvailable => VaultStoreError::CaseKeyUnavailable,
                other => other,
            })?;
        let record: WrappedCaseKeyRecordV1 =
            strict_json_v1_from_slice(&bytes).map_err(|_| VaultStoreError::KeyRecordInvalid)?;
        if record.schema_version != VAULT_CASE_KEY_RECORD_VERSION
            || record.wrap_provider != VAULT_KEY_WRAP_PROVIDER
            || record.workspace_instance_id != self.workspace_instance_id
            || record.case_id != *case_id
            || record.created_at_unix == 0
        {
            return Err(VaultStoreError::KeyRecordInvalid);
        }
        let wrapped = BASE64_STANDARD
            .decode(record.wrapped_key_base64.as_bytes())
            .map_err(|_| VaultStoreError::KeyRecordInvalid)?;
        if wrapped.is_empty()
            || wrapped.len() > MAX_WRAPPED_CASE_KEY_BYTES
            || sha256_hex(&wrapped) != record.wrapped_key_sha256.as_str()
        {
            return Err(VaultStoreError::KeyRecordInvalid);
        }
        unwrap_case_key(&wrapped).map_err(|_| VaultStoreError::CaseKeyUnavailable)
    }

    fn case_key_path(&self, case_id: &CaseId) -> PathBuf {
        self.root
            .keys
            .join(format!("{}.key.json", case_id.as_str()))
    }

    fn object_directory(&self, case_id: &CaseId, object_id: &ObjectId, version: u64) -> PathBuf {
        self.root
            .objects
            .join(case_id.as_str())
            .join(object_id.as_str())
            .join(version_directory_name(version))
    }
}

/// Misuse-resistant fixed-local storage boundary shared by privacy stores.
///
/// Visibility is deliberately restricted to this crate so neither MCP nor application commands
/// can obtain the canonical private root. Callers provide only relative paths made entirely from
/// normal components; absolute paths, parent traversal, roots and Windows prefixes are rejected.
#[derive(Clone)]
pub(crate) struct FixedLocalStorageRoot {
    canonical_root: PathBuf,
}

impl FixedLocalStorageRoot {
    pub(crate) fn initialize(root: &Path) -> Result<Self, VaultStoreError> {
        if !root.is_absolute() {
            return Err(VaultStoreError::InvalidRoot);
        }
        platform::reject_reparse_ancestors(root)?;
        fs::create_dir_all(root).map_err(|_| VaultStoreError::IoFailed)?;
        platform::validate_fixed_local_root(root)?;
        let canonical_root = fs::canonicalize(root).map_err(|_| VaultStoreError::InvalidRoot)?;
        platform::mark_not_content_indexed(&canonical_root)?;
        Ok(Self { canonical_root })
    }

    pub(crate) fn open(root: &Path) -> Result<Self, VaultStoreError> {
        if !root.is_absolute() || !root.is_dir() {
            return Err(VaultStoreError::InvalidRoot);
        }
        platform::validate_fixed_local_root(root)?;
        let canonical_root = fs::canonicalize(root).map_err(|_| VaultStoreError::InvalidRoot)?;
        Ok(Self { canonical_root })
    }

    pub(crate) fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    pub(crate) fn ensure_directory(&self, relative: &Path) -> Result<PathBuf, VaultStoreError> {
        validate_relative_storage_path(relative)?;
        let mut current = self.canonical_root.clone();
        for component in relative.components() {
            let std::path::Component::Normal(name) = component else {
                return Err(VaultStoreError::UnsafeFilesystem);
            };
            current.push(name);
            if current.exists() {
                platform::reject_reparse_components(&self.canonical_root, &current)?;
                let metadata =
                    fs::symlink_metadata(&current).map_err(|_| VaultStoreError::IoFailed)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(VaultStoreError::UnsafeFilesystem);
                }
            } else {
                fs::create_dir(&current).map_err(|_| VaultStoreError::IoFailed)?;
                platform::reject_reparse_components(&self.canonical_root, &current)?;
            }
            platform::mark_not_content_indexed(&current)?;
        }
        Ok(current)
    }

    pub(crate) fn validate_existing_file(
        &self,
        relative: &Path,
    ) -> Result<PathBuf, VaultStoreError> {
        self.validate_existing(relative, true)
    }

    pub(crate) fn validate_existing_directory(
        &self,
        relative: &Path,
    ) -> Result<PathBuf, VaultStoreError> {
        self.validate_existing(relative, false)
    }

    // Reserved for sibling privacy stores that atomically create files below this boundary.
    #[allow(dead_code)]
    pub(crate) fn validate_new_path(&self, relative: &Path) -> Result<PathBuf, VaultStoreError> {
        let path = self.resolve(relative)?;
        if path.exists() {
            return Err(VaultStoreError::AlreadyExists);
        }
        let parent = path.parent().ok_or(VaultStoreError::UnsafeFilesystem)?;
        if !parent.is_dir() {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        platform::reject_reparse_components(&self.canonical_root, parent)?;
        Ok(path)
    }

    fn validate_existing(
        &self,
        relative: &Path,
        require_file: bool,
    ) -> Result<PathBuf, VaultStoreError> {
        let path = self.resolve(relative)?;
        platform::reject_reparse_components(&self.canonical_root, &path)?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| VaultStoreError::ObjectNotAvailable)?;
        if metadata.file_type().is_symlink()
            || (require_file && !metadata.is_file())
            || (!require_file && !metadata.is_dir())
        {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        Ok(path)
    }

    fn resolve(&self, relative: &Path) -> Result<PathBuf, VaultStoreError> {
        validate_relative_storage_path(relative)?;
        Ok(self.canonical_root.join(relative))
    }
}

fn validate_relative_storage_path(relative: &Path) -> Result<(), VaultStoreError> {
    let mut components = relative.components();
    if components.clone().next().is_none()
        || !components.all(|component| matches!(component, std::path::Component::Normal(_)))
    {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    Ok(())
}

#[derive(Clone)]
struct ValidatedVaultRoot {
    root: PathBuf,
    objects: PathBuf,
    keys: PathBuf,
    staging: PathBuf,
    quarantine: PathBuf,
    database: PathBuf,
}

impl ValidatedVaultRoot {
    fn initialize(root: &Path) -> Result<Self, VaultStoreError> {
        let fixed_root = FixedLocalStorageRoot::initialize(root)?;
        for relative in ["objects", "keys", ".staging", ".quarantine"] {
            fixed_root.ensure_directory(Path::new(relative))?;
        }
        Ok(Self::from_canonical(
            fixed_root.canonical_root().to_path_buf(),
        ))
    }

    fn open(root: &Path) -> Result<Self, VaultStoreError> {
        let fixed_root = FixedLocalStorageRoot::open(root)?;
        for relative in ["objects", "keys", ".staging", ".quarantine"] {
            fixed_root.validate_existing_directory(Path::new(relative))?;
        }
        fixed_root.validate_existing_file(Path::new("vault-state.sqlite"))?;
        Ok(Self::from_canonical(
            fixed_root.canonical_root().to_path_buf(),
        ))
    }

    fn from_canonical(root: PathBuf) -> Self {
        Self {
            objects: root.join("objects"),
            keys: root.join("keys"),
            staging: root.join(".staging"),
            quarantine: root.join(".quarantine"),
            database: root.join("vault-state.sqlite"),
            root,
        }
    }
}

fn initialize_database(
    root: &ValidatedVaultRoot,
    workspace_instance_id: &WorkspaceInstanceId,
) -> Result<(), VaultStoreError> {
    if !root.database.exists()
        && (!directory_is_empty(&root.objects)? || !directory_is_empty(&root.keys)?)
    {
        return Err(VaultStoreError::DatabaseFailed);
    }
    if root.database.exists() {
        validate_controlled_path(root, &root.database, true)?;
    } else {
        validate_new_controlled_path(root, &root.database)?;
    }
    let db = Connection::open(&root.database).map_err(|_| VaultStoreError::DatabaseFailed)?;
    db.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         PRAGMA secure_delete=ON;
         CREATE TABLE IF NOT EXISTS vault_meta(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             schema_version INTEGER NOT NULL,
             workspace_instance_id TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS object_journal(
             object_id TEXT NOT NULL,
             version INTEGER NOT NULL CHECK(version>0),
             workspace_instance_id TEXT NOT NULL,
             case_id TEXT NOT NULL,
             object_kind TEXT NOT NULL,
             state TEXT NOT NULL CHECK(state IN('allocated','prepared','committed','quarantined')),
             envelope_sha256 TEXT,
             content_bytes INTEGER,
             chunk_count INTEGER,
             created_at_unix INTEGER NOT NULL,
             committed_at_unix INTEGER,
             PRIMARY KEY(object_id,version)
         );
         CREATE TABLE IF NOT EXISTS nonce_reservations(
             case_id TEXT NOT NULL,
             nonce_hex TEXT NOT NULL CHECK(length(nonce_hex)=24),
             object_id TEXT NOT NULL,
             version INTEGER NOT NULL CHECK(version>0),
             component TEXT NOT NULL CHECK(component IN('content','private_metadata')),
             chunk_index INTEGER NOT NULL CHECK(chunk_index>=-1),
             reserved_at_unix INTEGER NOT NULL,
             PRIMARY KEY(case_id,nonce_hex),
             FOREIGN KEY(object_id,version) REFERENCES object_journal(object_id,version),
             UNIQUE(object_id,version,component,chunk_index)
         );
         CREATE INDEX IF NOT EXISTS nonce_object_component
             ON nonce_reservations(object_id,version,component,chunk_index);",
    )
    .map_err(|_| VaultStoreError::DatabaseFailed)?;
    let existing: Option<(u32, String)> = db
        .query_row(
            "SELECT schema_version,workspace_instance_id FROM vault_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    match existing {
        Some((version, workspace))
            if version == VAULT_STORE_SCHEMA_VERSION
                && workspace == workspace_instance_id.as_str() => {}
        Some(_) => return Err(VaultStoreError::DatabaseFailed),
        None => {
            let journal_count: i64 = db
                .query_row("SELECT COUNT(*) FROM object_journal", [], |row| row.get(0))
                .map_err(|_| VaultStoreError::DatabaseFailed)?;
            if journal_count != 0
                || !directory_is_empty(&root.objects)?
                || !directory_is_empty(&root.keys)?
            {
                // Never bless an existing orphan object/key layout by manufacturing a new
                // workspace identity database around it.
                return Err(VaultStoreError::DatabaseFailed);
            }
            db.execute(
                "INSERT INTO vault_meta(singleton,schema_version,workspace_instance_id)
                 VALUES(1,?1,?2)",
                params![VAULT_STORE_SCHEMA_VERSION, workspace_instance_id.as_str()],
            )
            .map_err(|_| VaultStoreError::DatabaseFailed)?;
        }
    }
    platform::mark_not_content_indexed(&root.database)?;
    Ok(())
}

fn validate_database(
    root: &ValidatedVaultRoot,
    workspace_instance_id: &WorkspaceInstanceId,
) -> Result<(), VaultStoreError> {
    let db = open_database(root)?;
    let (version, workspace): (u32, String) = db
        .query_row(
            "SELECT schema_version,workspace_instance_id FROM vault_meta WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    if version != VAULT_STORE_SCHEMA_VERSION || workspace != workspace_instance_id.as_str() {
        return Err(VaultStoreError::DatabaseFailed);
    }
    Ok(())
}

fn open_database(root: &ValidatedVaultRoot) -> Result<Connection, VaultStoreError> {
    validate_controlled_path(root, &root.database, true)?;
    let db = Connection::open_with_flags(&root.database, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    db.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;")
        .map_err(|_| VaultStoreError::DatabaseFailed)?;
    Ok(db)
}

#[allow(clippy::too_many_arguments)]
fn build_aad(
    workspace_instance_id: &WorkspaceInstanceId,
    case_id: &CaseId,
    object_id: &ObjectId,
    object_kind: VaultObjectKind,
    version: u64,
    content_bytes: u64,
    created_at_unix: u64,
    component: &str,
    chunk_index: i64,
) -> Result<Vec<u8>, VaultStoreError> {
    if version == 0
        || content_bytes == 0
        || created_at_unix == 0
        || !matches!(component, CONTENT_COMPONENT | PRIVATE_METADATA_COMPONENT)
        || (component == CONTENT_COMPONENT && chunk_index < 0)
        || (component == PRIVATE_METADATA_COMPONENT && chunk_index != PRIVATE_METADATA_CHUNK_INDEX)
    {
        return Err(VaultStoreError::InvalidInput);
    }
    let mut aad = Vec::with_capacity(256);
    aad.extend_from_slice(AAD_DOMAIN);
    append_length_prefixed(&mut aad, workspace_instance_id.as_str())?;
    append_length_prefixed(&mut aad, case_id.as_str())?;
    append_length_prefixed(&mut aad, object_id.as_str())?;
    append_length_prefixed(&mut aad, object_kind.as_str())?;
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&content_bytes.to_be_bytes());
    aad.extend_from_slice(&created_at_unix.to_be_bytes());
    append_length_prefixed(&mut aad, component)?;
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    Ok(aad)
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &str) -> Result<(), VaultStoreError> {
    let length = u32::try_from(value.len()).map_err(|_| VaultStoreError::InvalidInput)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn validate_private_string(
    value: &str,
    max_bytes: usize,
    require_ascii: bool,
) -> Result<(), VaultStoreError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
        || (require_ascii && !value.is_ascii())
    {
        return Err(VaultStoreError::InvalidInput);
    }
    Ok(())
}

fn ensure_controlled_directory(
    root: &ValidatedVaultRoot,
    directory: &Path,
) -> Result<(), VaultStoreError> {
    if !directory.starts_with(&root.root) {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    fs::create_dir_all(directory).map_err(|_| VaultStoreError::IoFailed)?;
    platform::reject_reparse_components(&root.root, directory)?;
    let metadata = fs::symlink_metadata(directory).map_err(|_| VaultStoreError::IoFailed)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    platform::mark_not_content_indexed(directory)
}

fn validate_new_controlled_path(
    root: &ValidatedVaultRoot,
    path: &Path,
) -> Result<(), VaultStoreError> {
    if !path.starts_with(&root.root) || path.exists() {
        return Err(if path.exists() {
            VaultStoreError::AlreadyExists
        } else {
            VaultStoreError::UnsafeFilesystem
        });
    }
    let parent = path.parent().ok_or(VaultStoreError::UnsafeFilesystem)?;
    if !parent.starts_with(&root.root) || !parent.is_dir() {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    platform::reject_reparse_components(&root.root, parent)
}

fn validate_controlled_path(
    root: &ValidatedVaultRoot,
    path: &Path,
    require_file: bool,
) -> Result<(), VaultStoreError> {
    if !path.starts_with(&root.root) {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    platform::reject_reparse_components(&root.root, path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| VaultStoreError::ObjectNotAvailable)?;
    if metadata.file_type().is_symlink()
        || (require_file && !metadata.is_file())
        || (!require_file && !metadata.is_dir())
    {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), VaultStoreError> {
    if bytes.is_empty() {
        return Err(VaultStoreError::InvalidInput);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| VaultStoreError::IoFailed)?;
    file.write_all(bytes)
        .map_err(|_| VaultStoreError::IoFailed)?;
    file.sync_all().map_err(|_| VaultStoreError::IoFailed)?;
    platform::mark_not_content_indexed(path)
}

fn read_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, VaultStoreError> {
    let metadata = fs::metadata(path).map_err(|_| VaultStoreError::ObjectNotAvailable)?;
    let length = usize::try_from(metadata.len()).map_err(|_| VaultStoreError::ContentCorrupt)?;
    if length == 0 || length > max_bytes {
        return Err(VaultStoreError::ContentCorrupt);
    }
    let mut bytes = Vec::with_capacity(length);
    File::open(path)
        .map_err(|_| VaultStoreError::ObjectNotAvailable)?
        .read_to_end(&mut bytes)
        .map_err(|_| VaultStoreError::IoFailed)?;
    if bytes.len() != length {
        return Err(VaultStoreError::ContentCorrupt);
    }
    Ok(bytes)
}

fn read_exact_bytes(path: &Path, expected_bytes: u64) -> Result<Vec<u8>, VaultStoreError> {
    let expected = usize::try_from(expected_bytes).map_err(|_| VaultStoreError::ContentCorrupt)?;
    if expected == 0 || expected > MAX_VAULT_CHUNK_BYTES.max(MAX_VAULT_PRIVATE_METADATA_BYTES) {
        return Err(VaultStoreError::ContentCorrupt);
    }
    let metadata = fs::metadata(path).map_err(|_| VaultStoreError::ObjectNotAvailable)?;
    if metadata.len() != expected_bytes {
        return Err(VaultStoreError::ContentCorrupt);
    }
    let mut bytes = Vec::with_capacity(expected);
    File::open(path)
        .map_err(|_| VaultStoreError::ObjectNotAvailable)?
        .read_to_end(&mut bytes)
        .map_err(|_| VaultStoreError::IoFailed)?;
    if bytes.len() != expected {
        return Err(VaultStoreError::ContentCorrupt);
    }
    Ok(bytes)
}

fn directory_is_empty(path: &Path) -> Result<bool, VaultStoreError> {
    let mut entries = fs::read_dir(path).map_err(|_| VaultStoreError::IoFailed)?;
    Ok(entries.next().is_none())
}

struct ZeroizingBytes(Vec<u8>);

impl ZeroizingBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl std::ops::Deref for ZeroizingBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ZeroizingBytes {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0);
    }
}

fn zeroize_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_string(value: &mut String) {
    unsafe {
        zeroize_bytes(value.as_mut_vec());
    }
    value.clear();
}

fn quarantine_path(root: &ValidatedVaultRoot, path: &Path) -> Result<(), VaultStoreError> {
    if !path.exists() {
        return Ok(());
    }
    if !path.starts_with(&root.root) {
        return Err(VaultStoreError::UnsafeFilesystem);
    }
    let file_name = path.file_name().ok_or(VaultStoreError::UnsafeFilesystem)?;
    let destination = root.quarantine.join(format!(
        "{}-{}",
        file_name.to_string_lossy(),
        random_hex(8)?
    ));
    validate_new_controlled_path(root, &destination)?;
    fs::rename(path, destination).map_err(|_| VaultStoreError::IoFailed)
}

fn random_object_id() -> Result<ObjectId, VaultStoreError> {
    ObjectId::parse(format!("obj_{}", random_hex(16)?))
        .map_err(|_| VaultStoreError::ObjectAllocationFailed)
}

fn random_hex(bytes: usize) -> Result<String, VaultStoreError> {
    let mut random = vec![0_u8; bytes];
    platform::random(&mut random)?;
    Ok(hex_lower(&random))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], VaultStoreError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VaultStoreError::EnvelopeInvalid);
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8, VaultStoreError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(VaultStoreError::EnvelopeInvalid),
    }
}

fn chunk_file_name(index: u32) -> String {
    format!("chunk-{index:08}.bin")
}

fn version_directory_name(version: u64) -> String {
    format!("v{version:020}")
}

fn sql_i64(value: u64) -> Result<i64, VaultStoreError> {
    i64::try_from(value).map_err(|_| VaultStoreError::InvalidInput)
}

fn map_key_generation_error(error: VaultCryptoError) -> VaultStoreError {
    if error == VaultCryptoError::PlatformUnavailable {
        VaultStoreError::PlatformUnavailable
    } else {
        VaultStoreError::CaseKeyUnavailable
    }
}

fn map_seal_error(error: VaultCryptoError) -> VaultStoreError {
    match error {
        VaultCryptoError::PlatformUnavailable => VaultStoreError::PlatformUnavailable,
        VaultCryptoError::ObjectTooLarge => VaultStoreError::ObjectTooLarge,
        _ => VaultStoreError::AuthenticationFailed,
    }
}

fn map_open_error(error: VaultCryptoError) -> VaultStoreError {
    match error {
        VaultCryptoError::PlatformUnavailable => VaultStoreError::PlatformUnavailable,
        _ => VaultStoreError::AuthenticationFailed,
    }
}

#[cfg(windows)]
mod platform {
    use super::VaultStoreError;
    use std::{
        os::windows::ffi::OsStrExt,
        path::{Path, PathBuf},
        ptr,
    };
    use windows_sys::Win32::{
        Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        Storage::FileSystem::{
            GetDriveTypeW, GetFileAttributesW, SetFileAttributesW,
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_REPARSE_POINT,
            INVALID_FILE_ATTRIBUTES,
        },
    };

    const DRIVE_FIXED_TYPE: u32 = 3;

    pub fn random(output: &mut [u8]) -> Result<(), VaultStoreError> {
        let length = u32::try_from(output.len()).map_err(|_| VaultStoreError::InvalidInput)?;
        let status = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                output.as_mut_ptr(),
                length,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(VaultStoreError::PlatformUnavailable);
        }
        Ok(())
    }

    pub fn reject_reparse_ancestors(path: &Path) -> Result<(), VaultStoreError> {
        for ancestor in path.ancestors() {
            if ancestor.exists() {
                check_not_reparse(ancestor)?;
            }
        }
        Ok(())
    }

    pub fn validate_fixed_local_root(root: &Path) -> Result<(), VaultStoreError> {
        for ancestor in root.ancestors() {
            if ancestor.exists() {
                check_not_reparse(ancestor)?;
            }
        }
        let canonical = std::fs::canonicalize(root).map_err(|_| VaultStoreError::InvalidRoot)?;
        let drive_root = canonical
            .ancestors()
            .last()
            .map(PathBuf::from)
            .ok_or(VaultStoreError::InvalidRoot)?;
        let drive_wide = wide(&drive_root);
        if unsafe { GetDriveTypeW(drive_wide.as_ptr()) } != DRIVE_FIXED_TYPE {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        reject_reparse_components(&canonical, &canonical)
    }

    pub fn reject_reparse_components(root: &Path, path: &Path) -> Result<(), VaultStoreError> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| VaultStoreError::UnsafeFilesystem)?;
        let mut current = root.to_path_buf();
        check_not_reparse(&current)?;
        for component in relative.components() {
            current.push(component.as_os_str());
            check_not_reparse(&current)?;
        }
        Ok(())
    }

    pub fn mark_not_content_indexed(path: &Path) -> Result<(), VaultStoreError> {
        let wide = wide(path);
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        let changed = unsafe {
            SetFileAttributesW(
                wide.as_ptr(),
                attributes | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            )
        };
        if changed == 0 {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        Ok(())
    }

    fn check_not_reparse(path: &Path) -> Result<(), VaultStoreError> {
        let wide = wide(path);
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(VaultStoreError::UnsafeFilesystem);
        }
        Ok(())
    }

    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::VaultStoreError;
    use std::path::Path;

    pub fn random(_output: &mut [u8]) -> Result<(), VaultStoreError> {
        Err(VaultStoreError::PlatformUnavailable)
    }

    pub fn reject_reparse_ancestors(_path: &Path) -> Result<(), VaultStoreError> {
        Err(VaultStoreError::PlatformUnavailable)
    }

    pub fn validate_fixed_local_root(_root: &Path) -> Result<(), VaultStoreError> {
        Err(VaultStoreError::PlatformUnavailable)
    }

    pub fn reject_reparse_components(_root: &Path, _path: &Path) -> Result<(), VaultStoreError> {
        Err(VaultStoreError::PlatformUnavailable)
    }

    pub fn mark_not_content_indexed(_path: &Path) -> Result<(), VaultStoreError> {
        Err(VaultStoreError::PlatformUnavailable)
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn workspace_id() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse("ws_0123456789abcdef0123456789abcdef")
            .expect("synthetic workspace ID")
    }

    fn case_id(suffix: &str) -> CaseId {
        CaseId::parse(format!("case_{suffix}")).expect("synthetic case ID")
    }

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "la-vault-store-test-{}",
            random_hex(16).expect("random")
        ))
    }

    fn input(name: &str) -> VaultPrivateMetadataInputV1 {
        VaultPrivateMetadataInputV1 {
            original_file_name: name.to_owned(),
            original_source_path: Some(format!(r"C:\synthetic-only\{name}")),
            original_media_type: "application/pdf".to_owned(),
            imported_at_unix: 10,
        }
    }

    fn create(
        store: &VaultStore,
        case: &CaseId,
        name: &str,
        bytes: &[u8],
        timestamp: u64,
    ) -> VaultObjectSummaryV1 {
        store
            .create_source_object(case, input(name), bytes, timestamp)
            .expect("create synthetic encrypted object")
    }

    fn assert_tree_excludes_plaintext(directory: &Path, needles: &[&[u8]]) {
        for entry in fs::read_dir(directory).expect("read synthetic vault tree") {
            let entry = entry.expect("synthetic vault entry");
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).expect("synthetic vault metadata");
            assert!(!metadata.file_type().is_symlink());
            if metadata.is_dir() {
                assert_tree_excludes_plaintext(&path, needles);
            } else if metadata.is_file() {
                let bytes = fs::read(&path).expect("read synthetic vault file");
                for (index, needle) in needles.iter().enumerate() {
                    assert!(
                        !bytes.windows(needle.len()).any(|window| window == *needle),
                        "private synthetic needle {index} leaked at rest"
                    );
                }
            }
        }
    }

    #[test]
    fn round_trip_chunks_and_keeps_all_source_identity_encrypted() {
        let root = test_root();
        let store = VaultStore::initialize(&root, workspace_id()).expect("initialize");
        let case = case_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let mut source = vec![0x53_u8; MAX_VAULT_CHUNK_BYTES + 17];
        source[..31].copy_from_slice(b"SYNTHETIC_PRIVATE_CANARY_000001");
        let name = "synthetic-private-evidence.pdf";
        let summary = create(&store, &case, name, &source, 20);
        assert_eq!(summary.chunk_count, 2);
        let decrypted = store
            .read_object(&case, &summary.object_id, 1)
            .expect("decrypt local object");
        assert_eq!(decrypted.content, source);
        assert_eq!(decrypted.private_metadata.original_file_name, name);
        assert_eq!(
            decrypted.private_metadata.original_source_path.as_deref(),
            Some(r"C:\synthetic-only\synthetic-private-evidence.pdf")
        );

        let directory = store.object_directory(&case, &summary.object_id, 1);
        let public_envelope = fs::read(directory.join("envelope.json")).expect("envelope");
        let public_commit = fs::read(directory.join("commit.json")).expect("commit");
        let key_record = fs::read(store.case_key_path(&case)).expect("key record");
        let source_hash = sha256_hex(&source);
        for public_bytes in [&public_envelope, &public_commit, &key_record] {
            let public_text = String::from_utf8_lossy(public_bytes);
            assert!(!public_text.contains(name));
            assert!(!public_text.contains("synthetic-only"));
            assert!(!public_text.contains(&source_hash));
            assert!(!public_text.contains("SYNTHETIC_PRIVATE_CANARY"));
        }
        assert!(!format!("{decrypted:?}").contains(name));
        assert!(!format!("{decrypted:?}").contains("SYNTHETIC_PRIVATE_CANARY"));
        assert_tree_excludes_plaintext(
            &root,
            &[
                name.as_bytes(),
                b"synthetic-only",
                b"SYNTHETIC_PRIVATE_CANARY_000001",
                source_hash.as_bytes(),
            ],
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn tampering_and_truncation_are_rejected_before_plaintext_return() {
        let root = test_root();
        let store = VaultStore::initialize(&root, workspace_id()).expect("initialize");
        let case = case_id("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let source = b"SYNTHETIC_TAMPER_CANARY";
        let summary = create(&store, &case, "tamper.pdf", source, 30);
        let chunk = store
            .object_directory(&case, &summary.object_id, 1)
            .join(chunk_file_name(0));
        let original = fs::read(&chunk).expect("chunk");
        let mut tampered = original.clone();
        tampered[0] ^= 0x80;
        fs::write(&chunk, &tampered).expect("tamper synthetic ciphertext");
        assert!(matches!(
            store.read_object(&case, &summary.object_id, 1),
            Err(VaultStoreError::ContentCorrupt | VaultStoreError::AuthenticationFailed)
        ));

        fs::write(&chunk, &original[..original.len() - 1]).expect("truncate ciphertext");
        assert!(matches!(
            store.read_object(&case, &summary.object_id, 1),
            Err(VaultStoreError::ContentCorrupt)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn aad_rejects_cross_case_object_kind_version_and_chunk_swaps() {
        let root = test_root();
        let workspace = workspace_id();
        let store = VaultStore::initialize(&root, workspace.clone()).expect("initialize");
        let case_a = case_id("cccccccccccccccccccccccccccccccc");
        let case_b = case_id("dddddddddddddddddddddddddddddddd");
        let source = b"SYNTHETIC_CROSS_CASE_CANARY";
        let summary = create(&store, &case_a, "cross-case.pdf", source, 40);
        assert!(matches!(
            store.read_object(&case_b, &summary.object_id, 1),
            Err(VaultStoreError::ObjectNotAvailable)
        ));

        let directory = store.object_directory(&case_a, &summary.object_id, 1);
        let envelope: VaultObjectEnvelopeV1 = strict_json_v1_from_slice(
            &fs::read(directory.join("envelope.json")).expect("envelope"),
        )
        .expect("strict envelope");
        let record = &envelope.chunks[0];
        let nonce = decode_fixed_hex::<GCM_NONCE_BYTES>(&record.nonce_hex).expect("nonce");
        let tag = decode_fixed_hex::<GCM_TAG_BYTES>(&record.tag_hex).expect("tag");
        let sealed = AeadSealedV1::from_parts(
            &nonce,
            fs::read(directory.join(chunk_file_name(0))).expect("ciphertext"),
            &tag,
        )
        .expect("sealed");
        let key = store.load_case_key(&case_a).expect("case key");
        let wrong_bindings = [
            build_aad(
                &workspace,
                &case_b,
                &summary.object_id,
                VaultObjectKind::SourceMaterial,
                1,
                summary.content_bytes,
                40,
                CONTENT_COMPONENT,
                0,
            )
            .expect("case AAD"),
            build_aad(
                &workspace,
                &case_a,
                &summary.object_id,
                VaultObjectKind::ReviewDraft,
                1,
                summary.content_bytes,
                40,
                CONTENT_COMPONENT,
                0,
            )
            .expect("kind AAD"),
            build_aad(
                &workspace,
                &case_a,
                &summary.object_id,
                VaultObjectKind::SourceMaterial,
                2,
                summary.content_bytes,
                40,
                CONTENT_COMPONENT,
                0,
            )
            .expect("version AAD"),
            build_aad(
                &workspace,
                &case_a,
                &summary.object_id,
                VaultObjectKind::SourceMaterial,
                1,
                summary.content_bytes,
                40,
                CONTENT_COMPONENT,
                1,
            )
            .expect("chunk AAD"),
        ];
        for aad in wrong_bindings {
            assert_eq!(
                open(&key, &sealed, &aad),
                Err(VaultCryptoError::AuthenticationFailed)
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_case_key_fails_closed() {
        let root = test_root();
        let store = VaultStore::initialize(&root, workspace_id()).expect("initialize");
        let case = case_id("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let summary = create(
            &store,
            &case,
            "lost-key.pdf",
            b"SYNTHETIC_LOST_KEY_CANARY",
            50,
        );
        fs::remove_file(store.case_key_path(&case)).expect("remove synthetic test key");
        assert!(matches!(
            store.read_object(&case, &summary.object_id, 1),
            Err(VaultStoreError::CaseKeyUnavailable)
        ));
        assert!(matches!(
            store.create_source_object(
                &case,
                input("replacement-key-must-not-be-created.pdf"),
                b"SYNTHETIC_REPLACEMENT_KEY_CANARY",
                51,
            ),
            Err(VaultStoreError::CaseKeyUnavailable)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn every_content_and_metadata_nonce_is_reserved_once_per_case_key() {
        let root = test_root();
        let store = VaultStore::initialize(&root, workspace_id()).expect("initialize");
        let case = case_id("ffffffffffffffffffffffffffffffff");
        for index in 0_u64..32 {
            create(
                &store,
                &case,
                &format!("nonce-{index}.pdf"),
                format!("SYNTHETIC_NONCE_CANARY_{index}").as_bytes(),
                100 + index,
            );
        }
        let db = open_database(&store.root).expect("database");
        let (count, distinct): (i64, i64) = db
            .query_row(
                "SELECT COUNT(*),COUNT(DISTINCT nonce_hex)
                 FROM nonce_reservations WHERE case_id=?1",
                params![case.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("nonce counts");
        assert_eq!(count, 64);
        assert_eq!(distinct, count);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn fixed_local_storage_helper_rejects_traversal_and_reparse_points() {
        let root = test_root();
        let fixed = FixedLocalStorageRoot::initialize(&root).expect("fixed root");
        assert!(matches!(
            fixed.validate_new_path(Path::new("../escape.bin")),
            Err(VaultStoreError::UnsafeFilesystem)
        ));
        assert!(matches!(
            fixed.validate_existing_directory(Path::new("C:\\absolute")),
            Err(VaultStoreError::UnsafeFilesystem)
        ));

        let safe_directory = fixed
            .ensure_directory(Path::new("work-products/synthetic"))
            .expect("safe directory");
        assert_eq!(
            fixed
                .validate_existing_directory(Path::new("work-products/synthetic"))
                .expect("validated directory"),
            safe_directory
        );
        let safe_file = fixed
            .validate_new_path(Path::new("work-products/synthetic/object.bin"))
            .expect("new path");
        write_new_file(&safe_file, b"SYNTHETIC_ENCRYPTED_BYTES").expect("safe file");
        assert_eq!(
            fixed
                .validate_existing_file(Path::new("work-products/synthetic/object.bin"))
                .expect("validated file"),
            safe_file
        );

        // Windows symlink creation depends on developer-mode/admin policy. Whenever the host
        // permits creating the synthetic link, the boundary must identify the reparse point and
        // reject it. Hosts that forbid symlink creation still exercise traversal/type checks.
        let reparse_target = fixed
            .ensure_directory(Path::new("synthetic-reparse-target"))
            .expect("reparse target");
        let reparse_link = root.join("synthetic-reparse-link");
        if std::os::windows::fs::symlink_dir(&reparse_target, &reparse_link).is_ok() {
            assert!(matches!(
                fixed.validate_existing_directory(Path::new("synthetic-reparse-link")),
                Err(VaultStoreError::UnsafeFilesystem)
            ));
            fs::remove_dir(&reparse_link).expect("remove synthetic reparse link");
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_roots_and_workspace_database_swaps_fail_closed() {
        assert!(matches!(
            VaultStore::initialize(Path::new("relative-vault"), workspace_id()),
            Err(VaultStoreError::InvalidRoot)
        ));

        let root = test_root();
        VaultStore::initialize(&root, workspace_id()).expect("initialize");
        let other = WorkspaceInstanceId::parse("ws_11111111111111111111111111111111")
            .expect("other workspace");
        assert!(matches!(
            VaultStore::open(&root, other),
            Err(VaultStoreError::DatabaseFailed)
        ));
        let _ = fs::remove_dir_all(&root);
    }
}
