#![allow(unsafe_code)]

//! Authenticated DPAPI-bound application backup with V3 five-component output and V2 read
//! compatibility.
//!
//! V3 encrypts the user database, encrypted privacy lifecycle bundle, ciphertext-only Vault
//! archive, approved-workspace archive, and encrypted work-products archive again in independent
//! authenticated chunks. A fresh AES-256-GCM key is wrapped with Windows DPAPI CurrentUser;
//! component-specific AAD binds all five hashes, sizes, schemas, app/workspace identity, validity
//! window, archive manifests, and chunk ordering. V2's historical three-component schema remains
//! accepted only by the reader/restorer; V1 is rejected.

#[path = "application_backup_zeroizing.rs"]
mod application_backup_zeroizing;
use application_backup_zeroizing::ZeroizingAccumulator;

use crate::{
    lifecycle::MAX_PORTABLE_BACKUP_BYTES,
    sha256_hex,
    vault_backup::MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    vault_crypto::{open, seal, unwrap_case_key, wrap_case_key, AeadSealedV1, SecretKey32},
    vnext::{canonical_json_v1, strict_json_v1_from_slice, WorkspaceInstanceId},
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    error::Error,
    fmt,
    sync::atomic::{compiler_fence, Ordering},
};

pub const APPLICATION_BACKUP_SCHEMA_VERSION: &str = "lawyer-assistance-backup-v2";
pub const APPLICATION_BACKUP_CRYPTO_SUITE: &str =
    "aes-256-gcm-three-component-chunked-dpapi-current-user-v2";
pub const APPLICATION_BACKUP_V3_SCHEMA_VERSION: &str = "lawyer-assistance-backup-v3";
pub const APPLICATION_BACKUP_V3_CRYPTO_SUITE: &str =
    "aes-256-gcm-five-component-chunked-dpapi-current-user-v3";
pub const APPLICATION_BACKUP_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_USER_DATABASE_BACKUP_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_APPROVED_WORKSPACE_BACKUP_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_WORK_PRODUCTS_BACKUP_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_APPLICATION_BACKUP_BYTES: usize = 2_100 * 1024 * 1024;
const MAX_BACKUP_ID_BYTES: usize = 128;
const MAX_APP_VERSION_BYTES: usize = 128;
const MAX_WRAPPED_KEY_BYTES: usize = 64 * 1024;
const AAD_SCHEMA_VERSION: &str = "lawyer-assistance-backup-aad-v2";
const AAD_V3_SCHEMA_VERSION: &str = "lawyer-assistance-backup-aad-v3";
const USER_COMPONENT: &str = "user_database";
const PRIVACY_COMPONENT: &str = "encrypted_privacy_bundle";
const VAULT_COMPONENT: &str = "encrypted_vault_bundle";
const APPROVED_WORKSPACE_COMPONENT: &str = "approved_workspace_bundle";
const WORK_PRODUCTS_COMPONENT: &str = "work_products_bundle";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationBackupError {
    InvalidInput,
    UnsupportedSchema,
    TooLarge,
    Crypto,
    Tampered,
    EnvironmentMismatch,
    Expired,
}

impl ApplicationBackupError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "application_backup_invalid_input",
            Self::UnsupportedSchema => "application_backup_schema_unsupported",
            Self::TooLarge => "application_backup_too_large",
            Self::Crypto => "application_backup_crypto_failed",
            Self::Tampered => "application_backup_tampered",
            Self::EnvironmentMismatch => "application_backup_environment_mismatch",
            Self::Expired => "application_backup_expired",
        }
    }
}

impl fmt::Display for ApplicationBackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for ApplicationBackupError {}

#[derive(Clone)]
pub struct ApplicationBackupCreateRequest<'a> {
    pub backup_id: &'a str,
    pub privacy_backup_id: &'a str,
    pub workspace_instance_id: &'a WorkspaceInstanceId,
    pub app_version: &'a str,
    pub user_schema_version: i64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub user_database: &'a [u8],
    pub encrypted_privacy_bundle: &'a [u8],
    pub encrypted_vault_bundle: &'a [u8],
    pub vault_manifest_sha256: &'a str,
}

#[derive(Clone)]
pub struct ApplicationBackupCreateRequestV3<'a> {
    pub backup_id: &'a str,
    pub privacy_backup_id: &'a str,
    pub workspace_instance_id: &'a WorkspaceInstanceId,
    pub app_version: &'a str,
    pub user_schema_version: i64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub user_database: &'a [u8],
    pub encrypted_privacy_bundle: &'a [u8],
    pub encrypted_vault_bundle: &'a [u8],
    pub vault_manifest_sha256: &'a str,
    pub approved_workspace_bundle: &'a [u8],
    pub approved_workspace_manifest_sha256: &'a str,
    pub work_products_bundle: &'a [u8],
    pub work_products_manifest_sha256: &'a str,
}

impl fmt::Debug for ApplicationBackupCreateRequestV3<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationBackupCreateRequestV3")
            .field("backup_id", &self.backup_id)
            .field("privacy_backup_id", &self.privacy_backup_id)
            .field("workspace_instance_id", &self.workspace_instance_id)
            .field("app_version", &self.app_version)
            .field("user_schema_version", &self.user_schema_version)
            .field("created_at_unix", &self.created_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field(
                "user_database",
                &format_args!("[PROTECTED {} BYTES]", self.user_database.len()),
            )
            .field(
                "encrypted_privacy_bundle",
                &format_args!(
                    "[ENCRYPTED PRIVACY BUNDLE {} BYTES]",
                    self.encrypted_privacy_bundle.len()
                ),
            )
            .field(
                "encrypted_vault_bundle",
                &format_args!(
                    "[ENCRYPTED VAULT BUNDLE {} BYTES]",
                    self.encrypted_vault_bundle.len()
                ),
            )
            .field(
                "approved_workspace_bundle",
                &format_args!(
                    "[ENCRYPTED OUTER APPROVED ARCHIVE {} BYTES]",
                    self.approved_workspace_bundle.len()
                ),
            )
            .field(
                "work_products_bundle",
                &format_args!(
                    "[ENCRYPTED OUTER WORK PRODUCT ARCHIVE {} BYTES]",
                    self.work_products_bundle.len()
                ),
            )
            .field("vault_manifest_sha256", &self.vault_manifest_sha256)
            .field(
                "approved_workspace_manifest_sha256",
                &self.approved_workspace_manifest_sha256,
            )
            .field(
                "work_products_manifest_sha256",
                &self.work_products_manifest_sha256,
            )
            .finish()
    }
}

impl fmt::Debug for ApplicationBackupCreateRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApplicationBackupCreateRequest")
            .field("backup_id", &self.backup_id)
            .field("privacy_backup_id", &self.privacy_backup_id)
            .field("workspace_instance_id", &self.workspace_instance_id)
            .field("app_version", &self.app_version)
            .field("user_schema_version", &self.user_schema_version)
            .field("created_at_unix", &self.created_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field(
                "user_database",
                &format_args!("[PROTECTED {} BYTES]", self.user_database.len()),
            )
            .field(
                "encrypted_privacy_bundle",
                &format_args!(
                    "[ENCRYPTED PRIVACY BUNDLE {} BYTES]",
                    self.encrypted_privacy_bundle.len()
                ),
            )
            .field(
                "encrypted_vault_bundle",
                &format_args!(
                    "[ENCRYPTED VAULT BUNDLE {} BYTES]",
                    self.encrypted_vault_bundle.len()
                ),
            )
            .field("vault_manifest_sha256", &self.vault_manifest_sha256)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ApplicationBackupOpenContext<'a> {
    pub expected_workspace_instance_id: &'a WorkspaceInstanceId,
    pub expected_app_version: &'a str,
    pub expected_user_schema_version: i64,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicationBackupMetadata {
    pub backup_id: String,
    pub privacy_backup_id: String,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub app_version: String,
    pub user_schema_version: i64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub user_database_bytes: u64,
    pub user_database_sha256: String,
    pub encrypted_privacy_bundle_bytes: u64,
    pub encrypted_privacy_bundle_sha256: String,
    pub encrypted_vault_bundle_bytes: u64,
    pub encrypted_vault_bundle_sha256: String,
    pub vault_manifest_sha256: String,
    pub user_database_chunk_count: u32,
    pub privacy_bundle_chunk_count: u32,
    pub vault_bundle_chunk_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_workspace_bundle_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_workspace_bundle_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_workspace_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_workspace_bundle_chunk_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_products_bundle_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_products_bundle_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_products_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_products_bundle_chunk_count: Option<u32>,
    pub chunk_count: u32,
    pub bundle_sha256: String,
}

#[derive(PartialEq, Eq)]
pub struct OpenedApplicationBackup {
    pub metadata: ApplicationBackupMetadata,
    pub user_database: Vec<u8>,
    pub encrypted_privacy_bundle: Vec<u8>,
    pub encrypted_vault_bundle: Vec<u8>,
    pub approved_workspace_bundle: Option<Vec<u8>>,
    pub work_products_bundle: Option<Vec<u8>>,
}

impl fmt::Debug for OpenedApplicationBackup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedApplicationBackup")
            .field("metadata", &self.metadata)
            .field(
                "user_database",
                &format_args!("[PROTECTED {} BYTES]", self.user_database.len()),
            )
            .field(
                "encrypted_privacy_bundle",
                &format_args!(
                    "[ENCRYPTED PRIVACY BUNDLE {} BYTES]",
                    self.encrypted_privacy_bundle.len()
                ),
            )
            .field(
                "encrypted_vault_bundle",
                &format_args!(
                    "[ENCRYPTED VAULT BUNDLE {} BYTES]",
                    self.encrypted_vault_bundle.len()
                ),
            )
            .field(
                "approved_workspace_bundle",
                &self
                    .approved_workspace_bundle
                    .as_ref()
                    .map(|value| format!("[PROTECTED {} BYTES]", value.len())),
            )
            .field(
                "work_products_bundle",
                &self
                    .work_products_bundle
                    .as_ref()
                    .map(|value| format!("[PROTECTED {} BYTES]", value.len())),
            )
            .finish()
    }
}

impl Drop for OpenedApplicationBackup {
    fn drop(&mut self) {
        zeroize(&mut self.user_database);
        zeroize(&mut self.encrypted_privacy_bundle);
        zeroize(&mut self.encrypted_vault_bundle);
        if let Some(bytes) = &mut self.approved_workspace_bundle {
            zeroize(bytes);
        }
        if let Some(bytes) = &mut self.work_products_bundle {
            zeroize(bytes);
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationBackupSchemaProbe {
    schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplicationBackupEnvelopeV2 {
    schema_version: String,
    crypto_suite: String,
    backup_id: String,
    privacy_backup_id: String,
    workspace_instance_id: WorkspaceInstanceId,
    app_version: String,
    user_schema_version: i64,
    created_at_unix: u64,
    expires_at_unix: u64,
    user_database_bytes: u64,
    user_database_sha256: String,
    encrypted_privacy_bundle_bytes: u64,
    encrypted_privacy_bundle_sha256: String,
    encrypted_vault_bundle_bytes: u64,
    encrypted_vault_bundle_sha256: String,
    vault_manifest_sha256: String,
    chunk_bytes: u32,
    user_database_chunk_count: u32,
    privacy_bundle_chunk_count: u32,
    vault_bundle_chunk_count: u32,
    chunk_count: u32,
    wrapped_data_key_base64: String,
    wrapped_data_key_sha256: String,
    aad_sha256: String,
    user_database_chunks: Vec<EncryptedChunkV2>,
    encrypted_privacy_bundle_chunks: Vec<EncryptedChunkV2>,
    encrypted_vault_bundle_chunks: Vec<EncryptedChunkV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ApplicationBackupEnvelopeV3 {
    schema_version: String,
    crypto_suite: String,
    backup_id: String,
    privacy_backup_id: String,
    workspace_instance_id: WorkspaceInstanceId,
    app_version: String,
    user_schema_version: i64,
    created_at_unix: u64,
    expires_at_unix: u64,
    user_database_bytes: u64,
    user_database_sha256: String,
    encrypted_privacy_bundle_bytes: u64,
    encrypted_privacy_bundle_sha256: String,
    encrypted_vault_bundle_bytes: u64,
    encrypted_vault_bundle_sha256: String,
    vault_manifest_sha256: String,
    approved_workspace_bundle_bytes: u64,
    approved_workspace_bundle_sha256: String,
    approved_workspace_manifest_sha256: String,
    work_products_bundle_bytes: u64,
    work_products_bundle_sha256: String,
    work_products_manifest_sha256: String,
    chunk_bytes: u32,
    user_database_chunk_count: u32,
    privacy_bundle_chunk_count: u32,
    vault_bundle_chunk_count: u32,
    approved_workspace_bundle_chunk_count: u32,
    work_products_bundle_chunk_count: u32,
    chunk_count: u32,
    wrapped_data_key_base64: String,
    wrapped_data_key_sha256: String,
    aad_sha256: String,
    user_database_chunks: Vec<EncryptedChunkV2>,
    encrypted_privacy_bundle_chunks: Vec<EncryptedChunkV2>,
    encrypted_vault_bundle_chunks: Vec<EncryptedChunkV2>,
    approved_workspace_bundle_chunks: Vec<EncryptedChunkV2>,
    work_products_bundle_chunks: Vec<EncryptedChunkV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EncryptedChunkV2 {
    index: u32,
    plaintext_bytes: u32,
    plaintext_sha256: String,
    nonce_base64: String,
    ciphertext_base64: String,
    ciphertext_sha256: String,
    tag_base64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationBackupAadV2<'a> {
    aad_schema_version: &'static str,
    schema_version: &'static str,
    crypto_suite: &'static str,
    backup_id: &'a str,
    privacy_backup_id: &'a str,
    workspace_instance_id: &'a WorkspaceInstanceId,
    app_version: &'a str,
    user_schema_version: i64,
    created_at_unix: u64,
    expires_at_unix: u64,
    user_database_bytes: u64,
    user_database_sha256: &'a str,
    encrypted_privacy_bundle_bytes: u64,
    encrypted_privacy_bundle_sha256: &'a str,
    encrypted_vault_bundle_bytes: u64,
    encrypted_vault_bundle_sha256: &'a str,
    vault_manifest_sha256: &'a str,
    chunk_bytes: u32,
    user_database_chunk_count: u32,
    privacy_bundle_chunk_count: u32,
    vault_bundle_chunk_count: u32,
    chunk_count: u32,
    wrapped_data_key_sha256: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationBackupAadV3<'a> {
    aad_schema_version: &'static str,
    schema_version: &'static str,
    crypto_suite: &'static str,
    backup_id: &'a str,
    privacy_backup_id: &'a str,
    workspace_instance_id: &'a WorkspaceInstanceId,
    app_version: &'a str,
    user_schema_version: i64,
    created_at_unix: u64,
    expires_at_unix: u64,
    user_database_bytes: u64,
    user_database_sha256: &'a str,
    encrypted_privacy_bundle_bytes: u64,
    encrypted_privacy_bundle_sha256: &'a str,
    encrypted_vault_bundle_bytes: u64,
    encrypted_vault_bundle_sha256: &'a str,
    vault_manifest_sha256: &'a str,
    approved_workspace_bundle_bytes: u64,
    approved_workspace_bundle_sha256: &'a str,
    approved_workspace_manifest_sha256: &'a str,
    work_products_bundle_bytes: u64,
    work_products_bundle_sha256: &'a str,
    work_products_manifest_sha256: &'a str,
    chunk_bytes: u32,
    user_database_chunk_count: u32,
    privacy_bundle_chunk_count: u32,
    vault_bundle_chunk_count: u32,
    approved_workspace_bundle_chunk_count: u32,
    work_products_bundle_chunk_count: u32,
    chunk_count: u32,
    wrapped_data_key_sha256: &'a str,
}

pub fn seal_application_backup(
    request: &ApplicationBackupCreateRequest<'_>,
) -> Result<(Vec<u8>, ApplicationBackupMetadata), ApplicationBackupError> {
    validate_backup_id(request.backup_id)?;
    validate_privacy_backup_id(request.privacy_backup_id)?;
    validate_app_version(request.app_version)?;
    if request.user_schema_version <= 0
        || request.created_at_unix == 0
        || request.expires_at_unix <= request.created_at_unix
        || request.user_database.is_empty()
        || request.encrypted_privacy_bundle.is_empty()
        || request.encrypted_vault_bundle.is_empty()
        || !is_hash(request.vault_manifest_sha256)
    {
        return Err(ApplicationBackupError::InvalidInput);
    }
    validate_component_bound(request.user_database, MAX_USER_DATABASE_BACKUP_BYTES)?;
    validate_component_bound(request.encrypted_privacy_bundle, MAX_PORTABLE_BACKUP_BYTES)?;
    validate_component_bound(
        request.encrypted_vault_bundle,
        MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    )?;

    let user_count = component_chunk_count(request.user_database.len())?;
    let privacy_count = component_chunk_count(request.encrypted_privacy_bundle.len())?;
    let vault_count = component_chunk_count(request.encrypted_vault_bundle.len())?;
    let total_count = user_count
        .checked_add(privacy_count)
        .and_then(|value| value.checked_add(vault_count))
        .ok_or(ApplicationBackupError::TooLarge)?;
    let user_sha256 = sha256_hex(request.user_database);
    let privacy_sha256 = sha256_hex(request.encrypted_privacy_bundle);
    let vault_sha256 = sha256_hex(request.encrypted_vault_bundle);
    let key = SecretKey32::generate().map_err(|_| ApplicationBackupError::Crypto)?;
    let wrapped_key = wrap_case_key(&key).map_err(|_| ApplicationBackupError::Crypto)?;
    if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES {
        return Err(ApplicationBackupError::Crypto);
    }
    let wrapped_key_sha256 = sha256_hex(&wrapped_key);
    let aad = application_aad(
        request,
        &user_sha256,
        &privacy_sha256,
        &vault_sha256,
        user_count,
        privacy_count,
        vault_count,
        total_count,
        &wrapped_key_sha256,
    )?;
    let aad_sha256 = sha256_hex(&aad);
    let user_chunks = seal_component(
        &key,
        &aad,
        USER_COMPONENT,
        request.user_database,
        user_count,
    )?;
    let privacy_chunks = seal_component(
        &key,
        &aad,
        PRIVACY_COMPONENT,
        request.encrypted_privacy_bundle,
        privacy_count,
    )?;
    let vault_chunks = seal_component(
        &key,
        &aad,
        VAULT_COMPONENT,
        request.encrypted_vault_bundle,
        vault_count,
    )?;
    let envelope = ApplicationBackupEnvelopeV2 {
        schema_version: APPLICATION_BACKUP_SCHEMA_VERSION.to_owned(),
        crypto_suite: APPLICATION_BACKUP_CRYPTO_SUITE.to_owned(),
        backup_id: request.backup_id.to_owned(),
        privacy_backup_id: request.privacy_backup_id.to_owned(),
        workspace_instance_id: request.workspace_instance_id.clone(),
        app_version: request.app_version.to_owned(),
        user_schema_version: request.user_schema_version,
        created_at_unix: request.created_at_unix,
        expires_at_unix: request.expires_at_unix,
        user_database_bytes: request.user_database.len() as u64,
        user_database_sha256: user_sha256,
        encrypted_privacy_bundle_bytes: request.encrypted_privacy_bundle.len() as u64,
        encrypted_privacy_bundle_sha256: privacy_sha256,
        encrypted_vault_bundle_bytes: request.encrypted_vault_bundle.len() as u64,
        encrypted_vault_bundle_sha256: vault_sha256,
        vault_manifest_sha256: request.vault_manifest_sha256.to_owned(),
        chunk_bytes: APPLICATION_BACKUP_CHUNK_BYTES as u32,
        user_database_chunk_count: user_count,
        privacy_bundle_chunk_count: privacy_count,
        vault_bundle_chunk_count: vault_count,
        chunk_count: total_count,
        wrapped_data_key_base64: BASE64_STANDARD.encode(&wrapped_key),
        wrapped_data_key_sha256: wrapped_key_sha256,
        aad_sha256,
        user_database_chunks: user_chunks,
        encrypted_privacy_bundle_chunks: privacy_chunks,
        encrypted_vault_bundle_chunks: vault_chunks,
    };
    let bytes = canonical_json_v1(&envelope).map_err(|_| ApplicationBackupError::InvalidInput)?;
    if bytes.is_empty() || bytes.len() > MAX_APPLICATION_BACKUP_BYTES {
        return Err(ApplicationBackupError::TooLarge);
    }
    let metadata = metadata_from_envelope(&envelope, sha256_hex(&bytes))?;
    Ok((bytes, metadata))
}

/// Creates the five-component application backup introduced in v3. The two case-workspace
/// archives are already locally protected at rest by their stores, but are deliberately treated
/// as plaintext components here so the outer per-backup key and component-specific AAD protect
/// their exact bytes as one coherent restore unit.
pub fn seal_application_backup_v3(
    request: &ApplicationBackupCreateRequestV3<'_>,
) -> Result<(Vec<u8>, ApplicationBackupMetadata), ApplicationBackupError> {
    validate_backup_id(request.backup_id)?;
    validate_privacy_backup_id(request.privacy_backup_id)?;
    validate_app_version(request.app_version)?;
    if request.user_schema_version <= 0
        || request.created_at_unix == 0
        || request.expires_at_unix <= request.created_at_unix
        || !is_hash(request.vault_manifest_sha256)
        || !is_hash(request.approved_workspace_manifest_sha256)
        || !is_hash(request.work_products_manifest_sha256)
    {
        return Err(ApplicationBackupError::InvalidInput);
    }
    validate_component_bound(request.user_database, MAX_USER_DATABASE_BACKUP_BYTES)?;
    validate_component_bound(request.encrypted_privacy_bundle, MAX_PORTABLE_BACKUP_BYTES)?;
    validate_component_bound(
        request.encrypted_vault_bundle,
        MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    )?;
    validate_component_bound(
        request.approved_workspace_bundle,
        MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
    )?;
    validate_component_bound(request.work_products_bundle, MAX_WORK_PRODUCTS_BACKUP_BYTES)?;

    let user_count = component_chunk_count(request.user_database.len())?;
    let privacy_count = component_chunk_count(request.encrypted_privacy_bundle.len())?;
    let vault_count = component_chunk_count(request.encrypted_vault_bundle.len())?;
    let approved_count = component_chunk_count(request.approved_workspace_bundle.len())?;
    let work_products_count = component_chunk_count(request.work_products_bundle.len())?;
    let total_count = [
        user_count,
        privacy_count,
        vault_count,
        approved_count,
        work_products_count,
    ]
    .into_iter()
    .try_fold(0_u32, |total, value| total.checked_add(value))
    .ok_or(ApplicationBackupError::TooLarge)?;
    let user_sha256 = sha256_hex(request.user_database);
    let privacy_sha256 = sha256_hex(request.encrypted_privacy_bundle);
    let vault_sha256 = sha256_hex(request.encrypted_vault_bundle);
    let approved_sha256 = sha256_hex(request.approved_workspace_bundle);
    let work_products_sha256 = sha256_hex(request.work_products_bundle);
    let key = SecretKey32::generate().map_err(|_| ApplicationBackupError::Crypto)?;
    let wrapped_key = wrap_case_key(&key).map_err(|_| ApplicationBackupError::Crypto)?;
    if wrapped_key.is_empty() || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES {
        return Err(ApplicationBackupError::Crypto);
    }
    let wrapped_key_sha256 = sha256_hex(&wrapped_key);
    let aad = application_aad_v3(
        request,
        &user_sha256,
        &privacy_sha256,
        &vault_sha256,
        &approved_sha256,
        &work_products_sha256,
        user_count,
        privacy_count,
        vault_count,
        approved_count,
        work_products_count,
        total_count,
        &wrapped_key_sha256,
    )?;
    let aad_sha256 = sha256_hex(&aad);
    let envelope = ApplicationBackupEnvelopeV3 {
        schema_version: APPLICATION_BACKUP_V3_SCHEMA_VERSION.to_owned(),
        crypto_suite: APPLICATION_BACKUP_V3_CRYPTO_SUITE.to_owned(),
        backup_id: request.backup_id.to_owned(),
        privacy_backup_id: request.privacy_backup_id.to_owned(),
        workspace_instance_id: request.workspace_instance_id.clone(),
        app_version: request.app_version.to_owned(),
        user_schema_version: request.user_schema_version,
        created_at_unix: request.created_at_unix,
        expires_at_unix: request.expires_at_unix,
        user_database_bytes: request.user_database.len() as u64,
        user_database_sha256: user_sha256,
        encrypted_privacy_bundle_bytes: request.encrypted_privacy_bundle.len() as u64,
        encrypted_privacy_bundle_sha256: privacy_sha256,
        encrypted_vault_bundle_bytes: request.encrypted_vault_bundle.len() as u64,
        encrypted_vault_bundle_sha256: vault_sha256,
        vault_manifest_sha256: request.vault_manifest_sha256.to_owned(),
        approved_workspace_bundle_bytes: request.approved_workspace_bundle.len() as u64,
        approved_workspace_bundle_sha256: approved_sha256,
        approved_workspace_manifest_sha256: request.approved_workspace_manifest_sha256.to_owned(),
        work_products_bundle_bytes: request.work_products_bundle.len() as u64,
        work_products_bundle_sha256: work_products_sha256,
        work_products_manifest_sha256: request.work_products_manifest_sha256.to_owned(),
        chunk_bytes: APPLICATION_BACKUP_CHUNK_BYTES as u32,
        user_database_chunk_count: user_count,
        privacy_bundle_chunk_count: privacy_count,
        vault_bundle_chunk_count: vault_count,
        approved_workspace_bundle_chunk_count: approved_count,
        work_products_bundle_chunk_count: work_products_count,
        chunk_count: total_count,
        wrapped_data_key_base64: BASE64_STANDARD.encode(&wrapped_key),
        wrapped_data_key_sha256: wrapped_key_sha256,
        aad_sha256,
        user_database_chunks: seal_component_v3(
            &key,
            &aad,
            USER_COMPONENT,
            request.user_database,
            user_count,
        )?,
        encrypted_privacy_bundle_chunks: seal_component_v3(
            &key,
            &aad,
            PRIVACY_COMPONENT,
            request.encrypted_privacy_bundle,
            privacy_count,
        )?,
        encrypted_vault_bundle_chunks: seal_component_v3(
            &key,
            &aad,
            VAULT_COMPONENT,
            request.encrypted_vault_bundle,
            vault_count,
        )?,
        approved_workspace_bundle_chunks: seal_component_v3(
            &key,
            &aad,
            APPROVED_WORKSPACE_COMPONENT,
            request.approved_workspace_bundle,
            approved_count,
        )?,
        work_products_bundle_chunks: seal_component_v3(
            &key,
            &aad,
            WORK_PRODUCTS_COMPONENT,
            request.work_products_bundle,
            work_products_count,
        )?,
    };
    let bytes = canonical_json_v1(&envelope).map_err(|_| ApplicationBackupError::InvalidInput)?;
    if bytes.is_empty() || bytes.len() > MAX_APPLICATION_BACKUP_BYTES {
        return Err(ApplicationBackupError::TooLarge);
    }
    let metadata = metadata_from_envelope_v3(&envelope, sha256_hex(&bytes))?;
    Ok((bytes, metadata))
}

pub fn open_application_backup(
    bytes: &[u8],
    context: &ApplicationBackupOpenContext<'_>,
) -> Result<OpenedApplicationBackup, ApplicationBackupError> {
    if bytes.is_empty() || bytes.len() > MAX_APPLICATION_BACKUP_BYTES {
        return Err(ApplicationBackupError::TooLarge);
    }
    validate_app_version(context.expected_app_version)?;
    if context.expected_user_schema_version <= 0 || context.now_unix == 0 {
        return Err(ApplicationBackupError::InvalidInput);
    }
    let probe: ApplicationBackupSchemaProbe =
        strict_json_v1_from_slice(bytes).map_err(|_| ApplicationBackupError::Tampered)?;
    if probe.schema_version == APPLICATION_BACKUP_V3_SCHEMA_VERSION {
        return open_application_backup_v3(bytes, context);
    }
    if probe.schema_version != APPLICATION_BACKUP_SCHEMA_VERSION {
        return Err(ApplicationBackupError::UnsupportedSchema);
    }
    let envelope: ApplicationBackupEnvelopeV2 =
        strict_json_v1_from_slice(bytes).map_err(|_| ApplicationBackupError::Tampered)?;
    validate_envelope_shape(&envelope)?;
    if envelope.crypto_suite != APPLICATION_BACKUP_CRYPTO_SUITE {
        return Err(ApplicationBackupError::UnsupportedSchema);
    }
    if envelope.workspace_instance_id != *context.expected_workspace_instance_id
        || envelope.app_version != context.expected_app_version
        || envelope.user_schema_version != context.expected_user_schema_version
    {
        return Err(ApplicationBackupError::EnvironmentMismatch);
    }
    if context.now_unix < envelope.created_at_unix || context.now_unix >= envelope.expires_at_unix {
        return Err(ApplicationBackupError::Expired);
    }
    let wrapped_key = BASE64_STANDARD
        .decode(envelope.wrapped_data_key_base64.as_bytes())
        .map_err(|_| ApplicationBackupError::Tampered)?;
    if wrapped_key.is_empty()
        || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES
        || sha256_hex(&wrapped_key) != envelope.wrapped_data_key_sha256
    {
        return Err(ApplicationBackupError::Tampered);
    }
    let aad = application_aad_from_envelope(&envelope)?;
    if sha256_hex(&aad) != envelope.aad_sha256 {
        return Err(ApplicationBackupError::Tampered);
    }
    let key = unwrap_case_key(&wrapped_key).map_err(|_| ApplicationBackupError::Crypto)?;
    let user_database = open_component(
        &key,
        &aad,
        USER_COMPONENT,
        &envelope.user_database_chunks,
        envelope.user_database_chunk_count,
        envelope.user_database_bytes,
        &envelope.user_database_sha256,
        MAX_USER_DATABASE_BACKUP_BYTES,
    )?;
    let privacy_bundle = open_component(
        &key,
        &aad,
        PRIVACY_COMPONENT,
        &envelope.encrypted_privacy_bundle_chunks,
        envelope.privacy_bundle_chunk_count,
        envelope.encrypted_privacy_bundle_bytes,
        &envelope.encrypted_privacy_bundle_sha256,
        MAX_PORTABLE_BACKUP_BYTES,
    )?;
    let vault_bundle = open_component(
        &key,
        &aad,
        VAULT_COMPONENT,
        &envelope.encrypted_vault_bundle_chunks,
        envelope.vault_bundle_chunk_count,
        envelope.encrypted_vault_bundle_bytes,
        &envelope.encrypted_vault_bundle_sha256,
        MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    )?;
    let metadata = metadata_from_envelope(&envelope, sha256_hex(bytes))?;
    Ok(OpenedApplicationBackup {
        metadata,
        user_database: user_database.into_inner(),
        encrypted_privacy_bundle: privacy_bundle.into_inner(),
        encrypted_vault_bundle: vault_bundle.into_inner(),
        approved_workspace_bundle: None,
        work_products_bundle: None,
    })
}

fn open_application_backup_v3(
    bytes: &[u8],
    context: &ApplicationBackupOpenContext<'_>,
) -> Result<OpenedApplicationBackup, ApplicationBackupError> {
    let envelope: ApplicationBackupEnvelopeV3 =
        strict_json_v1_from_slice(bytes).map_err(|_| ApplicationBackupError::Tampered)?;
    validate_envelope_v3_shape(&envelope)?;
    if envelope.crypto_suite != APPLICATION_BACKUP_V3_CRYPTO_SUITE {
        return Err(ApplicationBackupError::UnsupportedSchema);
    }
    if envelope.workspace_instance_id != *context.expected_workspace_instance_id
        || envelope.app_version != context.expected_app_version
        || envelope.user_schema_version != context.expected_user_schema_version
    {
        return Err(ApplicationBackupError::EnvironmentMismatch);
    }
    if context.now_unix < envelope.created_at_unix || context.now_unix >= envelope.expires_at_unix {
        return Err(ApplicationBackupError::Expired);
    }
    let wrapped_key = BASE64_STANDARD
        .decode(envelope.wrapped_data_key_base64.as_bytes())
        .map_err(|_| ApplicationBackupError::Tampered)?;
    if wrapped_key.is_empty()
        || wrapped_key.len() > MAX_WRAPPED_KEY_BYTES
        || sha256_hex(&wrapped_key) != envelope.wrapped_data_key_sha256
    {
        return Err(ApplicationBackupError::Tampered);
    }
    let aad = application_aad_v3_from_envelope(&envelope)?;
    if sha256_hex(&aad) != envelope.aad_sha256 {
        return Err(ApplicationBackupError::Tampered);
    }
    let key = unwrap_case_key(&wrapped_key).map_err(|_| ApplicationBackupError::Crypto)?;
    let user_database = open_component_v3(
        &key,
        &aad,
        USER_COMPONENT,
        &envelope.user_database_chunks,
        envelope.user_database_chunk_count,
        envelope.user_database_bytes,
        &envelope.user_database_sha256,
        MAX_USER_DATABASE_BACKUP_BYTES,
    )?;
    let privacy_bundle = open_component_v3(
        &key,
        &aad,
        PRIVACY_COMPONENT,
        &envelope.encrypted_privacy_bundle_chunks,
        envelope.privacy_bundle_chunk_count,
        envelope.encrypted_privacy_bundle_bytes,
        &envelope.encrypted_privacy_bundle_sha256,
        MAX_PORTABLE_BACKUP_BYTES,
    )?;
    let vault_bundle = open_component_v3(
        &key,
        &aad,
        VAULT_COMPONENT,
        &envelope.encrypted_vault_bundle_chunks,
        envelope.vault_bundle_chunk_count,
        envelope.encrypted_vault_bundle_bytes,
        &envelope.encrypted_vault_bundle_sha256,
        MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    )?;
    let approved_workspace = open_component_v3(
        &key,
        &aad,
        APPROVED_WORKSPACE_COMPONENT,
        &envelope.approved_workspace_bundle_chunks,
        envelope.approved_workspace_bundle_chunk_count,
        envelope.approved_workspace_bundle_bytes,
        &envelope.approved_workspace_bundle_sha256,
        MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
    )?;
    let work_products = open_component_v3(
        &key,
        &aad,
        WORK_PRODUCTS_COMPONENT,
        &envelope.work_products_bundle_chunks,
        envelope.work_products_bundle_chunk_count,
        envelope.work_products_bundle_bytes,
        &envelope.work_products_bundle_sha256,
        MAX_WORK_PRODUCTS_BACKUP_BYTES,
    )?;
    Ok(OpenedApplicationBackup {
        metadata: metadata_from_envelope_v3(&envelope, sha256_hex(bytes))?,
        user_database: user_database.into_inner(),
        encrypted_privacy_bundle: privacy_bundle.into_inner(),
        encrypted_vault_bundle: vault_bundle.into_inner(),
        approved_workspace_bundle: Some(approved_workspace.into_inner()),
        work_products_bundle: Some(work_products.into_inner()),
    })
}

fn seal_component(
    key: &SecretKey32,
    base_aad: &[u8],
    component: &str,
    plaintext: &[u8],
    chunk_count: u32,
) -> Result<Vec<EncryptedChunkV2>, ApplicationBackupError> {
    let mut chunks = Vec::with_capacity(chunk_count as usize);
    for (index, plaintext) in plaintext.chunks(APPLICATION_BACKUP_CHUNK_BYTES).enumerate() {
        let index = u32::try_from(index).map_err(|_| ApplicationBackupError::TooLarge)?;
        let aad = component_chunk_aad(base_aad, component, index, chunk_count)?;
        let sealed = seal(key, plaintext, &aad).map_err(|_| ApplicationBackupError::Crypto)?;
        chunks.push(EncryptedChunkV2 {
            index,
            plaintext_bytes: u32::try_from(plaintext.len())
                .map_err(|_| ApplicationBackupError::TooLarge)?,
            plaintext_sha256: sha256_hex(plaintext),
            nonce_base64: BASE64_STANDARD.encode(sealed.nonce()),
            ciphertext_base64: BASE64_STANDARD.encode(sealed.ciphertext()),
            ciphertext_sha256: sha256_hex(sealed.ciphertext()),
            tag_base64: BASE64_STANDARD.encode(sealed.tag()),
        });
    }
    if chunks.len() as u32 != chunk_count {
        return Err(ApplicationBackupError::InvalidInput);
    }
    Ok(chunks)
}

fn seal_component_v3(
    key: &SecretKey32,
    base_aad: &[u8],
    component: &str,
    plaintext: &[u8],
    chunk_count: u32,
) -> Result<Vec<EncryptedChunkV2>, ApplicationBackupError> {
    let mut chunks = Vec::with_capacity(chunk_count as usize);
    for (index, plaintext) in plaintext.chunks(APPLICATION_BACKUP_CHUNK_BYTES).enumerate() {
        let index = u32::try_from(index).map_err(|_| ApplicationBackupError::TooLarge)?;
        let aad = component_chunk_aad_v3(base_aad, component, index, chunk_count)?;
        let sealed = seal(key, plaintext, &aad).map_err(|_| ApplicationBackupError::Crypto)?;
        chunks.push(EncryptedChunkV2 {
            index,
            plaintext_bytes: u32::try_from(plaintext.len())
                .map_err(|_| ApplicationBackupError::TooLarge)?,
            plaintext_sha256: sha256_hex(plaintext),
            nonce_base64: BASE64_STANDARD.encode(sealed.nonce()),
            ciphertext_base64: BASE64_STANDARD.encode(sealed.ciphertext()),
            ciphertext_sha256: sha256_hex(sealed.ciphertext()),
            tag_base64: BASE64_STANDARD.encode(sealed.tag()),
        });
    }
    if chunks.len() as u32 != chunk_count {
        return Err(ApplicationBackupError::InvalidInput);
    }
    Ok(chunks)
}

#[allow(clippy::too_many_arguments)]
fn open_component(
    key: &SecretKey32,
    base_aad: &[u8],
    component: &str,
    chunks: &[EncryptedChunkV2],
    chunk_count: u32,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_bytes: usize,
) -> Result<ZeroizingAccumulator, ApplicationBackupError> {
    let capacity = usize::try_from(expected_bytes).map_err(|_| ApplicationBackupError::TooLarge)?;
    if capacity == 0 || capacity > maximum_bytes || chunks.len() as u32 != chunk_count {
        return Err(ApplicationBackupError::Tampered);
    }
    let mut output = ZeroizingAccumulator::with_capacity(capacity);
    for (position, chunk) in chunks.iter().enumerate() {
        let expected_index =
            u32::try_from(position).map_err(|_| ApplicationBackupError::TooLarge)?;
        if chunk.index != expected_index
            || chunk.plaintext_bytes == 0
            || chunk.plaintext_bytes as usize > APPLICATION_BACKUP_CHUNK_BYTES
            || !is_hash(&chunk.plaintext_sha256)
            || !is_hash(&chunk.ciphertext_sha256)
        {
            return Err(ApplicationBackupError::Tampered);
        }
        let nonce = BASE64_STANDARD
            .decode(chunk.nonce_base64.as_bytes())
            .map_err(|_| ApplicationBackupError::Tampered)?;
        let ciphertext = BASE64_STANDARD
            .decode(chunk.ciphertext_base64.as_bytes())
            .map_err(|_| ApplicationBackupError::Tampered)?;
        let tag = BASE64_STANDARD
            .decode(chunk.tag_base64.as_bytes())
            .map_err(|_| ApplicationBackupError::Tampered)?;
        if ciphertext.len() != chunk.plaintext_bytes as usize
            || sha256_hex(&ciphertext) != chunk.ciphertext_sha256
        {
            return Err(ApplicationBackupError::Tampered);
        }
        let sealed = AeadSealedV1::from_parts(&nonce, ciphertext, &tag)
            .map_err(|_| ApplicationBackupError::Tampered)?;
        let aad = component_chunk_aad(base_aad, component, chunk.index, chunk_count)?;
        let mut plaintext =
            open(key, &sealed, &aad).map_err(|_| ApplicationBackupError::Tampered)?;
        if plaintext.len() != chunk.plaintext_bytes as usize
            || sha256_hex(&plaintext) != chunk.plaintext_sha256
        {
            zeroize(&mut plaintext);
            return Err(ApplicationBackupError::Tampered);
        }
        output.extend_from_slice(&plaintext);
        zeroize(&mut plaintext);
        if output.len() > maximum_bytes {
            return Err(ApplicationBackupError::TooLarge);
        }
    }
    if output.len() as u64 != expected_bytes || sha256_hex(&output) != expected_sha256 {
        return Err(ApplicationBackupError::Tampered);
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn open_component_v3(
    key: &SecretKey32,
    base_aad: &[u8],
    component: &str,
    chunks: &[EncryptedChunkV2],
    chunk_count: u32,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_bytes: usize,
) -> Result<ZeroizingAccumulator, ApplicationBackupError> {
    let capacity = usize::try_from(expected_bytes).map_err(|_| ApplicationBackupError::TooLarge)?;
    if capacity == 0 || capacity > maximum_bytes || chunks.len() as u32 != chunk_count {
        return Err(ApplicationBackupError::Tampered);
    }
    let mut output = ZeroizingAccumulator::with_capacity(capacity);
    for (position, chunk) in chunks.iter().enumerate() {
        let expected_index =
            u32::try_from(position).map_err(|_| ApplicationBackupError::TooLarge)?;
        if chunk.index != expected_index
            || chunk.plaintext_bytes == 0
            || chunk.plaintext_bytes as usize > APPLICATION_BACKUP_CHUNK_BYTES
            || !is_hash(&chunk.plaintext_sha256)
            || !is_hash(&chunk.ciphertext_sha256)
        {
            return Err(ApplicationBackupError::Tampered);
        }
        let nonce = BASE64_STANDARD
            .decode(chunk.nonce_base64.as_bytes())
            .map_err(|_| ApplicationBackupError::Tampered)?;
        let ciphertext = BASE64_STANDARD
            .decode(chunk.ciphertext_base64.as_bytes())
            .map_err(|_| ApplicationBackupError::Tampered)?;
        let tag = BASE64_STANDARD
            .decode(chunk.tag_base64.as_bytes())
            .map_err(|_| ApplicationBackupError::Tampered)?;
        if ciphertext.len() != chunk.plaintext_bytes as usize
            || sha256_hex(&ciphertext) != chunk.ciphertext_sha256
        {
            return Err(ApplicationBackupError::Tampered);
        }
        let sealed = AeadSealedV1::from_parts(&nonce, ciphertext, &tag)
            .map_err(|_| ApplicationBackupError::Tampered)?;
        let aad = component_chunk_aad_v3(base_aad, component, chunk.index, chunk_count)?;
        let mut plaintext =
            open(key, &sealed, &aad).map_err(|_| ApplicationBackupError::Tampered)?;
        if plaintext.len() != chunk.plaintext_bytes as usize
            || sha256_hex(&plaintext) != chunk.plaintext_sha256
        {
            zeroize(&mut plaintext);
            return Err(ApplicationBackupError::Tampered);
        }
        output.extend_from_slice(&plaintext);
        zeroize(&mut plaintext);
        if output.len() > maximum_bytes {
            return Err(ApplicationBackupError::TooLarge);
        }
    }
    if output.len() as u64 != expected_bytes || sha256_hex(&output) != expected_sha256 {
        return Err(ApplicationBackupError::Tampered);
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn application_aad(
    request: &ApplicationBackupCreateRequest<'_>,
    user_hash: &str,
    privacy_hash: &str,
    vault_hash: &str,
    user_count: u32,
    privacy_count: u32,
    vault_count: u32,
    total_count: u32,
    wrapped_key_hash: &str,
) -> Result<Vec<u8>, ApplicationBackupError> {
    canonical_json_v1(&ApplicationBackupAadV2 {
        aad_schema_version: AAD_SCHEMA_VERSION,
        schema_version: APPLICATION_BACKUP_SCHEMA_VERSION,
        crypto_suite: APPLICATION_BACKUP_CRYPTO_SUITE,
        backup_id: request.backup_id,
        privacy_backup_id: request.privacy_backup_id,
        workspace_instance_id: request.workspace_instance_id,
        app_version: request.app_version,
        user_schema_version: request.user_schema_version,
        created_at_unix: request.created_at_unix,
        expires_at_unix: request.expires_at_unix,
        user_database_bytes: request.user_database.len() as u64,
        user_database_sha256: user_hash,
        encrypted_privacy_bundle_bytes: request.encrypted_privacy_bundle.len() as u64,
        encrypted_privacy_bundle_sha256: privacy_hash,
        encrypted_vault_bundle_bytes: request.encrypted_vault_bundle.len() as u64,
        encrypted_vault_bundle_sha256: vault_hash,
        vault_manifest_sha256: request.vault_manifest_sha256,
        chunk_bytes: APPLICATION_BACKUP_CHUNK_BYTES as u32,
        user_database_chunk_count: user_count,
        privacy_bundle_chunk_count: privacy_count,
        vault_bundle_chunk_count: vault_count,
        chunk_count: total_count,
        wrapped_data_key_sha256: wrapped_key_hash,
    })
    .map_err(|_| ApplicationBackupError::InvalidInput)
}

fn application_aad_from_envelope(
    envelope: &ApplicationBackupEnvelopeV2,
) -> Result<Vec<u8>, ApplicationBackupError> {
    canonical_json_v1(&ApplicationBackupAadV2 {
        aad_schema_version: AAD_SCHEMA_VERSION,
        schema_version: APPLICATION_BACKUP_SCHEMA_VERSION,
        crypto_suite: APPLICATION_BACKUP_CRYPTO_SUITE,
        backup_id: &envelope.backup_id,
        privacy_backup_id: &envelope.privacy_backup_id,
        workspace_instance_id: &envelope.workspace_instance_id,
        app_version: &envelope.app_version,
        user_schema_version: envelope.user_schema_version,
        created_at_unix: envelope.created_at_unix,
        expires_at_unix: envelope.expires_at_unix,
        user_database_bytes: envelope.user_database_bytes,
        user_database_sha256: &envelope.user_database_sha256,
        encrypted_privacy_bundle_bytes: envelope.encrypted_privacy_bundle_bytes,
        encrypted_privacy_bundle_sha256: &envelope.encrypted_privacy_bundle_sha256,
        encrypted_vault_bundle_bytes: envelope.encrypted_vault_bundle_bytes,
        encrypted_vault_bundle_sha256: &envelope.encrypted_vault_bundle_sha256,
        vault_manifest_sha256: &envelope.vault_manifest_sha256,
        chunk_bytes: envelope.chunk_bytes,
        user_database_chunk_count: envelope.user_database_chunk_count,
        privacy_bundle_chunk_count: envelope.privacy_bundle_chunk_count,
        vault_bundle_chunk_count: envelope.vault_bundle_chunk_count,
        chunk_count: envelope.chunk_count,
        wrapped_data_key_sha256: &envelope.wrapped_data_key_sha256,
    })
    .map_err(|_| ApplicationBackupError::Tampered)
}

#[allow(clippy::too_many_arguments)]
fn application_aad_v3(
    request: &ApplicationBackupCreateRequestV3<'_>,
    user_hash: &str,
    privacy_hash: &str,
    vault_hash: &str,
    approved_hash: &str,
    work_products_hash: &str,
    user_count: u32,
    privacy_count: u32,
    vault_count: u32,
    approved_count: u32,
    work_products_count: u32,
    total_count: u32,
    wrapped_key_hash: &str,
) -> Result<Vec<u8>, ApplicationBackupError> {
    canonical_json_v1(&ApplicationBackupAadV3 {
        aad_schema_version: AAD_V3_SCHEMA_VERSION,
        schema_version: APPLICATION_BACKUP_V3_SCHEMA_VERSION,
        crypto_suite: APPLICATION_BACKUP_V3_CRYPTO_SUITE,
        backup_id: request.backup_id,
        privacy_backup_id: request.privacy_backup_id,
        workspace_instance_id: request.workspace_instance_id,
        app_version: request.app_version,
        user_schema_version: request.user_schema_version,
        created_at_unix: request.created_at_unix,
        expires_at_unix: request.expires_at_unix,
        user_database_bytes: request.user_database.len() as u64,
        user_database_sha256: user_hash,
        encrypted_privacy_bundle_bytes: request.encrypted_privacy_bundle.len() as u64,
        encrypted_privacy_bundle_sha256: privacy_hash,
        encrypted_vault_bundle_bytes: request.encrypted_vault_bundle.len() as u64,
        encrypted_vault_bundle_sha256: vault_hash,
        vault_manifest_sha256: request.vault_manifest_sha256,
        approved_workspace_bundle_bytes: request.approved_workspace_bundle.len() as u64,
        approved_workspace_bundle_sha256: approved_hash,
        approved_workspace_manifest_sha256: request.approved_workspace_manifest_sha256,
        work_products_bundle_bytes: request.work_products_bundle.len() as u64,
        work_products_bundle_sha256: work_products_hash,
        work_products_manifest_sha256: request.work_products_manifest_sha256,
        chunk_bytes: APPLICATION_BACKUP_CHUNK_BYTES as u32,
        user_database_chunk_count: user_count,
        privacy_bundle_chunk_count: privacy_count,
        vault_bundle_chunk_count: vault_count,
        approved_workspace_bundle_chunk_count: approved_count,
        work_products_bundle_chunk_count: work_products_count,
        chunk_count: total_count,
        wrapped_data_key_sha256: wrapped_key_hash,
    })
    .map_err(|_| ApplicationBackupError::InvalidInput)
}

fn application_aad_v3_from_envelope(
    envelope: &ApplicationBackupEnvelopeV3,
) -> Result<Vec<u8>, ApplicationBackupError> {
    canonical_json_v1(&ApplicationBackupAadV3 {
        aad_schema_version: AAD_V3_SCHEMA_VERSION,
        schema_version: APPLICATION_BACKUP_V3_SCHEMA_VERSION,
        crypto_suite: APPLICATION_BACKUP_V3_CRYPTO_SUITE,
        backup_id: &envelope.backup_id,
        privacy_backup_id: &envelope.privacy_backup_id,
        workspace_instance_id: &envelope.workspace_instance_id,
        app_version: &envelope.app_version,
        user_schema_version: envelope.user_schema_version,
        created_at_unix: envelope.created_at_unix,
        expires_at_unix: envelope.expires_at_unix,
        user_database_bytes: envelope.user_database_bytes,
        user_database_sha256: &envelope.user_database_sha256,
        encrypted_privacy_bundle_bytes: envelope.encrypted_privacy_bundle_bytes,
        encrypted_privacy_bundle_sha256: &envelope.encrypted_privacy_bundle_sha256,
        encrypted_vault_bundle_bytes: envelope.encrypted_vault_bundle_bytes,
        encrypted_vault_bundle_sha256: &envelope.encrypted_vault_bundle_sha256,
        vault_manifest_sha256: &envelope.vault_manifest_sha256,
        approved_workspace_bundle_bytes: envelope.approved_workspace_bundle_bytes,
        approved_workspace_bundle_sha256: &envelope.approved_workspace_bundle_sha256,
        approved_workspace_manifest_sha256: &envelope.approved_workspace_manifest_sha256,
        work_products_bundle_bytes: envelope.work_products_bundle_bytes,
        work_products_bundle_sha256: &envelope.work_products_bundle_sha256,
        work_products_manifest_sha256: &envelope.work_products_manifest_sha256,
        chunk_bytes: envelope.chunk_bytes,
        user_database_chunk_count: envelope.user_database_chunk_count,
        privacy_bundle_chunk_count: envelope.privacy_bundle_chunk_count,
        vault_bundle_chunk_count: envelope.vault_bundle_chunk_count,
        approved_workspace_bundle_chunk_count: envelope.approved_workspace_bundle_chunk_count,
        work_products_bundle_chunk_count: envelope.work_products_bundle_chunk_count,
        chunk_count: envelope.chunk_count,
        wrapped_data_key_sha256: &envelope.wrapped_data_key_sha256,
    })
    .map_err(|_| ApplicationBackupError::Tampered)
}

fn component_chunk_aad(
    base: &[u8],
    component: &str,
    index: u32,
    count: u32,
) -> Result<Vec<u8>, ApplicationBackupError> {
    if !matches!(
        component,
        USER_COMPONENT | PRIVACY_COMPONENT | VAULT_COMPONENT
    ) || count == 0
        || index >= count
    {
        return Err(ApplicationBackupError::InvalidInput);
    }
    let suffix = format!("\0application-backup-component-chunk-v2\0{component}\0{index}\0{count}");
    let mut aad = Vec::with_capacity(base.len().saturating_add(suffix.len()));
    aad.extend_from_slice(base);
    aad.extend_from_slice(suffix.as_bytes());
    if aad.len() > 64 * 1024 {
        return Err(ApplicationBackupError::InvalidInput);
    }
    Ok(aad)
}

fn component_chunk_aad_v3(
    base: &[u8],
    component: &str,
    index: u32,
    count: u32,
) -> Result<Vec<u8>, ApplicationBackupError> {
    if !matches!(
        component,
        USER_COMPONENT
            | PRIVACY_COMPONENT
            | VAULT_COMPONENT
            | APPROVED_WORKSPACE_COMPONENT
            | WORK_PRODUCTS_COMPONENT
    ) || count == 0
        || index >= count
    {
        return Err(ApplicationBackupError::InvalidInput);
    }
    let suffix = format!("\0application-backup-component-chunk-v3\0{component}\0{index}\0{count}");
    let mut aad = Vec::with_capacity(base.len().saturating_add(suffix.len()));
    aad.extend_from_slice(base);
    aad.extend_from_slice(suffix.as_bytes());
    if aad.len() > 64 * 1024 {
        return Err(ApplicationBackupError::InvalidInput);
    }
    Ok(aad)
}

fn validate_envelope_shape(
    envelope: &ApplicationBackupEnvelopeV2,
) -> Result<(), ApplicationBackupError> {
    validate_backup_id(&envelope.backup_id)?;
    validate_privacy_backup_id(&envelope.privacy_backup_id)?;
    validate_app_version(&envelope.app_version)?;
    let expected_user =
        expected_count(envelope.user_database_bytes, MAX_USER_DATABASE_BACKUP_BYTES)?;
    let expected_privacy = expected_count(
        envelope.encrypted_privacy_bundle_bytes,
        MAX_PORTABLE_BACKUP_BYTES,
    )?;
    let expected_vault = expected_count(
        envelope.encrypted_vault_bundle_bytes,
        MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    )?;
    let expected_total = expected_user
        .checked_add(expected_privacy)
        .and_then(|value| value.checked_add(expected_vault))
        .ok_or(ApplicationBackupError::TooLarge)?;
    if envelope.schema_version != APPLICATION_BACKUP_SCHEMA_VERSION
        || envelope.user_schema_version <= 0
        || envelope.created_at_unix == 0
        || envelope.expires_at_unix <= envelope.created_at_unix
        || envelope.chunk_bytes != APPLICATION_BACKUP_CHUNK_BYTES as u32
        || envelope.user_database_chunk_count != expected_user
        || envelope.privacy_bundle_chunk_count != expected_privacy
        || envelope.vault_bundle_chunk_count != expected_vault
        || envelope.chunk_count != expected_total
        || envelope.user_database_chunks.len() as u32 != expected_user
        || envelope.encrypted_privacy_bundle_chunks.len() as u32 != expected_privacy
        || envelope.encrypted_vault_bundle_chunks.len() as u32 != expected_vault
        || !is_hash(&envelope.user_database_sha256)
        || !is_hash(&envelope.encrypted_privacy_bundle_sha256)
        || !is_hash(&envelope.encrypted_vault_bundle_sha256)
        || !is_hash(&envelope.vault_manifest_sha256)
        || !is_hash(&envelope.wrapped_data_key_sha256)
        || !is_hash(&envelope.aad_sha256)
        || envelope.wrapped_data_key_base64.is_empty()
        || envelope.wrapped_data_key_base64.len() > MAX_WRAPPED_KEY_BYTES * 2
    {
        return Err(ApplicationBackupError::Tampered);
    }
    validate_chunk_shape(&envelope.user_database_chunks)?;
    validate_chunk_shape(&envelope.encrypted_privacy_bundle_chunks)?;
    validate_chunk_shape(&envelope.encrypted_vault_bundle_chunks)
}

fn validate_envelope_v3_shape(
    envelope: &ApplicationBackupEnvelopeV3,
) -> Result<(), ApplicationBackupError> {
    validate_backup_id(&envelope.backup_id)?;
    validate_privacy_backup_id(&envelope.privacy_backup_id)?;
    validate_app_version(&envelope.app_version)?;
    let expected_user =
        expected_count(envelope.user_database_bytes, MAX_USER_DATABASE_BACKUP_BYTES)?;
    let expected_privacy = expected_count(
        envelope.encrypted_privacy_bundle_bytes,
        MAX_PORTABLE_BACKUP_BYTES,
    )?;
    let expected_vault = expected_count(
        envelope.encrypted_vault_bundle_bytes,
        MAX_ENCRYPTED_VAULT_BACKUP_BYTES,
    )?;
    let expected_approved = expected_count(
        envelope.approved_workspace_bundle_bytes,
        MAX_APPROVED_WORKSPACE_BACKUP_BYTES,
    )?;
    let expected_work_products = expected_count(
        envelope.work_products_bundle_bytes,
        MAX_WORK_PRODUCTS_BACKUP_BYTES,
    )?;
    let expected_total = [
        expected_user,
        expected_privacy,
        expected_vault,
        expected_approved,
        expected_work_products,
    ]
    .into_iter()
    .try_fold(0_u32, |total, value| total.checked_add(value))
    .ok_or(ApplicationBackupError::TooLarge)?;
    if envelope.schema_version != APPLICATION_BACKUP_V3_SCHEMA_VERSION
        || envelope.user_schema_version <= 0
        || envelope.created_at_unix == 0
        || envelope.expires_at_unix <= envelope.created_at_unix
        || envelope.chunk_bytes != APPLICATION_BACKUP_CHUNK_BYTES as u32
        || envelope.user_database_chunk_count != expected_user
        || envelope.privacy_bundle_chunk_count != expected_privacy
        || envelope.vault_bundle_chunk_count != expected_vault
        || envelope.approved_workspace_bundle_chunk_count != expected_approved
        || envelope.work_products_bundle_chunk_count != expected_work_products
        || envelope.chunk_count != expected_total
        || envelope.user_database_chunks.len() as u32 != expected_user
        || envelope.encrypted_privacy_bundle_chunks.len() as u32 != expected_privacy
        || envelope.encrypted_vault_bundle_chunks.len() as u32 != expected_vault
        || envelope.approved_workspace_bundle_chunks.len() as u32 != expected_approved
        || envelope.work_products_bundle_chunks.len() as u32 != expected_work_products
        || !is_hash(&envelope.user_database_sha256)
        || !is_hash(&envelope.encrypted_privacy_bundle_sha256)
        || !is_hash(&envelope.encrypted_vault_bundle_sha256)
        || !is_hash(&envelope.vault_manifest_sha256)
        || !is_hash(&envelope.approved_workspace_bundle_sha256)
        || !is_hash(&envelope.approved_workspace_manifest_sha256)
        || !is_hash(&envelope.work_products_bundle_sha256)
        || !is_hash(&envelope.work_products_manifest_sha256)
        || !is_hash(&envelope.wrapped_data_key_sha256)
        || !is_hash(&envelope.aad_sha256)
        || envelope.wrapped_data_key_base64.is_empty()
        || envelope.wrapped_data_key_base64.len() > MAX_WRAPPED_KEY_BYTES * 2
    {
        return Err(ApplicationBackupError::Tampered);
    }
    validate_chunk_shape(&envelope.user_database_chunks)?;
    validate_chunk_shape(&envelope.encrypted_privacy_bundle_chunks)?;
    validate_chunk_shape(&envelope.encrypted_vault_bundle_chunks)?;
    validate_chunk_shape(&envelope.approved_workspace_bundle_chunks)?;
    validate_chunk_shape(&envelope.work_products_bundle_chunks)
}

fn validate_chunk_shape(chunks: &[EncryptedChunkV2]) -> Result<(), ApplicationBackupError> {
    for (position, chunk) in chunks.iter().enumerate() {
        if chunk.index != position as u32
            || chunk.plaintext_bytes == 0
            || chunk.plaintext_bytes as usize > APPLICATION_BACKUP_CHUNK_BYTES
            || !is_hash(&chunk.plaintext_sha256)
            || !is_hash(&chunk.ciphertext_sha256)
            || chunk.nonce_base64.is_empty()
            || chunk.tag_base64.is_empty()
            || chunk.ciphertext_base64.is_empty()
        {
            return Err(ApplicationBackupError::Tampered);
        }
    }
    Ok(())
}

fn metadata_from_envelope(
    envelope: &ApplicationBackupEnvelopeV2,
    bundle_sha256: String,
) -> Result<ApplicationBackupMetadata, ApplicationBackupError> {
    if !is_hash(&bundle_sha256) {
        return Err(ApplicationBackupError::Tampered);
    }
    Ok(ApplicationBackupMetadata {
        backup_id: envelope.backup_id.clone(),
        privacy_backup_id: envelope.privacy_backup_id.clone(),
        workspace_instance_id: envelope.workspace_instance_id.clone(),
        app_version: envelope.app_version.clone(),
        user_schema_version: envelope.user_schema_version,
        created_at_unix: envelope.created_at_unix,
        expires_at_unix: envelope.expires_at_unix,
        user_database_bytes: envelope.user_database_bytes,
        user_database_sha256: envelope.user_database_sha256.clone(),
        encrypted_privacy_bundle_bytes: envelope.encrypted_privacy_bundle_bytes,
        encrypted_privacy_bundle_sha256: envelope.encrypted_privacy_bundle_sha256.clone(),
        encrypted_vault_bundle_bytes: envelope.encrypted_vault_bundle_bytes,
        encrypted_vault_bundle_sha256: envelope.encrypted_vault_bundle_sha256.clone(),
        vault_manifest_sha256: envelope.vault_manifest_sha256.clone(),
        user_database_chunk_count: envelope.user_database_chunk_count,
        privacy_bundle_chunk_count: envelope.privacy_bundle_chunk_count,
        vault_bundle_chunk_count: envelope.vault_bundle_chunk_count,
        approved_workspace_bundle_bytes: None,
        approved_workspace_bundle_sha256: None,
        approved_workspace_manifest_sha256: None,
        approved_workspace_bundle_chunk_count: None,
        work_products_bundle_bytes: None,
        work_products_bundle_sha256: None,
        work_products_manifest_sha256: None,
        work_products_bundle_chunk_count: None,
        chunk_count: envelope.chunk_count,
        bundle_sha256,
    })
}

fn metadata_from_envelope_v3(
    envelope: &ApplicationBackupEnvelopeV3,
    bundle_sha256: String,
) -> Result<ApplicationBackupMetadata, ApplicationBackupError> {
    if !is_hash(&bundle_sha256) {
        return Err(ApplicationBackupError::Tampered);
    }
    Ok(ApplicationBackupMetadata {
        backup_id: envelope.backup_id.clone(),
        privacy_backup_id: envelope.privacy_backup_id.clone(),
        workspace_instance_id: envelope.workspace_instance_id.clone(),
        app_version: envelope.app_version.clone(),
        user_schema_version: envelope.user_schema_version,
        created_at_unix: envelope.created_at_unix,
        expires_at_unix: envelope.expires_at_unix,
        user_database_bytes: envelope.user_database_bytes,
        user_database_sha256: envelope.user_database_sha256.clone(),
        encrypted_privacy_bundle_bytes: envelope.encrypted_privacy_bundle_bytes,
        encrypted_privacy_bundle_sha256: envelope.encrypted_privacy_bundle_sha256.clone(),
        encrypted_vault_bundle_bytes: envelope.encrypted_vault_bundle_bytes,
        encrypted_vault_bundle_sha256: envelope.encrypted_vault_bundle_sha256.clone(),
        vault_manifest_sha256: envelope.vault_manifest_sha256.clone(),
        user_database_chunk_count: envelope.user_database_chunk_count,
        privacy_bundle_chunk_count: envelope.privacy_bundle_chunk_count,
        vault_bundle_chunk_count: envelope.vault_bundle_chunk_count,
        approved_workspace_bundle_bytes: Some(envelope.approved_workspace_bundle_bytes),
        approved_workspace_bundle_sha256: Some(envelope.approved_workspace_bundle_sha256.clone()),
        approved_workspace_manifest_sha256: Some(
            envelope.approved_workspace_manifest_sha256.clone(),
        ),
        approved_workspace_bundle_chunk_count: Some(envelope.approved_workspace_bundle_chunk_count),
        work_products_bundle_bytes: Some(envelope.work_products_bundle_bytes),
        work_products_bundle_sha256: Some(envelope.work_products_bundle_sha256.clone()),
        work_products_manifest_sha256: Some(envelope.work_products_manifest_sha256.clone()),
        work_products_bundle_chunk_count: Some(envelope.work_products_bundle_chunk_count),
        chunk_count: envelope.chunk_count,
        bundle_sha256,
    })
}

fn component_chunk_count(bytes: usize) -> Result<u32, ApplicationBackupError> {
    if bytes == 0 {
        return Err(ApplicationBackupError::InvalidInput);
    }
    u32::try_from(bytes.div_ceil(APPLICATION_BACKUP_CHUNK_BYTES))
        .map_err(|_| ApplicationBackupError::TooLarge)
}

fn expected_count(bytes: u64, maximum: usize) -> Result<u32, ApplicationBackupError> {
    if bytes == 0 || bytes > maximum as u64 {
        return Err(ApplicationBackupError::Tampered);
    }
    let chunk_bytes = APPLICATION_BACKUP_CHUNK_BYTES as u64;
    u32::try_from(bytes.div_ceil(chunk_bytes)).map_err(|_| ApplicationBackupError::TooLarge)
}

fn validate_component_bound(bytes: &[u8], maximum: usize) -> Result<(), ApplicationBackupError> {
    if bytes.is_empty() {
        Err(ApplicationBackupError::InvalidInput)
    } else if bytes.len() > maximum {
        Err(ApplicationBackupError::TooLarge)
    } else {
        Ok(())
    }
}

fn validate_backup_id(value: &str) -> Result<(), ApplicationBackupError> {
    if value.len() <= "appbkp_".len()
        || value.len() > MAX_BACKUP_ID_BYTES
        || !value.starts_with("appbkp_")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(ApplicationBackupError::InvalidInput);
    }
    Ok(())
}

fn validate_privacy_backup_id(value: &str) -> Result<(), ApplicationBackupError> {
    if value.len() <= "bkp_".len()
        || value.len() > MAX_BACKUP_ID_BYTES
        || !value.starts_with("bkp_")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(ApplicationBackupError::InvalidInput);
    }
    Ok(())
}

fn validate_app_version(value: &str) -> Result<(), ApplicationBackupError> {
    if value.is_empty()
        || value.len() > MAX_APP_VERSION_BYTES
        || value.chars().any(char::is_control)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
    {
        return Err(ApplicationBackupError::InvalidInput);
    }
    Ok(())
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

    fn test_workspace(value: char) -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse(format!("ws_{}", value.to_string().repeat(32)))
            .expect("workspace")
    }

    fn request<'a>(
        workspace: &'a WorkspaceInstanceId,
        user_database: &'a [u8],
        privacy_bundle: &'a [u8],
        vault_bundle: &'a [u8],
        vault_manifest_sha256: &'a str,
    ) -> ApplicationBackupCreateRequest<'a> {
        ApplicationBackupCreateRequest {
            backup_id: "appbkp_11111111111111111111111111111111",
            privacy_backup_id: "bkp_22222222222222222222222222222222",
            workspace_instance_id: workspace,
            app_version: "0.4.0-beta.2",
            user_schema_version: 9,
            created_at_unix: 10_000,
            expires_at_unix: 20_000,
            user_database,
            encrypted_privacy_bundle: privacy_bundle,
            encrypted_vault_bundle: vault_bundle,
            vault_manifest_sha256,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn request_v3<'a>(
        workspace: &'a WorkspaceInstanceId,
        user_database: &'a [u8],
        privacy_bundle: &'a [u8],
        vault_bundle: &'a [u8],
        vault_manifest_sha256: &'a str,
        approved_workspace_bundle: &'a [u8],
        approved_workspace_manifest_sha256: &'a str,
        work_products_bundle: &'a [u8],
        work_products_manifest_sha256: &'a str,
    ) -> ApplicationBackupCreateRequestV3<'a> {
        ApplicationBackupCreateRequestV3 {
            backup_id: "appbkp_33333333333333333333333333333333",
            privacy_backup_id: "bkp_44444444444444444444444444444444",
            workspace_instance_id: workspace,
            app_version: "0.4.0-beta.2",
            user_schema_version: 9,
            created_at_unix: 10_000,
            expires_at_unix: 20_000,
            user_database,
            encrypted_privacy_bundle: privacy_bundle,
            encrypted_vault_bundle: vault_bundle,
            vault_manifest_sha256,
            approved_workspace_bundle,
            approved_workspace_manifest_sha256,
            work_products_bundle,
            work_products_manifest_sha256,
        }
    }

    #[test]
    fn three_component_round_trip_hides_all_components_and_rejects_drift() {
        let workspace = test_workspace('a');
        let user_database = b"SQLite format 3\0SYNTHETIC_USER_DATABASE_PRIVATE_CANARY";
        let privacy_bundle = b"SYNTHETIC_ENCRYPTED_PRIVACY_BUNDLE_CANARY";
        let vault_bundle = b"SYNTHETIC_ENCRYPTED_VAULT_ARCHIVE_CANARY";
        let manifest = sha256_hex(b"synthetic-vault-manifest");
        let request = request(
            &workspace,
            user_database,
            privacy_bundle,
            vault_bundle,
            &manifest,
        );
        let request_debug = format!("{request:?}");
        assert!(!request_debug.contains("CANARY"));
        let (bundle, metadata) = seal_application_backup(&request).expect("seal complete bundle");
        for needle in [
            b"SYNTHETIC_USER_DATABASE_PRIVATE_CANARY".as_slice(),
            privacy_bundle.as_slice(),
            vault_bundle.as_slice(),
        ] {
            assert!(!bundle.windows(needle.len()).any(|window| window == needle));
        }
        let context = ApplicationBackupOpenContext {
            expected_workspace_instance_id: &workspace,
            expected_app_version: "0.4.0-beta.2",
            expected_user_schema_version: 9,
            now_unix: 10_001,
        };
        let opened = open_application_backup(&bundle, &context).expect("open complete bundle");
        assert_eq!(opened.user_database, user_database);
        assert_eq!(opened.encrypted_privacy_bundle, privacy_bundle);
        assert_eq!(opened.encrypted_vault_bundle, vault_bundle);
        assert_eq!(opened.metadata, metadata);
        assert_eq!(opened.metadata.vault_manifest_sha256, manifest);
        assert_eq!(opened.metadata.chunk_count, 3);
        assert!(!format!("{opened:?}").contains("CANARY"));

        assert_eq!(
            open_application_backup(
                &bundle,
                &ApplicationBackupOpenContext {
                    expected_workspace_instance_id: &test_workspace('b'),
                    ..context.clone()
                }
            ),
            Err(ApplicationBackupError::EnvironmentMismatch)
        );
        assert_eq!(
            open_application_backup(
                &bundle,
                &ApplicationBackupOpenContext {
                    expected_app_version: "0.4.0-beta.3",
                    ..context.clone()
                }
            ),
            Err(ApplicationBackupError::EnvironmentMismatch)
        );
        assert_eq!(
            open_application_backup(
                &bundle,
                &ApplicationBackupOpenContext {
                    now_unix: 20_000,
                    ..context
                }
            ),
            Err(ApplicationBackupError::Expired)
        );
    }

    #[test]
    fn tamper_component_swap_and_v1_are_rejected_fail_closed() {
        let workspace = test_workspace('c');
        let manifest = sha256_hex(b"manifest");
        let (bundle, _) = seal_application_backup(&request(
            &workspace,
            b"SQLite format 3\0SYNTHETIC",
            b"SYNTHETIC_PRIVACY",
            b"SYNTHETIC_VAULT__",
            &manifest,
        ))
        .expect("seal");
        let context = ApplicationBackupOpenContext {
            expected_workspace_instance_id: &workspace,
            expected_app_version: "0.4.0-beta.2",
            expected_user_schema_version: 9,
            now_unix: 10_001,
        };
        let mut envelope: ApplicationBackupEnvelopeV2 =
            strict_json_v1_from_slice(&bundle).expect("strict envelope");
        std::mem::swap(
            &mut envelope.encrypted_privacy_bundle_chunks,
            &mut envelope.encrypted_vault_bundle_chunks,
        );
        let swapped = canonical_json_v1(&envelope).expect("canonical swapped");
        assert_eq!(
            open_application_backup(&swapped, &context),
            Err(ApplicationBackupError::Tampered)
        );

        let mut tampered = bundle;
        let middle = tampered.len() / 2;
        tampered[middle] ^= 1;
        assert!(open_application_backup(&tampered, &context).is_err());

        let v1 = br#"{"schemaVersion":"lawyer-assistance-backup-v1"}"#;
        assert_eq!(
            open_application_backup(v1, &context),
            Err(ApplicationBackupError::UnsupportedSchema)
        );
    }

    #[test]
    fn five_component_v3_round_trip_outer_encrypts_every_component() {
        let workspace = test_workspace('d');
        let user = b"SQLite format 3\0SYNTHETIC_V3_USER_DATABASE_CANARY";
        let privacy = b"SYNTHETIC_V3_PRIVACY_BUNDLE_CANARY";
        let vault = b"SYNTHETIC_V3_VAULT_BUNDLE_CANARY";
        let approved = b"SYNTHETIC_V3_APPROVED_GENERATIONS_CANARY";
        let work_products = b"SYNTHETIC_V3_ENCRYPTED_WORK_PRODUCTS_CANARY";
        let vault_manifest = sha256_hex(b"v3-vault-manifest");
        let approved_manifest = sha256_hex(b"v3-approved-manifest");
        let work_products_manifest = sha256_hex(b"v3-work-products-manifest");
        let request = request_v3(
            &workspace,
            user,
            privacy,
            vault,
            &vault_manifest,
            approved,
            &approved_manifest,
            work_products,
            &work_products_manifest,
        );
        assert!(!format!("{request:?}").contains("CANARY"));
        let (bundle, metadata) = seal_application_backup_v3(&request).expect("seal v3");
        for canary in [
            user.as_slice(),
            privacy.as_slice(),
            vault.as_slice(),
            approved.as_slice(),
            work_products.as_slice(),
        ] {
            assert!(!bundle.windows(canary.len()).any(|window| window == canary));
        }
        let opened = open_application_backup(
            &bundle,
            &ApplicationBackupOpenContext {
                expected_workspace_instance_id: &workspace,
                expected_app_version: "0.4.0-beta.2",
                expected_user_schema_version: 9,
                now_unix: 10_001,
            },
        )
        .expect("open v3");
        assert_eq!(opened.metadata, metadata);
        assert_eq!(opened.metadata.chunk_count, 5);
        assert_eq!(opened.user_database, user);
        assert_eq!(opened.encrypted_privacy_bundle, privacy);
        assert_eq!(opened.encrypted_vault_bundle, vault);
        assert_eq!(
            opened.approved_workspace_bundle.as_deref(),
            Some(approved.as_slice())
        );
        assert_eq!(
            opened.work_products_bundle.as_deref(),
            Some(work_products.as_slice())
        );
        assert_eq!(
            opened
                .metadata
                .approved_workspace_manifest_sha256
                .as_deref(),
            Some(approved_manifest.as_str())
        );
        assert_eq!(
            opened.metadata.work_products_manifest_sha256.as_deref(),
            Some(work_products_manifest.as_str())
        );
        assert!(!format!("{opened:?}").contains("CANARY"));
    }

    #[test]
    fn five_component_v3_rejects_component_swap_manifest_tamper_and_unknown_fields() {
        let workspace = test_workspace('e');
        let vault_manifest = sha256_hex(b"vault-manifest");
        let approved_manifest = sha256_hex(b"approved-manifest");
        let work_products_manifest = sha256_hex(b"work-products-manifest");
        let (bundle, _) = seal_application_backup_v3(&request_v3(
            &workspace,
            b"SQLite format 3\0SYNTHETIC-V3",
            b"SYNTHETIC_PRIVACY_V3",
            b"SYNTHETIC_VAULT___V3",
            &vault_manifest,
            b"SYNTHETIC_APPROVED_V3",
            &approved_manifest,
            b"SYNTHETIC_WORKPROD_V3",
            &work_products_manifest,
        ))
        .expect("seal v3");
        let context = ApplicationBackupOpenContext {
            expected_workspace_instance_id: &workspace,
            expected_app_version: "0.4.0-beta.2",
            expected_user_schema_version: 9,
            now_unix: 10_001,
        };

        let mut swapped: ApplicationBackupEnvelopeV3 =
            strict_json_v1_from_slice(&bundle).expect("v3 envelope");
        std::mem::swap(
            &mut swapped.approved_workspace_bundle_chunks,
            &mut swapped.work_products_bundle_chunks,
        );
        assert_eq!(
            open_application_backup(&canonical_json_v1(&swapped).expect("swapped"), &context),
            Err(ApplicationBackupError::Tampered)
        );

        let mut manifest_tamper: ApplicationBackupEnvelopeV3 =
            strict_json_v1_from_slice(&bundle).expect("v3 envelope");
        manifest_tamper.approved_workspace_manifest_sha256 = sha256_hex(b"other manifest");
        assert_eq!(
            open_application_backup(
                &canonical_json_v1(&manifest_tamper).expect("manifest tamper"),
                &context,
            ),
            Err(ApplicationBackupError::Tampered)
        );

        let mut unknown: serde_json::Value = serde_json::from_slice(&bundle).expect("json");
        unknown
            .as_object_mut()
            .expect("object")
            .insert("unexpectedSecretField".to_owned(), serde_json::json!(true));
        assert_eq!(
            open_application_backup(&serde_json::to_vec(&unknown).expect("unknown"), &context),
            Err(ApplicationBackupError::Tampered)
        );
    }

    #[test]
    fn v2_three_component_backup_remains_read_compatible() {
        let workspace = test_workspace('f');
        let manifest = sha256_hex(b"v2-manifest");
        let (bundle, metadata) = seal_application_backup(&request(
            &workspace,
            b"SQLite format 3\0V2",
            b"V2_PRIVACY",
            b"V2_VAULT",
            &manifest,
        ))
        .expect("seal v2");
        let opened = open_application_backup(
            &bundle,
            &ApplicationBackupOpenContext {
                expected_workspace_instance_id: &workspace,
                expected_app_version: "0.4.0-beta.2",
                expected_user_schema_version: 9,
                now_unix: 10_001,
            },
        )
        .expect("open v2 through current dispatcher");
        assert_eq!(opened.metadata, metadata);
        assert!(opened.approved_workspace_bundle.is_none());
        assert!(opened.work_products_bundle.is_none());
    }
}
