#![allow(unsafe_code)]

//! Migration-only v0.3.1 original-state rollback envelope.
//!
//! This wire format is deliberately independent from ordinary V2/V3 application
//! backups. It authenticates two self-contained SQLite images and three distinct
//! authenticated-absence sentinels with a fresh AES-256-GCM data key wrapped by
//! Windows DPAPI CurrentUser. The separately DPAPI-protected identity binds the
//! exact installed bundle without introducing an identity/bundle hash cycle.

use crate::{
    application_backup::MAX_USER_DATABASE_BACKUP_BYTES,
    lifecycle::max_backup_database_bytes_for_schema,
    protected_blob::{protect_local, unprotect_local},
    receipt::sha256_hex,
    vault_crypto::{
        open, seal, unwrap_case_key, wrap_case_key, AeadSealedV1, SecretKey32, GCM_NONCE_BYTES,
        GCM_TAG_BYTES,
    },
    vnext::{canonical_json_v1, strict_json_v1_from_slice},
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    sync::atomic::{compiler_fence, Ordering},
};

pub const V031_ORIGINAL_ROLLBACK_FORMAT_VERSION: u16 = 2;
pub const V031_ORIGINAL_ROLLBACK_IDENTITY_SCHEMA_VERSION: &str =
    "lawyer-assistance-v031-original-rollback-identity-v2";
pub const V031_ORIGINAL_ROLLBACK_ENVELOPE_SCHEMA_VERSION: &str =
    "lawyer-assistance-v031-original-rollback-envelope-v2";
pub const V031_ORIGINAL_ROLLBACK_AAD_SCHEMA_VERSION: &str =
    "lawyer-assistance-v031-original-rollback-aad-v2";
pub const V031_ORIGINAL_ROLLBACK_CRYPTO_SUITE: &str =
    "aes-256-gcm-five-slot-chunked-dpapi-current-user-v2";
pub const V031_ORIGINAL_ROLLBACK_MIGRATION_ID: &str = "v0.3.1-to-v0.4.0-user-schema-v1";
pub const V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION: &str = "0.4.0";
pub const V031_ORIGINAL_ROLLBACK_SOURCE_PROFILE: &str = "v0.3.1-exact";
pub const V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX: u64 = 253_402_300_799;
pub const V031_ORIGINAL_ROLLBACK_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const V031_ORIGINAL_ROLLBACK_IDENTITY_FILE_NAME: &str =
    "v031-original-rollback-v2.identity.dpapi";
pub const V031_ORIGINAL_ROLLBACK_IDENTITY_INCOMING_FILE_NAME: &str =
    "v031-original-rollback-v2.identity.dpapi.incoming";
pub const V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME: &str = "v031-original-rollback-v2.bundle";
pub const V031_ORIGINAL_ROLLBACK_BUNDLE_INCOMING_FILE_NAME: &str =
    "v031-original-rollback-v2.bundle.incoming";
pub const V031_ORIGINAL_ROLLBACK_USER_SNAPSHOT_INCOMING_FILE_NAME: &str =
    "user_database.snapshot.sqlite.incoming";
pub const V031_ORIGINAL_ROLLBACK_PRIVACY_SNAPSHOT_INCOMING_FILE_NAME: &str =
    "privacy_store.snapshot.sqlite.incoming";
pub const MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES: usize = 128 * 1024;
pub const MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES: usize = 1024 * 1024 * 1024;

const V031_USER_SCHEMA_VERSION: i64 = 10;
const V031_PRIVACY_SCHEMA_VERSION: i64 = 1;
const MAX_WRAPPED_DATA_KEY_BYTES: usize = 64 * 1024;
const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";
const SLOT_CHUNK_AAD_DOMAIN: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0slot-chunk-aad-v2\0";

pub const V031_VAULT_AUTHENTICATED_ABSENT_SENTINEL: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0vault_store\0";
pub const V031_APPROVED_WORKSPACE_AUTHENTICATED_ABSENT_SENTINEL: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0approved_workspace\0";
pub const V031_WORK_PRODUCTS_AUTHENTICATED_ABSENT_SENTINEL: &[u8] =
    b"lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0work_products\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V031OriginalRollbackError {
    InvalidInput,
    UnsupportedSchema,
    TooLarge,
    Crypto,
    Tampered,
    EnvironmentMismatch,
}

impl V031OriginalRollbackError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "v031_original_rollback_invalid_input",
            Self::UnsupportedSchema => "v031_original_rollback_schema_unsupported",
            Self::TooLarge => "v031_original_rollback_too_large",
            Self::Crypto => "v031_original_rollback_crypto_failed",
            Self::Tampered => "v031_original_rollback_tampered",
            Self::EnvironmentMismatch => "v031_original_rollback_environment_mismatch",
        }
    }
}

impl fmt::Display for V031OriginalRollbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for V031OriginalRollbackError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V031OriginalRollbackSlotName {
    UserDatabase,
    PrivacyStore,
    VaultStore,
    ApprovedWorkspace,
    WorkProducts,
}

impl V031OriginalRollbackSlotName {
    const fn as_str(self) -> &'static str {
        match self {
            Self::UserDatabase => "user_database",
            Self::PrivacyStore => "privacy_store",
            Self::VaultStore => "vault_store",
            Self::ApprovedWorkspace => "approved_workspace",
            Self::WorkProducts => "work_products",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V031OriginalRollbackPresence {
    Present,
    AuthenticatedAbsent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V031OriginalRollbackEncoding {
    RawSqlite,
    AuthenticatedAbsentSentinelV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V031OriginalRollbackSlotIdentityV2 {
    pub ordinal: u8,
    pub name: V031OriginalRollbackSlotName,
    pub presence: V031OriginalRollbackPresence,
    pub encoding: V031OriginalRollbackEncoding,
    pub source_schema_version: Option<i64>,
    pub plaintext_bytes: u64,
    pub plaintext_sha256: String,
    pub logical_manifest_sha256: Option<String>,
    pub business_manifest_sha256: Option<String>,
    pub chunk_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct V031OriginalRollbackIdentityV2 {
    pub schema_version: String,
    pub format_version: u16,
    pub migration_id: String,
    pub creator_app_version: String,
    pub source_profile: String,
    pub source_profile_proof_sha256: String,
    pub source_user_physical_file_set_sha256: String,
    pub source_privacy_physical_file_set_sha256: String,
    pub source_user_logical_manifest_sha256: String,
    pub source_user_business_manifest_sha256: String,
    pub source_privacy_logical_manifest_sha256: String,
    pub source_privacy_business_manifest_sha256: String,
    pub envelope_binding_id: String,
    pub lineage_id: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub bundle_file_name: String,
    pub bundle_bytes: u64,
    pub bundle_sha256: String,
    pub wrapped_data_key_sha256: String,
    pub chunk_bytes: u32,
    pub total_chunk_count: u32,
    pub slots: Vec<V031OriginalRollbackSlotIdentityV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V031OriginalRollbackMetadataV2 {
    pub source_profile_proof_sha256: String,
    pub source_user_physical_file_set_sha256: String,
    pub source_privacy_physical_file_set_sha256: String,
    pub source_user_logical_manifest_sha256: String,
    pub source_user_business_manifest_sha256: String,
    pub source_privacy_logical_manifest_sha256: String,
    pub source_privacy_business_manifest_sha256: String,
    pub envelope_binding_id: String,
    pub lineage_id: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub bundle_bytes: u64,
    pub bundle_sha256: String,
    pub wrapped_data_key_sha256: String,
    pub total_chunk_count: u32,
    pub slots: Vec<V031OriginalRollbackSlotIdentityV2>,
}

pub struct V031OriginalRollbackCreateRequest<'a> {
    pub source_profile_proof_sha256: &'a str,
    pub source_user_physical_file_set_sha256: &'a str,
    pub source_privacy_physical_file_set_sha256: &'a str,
    pub source_user_logical_manifest_sha256: &'a str,
    pub source_user_business_manifest_sha256: &'a str,
    pub source_privacy_logical_manifest_sha256: &'a str,
    pub source_privacy_business_manifest_sha256: &'a str,
    pub envelope_binding_id: &'a str,
    pub lineage_id: &'a str,
    pub created_at_unix: u64,
    pub user_database: &'a [u8],
    pub privacy_store: &'a [u8],
}

impl fmt::Debug for V031OriginalRollbackCreateRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031OriginalRollbackCreateRequest")
            .field(
                "source_profile_proof_sha256",
                &self.source_profile_proof_sha256,
            )
            .field("envelope_binding_id", &self.envelope_binding_id)
            .field("lineage_id", &self.lineage_id)
            .field("created_at_unix", &self.created_at_unix)
            .field(
                "user_database",
                &format_args!("[PROTECTED {} BYTES]", self.user_database.len()),
            )
            .field(
                "privacy_store",
                &format_args!("[PROTECTED {} BYTES]", self.privacy_store.len()),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct V031OriginalRollbackOpenContext<'a> {
    pub expected_source_profile_proof_sha256: &'a str,
    pub expected_source_user_physical_file_set_sha256: &'a str,
    pub expected_source_privacy_physical_file_set_sha256: &'a str,
    pub expected_source_user_logical_manifest_sha256: &'a str,
    pub expected_source_user_business_manifest_sha256: &'a str,
    pub expected_source_privacy_logical_manifest_sha256: &'a str,
    pub expected_source_privacy_business_manifest_sha256: &'a str,
    pub expected_envelope_binding_id: &'a str,
    pub expected_lineage_id: &'a str,
    pub expected_created_at_unix: u64,
    pub expected_bundle_sha256: &'a str,
}

#[derive(PartialEq, Eq)]
pub struct OpenedV031OriginalRollbackV2 {
    pub metadata: V031OriginalRollbackMetadataV2,
    pub user_database: Vec<u8>,
    pub privacy_store: Vec<u8>,
    pub authenticated_absent_slots: [V031OriginalRollbackSlotName; 3],
}

impl fmt::Debug for OpenedV031OriginalRollbackV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenedV031OriginalRollbackV2")
            .field("metadata", &self.metadata)
            .field(
                "user_database",
                &format_args!("[PROTECTED {} BYTES]", self.user_database.len()),
            )
            .field(
                "privacy_store",
                &format_args!("[PROTECTED {} BYTES]", self.privacy_store.len()),
            )
            .field(
                "authenticated_absent_slots",
                &self.authenticated_absent_slots,
            )
            .finish()
    }
}

impl Drop for OpenedV031OriginalRollbackV2 {
    fn drop(&mut self) {
        zeroize(&mut self.user_database);
        zeroize(&mut self.privacy_store);
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031OriginalRollbackEnvelopeV2 {
    schema_version: String,
    format_version: u16,
    crypto_suite: String,
    aad_schema_version: String,
    migration_id: String,
    creator_app_version: String,
    source_profile: String,
    source_profile_proof_sha256: String,
    source_user_physical_file_set_sha256: String,
    source_privacy_physical_file_set_sha256: String,
    source_user_logical_manifest_sha256: String,
    source_user_business_manifest_sha256: String,
    source_privacy_logical_manifest_sha256: String,
    source_privacy_business_manifest_sha256: String,
    envelope_binding_id: String,
    lineage_id: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    chunk_bytes: u32,
    total_chunk_count: u32,
    wrapped_data_key_base64: String,
    wrapped_data_key_sha256: String,
    slots: Vec<V031OriginalRollbackSlotIdentityV2>,
    slot_chunks: Vec<V031OriginalRollbackEncryptedChunkV2>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031OriginalRollbackAadV2<'a> {
    aad_schema_version: &'a str,
    schema_version: &'a str,
    format_version: u16,
    crypto_suite: &'a str,
    migration_id: &'a str,
    creator_app_version: &'a str,
    source_profile: &'a str,
    source_profile_proof_sha256: &'a str,
    source_user_physical_file_set_sha256: &'a str,
    source_privacy_physical_file_set_sha256: &'a str,
    source_user_logical_manifest_sha256: &'a str,
    source_user_business_manifest_sha256: &'a str,
    source_privacy_logical_manifest_sha256: &'a str,
    source_privacy_business_manifest_sha256: &'a str,
    envelope_binding_id: &'a str,
    lineage_id: &'a str,
    created_at_unix: u64,
    expires_at_unix: u64,
    chunk_bytes: u32,
    total_chunk_count: u32,
    wrapped_data_key_sha256: &'a str,
    slots: &'a [V031OriginalRollbackSlotIdentityV2],
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031OriginalRollbackEncryptedChunkV2 {
    slot_ordinal: u8,
    index: u32,
    plaintext_bytes: u32,
    plaintext_sha256: String,
    nonce_base64: String,
    ciphertext_base64: String,
    ciphertext_sha256: String,
    tag_base64: String,
}

struct SensitiveBytes(Vec<u8>);

impl SensitiveBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

pub fn seal_v031_original_rollback_v2(
    request: &V031OriginalRollbackCreateRequest<'_>,
) -> Result<(Vec<u8>, V031OriginalRollbackMetadataV2), V031OriginalRollbackError> {
    seal_v031_original_rollback_v2_with_absent_slots(
        request,
        [
            V031_VAULT_AUTHENTICATED_ABSENT_SENTINEL,
            V031_APPROVED_WORKSPACE_AUTHENTICATED_ABSENT_SENTINEL,
            V031_WORK_PRODUCTS_AUTHENTICATED_ABSENT_SENTINEL,
        ],
    )
}

fn seal_v031_original_rollback_v2_with_absent_slots(
    request: &V031OriginalRollbackCreateRequest<'_>,
    absent_slots: [&[u8]; 3],
) -> Result<(Vec<u8>, V031OriginalRollbackMetadataV2), V031OriginalRollbackError> {
    validate_create_request(request)?;
    let plaintexts = [
        request.user_database,
        request.privacy_store,
        absent_slots[0],
        absent_slots[1],
        absent_slots[2],
    ];
    let slots = build_slot_descriptors(request, &plaintexts)?;
    let total_chunk_count = slots.iter().try_fold(0_u32, |total, slot| {
        total
            .checked_add(slot.chunk_count)
            .ok_or(V031OriginalRollbackError::TooLarge)
    })?;

    let data_key = SecretKey32::generate().map_err(|_| V031OriginalRollbackError::Crypto)?;
    let mut wrapped_data_key =
        wrap_case_key(&data_key).map_err(|_| V031OriginalRollbackError::Crypto)?;
    if wrapped_data_key.is_empty() || wrapped_data_key.len() > MAX_WRAPPED_DATA_KEY_BYTES {
        zeroize(&mut wrapped_data_key);
        return Err(V031OriginalRollbackError::Crypto);
    }
    let wrapped_data_key_sha256 = sha256_hex(&wrapped_data_key);
    let wrapped_data_key_base64 = BASE64_STANDARD.encode(&wrapped_data_key);
    zeroize(&mut wrapped_data_key);

    let aad = canonical_aad(
        request.source_profile_proof_sha256,
        request.source_user_physical_file_set_sha256,
        request.source_privacy_physical_file_set_sha256,
        request.source_user_logical_manifest_sha256,
        request.source_user_business_manifest_sha256,
        request.source_privacy_logical_manifest_sha256,
        request.source_privacy_business_manifest_sha256,
        request.envelope_binding_id,
        request.lineage_id,
        request.created_at_unix,
        total_chunk_count,
        &wrapped_data_key_sha256,
        &slots,
    )?;

    let mut slot_chunks = Vec::with_capacity(total_chunk_count as usize);
    let mut nonces = BTreeSet::new();
    for (slot, plaintext) in slots.iter().zip(plaintexts) {
        for (index, chunk) in plaintext
            .chunks(V031_ORIGINAL_ROLLBACK_CHUNK_BYTES)
            .enumerate()
        {
            let index = u32::try_from(index).map_err(|_| V031OriginalRollbackError::TooLarge)?;
            let chunk_aad = slot_chunk_aad(&aad, slot, index)?;
            let sealed = seal(&data_key, chunk, &chunk_aad)
                .map_err(|_| V031OriginalRollbackError::Crypto)?;
            let nonce_base64 = BASE64_STANDARD.encode(sealed.nonce());
            if !nonces.insert(nonce_base64.clone()) {
                return Err(V031OriginalRollbackError::Crypto);
            }
            let plaintext_bytes =
                u32::try_from(chunk.len()).map_err(|_| V031OriginalRollbackError::TooLarge)?;
            slot_chunks.push(V031OriginalRollbackEncryptedChunkV2 {
                slot_ordinal: slot.ordinal,
                index,
                plaintext_bytes,
                plaintext_sha256: sha256_hex(chunk),
                nonce_base64,
                ciphertext_base64: BASE64_STANDARD.encode(sealed.ciphertext()),
                ciphertext_sha256: sha256_hex(sealed.ciphertext()),
                tag_base64: BASE64_STANDARD.encode(sealed.tag()),
            });
        }
    }

    let envelope = V031OriginalRollbackEnvelopeV2 {
        schema_version: V031_ORIGINAL_ROLLBACK_ENVELOPE_SCHEMA_VERSION.to_owned(),
        format_version: V031_ORIGINAL_ROLLBACK_FORMAT_VERSION,
        crypto_suite: V031_ORIGINAL_ROLLBACK_CRYPTO_SUITE.to_owned(),
        aad_schema_version: V031_ORIGINAL_ROLLBACK_AAD_SCHEMA_VERSION.to_owned(),
        migration_id: V031_ORIGINAL_ROLLBACK_MIGRATION_ID.to_owned(),
        creator_app_version: V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION.to_owned(),
        source_profile: V031_ORIGINAL_ROLLBACK_SOURCE_PROFILE.to_owned(),
        source_profile_proof_sha256: request.source_profile_proof_sha256.to_owned(),
        source_user_physical_file_set_sha256: request
            .source_user_physical_file_set_sha256
            .to_owned(),
        source_privacy_physical_file_set_sha256: request
            .source_privacy_physical_file_set_sha256
            .to_owned(),
        source_user_logical_manifest_sha256: request.source_user_logical_manifest_sha256.to_owned(),
        source_user_business_manifest_sha256: request
            .source_user_business_manifest_sha256
            .to_owned(),
        source_privacy_logical_manifest_sha256: request
            .source_privacy_logical_manifest_sha256
            .to_owned(),
        source_privacy_business_manifest_sha256: request
            .source_privacy_business_manifest_sha256
            .to_owned(),
        envelope_binding_id: request.envelope_binding_id.to_owned(),
        lineage_id: request.lineage_id.to_owned(),
        created_at_unix: request.created_at_unix,
        expires_at_unix: V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX,
        chunk_bytes: V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u32,
        total_chunk_count,
        wrapped_data_key_base64,
        wrapped_data_key_sha256,
        slots,
        slot_chunks,
    };
    let bytes =
        canonical_json_v1(&envelope).map_err(|_| V031OriginalRollbackError::InvalidInput)?;
    if bytes.is_empty() || bytes.len() > MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES {
        return Err(V031OriginalRollbackError::TooLarge);
    }
    let metadata = metadata_from_envelope(&envelope, bytes.len(), sha256_hex(&bytes))?;
    Ok((bytes, metadata))
}

pub fn create_v031_original_rollback_identity_v2(
    metadata: &V031OriginalRollbackMetadataV2,
) -> Result<V031OriginalRollbackIdentityV2, V031OriginalRollbackError> {
    let identity = V031OriginalRollbackIdentityV2 {
        schema_version: V031_ORIGINAL_ROLLBACK_IDENTITY_SCHEMA_VERSION.to_owned(),
        format_version: V031_ORIGINAL_ROLLBACK_FORMAT_VERSION,
        migration_id: V031_ORIGINAL_ROLLBACK_MIGRATION_ID.to_owned(),
        creator_app_version: V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION.to_owned(),
        source_profile: V031_ORIGINAL_ROLLBACK_SOURCE_PROFILE.to_owned(),
        source_profile_proof_sha256: metadata.source_profile_proof_sha256.clone(),
        source_user_physical_file_set_sha256: metadata.source_user_physical_file_set_sha256.clone(),
        source_privacy_physical_file_set_sha256: metadata
            .source_privacy_physical_file_set_sha256
            .clone(),
        source_user_logical_manifest_sha256: metadata.source_user_logical_manifest_sha256.clone(),
        source_user_business_manifest_sha256: metadata.source_user_business_manifest_sha256.clone(),
        source_privacy_logical_manifest_sha256: metadata
            .source_privacy_logical_manifest_sha256
            .clone(),
        source_privacy_business_manifest_sha256: metadata
            .source_privacy_business_manifest_sha256
            .clone(),
        envelope_binding_id: metadata.envelope_binding_id.clone(),
        lineage_id: metadata.lineage_id.clone(),
        created_at_unix: metadata.created_at_unix,
        expires_at_unix: metadata.expires_at_unix,
        bundle_file_name: V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME.to_owned(),
        bundle_bytes: metadata.bundle_bytes,
        bundle_sha256: metadata.bundle_sha256.clone(),
        wrapped_data_key_sha256: metadata.wrapped_data_key_sha256.clone(),
        chunk_bytes: V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u32,
        total_chunk_count: metadata.total_chunk_count,
        slots: metadata.slots.clone(),
    };
    validate_identity(&identity)?;
    Ok(identity)
}

pub fn protect_v031_original_rollback_identity_v2(
    identity: &V031OriginalRollbackIdentityV2,
) -> Result<Vec<u8>, V031OriginalRollbackError> {
    validate_identity(identity)?;
    let mut plaintext =
        canonical_json_v1(identity).map_err(|_| V031OriginalRollbackError::InvalidInput)?;
    let protected = protect_local(&plaintext).map_err(|_| V031OriginalRollbackError::Crypto);
    zeroize(&mut plaintext);
    let protected = protected?;
    if protected.is_empty() || protected.len() > MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES {
        return Err(V031OriginalRollbackError::TooLarge);
    }
    Ok(protected)
}

pub fn open_v031_original_rollback_identity_v2(
    protected: &[u8],
) -> Result<V031OriginalRollbackIdentityV2, V031OriginalRollbackError> {
    if protected.is_empty() || protected.len() > MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES {
        return Err(V031OriginalRollbackError::TooLarge);
    }
    let plaintext = SensitiveBytes(
        unprotect_local(protected).map_err(|_| V031OriginalRollbackError::EnvironmentMismatch)?,
    );
    let identity: V031OriginalRollbackIdentityV2 = strict_json_v1_from_slice(plaintext.as_slice())
        .map_err(|_| V031OriginalRollbackError::Tampered)?;
    let canonical =
        canonical_json_v1(&identity).map_err(|_| V031OriginalRollbackError::Tampered)?;
    if canonical != plaintext.as_slice() {
        return Err(V031OriginalRollbackError::Tampered);
    }
    validate_identity(&identity)?;
    Ok(identity)
}

pub fn open_v031_original_rollback_v2_for_identity(
    bytes: &[u8],
    identity: &V031OriginalRollbackIdentityV2,
) -> Result<OpenedV031OriginalRollbackV2, V031OriginalRollbackError> {
    validate_identity(identity)?;
    let opened = open_v031_original_rollback_v2(
        bytes,
        &V031OriginalRollbackOpenContext {
            expected_source_profile_proof_sha256: &identity.source_profile_proof_sha256,
            expected_source_user_physical_file_set_sha256: &identity
                .source_user_physical_file_set_sha256,
            expected_source_privacy_physical_file_set_sha256: &identity
                .source_privacy_physical_file_set_sha256,
            expected_source_user_logical_manifest_sha256: &identity
                .source_user_logical_manifest_sha256,
            expected_source_user_business_manifest_sha256: &identity
                .source_user_business_manifest_sha256,
            expected_source_privacy_logical_manifest_sha256: &identity
                .source_privacy_logical_manifest_sha256,
            expected_source_privacy_business_manifest_sha256: &identity
                .source_privacy_business_manifest_sha256,
            expected_envelope_binding_id: &identity.envelope_binding_id,
            expected_lineage_id: &identity.lineage_id,
            expected_created_at_unix: identity.created_at_unix,
            expected_bundle_sha256: &identity.bundle_sha256,
        },
    )?;
    if identity.bundle_bytes != opened.metadata.bundle_bytes
        || identity.expires_at_unix != opened.metadata.expires_at_unix
        || identity.wrapped_data_key_sha256 != opened.metadata.wrapped_data_key_sha256
        || identity.total_chunk_count != opened.metadata.total_chunk_count
        || identity.slots != opened.metadata.slots
    {
        return Err(V031OriginalRollbackError::Tampered);
    }
    Ok(opened)
}

pub fn open_v031_original_rollback_v2(
    bytes: &[u8],
    context: &V031OriginalRollbackOpenContext<'_>,
) -> Result<OpenedV031OriginalRollbackV2, V031OriginalRollbackError> {
    if bytes.is_empty() || bytes.len() > MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES {
        return Err(V031OriginalRollbackError::TooLarge);
    }
    validate_open_context(context)?;
    if sha256_hex(bytes) != context.expected_bundle_sha256 {
        return Err(V031OriginalRollbackError::Tampered);
    }
    let envelope: V031OriginalRollbackEnvelopeV2 = strict_json_v1_from_slice(bytes)
        .map_err(|_| V031OriginalRollbackError::UnsupportedSchema)?;
    let canonical =
        canonical_json_v1(&envelope).map_err(|_| V031OriginalRollbackError::Tampered)?;
    if canonical != bytes {
        return Err(V031OriginalRollbackError::Tampered);
    }
    validate_envelope_shape(&envelope)?;
    validate_envelope_context(&envelope, context)?;

    let mut wrapped_data_key = decode_canonical_base64(
        &envelope.wrapped_data_key_base64,
        MAX_WRAPPED_DATA_KEY_BYTES,
    )?;
    if sha256_hex(&wrapped_data_key) != envelope.wrapped_data_key_sha256 {
        zeroize(&mut wrapped_data_key);
        return Err(V031OriginalRollbackError::Tampered);
    }
    let data_key = match unwrap_case_key(&wrapped_data_key) {
        Ok(key) => key,
        Err(_) => {
            zeroize(&mut wrapped_data_key);
            return Err(V031OriginalRollbackError::EnvironmentMismatch);
        }
    };
    zeroize(&mut wrapped_data_key);
    let aad = aad_from_envelope(&envelope)?;
    let mut nonces = BTreeSet::new();
    let mut plaintext_slots = Vec::with_capacity(envelope.slots.len());
    let mut chunk_position = 0_usize;

    for slot in &envelope.slots {
        let capacity = usize::try_from(slot.plaintext_bytes)
            .map_err(|_| V031OriginalRollbackError::TooLarge)?;
        let mut plaintext = SensitiveBytes(Vec::with_capacity(capacity));
        for expected_index in 0..slot.chunk_count {
            let chunk = envelope
                .slot_chunks
                .get(chunk_position)
                .ok_or(V031OriginalRollbackError::Tampered)?;
            chunk_position = chunk_position
                .checked_add(1)
                .ok_or(V031OriginalRollbackError::TooLarge)?;
            if chunk.slot_ordinal != slot.ordinal || chunk.index != expected_index {
                return Err(V031OriginalRollbackError::Tampered);
            }
            validate_encrypted_chunk_shape(chunk, slot, expected_index)?;
            if !nonces.insert(chunk.nonce_base64.clone()) {
                return Err(V031OriginalRollbackError::Tampered);
            }
            let nonce = decode_canonical_base64(&chunk.nonce_base64, GCM_NONCE_BYTES)?;
            let ciphertext = decode_canonical_base64(
                &chunk.ciphertext_base64,
                V031_ORIGINAL_ROLLBACK_CHUNK_BYTES,
            )?;
            let tag = decode_canonical_base64(&chunk.tag_base64, GCM_TAG_BYTES)?;
            if nonce.len() != GCM_NONCE_BYTES
                || tag.len() != GCM_TAG_BYTES
                || ciphertext.len() != chunk.plaintext_bytes as usize
                || sha256_hex(&ciphertext) != chunk.ciphertext_sha256
            {
                return Err(V031OriginalRollbackError::Tampered);
            }
            let sealed = AeadSealedV1::from_parts(&nonce, ciphertext, &tag)
                .map_err(|_| V031OriginalRollbackError::Tampered)?;
            let chunk_aad = slot_chunk_aad(&aad, slot, expected_index)?;
            let mut opened = open(&data_key, &sealed, &chunk_aad)
                .map_err(|_| V031OriginalRollbackError::Tampered)?;
            if opened.len() != chunk.plaintext_bytes as usize
                || sha256_hex(&opened) != chunk.plaintext_sha256
            {
                zeroize(&mut opened);
                return Err(V031OriginalRollbackError::Tampered);
            }
            plaintext.0.extend_from_slice(&opened);
            zeroize(&mut opened);
        }
        if plaintext.0.len() != capacity || sha256_hex(&plaintext.0) != slot.plaintext_sha256 {
            return Err(V031OriginalRollbackError::Tampered);
        }
        validate_opened_slot(slot, plaintext.as_slice())?;
        plaintext_slots.push(plaintext);
    }
    if chunk_position != envelope.slot_chunks.len() || plaintext_slots.len() != 5 {
        return Err(V031OriginalRollbackError::Tampered);
    }

    let metadata = metadata_from_envelope(
        &envelope,
        bytes.len(),
        context.expected_bundle_sha256.to_owned(),
    )?;
    let mut plaintext_slots = plaintext_slots.into_iter();
    let user_database = plaintext_slots
        .next()
        .ok_or(V031OriginalRollbackError::Tampered)?;
    let privacy_store = plaintext_slots
        .next()
        .ok_or(V031OriginalRollbackError::Tampered)?;
    drop(plaintext_slots);
    Ok(OpenedV031OriginalRollbackV2 {
        metadata,
        user_database: user_database.into_vec(),
        privacy_store: privacy_store.into_vec(),
        authenticated_absent_slots: [
            V031OriginalRollbackSlotName::VaultStore,
            V031OriginalRollbackSlotName::ApprovedWorkspace,
            V031OriginalRollbackSlotName::WorkProducts,
        ],
    })
}

fn validate_create_request(
    request: &V031OriginalRollbackCreateRequest<'_>,
) -> Result<(), V031OriginalRollbackError> {
    for hash in [
        request.source_profile_proof_sha256,
        request.source_user_physical_file_set_sha256,
        request.source_privacy_physical_file_set_sha256,
        request.source_user_logical_manifest_sha256,
        request.source_user_business_manifest_sha256,
        request.source_privacy_logical_manifest_sha256,
        request.source_privacy_business_manifest_sha256,
    ] {
        if !is_hash(hash) {
            return Err(V031OriginalRollbackError::InvalidInput);
        }
    }
    if !valid_envelope_binding_id(request.envelope_binding_id)
        || !is_hash(request.lineage_id)
        || request.created_at_unix == 0
        || request.created_at_unix >= V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX
        || !valid_sqlite_image(request.user_database, MAX_USER_DATABASE_BACKUP_BYTES)
        || !valid_sqlite_image(request.privacy_store, privacy_v1_maximum_bytes()?)
    {
        return Err(V031OriginalRollbackError::InvalidInput);
    }
    Ok(())
}

fn validate_open_context(
    context: &V031OriginalRollbackOpenContext<'_>,
) -> Result<(), V031OriginalRollbackError> {
    for hash in [
        context.expected_source_profile_proof_sha256,
        context.expected_source_user_physical_file_set_sha256,
        context.expected_source_privacy_physical_file_set_sha256,
        context.expected_source_user_logical_manifest_sha256,
        context.expected_source_user_business_manifest_sha256,
        context.expected_source_privacy_logical_manifest_sha256,
        context.expected_source_privacy_business_manifest_sha256,
        context.expected_bundle_sha256,
    ] {
        if !is_hash(hash) {
            return Err(V031OriginalRollbackError::InvalidInput);
        }
    }
    if !valid_envelope_binding_id(context.expected_envelope_binding_id)
        || !is_hash(context.expected_lineage_id)
        || context.expected_created_at_unix == 0
        || context.expected_created_at_unix >= V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX
    {
        return Err(V031OriginalRollbackError::InvalidInput);
    }
    Ok(())
}

fn build_slot_descriptors(
    request: &V031OriginalRollbackCreateRequest<'_>,
    plaintexts: &[&[u8]; 5],
) -> Result<Vec<V031OriginalRollbackSlotIdentityV2>, V031OriginalRollbackError> {
    let specifications = [
        (
            V031OriginalRollbackSlotName::UserDatabase,
            V031OriginalRollbackPresence::Present,
            V031OriginalRollbackEncoding::RawSqlite,
            Some(V031_USER_SCHEMA_VERSION),
            Some(request.source_user_logical_manifest_sha256),
            Some(request.source_user_business_manifest_sha256),
        ),
        (
            V031OriginalRollbackSlotName::PrivacyStore,
            V031OriginalRollbackPresence::Present,
            V031OriginalRollbackEncoding::RawSqlite,
            Some(V031_PRIVACY_SCHEMA_VERSION),
            Some(request.source_privacy_logical_manifest_sha256),
            Some(request.source_privacy_business_manifest_sha256),
        ),
        (
            V031OriginalRollbackSlotName::VaultStore,
            V031OriginalRollbackPresence::AuthenticatedAbsent,
            V031OriginalRollbackEncoding::AuthenticatedAbsentSentinelV1,
            None,
            None,
            None,
        ),
        (
            V031OriginalRollbackSlotName::ApprovedWorkspace,
            V031OriginalRollbackPresence::AuthenticatedAbsent,
            V031OriginalRollbackEncoding::AuthenticatedAbsentSentinelV1,
            None,
            None,
            None,
        ),
        (
            V031OriginalRollbackSlotName::WorkProducts,
            V031OriginalRollbackPresence::AuthenticatedAbsent,
            V031OriginalRollbackEncoding::AuthenticatedAbsentSentinelV1,
            None,
            None,
            None,
        ),
    ];
    let mut slots = Vec::with_capacity(5);
    for (ordinal, (specification, plaintext)) in
        specifications.into_iter().zip(plaintexts).enumerate()
    {
        let plaintext_bytes =
            u64::try_from(plaintext.len()).map_err(|_| V031OriginalRollbackError::TooLarge)?;
        let chunk_count = expected_chunk_count(plaintext_bytes)?;
        slots.push(V031OriginalRollbackSlotIdentityV2 {
            ordinal: u8::try_from(ordinal).map_err(|_| V031OriginalRollbackError::TooLarge)?,
            name: specification.0,
            presence: specification.1,
            encoding: specification.2,
            source_schema_version: specification.3,
            plaintext_bytes,
            plaintext_sha256: sha256_hex(plaintext),
            logical_manifest_sha256: specification.4.map(str::to_owned),
            business_manifest_sha256: specification.5.map(str::to_owned),
            chunk_count,
        });
    }
    Ok(slots)
}

#[allow(clippy::too_many_arguments)]
fn canonical_aad(
    source_profile_proof_sha256: &str,
    source_user_physical_file_set_sha256: &str,
    source_privacy_physical_file_set_sha256: &str,
    source_user_logical_manifest_sha256: &str,
    source_user_business_manifest_sha256: &str,
    source_privacy_logical_manifest_sha256: &str,
    source_privacy_business_manifest_sha256: &str,
    envelope_binding_id: &str,
    lineage_id: &str,
    created_at_unix: u64,
    total_chunk_count: u32,
    wrapped_data_key_sha256: &str,
    slots: &[V031OriginalRollbackSlotIdentityV2],
) -> Result<Vec<u8>, V031OriginalRollbackError> {
    canonical_json_v1(&V031OriginalRollbackAadV2 {
        aad_schema_version: V031_ORIGINAL_ROLLBACK_AAD_SCHEMA_VERSION,
        schema_version: V031_ORIGINAL_ROLLBACK_ENVELOPE_SCHEMA_VERSION,
        format_version: V031_ORIGINAL_ROLLBACK_FORMAT_VERSION,
        crypto_suite: V031_ORIGINAL_ROLLBACK_CRYPTO_SUITE,
        migration_id: V031_ORIGINAL_ROLLBACK_MIGRATION_ID,
        creator_app_version: V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION,
        source_profile: V031_ORIGINAL_ROLLBACK_SOURCE_PROFILE,
        source_profile_proof_sha256,
        source_user_physical_file_set_sha256,
        source_privacy_physical_file_set_sha256,
        source_user_logical_manifest_sha256,
        source_user_business_manifest_sha256,
        source_privacy_logical_manifest_sha256,
        source_privacy_business_manifest_sha256,
        envelope_binding_id,
        lineage_id,
        created_at_unix,
        expires_at_unix: V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX,
        chunk_bytes: V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u32,
        total_chunk_count,
        wrapped_data_key_sha256,
        slots,
    })
    .map_err(|_| V031OriginalRollbackError::InvalidInput)
}

fn aad_from_envelope(
    envelope: &V031OriginalRollbackEnvelopeV2,
) -> Result<Vec<u8>, V031OriginalRollbackError> {
    canonical_aad(
        &envelope.source_profile_proof_sha256,
        &envelope.source_user_physical_file_set_sha256,
        &envelope.source_privacy_physical_file_set_sha256,
        &envelope.source_user_logical_manifest_sha256,
        &envelope.source_user_business_manifest_sha256,
        &envelope.source_privacy_logical_manifest_sha256,
        &envelope.source_privacy_business_manifest_sha256,
        &envelope.envelope_binding_id,
        &envelope.lineage_id,
        envelope.created_at_unix,
        envelope.total_chunk_count,
        &envelope.wrapped_data_key_sha256,
        &envelope.slots,
    )
    .map_err(|_| V031OriginalRollbackError::Tampered)
}

fn slot_chunk_aad(
    base: &[u8],
    slot: &V031OriginalRollbackSlotIdentityV2,
    index: u32,
) -> Result<Vec<u8>, V031OriginalRollbackError> {
    if index >= slot.chunk_count {
        return Err(V031OriginalRollbackError::InvalidInput);
    }
    let mut aad = Vec::with_capacity(base.len().saturating_add(192));
    aad.extend_from_slice(base);
    aad.extend_from_slice(SLOT_CHUNK_AAD_DOMAIN);
    append_field(&mut aad, 0x01, slot.name.as_str().as_bytes())?;
    append_field(&mut aad, 0x02, &[slot.ordinal])?;
    append_field(&mut aad, 0x03, &u64::from(index).to_be_bytes())?;
    append_field(&mut aad, 0x04, &u64::from(slot.chunk_count).to_be_bytes())?;
    if aad.len() > 64 * 1024 {
        return Err(V031OriginalRollbackError::TooLarge);
    }
    Ok(aad)
}

fn append_field(
    output: &mut Vec<u8>,
    tag: u8,
    value: &[u8],
) -> Result<(), V031OriginalRollbackError> {
    output.push(tag);
    let length = u64::try_from(value.len()).map_err(|_| V031OriginalRollbackError::TooLarge)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn validate_envelope_shape(
    envelope: &V031OriginalRollbackEnvelopeV2,
) -> Result<(), V031OriginalRollbackError> {
    if envelope.schema_version != V031_ORIGINAL_ROLLBACK_ENVELOPE_SCHEMA_VERSION
        || envelope.format_version != V031_ORIGINAL_ROLLBACK_FORMAT_VERSION
        || envelope.crypto_suite != V031_ORIGINAL_ROLLBACK_CRYPTO_SUITE
        || envelope.aad_schema_version != V031_ORIGINAL_ROLLBACK_AAD_SCHEMA_VERSION
        || envelope.migration_id != V031_ORIGINAL_ROLLBACK_MIGRATION_ID
        || envelope.creator_app_version != V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION
        || envelope.source_profile != V031_ORIGINAL_ROLLBACK_SOURCE_PROFILE
        || envelope.expires_at_unix != V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX
        || envelope.created_at_unix == 0
        || envelope.created_at_unix >= envelope.expires_at_unix
        || envelope.chunk_bytes != V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u32
        || !is_hash(&envelope.source_profile_proof_sha256)
        || !is_hash(&envelope.source_user_physical_file_set_sha256)
        || !is_hash(&envelope.source_privacy_physical_file_set_sha256)
        || !is_hash(&envelope.source_user_logical_manifest_sha256)
        || !is_hash(&envelope.source_user_business_manifest_sha256)
        || !is_hash(&envelope.source_privacy_logical_manifest_sha256)
        || !is_hash(&envelope.source_privacy_business_manifest_sha256)
        || !valid_envelope_binding_id(&envelope.envelope_binding_id)
        || !is_hash(&envelope.lineage_id)
        || !is_hash(&envelope.wrapped_data_key_sha256)
        || envelope.wrapped_data_key_base64.is_empty()
        || envelope.wrapped_data_key_base64.len() > MAX_WRAPPED_DATA_KEY_BYTES.saturating_mul(2)
    {
        return Err(V031OriginalRollbackError::Tampered);
    }
    validate_slots(&envelope.slots)?;
    validate_slot_manifest_bindings(
        &envelope.slots,
        &envelope.source_user_logical_manifest_sha256,
        &envelope.source_user_business_manifest_sha256,
        &envelope.source_privacy_logical_manifest_sha256,
        &envelope.source_privacy_business_manifest_sha256,
    )?;
    let expected_total = envelope.slots.iter().try_fold(0_u32, |total, slot| {
        total
            .checked_add(slot.chunk_count)
            .ok_or(V031OriginalRollbackError::TooLarge)
    })?;
    if envelope.total_chunk_count != expected_total
        || envelope.slot_chunks.len() != expected_total as usize
    {
        return Err(V031OriginalRollbackError::Tampered);
    }
    Ok(())
}

fn validate_envelope_context(
    envelope: &V031OriginalRollbackEnvelopeV2,
    context: &V031OriginalRollbackOpenContext<'_>,
) -> Result<(), V031OriginalRollbackError> {
    if envelope.source_profile_proof_sha256 != context.expected_source_profile_proof_sha256
        || envelope.source_user_physical_file_set_sha256
            != context.expected_source_user_physical_file_set_sha256
        || envelope.source_privacy_physical_file_set_sha256
            != context.expected_source_privacy_physical_file_set_sha256
        || envelope.source_user_logical_manifest_sha256
            != context.expected_source_user_logical_manifest_sha256
        || envelope.source_user_business_manifest_sha256
            != context.expected_source_user_business_manifest_sha256
        || envelope.source_privacy_logical_manifest_sha256
            != context.expected_source_privacy_logical_manifest_sha256
        || envelope.source_privacy_business_manifest_sha256
            != context.expected_source_privacy_business_manifest_sha256
        || envelope.envelope_binding_id != context.expected_envelope_binding_id
        || envelope.lineage_id != context.expected_lineage_id
        || envelope.created_at_unix != context.expected_created_at_unix
    {
        return Err(V031OriginalRollbackError::EnvironmentMismatch);
    }
    Ok(())
}

fn validate_identity(
    identity: &V031OriginalRollbackIdentityV2,
) -> Result<(), V031OriginalRollbackError> {
    if identity.schema_version != V031_ORIGINAL_ROLLBACK_IDENTITY_SCHEMA_VERSION {
        return Err(V031OriginalRollbackError::UnsupportedSchema);
    }
    if identity.format_version != V031_ORIGINAL_ROLLBACK_FORMAT_VERSION
        || identity.migration_id != V031_ORIGINAL_ROLLBACK_MIGRATION_ID
        || identity.creator_app_version != V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION
        || identity.source_profile != V031_ORIGINAL_ROLLBACK_SOURCE_PROFILE
        || identity.expires_at_unix != V031_ORIGINAL_ROLLBACK_EXPIRES_AT_UNIX
        || identity.created_at_unix == 0
        || identity.created_at_unix >= identity.expires_at_unix
        || identity.bundle_file_name != V031_ORIGINAL_ROLLBACK_BUNDLE_FILE_NAME
        || identity.bundle_bytes == 0
        || identity.bundle_bytes > MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES as u64
        || identity.chunk_bytes != V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u32
        || !is_hash(&identity.source_profile_proof_sha256)
        || !is_hash(&identity.source_user_physical_file_set_sha256)
        || !is_hash(&identity.source_privacy_physical_file_set_sha256)
        || !is_hash(&identity.source_user_logical_manifest_sha256)
        || !is_hash(&identity.source_user_business_manifest_sha256)
        || !is_hash(&identity.source_privacy_logical_manifest_sha256)
        || !is_hash(&identity.source_privacy_business_manifest_sha256)
        || !valid_envelope_binding_id(&identity.envelope_binding_id)
        || !is_hash(&identity.lineage_id)
        || !is_hash(&identity.bundle_sha256)
        || !is_hash(&identity.wrapped_data_key_sha256)
    {
        return Err(V031OriginalRollbackError::Tampered);
    }
    validate_slots(&identity.slots)?;
    validate_slot_manifest_bindings(
        &identity.slots,
        &identity.source_user_logical_manifest_sha256,
        &identity.source_user_business_manifest_sha256,
        &identity.source_privacy_logical_manifest_sha256,
        &identity.source_privacy_business_manifest_sha256,
    )?;
    let expected_total = identity.slots.iter().try_fold(0_u32, |total, slot| {
        total
            .checked_add(slot.chunk_count)
            .ok_or(V031OriginalRollbackError::TooLarge)
    })?;
    if identity.total_chunk_count != expected_total {
        return Err(V031OriginalRollbackError::Tampered);
    }
    Ok(())
}

fn validate_slots(
    slots: &[V031OriginalRollbackSlotIdentityV2],
) -> Result<(), V031OriginalRollbackError> {
    let expected_names = [
        V031OriginalRollbackSlotName::UserDatabase,
        V031OriginalRollbackSlotName::PrivacyStore,
        V031OriginalRollbackSlotName::VaultStore,
        V031OriginalRollbackSlotName::ApprovedWorkspace,
        V031OriginalRollbackSlotName::WorkProducts,
    ];
    if slots.len() != expected_names.len() {
        return Err(V031OriginalRollbackError::Tampered);
    }
    for (ordinal, (slot, expected_name)) in slots.iter().zip(expected_names).enumerate() {
        if slot.ordinal != ordinal as u8
            || slot.name != expected_name
            || slot.plaintext_bytes == 0
            || !is_hash(&slot.plaintext_sha256)
            || slot.chunk_count != expected_chunk_count(slot.plaintext_bytes)?
        {
            return Err(V031OriginalRollbackError::Tampered);
        }
        match expected_name {
            V031OriginalRollbackSlotName::UserDatabase => {
                if slot.presence != V031OriginalRollbackPresence::Present
                    || slot.encoding != V031OriginalRollbackEncoding::RawSqlite
                    || slot.source_schema_version != Some(V031_USER_SCHEMA_VERSION)
                    || slot.plaintext_bytes > MAX_USER_DATABASE_BACKUP_BYTES as u64
                    || slot
                        .logical_manifest_sha256
                        .as_deref()
                        .is_none_or(|value| !is_hash(value))
                    || slot
                        .business_manifest_sha256
                        .as_deref()
                        .is_none_or(|value| !is_hash(value))
                {
                    return Err(V031OriginalRollbackError::Tampered);
                }
            }
            V031OriginalRollbackSlotName::PrivacyStore => {
                if slot.presence != V031OriginalRollbackPresence::Present
                    || slot.encoding != V031OriginalRollbackEncoding::RawSqlite
                    || slot.source_schema_version != Some(V031_PRIVACY_SCHEMA_VERSION)
                    || slot.plaintext_bytes > privacy_v1_maximum_bytes()? as u64
                    || slot
                        .logical_manifest_sha256
                        .as_deref()
                        .is_none_or(|value| !is_hash(value))
                    || slot
                        .business_manifest_sha256
                        .as_deref()
                        .is_none_or(|value| !is_hash(value))
                {
                    return Err(V031OriginalRollbackError::Tampered);
                }
            }
            V031OriginalRollbackSlotName::VaultStore
            | V031OriginalRollbackSlotName::ApprovedWorkspace
            | V031OriginalRollbackSlotName::WorkProducts => {
                let sentinel = expected_absent_sentinel(expected_name)?;
                if slot.presence != V031OriginalRollbackPresence::AuthenticatedAbsent
                    || slot.encoding != V031OriginalRollbackEncoding::AuthenticatedAbsentSentinelV1
                    || slot.source_schema_version.is_some()
                    || slot.logical_manifest_sha256.is_some()
                    || slot.business_manifest_sha256.is_some()
                    || slot.plaintext_bytes != sentinel.len() as u64
                    || slot.plaintext_sha256 != sha256_hex(sentinel)
                {
                    return Err(V031OriginalRollbackError::Tampered);
                }
            }
        }
    }
    Ok(())
}

fn validate_slot_manifest_bindings(
    slots: &[V031OriginalRollbackSlotIdentityV2],
    user_logical_manifest_sha256: &str,
    user_business_manifest_sha256: &str,
    privacy_logical_manifest_sha256: &str,
    privacy_business_manifest_sha256: &str,
) -> Result<(), V031OriginalRollbackError> {
    let user = slots.first().ok_or(V031OriginalRollbackError::Tampered)?;
    let privacy = slots.get(1).ok_or(V031OriginalRollbackError::Tampered)?;
    if user.logical_manifest_sha256.as_deref() != Some(user_logical_manifest_sha256)
        || user.business_manifest_sha256.as_deref() != Some(user_business_manifest_sha256)
        || privacy.logical_manifest_sha256.as_deref() != Some(privacy_logical_manifest_sha256)
        || privacy.business_manifest_sha256.as_deref() != Some(privacy_business_manifest_sha256)
    {
        return Err(V031OriginalRollbackError::Tampered);
    }
    Ok(())
}

fn validate_encrypted_chunk_shape(
    chunk: &V031OriginalRollbackEncryptedChunkV2,
    slot: &V031OriginalRollbackSlotIdentityV2,
    expected_index: u32,
) -> Result<(), V031OriginalRollbackError> {
    if chunk.slot_ordinal > 4
        || chunk.plaintext_bytes == 0
        || chunk.plaintext_bytes as usize > V031_ORIGINAL_ROLLBACK_CHUNK_BYTES
        || chunk.plaintext_bytes != expected_chunk_plaintext_bytes(slot, expected_index)?
        || !is_hash(&chunk.plaintext_sha256)
        || !is_hash(&chunk.ciphertext_sha256)
        || chunk.nonce_base64.is_empty()
        || chunk.ciphertext_base64.is_empty()
        || chunk.tag_base64.is_empty()
    {
        return Err(V031OriginalRollbackError::Tampered);
    }
    Ok(())
}

fn validate_opened_slot(
    slot: &V031OriginalRollbackSlotIdentityV2,
    plaintext: &[u8],
) -> Result<(), V031OriginalRollbackError> {
    match slot.name {
        V031OriginalRollbackSlotName::UserDatabase => {
            if !valid_sqlite_image(plaintext, MAX_USER_DATABASE_BACKUP_BYTES) {
                return Err(V031OriginalRollbackError::Tampered);
            }
        }
        V031OriginalRollbackSlotName::PrivacyStore => {
            if !valid_sqlite_image(plaintext, privacy_v1_maximum_bytes()?) {
                return Err(V031OriginalRollbackError::Tampered);
            }
        }
        V031OriginalRollbackSlotName::VaultStore
        | V031OriginalRollbackSlotName::ApprovedWorkspace
        | V031OriginalRollbackSlotName::WorkProducts => {
            if plaintext != expected_absent_sentinel(slot.name)? {
                return Err(V031OriginalRollbackError::Tampered);
            }
        }
    }
    Ok(())
}

fn expected_absent_sentinel(
    slot: V031OriginalRollbackSlotName,
) -> Result<&'static [u8], V031OriginalRollbackError> {
    match slot {
        V031OriginalRollbackSlotName::VaultStore => Ok(V031_VAULT_AUTHENTICATED_ABSENT_SENTINEL),
        V031OriginalRollbackSlotName::ApprovedWorkspace => {
            Ok(V031_APPROVED_WORKSPACE_AUTHENTICATED_ABSENT_SENTINEL)
        }
        V031OriginalRollbackSlotName::WorkProducts => {
            Ok(V031_WORK_PRODUCTS_AUTHENTICATED_ABSENT_SENTINEL)
        }
        V031OriginalRollbackSlotName::UserDatabase | V031OriginalRollbackSlotName::PrivacyStore => {
            Err(V031OriginalRollbackError::InvalidInput)
        }
    }
}

fn metadata_from_envelope(
    envelope: &V031OriginalRollbackEnvelopeV2,
    bundle_bytes: usize,
    bundle_sha256: String,
) -> Result<V031OriginalRollbackMetadataV2, V031OriginalRollbackError> {
    if !is_hash(&bundle_sha256) {
        return Err(V031OriginalRollbackError::Tampered);
    }
    let bundle_bytes =
        u64::try_from(bundle_bytes).map_err(|_| V031OriginalRollbackError::TooLarge)?;
    Ok(V031OriginalRollbackMetadataV2 {
        source_profile_proof_sha256: envelope.source_profile_proof_sha256.clone(),
        source_user_physical_file_set_sha256: envelope.source_user_physical_file_set_sha256.clone(),
        source_privacy_physical_file_set_sha256: envelope
            .source_privacy_physical_file_set_sha256
            .clone(),
        source_user_logical_manifest_sha256: envelope.source_user_logical_manifest_sha256.clone(),
        source_user_business_manifest_sha256: envelope.source_user_business_manifest_sha256.clone(),
        source_privacy_logical_manifest_sha256: envelope
            .source_privacy_logical_manifest_sha256
            .clone(),
        source_privacy_business_manifest_sha256: envelope
            .source_privacy_business_manifest_sha256
            .clone(),
        envelope_binding_id: envelope.envelope_binding_id.clone(),
        lineage_id: envelope.lineage_id.clone(),
        created_at_unix: envelope.created_at_unix,
        expires_at_unix: envelope.expires_at_unix,
        bundle_bytes,
        bundle_sha256,
        wrapped_data_key_sha256: envelope.wrapped_data_key_sha256.clone(),
        total_chunk_count: envelope.total_chunk_count,
        slots: envelope.slots.clone(),
    })
}

fn decode_canonical_base64(
    value: &str,
    maximum: usize,
) -> Result<Vec<u8>, V031OriginalRollbackError> {
    let maximum_encoded = maximum
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(V031OriginalRollbackError::TooLarge)?;
    if value.is_empty() || value.len() > maximum_encoded {
        return Err(V031OriginalRollbackError::Tampered);
    }
    let decoded = BASE64_STANDARD
        .decode(value)
        .map_err(|_| V031OriginalRollbackError::Tampered)?;
    if decoded.is_empty() || decoded.len() > maximum || BASE64_STANDARD.encode(&decoded) != value {
        return Err(V031OriginalRollbackError::Tampered);
    }
    Ok(decoded)
}

fn expected_chunk_count(plaintext_bytes: u64) -> Result<u32, V031OriginalRollbackError> {
    if plaintext_bytes == 0 {
        return Err(V031OriginalRollbackError::InvalidInput);
    }
    let chunk_bytes = V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u64;
    u32::try_from(plaintext_bytes.div_ceil(chunk_bytes))
        .map_err(|_| V031OriginalRollbackError::TooLarge)
}

fn expected_chunk_plaintext_bytes(
    slot: &V031OriginalRollbackSlotIdentityV2,
    index: u32,
) -> Result<u32, V031OriginalRollbackError> {
    if index >= slot.chunk_count {
        return Err(V031OriginalRollbackError::Tampered);
    }
    let chunk_bytes = V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u64;
    let offset = u64::from(index)
        .checked_mul(chunk_bytes)
        .ok_or(V031OriginalRollbackError::TooLarge)?;
    let remaining = slot
        .plaintext_bytes
        .checked_sub(offset)
        .ok_or(V031OriginalRollbackError::Tampered)?;
    u32::try_from(remaining.min(chunk_bytes)).map_err(|_| V031OriginalRollbackError::TooLarge)
}

fn privacy_v1_maximum_bytes() -> Result<usize, V031OriginalRollbackError> {
    max_backup_database_bytes_for_schema(V031_PRIVACY_SCHEMA_VERSION)
        .ok_or(V031OriginalRollbackError::InvalidInput)
}

fn valid_sqlite_image(bytes: &[u8], maximum: usize) -> bool {
    bytes.len() >= SQLITE_HEADER.len() && bytes.len() <= maximum && bytes.starts_with(SQLITE_HEADER)
}

fn valid_envelope_binding_id(value: &str) -> bool {
    value.len() == 35
        && value.starts_with("ws_")
        && value.as_bytes()[3..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn zeroize(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    #[test]
    fn chunk_count_boundaries_are_exact_and_overflow_closed() {
        let chunk_bytes = V031_ORIGINAL_ROLLBACK_CHUNK_BYTES as u64;
        assert_eq!(expected_chunk_count(1), Ok(1));
        assert_eq!(expected_chunk_count(chunk_bytes), Ok(1));
        assert_eq!(expected_chunk_count(chunk_bytes + 1), Ok(2));
        assert_eq!(
            expected_chunk_count(u64::MAX),
            Err(V031OriginalRollbackError::TooLarge)
        );
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        application_backup::{open_application_backup, ApplicationBackupOpenContext},
        vnext::WorkspaceInstanceId,
        ApplicationBackupError,
    };

    const CREATED_AT: u64 = 1_754_000_000;

    struct TestHashes {
        source_profile: String,
        user_physical: String,
        privacy_physical: String,
        user_logical: String,
        user_business: String,
        privacy_logical: String,
        privacy_business: String,
    }

    fn hashes() -> TestHashes {
        TestHashes {
            source_profile: sha256_hex(b"source-profile"),
            user_physical: sha256_hex(b"user-physical-file-set"),
            privacy_physical: sha256_hex(b"privacy-physical-file-set"),
            user_logical: sha256_hex(b"user-logical"),
            user_business: sha256_hex(b"user-business"),
            privacy_logical: sha256_hex(b"privacy-logical"),
            privacy_business: sha256_hex(b"privacy-business"),
        }
    }

    fn request<'a>(
        hashes: &'a TestHashes,
        user: &'a [u8],
        privacy: &'a [u8],
    ) -> V031OriginalRollbackCreateRequest<'a> {
        V031OriginalRollbackCreateRequest {
            source_profile_proof_sha256: &hashes.source_profile,
            source_user_physical_file_set_sha256: &hashes.user_physical,
            source_privacy_physical_file_set_sha256: &hashes.privacy_physical,
            source_user_logical_manifest_sha256: &hashes.user_logical,
            source_user_business_manifest_sha256: &hashes.user_business,
            source_privacy_logical_manifest_sha256: &hashes.privacy_logical,
            source_privacy_business_manifest_sha256: &hashes.privacy_business,
            envelope_binding_id: "ws_0123456789abcdef0123456789abcdef",
            lineage_id: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            created_at_unix: CREATED_AT,
            user_database: user,
            privacy_store: privacy,
        }
    }

    fn context<'a>(
        request: &'a V031OriginalRollbackCreateRequest<'a>,
        bundle_sha256: &'a str,
    ) -> V031OriginalRollbackOpenContext<'a> {
        V031OriginalRollbackOpenContext {
            expected_source_profile_proof_sha256: request.source_profile_proof_sha256,
            expected_source_user_physical_file_set_sha256: request
                .source_user_physical_file_set_sha256,
            expected_source_privacy_physical_file_set_sha256: request
                .source_privacy_physical_file_set_sha256,
            expected_source_user_logical_manifest_sha256: request
                .source_user_logical_manifest_sha256,
            expected_source_user_business_manifest_sha256: request
                .source_user_business_manifest_sha256,
            expected_source_privacy_logical_manifest_sha256: request
                .source_privacy_logical_manifest_sha256,
            expected_source_privacy_business_manifest_sha256: request
                .source_privacy_business_manifest_sha256,
            expected_envelope_binding_id: request.envelope_binding_id,
            expected_lineage_id: request.lineage_id,
            expected_created_at_unix: request.created_at_unix,
            expected_bundle_sha256: bundle_sha256,
        }
    }

    #[test]
    fn five_slot_round_trip_hides_plaintext_and_protects_exact_identity() {
        let hashes = hashes();
        let user = b"SQLite format 3\0USER-PRIVATE-CANARY";
        let privacy = b"SQLite format 3\0PRIVACY-PRIVATE-CANARY";
        let request = request(&hashes, user, privacy);
        let debug = format!("{request:?}");
        assert!(!debug.contains("PRIVATE-CANARY"));

        let (bundle, metadata) =
            seal_v031_original_rollback_v2(&request).expect("seal original rollback");
        assert!(!bundle.windows(user.len()).any(|window| window == user));
        assert!(!bundle
            .windows(privacy.len())
            .any(|window| window == privacy));
        let opened =
            open_v031_original_rollback_v2(&bundle, &context(&request, &metadata.bundle_sha256))
                .expect("open original rollback");
        assert_eq!(opened.user_database, user);
        assert_eq!(opened.privacy_store, privacy);
        assert_eq!(
            opened.authenticated_absent_slots,
            [
                V031OriginalRollbackSlotName::VaultStore,
                V031OriginalRollbackSlotName::ApprovedWorkspace,
                V031OriginalRollbackSlotName::WorkProducts,
            ]
        );

        let identity =
            create_v031_original_rollback_identity_v2(&metadata).expect("build identity");
        let protected =
            protect_v031_original_rollback_identity_v2(&identity).expect("protect identity");
        assert!(!protected
            .windows(identity.lineage_id.len())
            .any(|window| window == identity.lineage_id.as_bytes()));
        let restored_identity =
            open_v031_original_rollback_identity_v2(&protected).expect("open identity");
        assert_eq!(restored_identity, identity);
        let reopened = open_v031_original_rollback_v2_for_identity(&bundle, &identity)
            .expect("identity-bound open");
        assert_eq!(reopened.user_database, user);
    }

    #[test]
    fn ciphertext_tamper_is_rejected_even_when_outer_hash_is_rebound() {
        let hashes = hashes();
        let request = request(
            &hashes,
            b"SQLite format 3\0user",
            b"SQLite format 3\0privacy",
        );
        let (bundle, _) = seal_v031_original_rollback_v2(&request).expect("seal");
        let mut envelope: V031OriginalRollbackEnvelopeV2 =
            strict_json_v1_from_slice(&bundle).expect("parse envelope");
        let mut ciphertext = BASE64_STANDARD
            .decode(&envelope.slot_chunks[0].ciphertext_base64)
            .expect("ciphertext");
        ciphertext[0] ^= 0x5a;
        envelope.slot_chunks[0].ciphertext_base64 = BASE64_STANDARD.encode(&ciphertext);
        envelope.slot_chunks[0].ciphertext_sha256 = sha256_hex(&ciphertext);
        let tampered = canonical_json_v1(&envelope).expect("canonical tampered envelope");
        let tampered_hash = sha256_hex(&tampered);
        assert_eq!(
            open_v031_original_rollback_v2(&tampered, &context(&request, &tampered_hash)),
            Err(V031OriginalRollbackError::Tampered)
        );
    }

    #[test]
    fn wrong_lineage_and_binding_are_environment_mismatches() {
        let hashes = hashes();
        let request = request(
            &hashes,
            b"SQLite format 3\0user",
            b"SQLite format 3\0privacy",
        );
        let (bundle, metadata) = seal_v031_original_rollback_v2(&request).expect("seal");
        let mut wrong_lineage = context(&request, &metadata.bundle_sha256);
        wrong_lineage.expected_lineage_id =
            "1111111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(
            open_v031_original_rollback_v2(&bundle, &wrong_lineage),
            Err(V031OriginalRollbackError::EnvironmentMismatch)
        );
        let mut wrong_binding = context(&request, &metadata.bundle_sha256);
        wrong_binding.expected_envelope_binding_id = "ws_11111111111111111111111111111111";
        assert_eq!(
            open_v031_original_rollback_v2(&bundle, &wrong_binding),
            Err(V031OriginalRollbackError::EnvironmentMismatch)
        );
    }

    #[test]
    fn physical_file_set_anchors_are_bound_to_open_context_and_envelope_aad() {
        let hashes = hashes();
        let request = request(
            &hashes,
            b"SQLite format 3\0user",
            b"SQLite format 3\0privacy",
        );
        let (bundle, metadata) = seal_v031_original_rollback_v2(&request).expect("seal");
        let wrong_user_physical = sha256_hex(b"wrong-user-physical-file-set");
        let mut wrong_context = context(&request, &metadata.bundle_sha256);
        wrong_context.expected_source_user_physical_file_set_sha256 = &wrong_user_physical;
        assert_eq!(
            open_v031_original_rollback_v2(&bundle, &wrong_context),
            Err(V031OriginalRollbackError::EnvironmentMismatch)
        );

        // Rebinding the outer bundle hash and expected context is insufficient:
        // the original ciphertext tags authenticate both physical anchors as AAD.
        let wrong_privacy_physical = sha256_hex(b"wrong-privacy-physical-file-set");
        let mut envelope: V031OriginalRollbackEnvelopeV2 =
            strict_json_v1_from_slice(&bundle).expect("parse envelope");
        envelope.source_privacy_physical_file_set_sha256 = wrong_privacy_physical.clone();
        let tampered = canonical_json_v1(&envelope).expect("canonical tampered envelope");
        let tampered_hash = sha256_hex(&tampered);
        let mut rebound_context = context(&request, &tampered_hash);
        rebound_context.expected_source_privacy_physical_file_set_sha256 = &wrong_privacy_physical;
        assert_eq!(
            open_v031_original_rollback_v2(&tampered, &rebound_context),
            Err(V031OriginalRollbackError::Tampered)
        );
    }

    #[test]
    fn a_cryptographically_valid_wrong_absence_sentinel_is_rejected() {
        let hashes = hashes();
        let request = request(
            &hashes,
            b"SQLite format 3\0user",
            b"SQLite format 3\0privacy",
        );
        let wrong_vault =
            b"lawyer-assistance\0v031-original-rollback\0authenticated-absent-v1\0wrong-vault\0";
        let (bundle, metadata) = seal_v031_original_rollback_v2_with_absent_slots(
            &request,
            [
                wrong_vault,
                V031_APPROVED_WORKSPACE_AUTHENTICATED_ABSENT_SENTINEL,
                V031_WORK_PRODUCTS_AUTHENTICATED_ABSENT_SENTINEL,
            ],
        )
        .expect("seal test-only wrong sentinel envelope");
        assert_eq!(
            open_v031_original_rollback_v2(&bundle, &context(&request, &metadata.bundle_sha256)),
            Err(V031OriginalRollbackError::Tampered)
        );
    }

    #[test]
    fn ordinary_application_backup_parser_rejects_migration_only_schema() {
        let hashes = hashes();
        let request = request(
            &hashes,
            b"SQLite format 3\0user",
            b"SQLite format 3\0privacy",
        );
        let (bundle, _) = seal_v031_original_rollback_v2(&request).expect("seal");
        let workspace = WorkspaceInstanceId::parse("ws_99999999999999999999999999999999")
            .expect("workspace identity");
        assert_eq!(
            open_application_backup(
                &bundle,
                &ApplicationBackupOpenContext {
                    expected_workspace_instance_id: &workspace,
                    expected_app_version: V031_ORIGINAL_ROLLBACK_CREATOR_APP_VERSION,
                    expected_user_schema_version: 11,
                    now_unix: CREATED_AT,
                },
            ),
            Err(ApplicationBackupError::UnsupportedSchema)
        );
    }

    #[test]
    fn protected_identity_tamper_is_rejected() {
        let hashes = hashes();
        let request = request(
            &hashes,
            b"SQLite format 3\0user",
            b"SQLite format 3\0privacy",
        );
        let (_, metadata) = seal_v031_original_rollback_v2(&request).expect("seal");
        let identity = create_v031_original_rollback_identity_v2(&metadata).expect("identity");
        let mut protected =
            protect_v031_original_rollback_identity_v2(&identity).expect("protect identity");
        let middle = protected.len() / 2;
        protected[middle] ^= 0x3c;
        assert_eq!(
            open_v031_original_rollback_identity_v2(&protected),
            Err(V031OriginalRollbackError::EnvironmentMismatch)
        );
    }
}
