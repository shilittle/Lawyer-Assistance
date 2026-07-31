#![allow(unsafe_code)]

//! Local lifecycle, encrypted alias mapping, and encrypted privacy-database backup.
//!
//! Sensitive mapping values are encrypted with per-generation AES-256-GCM keys. Those keys and
//! backup data-encryption keys are wrapped with Windows DPAPI CurrentUser. Database rows, cleanup
//! journals, debug output, and backup envelopes therefore contain only opaque identifiers,
//! hashes, ciphertext, and wrapped keys. Cleanup reports deliberately describe logical and
//! cryptographic erasure; they never claim forensic media wiping.

use crate::{
    protect_local, sha256_hex, unprotect_local,
    vault_crypto::{open, seal, unwrap_case_key, wrap_case_key, AeadSealedV1, SecretKey32},
    vault_store::{FixedLocalStorageRoot, VaultStoreError},
    vnext::{canonical_json_v1, strict_json_v1_from_slice, WorkspaceInstanceId},
    PrivacyStore, PrivacyStoreError, PrivacyStoreSchemaStatus, PRIVACY_STORE_SCHEMA_VERSION,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use rusqlite::{backup::Backup, params, Connection, OpenFlags, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{compiler_fence, Ordering},
    time::Duration,
};

pub const PRIVACY_LIFECYCLE_SCHEMA_VERSION: i64 = 1;
pub const SENSITIVE_MAPPING_SCHEMA_VERSION: &str = "sensitive-mapping-v1";
pub const ENCRYPTED_BACKUP_SCHEMA_VERSION: &str = "privacy-encrypted-backup-v1";
pub const PORTABLE_BACKUP_SCHEMA_VERSION: &str = "privacy-portable-backup-v1";
pub const BACKUP_CRYPTO_SUITE: &str = "windows-cng-aes-256-gcm-dpapi-current-user-v1";
pub const LOGICAL_ERASURE_DISCLOSURE: &str =
    "logical_and_cryptographic_erasure_only_not_forensic_media_wipe";
const RETENTION_PRECONDITION_CHANGED_ERROR_CODE: &str =
    "privacy_cleanup_retention_precondition_changed";
pub const MAX_MAPPING_ENTRIES: usize = 4_096;
pub const MAX_MAPPING_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_PRE_MIGRATION_BACKUP_DATABASE_BYTES: usize = 96 * 1024 * 1024;
pub const MAX_PRE_MIGRATION_BACKUP_ENVELOPE_BYTES: usize = 160 * 1024 * 1024;
pub const MAX_PRE_MIGRATION_PORTABLE_BACKUP_BYTES: usize = 224 * 1024 * 1024;
pub const MAX_BACKUP_DATABASE_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_BACKUP_ENVELOPE_BYTES: usize = 352 * 1024 * 1024;
pub const MAX_PORTABLE_BACKUP_BYTES: usize = 416 * 1024 * 1024;
pub const MAX_RETENTION_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;
const MAX_ID_BYTES: usize = 128;
const MAPPING_AAD_VERSION: &str = "mapping-aad-v1";
const BACKUP_AAD_VERSION: &str = "backup-aad-v1";
const DEFAULT_MAPPING_RETENTION_SECONDS: u64 = 90 * 24 * 60 * 60;
const DEFAULT_REVIEW_RETENTION_SECONDS: u64 = 90 * 24 * 60 * 60;
const DEFAULT_RECEIPT_GRACE_SECONDS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_BACKUP_RETENTION_SECONDS: u64 = 180 * 24 * 60 * 60;
const MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION: i64 = 1;
const MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION: i64 = 5;

pub const fn max_backup_database_bytes_for_schema(schema_version: i64) -> Option<usize> {
    if schema_version >= MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
        && schema_version <= MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
    {
        Some(MAX_PRE_MIGRATION_BACKUP_DATABASE_BYTES)
    } else if schema_version == PRIVACY_STORE_SCHEMA_VERSION {
        Some(MAX_BACKUP_DATABASE_BYTES)
    } else {
        None
    }
}

const fn max_backup_envelope_bytes_for_schema(schema_version: i64) -> Option<usize> {
    if schema_version >= MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
        && schema_version <= MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
    {
        Some(MAX_PRE_MIGRATION_BACKUP_ENVELOPE_BYTES)
    } else if schema_version == PRIVACY_STORE_SCHEMA_VERSION {
        Some(MAX_BACKUP_ENVELOPE_BYTES)
    } else {
        None
    }
}

pub const fn max_portable_backup_bytes_for_schema(schema_version: i64) -> Option<usize> {
    if schema_version >= MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
        && schema_version <= MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
    {
        Some(MAX_PRE_MIGRATION_PORTABLE_BACKUP_BYTES)
    } else if schema_version == PRIVACY_STORE_SCHEMA_VERSION {
        Some(MAX_PORTABLE_BACKUP_BYTES)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    Database,
    UnsupportedSchema,
    InvalidInput,
    Conflict,
    PlatformUnavailable,
    ProtectedBlob,
    Crypto,
    MappingNotAvailable,
    MappingAccessDenied,
    MappingRevoked,
    MappingExpired,
    CleanupNotPrepared,
    CleanupIntegrity,
    BackupNotAvailable,
    BackupInvalid,
    BackupTampered,
    BackupExpired,
    BackupRevoked,
    EnvironmentMismatch,
    UnsafeFilesystem,
    Io,
}

impl LifecycleError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Database => "privacy_lifecycle_database_error",
            Self::UnsupportedSchema => "privacy_lifecycle_schema_unsupported",
            Self::InvalidInput => "privacy_lifecycle_invalid_input",
            Self::Conflict => "privacy_lifecycle_conflict",
            Self::PlatformUnavailable => "privacy_lifecycle_platform_unavailable",
            Self::ProtectedBlob => "privacy_lifecycle_protected_blob_error",
            Self::Crypto => "privacy_lifecycle_authentication_failed",
            Self::MappingNotAvailable => "sensitive_mapping_not_available",
            Self::MappingAccessDenied => "sensitive_mapping_access_denied",
            Self::MappingRevoked => "sensitive_mapping_revoked",
            Self::MappingExpired => "sensitive_mapping_expired",
            Self::CleanupNotPrepared => "privacy_cleanup_not_prepared",
            Self::CleanupIntegrity => "privacy_cleanup_integrity_failed",
            Self::BackupNotAvailable => "privacy_backup_not_available",
            Self::BackupInvalid => "privacy_backup_invalid",
            Self::BackupTampered => "privacy_backup_tampered",
            Self::BackupExpired => "privacy_backup_expired",
            Self::BackupRevoked => "privacy_backup_revoked",
            Self::EnvironmentMismatch => "privacy_backup_environment_mismatch",
            Self::UnsafeFilesystem => "privacy_backup_unsafe_filesystem",
            Self::Io => "privacy_lifecycle_io_error",
        }
    }
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for LifecycleError {}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SensitiveMappingEntryV1 {
    pub alias: String,
    pub sensitive_value: String,
}

impl fmt::Debug for SensitiveMappingEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveMappingEntryV1")
            .field("alias", &self.alias)
            .field("sensitive_value", &"[ENCRYPTED_SENSITIVE_VALUE]")
            .finish()
    }
}

impl Drop for SensitiveMappingEntryV1 {
    fn drop(&mut self) {
        zeroize_string(&mut self.sensitive_value);
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SensitiveMappingPayloadV1 {
    pub schema_version: String,
    pub entries: Vec<SensitiveMappingEntryV1>,
}

impl fmt::Debug for SensitiveMappingPayloadV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitiveMappingPayloadV1")
            .field("schema_version", &self.schema_version)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl SensitiveMappingPayloadV1 {
    pub fn new(entries: Vec<SensitiveMappingEntryV1>) -> Result<Self, LifecycleError> {
        let payload = Self {
            schema_version: SENSITIVE_MAPPING_SCHEMA_VERSION.to_owned(),
            entries,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        if self.schema_version != SENSITIVE_MAPPING_SCHEMA_VERSION
            || self.entries.is_empty()
            || self.entries.len() > MAX_MAPPING_ENTRIES
        {
            return Err(LifecycleError::InvalidInput);
        }
        let mut aliases = BTreeSet::new();
        for entry in &self.entries {
            valid_private_string(&entry.alias, 256)?;
            valid_private_string(&entry.sensitive_value, 32 * 1024)?;
            if !aliases.insert(entry.alias.as_str()) {
                return Err(LifecycleError::InvalidInput);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RetentionPolicyV1 {
    pub policy_id: String,
    pub review_retention_seconds: u64,
    pub mapping_retention_seconds: u64,
    pub receipt_grace_seconds: u64,
    pub backup_retention_seconds: u64,
    pub revision: u64,
    pub updated_at_unix: u64,
}

impl RetentionPolicyV1 {
    pub fn default_at(updated_at_unix: u64) -> Result<Self, LifecycleError> {
        let policy = Self {
            policy_id: "privacy-default-retention-v1".to_owned(),
            review_retention_seconds: DEFAULT_REVIEW_RETENTION_SECONDS,
            mapping_retention_seconds: DEFAULT_MAPPING_RETENTION_SECONDS,
            receipt_grace_seconds: DEFAULT_RECEIPT_GRACE_SECONDS,
            backup_retention_seconds: DEFAULT_BACKUP_RETENTION_SECONDS,
            revision: 1,
            updated_at_unix,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), LifecycleError> {
        valid_identifier(&self.policy_id)?;
        if self.revision == 0
            || self.updated_at_unix == 0
            || self.review_retention_seconds == 0
            || self.mapping_retention_seconds == 0
            || self.backup_retention_seconds == 0
            || self.review_retention_seconds > MAX_RETENTION_SECONDS
            || self.mapping_retention_seconds > MAX_RETENTION_SECONDS
            || self.receipt_grace_seconds > MAX_RETENTION_SECONDS
            || self.backup_retention_seconds > MAX_RETENTION_SECONDS
        {
            return Err(LifecycleError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRevisionSummaryV1 {
    pub mapping_id: String,
    pub redaction_id: String,
    pub revision: u64,
    pub key_version: u64,
    pub mapping_revision_sha256: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRevisionStatusV1 {
    pub mapping_id: String,
    pub redaction_id: String,
    pub revision: u64,
    pub key_version: u64,
    pub mapping_revision_sha256: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingKeySummaryV1 {
    pub key_version: u64,
    pub protected_key_sha256: String,
    pub state: String,
    pub created_at_unix: u64,
    pub retired_at_unix: Option<u64>,
    pub revoked_at_unix: Option<u64>,
    pub destroyed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionBindingSummaryV1 {
    pub redaction_id: String,
    pub expires_at_unix: u64,
    pub legal_hold: bool,
    pub bound_at_unix: u64,
    pub policy_revision: u64,
    pub hold_changed_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingAccessContextV1<'a> {
    pub access_id: &'a str,
    pub redaction_id: &'a str,
    pub purpose: &'a str,
    pub now_unix: u64,
    pub private_mapping_access_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupReportV1 {
    pub cleanup_id: String,
    pub state: String,
    pub candidates: u64,
    pub removed: u64,
    pub keys_destroyed: u64,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub event_hash: String,
    pub erasure_disclosure: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactionCleanupAuthorizationV1 {
    pub redaction_id: String,
    pub material_id: String,
    pub generation_number: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupAuthorizationSnapshotV1 {
    pub redactions: Vec<RedactionCleanupAuthorizationV1>,
    pub tombstoned_material_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupExportRequestV1<'a> {
    pub backup_id: &'a str,
    pub created_at_unix: u64,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupVerificationContextV1<'a> {
    pub expected_workspace_instance_id: &'a WorkspaceInstanceId,
    pub expected_key_epoch: u64,
    pub now_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreMigrationBackupExportContextV1 {
    pub expected_privacy_store_schema_version: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreMigrationBackupVerificationContextV1<'a> {
    pub expected_workspace_instance_id: &'a WorkspaceInstanceId,
    pub expected_key_epoch: u64,
    pub expected_privacy_store_schema_version: i64,
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBackupV1 {
    pub backup_id: String,
    pub workspace_instance_id: WorkspaceInstanceId,
    pub privacy_store_schema_version: i64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub key_epoch: u64,
    pub database_sha256: String,
    pub envelope_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct BackupEnvelopeV1 {
    schema_version: String,
    crypto_suite: String,
    backup_id: String,
    workspace_instance_id: WorkspaceInstanceId,
    privacy_store_schema_version: i64,
    lifecycle_schema_version: i64,
    key_epoch: u64,
    created_at_unix: u64,
    expires_at_unix: u64,
    database_bytes: u64,
    database_sha256: String,
    wrapped_data_key_base64: String,
    wrapped_data_key_sha256: String,
    nonce_base64: String,
    ciphertext_base64: String,
    ciphertext_sha256: String,
    tag_base64: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BackupAadV1<'a> {
    aad_version: &'static str,
    schema_version: &'a str,
    crypto_suite: &'a str,
    backup_id: &'a str,
    workspace_instance_id: &'a WorkspaceInstanceId,
    privacy_store_schema_version: i64,
    lifecycle_schema_version: i64,
    key_epoch: u64,
    created_at_unix: u64,
    expires_at_unix: u64,
    database_bytes: u64,
    database_sha256: &'a str,
    wrapped_data_key_sha256: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupSchemaExpectation {
    Current,
    PreMigration(i64),
}

impl BackupSchemaExpectation {
    fn expected_version(self) -> Result<i64, LifecycleError> {
        match self {
            Self::Current => Ok(PRIVACY_STORE_SCHEMA_VERSION),
            Self::PreMigration(version)
                if (MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
                    ..=MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION)
                    .contains(&version) =>
            {
                Ok(version)
            }
            Self::PreMigration(_) => Err(LifecycleError::InvalidInput),
        }
    }

    fn validate_actual(self, actual: i64) -> Result<i64, LifecycleError> {
        let expected = self.expected_version()?;
        match self {
            Self::Current if actual == expected => Ok(actual),
            Self::Current => Err(LifecycleError::UnsupportedSchema),
            Self::PreMigration(_)
                if !(MIN_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION
                    ..=MAX_PRE_MIGRATION_PRIVACY_STORE_SCHEMA_VERSION)
                    .contains(&actual) =>
            {
                Err(LifecycleError::UnsupportedSchema)
            }
            Self::PreMigration(_) if actual == expected => Ok(actual),
            Self::PreMigration(_) => Err(LifecycleError::EnvironmentMismatch),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BackupVerificationExpectation<'a> {
    expected_workspace_instance_id: &'a WorkspaceInstanceId,
    expected_key_epoch: u64,
    expected_privacy_store_schema_version: i64,
    now_unix: u64,
}

fn current_backup_verification_expectation<'a>(
    context: &BackupVerificationContextV1<'a>,
) -> BackupVerificationExpectation<'a> {
    BackupVerificationExpectation {
        expected_workspace_instance_id: context.expected_workspace_instance_id,
        expected_key_epoch: context.expected_key_epoch,
        expected_privacy_store_schema_version: PRIVACY_STORE_SCHEMA_VERSION,
        now_unix: context.now_unix,
    }
}

fn pre_migration_backup_verification_expectation<'a>(
    context: &PreMigrationBackupVerificationContextV1<'a>,
) -> Result<BackupVerificationExpectation<'a>, LifecycleError> {
    let expected_privacy_store_schema_version =
        BackupSchemaExpectation::PreMigration(context.expected_privacy_store_schema_version)
            .expected_version()?;
    Ok(BackupVerificationExpectation {
        expected_workspace_instance_id: context.expected_workspace_instance_id,
        expected_key_epoch: context.expected_key_epoch,
        expected_privacy_store_schema_version,
        now_unix: context.now_unix,
    })
}

pub struct PrivacyLifecycle {
    workspace_instance_id: WorkspaceInstanceId,
}

impl PrivacyLifecycle {
    pub fn initialize(
        connection: &mut Connection,
        workspace_instance_id: WorkspaceInstanceId,
        now_unix: u64,
    ) -> Result<Self, LifecycleError> {
        if now_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        initialize_lifecycle_schema(connection).map_err(map_store_error)?;
        let transaction = connection
            .transaction()
            .map_err(|_| LifecycleError::Database)?;
        let existing: Option<(String, i64, i64)> = transaction
            .query_row(
                "SELECT workspace_instance_id,schema_version,key_epoch
                 FROM privacy_lifecycle_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?;
        match existing {
            Some((workspace, schema_version, key_epoch)) => {
                if workspace != workspace_instance_id.as_str()
                    || schema_version != PRIVACY_LIFECYCLE_SCHEMA_VERSION
                    || key_epoch <= 0
                {
                    return Err(LifecycleError::EnvironmentMismatch);
                }
            }
            None => {
                let key = SecretKey32::generate().map_err(map_crypto_error)?;
                let wrapped = wrap_case_key(&key).map_err(map_crypto_error)?;
                let wrapped_sha256 = sha256_hex(&wrapped);
                transaction
                    .execute(
                        "INSERT INTO privacy_lifecycle_meta(
                           singleton,schema_version,workspace_instance_id,active_mapping_key_version,
                           key_epoch,created_at_unix
                         ) VALUES(1,?1,?2,1,1,?3)",
                        params![
                            PRIVACY_LIFECYCLE_SCHEMA_VERSION,
                            workspace_instance_id.as_str(),
                            sql_i64(now_unix)?
                        ],
                    )
                    .map_err(|_| LifecycleError::Database)?;
                transaction
                    .execute(
                        "INSERT INTO privacy_mapping_keys(
                           key_version,protected_key,protected_key_sha256,state,created_at_unix
                         ) VALUES(1,?1,?2,'active',?3)",
                        params![wrapped, wrapped_sha256, sql_i64(now_unix)?],
                    )
                    .map_err(|_| LifecycleError::Database)?;
                let policy = RetentionPolicyV1::default_at(now_unix)?;
                insert_retention_policy(&transaction, &policy)?;
            }
        }
        transaction.commit().map_err(|_| LifecycleError::Database)?;
        Ok(Self {
            workspace_instance_id,
        })
    }

    pub fn open(
        connection: &Connection,
        workspace_instance_id: WorkspaceInstanceId,
    ) -> Result<Self, LifecycleError> {
        let row: Option<(String, i64)> = connection
            .query_row(
                "SELECT workspace_instance_id,schema_version FROM privacy_lifecycle_meta
                 WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?;
        if row
            != Some((
                workspace_instance_id.as_str().to_owned(),
                PRIVACY_LIFECYCLE_SCHEMA_VERSION,
            ))
        {
            return Err(LifecycleError::EnvironmentMismatch);
        }
        Ok(Self {
            workspace_instance_id,
        })
    }

    pub fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }

    pub fn current_key_epoch(&self, connection: &Connection) -> Result<u64, LifecycleError> {
        let value: i64 = connection
            .query_row(
                "SELECT key_epoch FROM privacy_lifecycle_meta
                 WHERE singleton=1 AND workspace_instance_id=?1",
                [self.workspace_instance_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| LifecycleError::EnvironmentMismatch)?;
        sql_u64(value)
    }

    pub fn retention_policy(
        &self,
        connection: &Connection,
    ) -> Result<RetentionPolicyV1, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        load_retention_policy(connection)
    }

    pub fn set_retention_policy(
        &self,
        connection: &mut Connection,
        policy: &RetentionPolicyV1,
    ) -> Result<(), LifecycleError> {
        policy.validate()?;
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let current = load_retention_policy(connection)?;
        if policy.revision != current.revision.saturating_add(1)
            || policy.updated_at_unix <= current.updated_at_unix
        {
            return Err(LifecycleError::Conflict);
        }
        connection
            .execute(
                "UPDATE privacy_retention_policy SET
                   policy_id=?1,review_retention_seconds=?2,mapping_retention_seconds=?3,
                   receipt_grace_seconds=?4,backup_retention_seconds=?5,revision=?6,
                   updated_at_unix=?7 WHERE singleton=1 AND revision=?8",
                params![
                    policy.policy_id,
                    sql_i64(policy.review_retention_seconds)?,
                    sql_i64(policy.mapping_retention_seconds)?,
                    sql_i64(policy.receipt_grace_seconds)?,
                    sql_i64(policy.backup_retention_seconds)?,
                    sql_i64(policy.revision)?,
                    sql_i64(policy.updated_at_unix)?,
                    sql_i64(current.revision)?
                ],
            )
            .map_err(|_| LifecycleError::Database)
            .and_then(|changed| {
                if changed == 1 {
                    Ok(())
                } else {
                    Err(LifecycleError::Conflict)
                }
            })
    }

    pub fn bind_redaction_retention(
        &self,
        connection: &Connection,
        redaction_id: &str,
        bound_at_unix: u64,
    ) -> Result<u64, LifecycleError> {
        valid_identifier(redaction_id)?;
        if bound_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        ensure_redaction_exists(connection, redaction_id)?;
        let policy = load_retention_policy(connection)?;
        let expires_at = bound_at_unix
            .checked_add(policy.review_retention_seconds)
            .ok_or(LifecycleError::InvalidInput)?;
        connection
            .execute(
                "INSERT INTO privacy_retention_bindings(
                   redaction_id,expires_at_unix,legal_hold,bound_at_unix,policy_revision
                 ) VALUES(?1,?2,0,?3,?4)
                 ON CONFLICT(redaction_id) DO UPDATE SET
                   expires_at_unix=excluded.expires_at_unix,
                   bound_at_unix=excluded.bound_at_unix,
                   policy_revision=excluded.policy_revision
                 WHERE privacy_retention_bindings.legal_hold=0",
                params![
                    redaction_id,
                    sql_i64(expires_at)?,
                    sql_i64(bound_at_unix)?,
                    sql_i64(policy.revision)?
                ],
            )
            .map_err(|_| LifecycleError::Database)?;
        Ok(expires_at)
    }

    pub fn set_legal_hold(
        &self,
        connection: &Connection,
        redaction_id: &str,
        enabled: bool,
        changed_at_unix: u64,
    ) -> Result<(), LifecycleError> {
        valid_identifier(redaction_id)?;
        if changed_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let changed = connection
            .execute(
                "UPDATE privacy_retention_bindings SET legal_hold=?2,hold_changed_at_unix=?3
                 WHERE redaction_id=?1",
                params![redaction_id, enabled, sql_i64(changed_at_unix)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(LifecycleError::MappingNotAvailable)
        }
    }

    pub fn list_retention_bindings(
        &self,
        connection: &Connection,
    ) -> Result<Vec<RetentionBindingSummaryV1>, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let mut statement = connection
            .prepare(
                "SELECT redaction_id,expires_at_unix,legal_hold,bound_at_unix,
                        policy_revision,hold_changed_at_unix
                 FROM privacy_retention_bindings ORDER BY redaction_id",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                ))
            })
            .map_err(|_| LifecycleError::Database)?;
        rows.map(|row| {
            let row = row.map_err(|_| LifecycleError::Database)?;
            valid_identifier(&row.0).map_err(|_| LifecycleError::Database)?;
            Ok(RetentionBindingSummaryV1 {
                redaction_id: row.0,
                expires_at_unix: sql_u64(row.1)?,
                legal_hold: row.2,
                bound_at_unix: sql_u64(row.3)?,
                policy_revision: sql_u64(row.4)?,
                hold_changed_at_unix: row.5.map(sql_u64).transpose()?,
            })
        })
        .collect()
    }

    pub fn list_mapping_revisions(
        &self,
        connection: &Connection,
        redaction_id: Option<&str>,
    ) -> Result<Vec<MappingRevisionStatusV1>, LifecycleError> {
        if let Some(redaction_id) = redaction_id {
            valid_identifier(redaction_id)?;
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let mut statement = connection
            .prepare(
                "SELECT mapping_id,redaction_id,revision,key_version,mapping_revision_sha256,
                        created_at_unix,expires_at_unix,revoked_at_unix
                 FROM privacy_sensitive_mappings
                 WHERE (?1 IS NULL OR redaction_id=?1)
                 ORDER BY redaction_id,revision,mapping_id",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([redaction_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })
            .map_err(|_| LifecycleError::Database)?;
        rows.map(|row| {
            let row = row.map_err(|_| LifecycleError::Database)?;
            valid_opaque_id(&row.0, "map_").map_err(|_| LifecycleError::Database)?;
            valid_identifier(&row.1).map_err(|_| LifecycleError::Database)?;
            valid_hash(&row.4).map_err(|_| LifecycleError::Database)?;
            Ok(MappingRevisionStatusV1 {
                mapping_id: row.0,
                redaction_id: row.1,
                revision: sql_u64(row.2)?,
                key_version: sql_u64(row.3)?,
                mapping_revision_sha256: row.4,
                created_at_unix: sql_u64(row.5)?,
                expires_at_unix: sql_u64(row.6)?,
                revoked: row.7.is_some(),
            })
        })
        .collect()
    }

    pub fn list_mapping_keys(
        &self,
        connection: &Connection,
    ) -> Result<Vec<MappingKeySummaryV1>, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let mut statement = connection
            .prepare(
                "SELECT key_version,protected_key_sha256,state,created_at_unix,
                        retired_at_unix,revoked_at_unix,destroyed_at_unix
                 FROM privacy_mapping_keys ORDER BY key_version",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                ))
            })
            .map_err(|_| LifecycleError::Database)?;
        rows.map(|row| {
            let row = row.map_err(|_| LifecycleError::Database)?;
            valid_hash(&row.1).map_err(|_| LifecycleError::Database)?;
            if !matches!(
                row.2.as_str(),
                "active" | "retired" | "revoked" | "destroyed"
            ) {
                return Err(LifecycleError::Database);
            }
            Ok(MappingKeySummaryV1 {
                key_version: sql_u64(row.0)?,
                protected_key_sha256: row.1,
                state: row.2,
                created_at_unix: sql_u64(row.3)?,
                retired_at_unix: row.4.map(sql_u64).transpose()?,
                revoked_at_unix: row.5.map(sql_u64).transpose()?,
                destroyed_at_unix: row.6.map(sql_u64).transpose()?,
            })
        })
        .collect()
    }

    pub fn save_mapping_revision(
        &self,
        connection: &mut Connection,
        mapping_id: &str,
        redaction_id: &str,
        revision: u64,
        payload: &SensitiveMappingPayloadV1,
        created_at_unix: u64,
    ) -> Result<MappingRevisionSummaryV1, LifecycleError> {
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| LifecycleError::Database)?;
        let summary = self.save_mapping_revision_in_transaction(
            &transaction,
            mapping_id,
            redaction_id,
            revision,
            payload,
            created_at_unix,
        )?;
        transaction.commit().map_err(|_| LifecycleError::Database)?;
        Ok(summary)
    }

    /// Saves a mapping inside a caller-owned transaction so review state,
    /// retention binding, and revision 1 can commit atomically.
    pub fn save_mapping_revision_in_transaction(
        &self,
        transaction: &Transaction<'_>,
        mapping_id: &str,
        redaction_id: &str,
        revision: u64,
        payload: &SensitiveMappingPayloadV1,
        created_at_unix: u64,
    ) -> Result<MappingRevisionSummaryV1, LifecycleError> {
        self.save_mapping_revision_on_connection(
            transaction,
            mapping_id,
            redaction_id,
            revision,
            payload,
            created_at_unix,
        )
    }

    fn save_mapping_revision_on_connection(
        &self,
        connection: &Connection,
        mapping_id: &str,
        redaction_id: &str,
        revision: u64,
        payload: &SensitiveMappingPayloadV1,
        created_at_unix: u64,
    ) -> Result<MappingRevisionSummaryV1, LifecycleError> {
        valid_opaque_id(mapping_id, "map_")?;
        valid_identifier(redaction_id)?;
        payload.validate()?;
        if revision == 0 || created_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        ensure_redaction_exists(connection, redaction_id)?;
        let plaintext = ZeroizingBytes::new(
            canonical_json_v1(payload).map_err(|_| LifecycleError::InvalidInput)?,
        );
        if plaintext.is_empty() || plaintext.len() > MAX_MAPPING_PLAINTEXT_BYTES {
            return Err(LifecycleError::InvalidInput);
        }
        let policy = load_retention_policy(connection)?;
        let expires_at_unix = created_at_unix
            .checked_add(policy.mapping_retention_seconds)
            .ok_or(LifecycleError::InvalidInput)?;
        let (key_version, key) = load_active_mapping_key(connection)?;
        let aad = mapping_aad(
            &self.workspace_instance_id,
            mapping_id,
            redaction_id,
            revision,
            key_version,
            created_at_unix,
            expires_at_unix,
        )?;
        let sealed = seal(&key, &plaintext, &aad).map_err(map_crypto_error)?;
        let mapping_revision_sha256 = sha256_hex(&plaintext);
        let ciphertext_sha256 = sha256_hex(sealed.ciphertext());
        connection
            .execute(
                "INSERT INTO privacy_sensitive_mappings(
                   mapping_id,redaction_id,revision,key_version,nonce,ciphertext,tag,
                   ciphertext_sha256,mapping_revision_sha256,created_at_unix,expires_at_unix
                 ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    mapping_id,
                    redaction_id,
                    sql_i64(revision)?,
                    sql_i64(key_version)?,
                    sealed.nonce().as_slice(),
                    sealed.ciphertext(),
                    sealed.tag().as_slice(),
                    ciphertext_sha256,
                    mapping_revision_sha256,
                    sql_i64(created_at_unix)?,
                    sql_i64(expires_at_unix)?
                ],
            )
            .map_err(|_| LifecycleError::Conflict)?;
        connection
            .execute(
                "INSERT INTO privacy_retention_bindings(
                   redaction_id,expires_at_unix,legal_hold,bound_at_unix,policy_revision
                 ) VALUES(?1,?2,0,?3,?4)
                 ON CONFLICT(redaction_id) DO NOTHING",
                params![
                    redaction_id,
                    sql_i64(
                        created_at_unix
                            .checked_add(policy.review_retention_seconds)
                            .ok_or(LifecycleError::InvalidInput)?
                    )?,
                    sql_i64(created_at_unix)?,
                    sql_i64(policy.revision)?
                ],
            )
            .map_err(|_| LifecycleError::Database)?;
        Ok(MappingRevisionSummaryV1 {
            mapping_id: mapping_id.to_owned(),
            redaction_id: redaction_id.to_owned(),
            revision,
            key_version,
            mapping_revision_sha256,
            created_at_unix,
            expires_at_unix,
        })
    }
    pub fn load_mapping_revision(
        &self,
        connection: &mut Connection,
        mapping_id: &str,
        context: &MappingAccessContextV1<'_>,
    ) -> Result<SensitiveMappingPayloadV1, LifecycleError> {
        valid_opaque_id(mapping_id, "map_")?;
        valid_identifier(context.access_id)?;
        valid_identifier(context.redaction_id)?;
        valid_identifier(context.purpose)?;
        if context.now_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        if !context.private_mapping_access_authorized {
            append_mapping_access_audit(
                connection,
                context,
                mapping_id,
                false,
                LifecycleError::MappingAccessDenied.code(),
            )?;
            return Err(LifecycleError::MappingAccessDenied);
        }
        let result = self.decrypt_mapping(connection, mapping_id, context);
        let (allowed, reason) = match &result {
            Ok(_) => (true, "sensitive_mapping_access_allowed"),
            Err(error) => (false, error.code()),
        };
        append_mapping_access_audit(connection, context, mapping_id, allowed, reason)?;
        result
    }

    fn decrypt_mapping(
        &self,
        connection: &Connection,
        mapping_id: &str,
        context: &MappingAccessContextV1<'_>,
    ) -> Result<SensitiveMappingPayloadV1, LifecycleError> {
        type MappingRow = (
            String,
            i64,
            i64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            String,
            String,
            i64,
            i64,
            Option<i64>,
        );
        let row: MappingRow = connection
            .query_row(
                "SELECT redaction_id,revision,key_version,nonce,ciphertext,tag,ciphertext_sha256,
                        mapping_revision_sha256,created_at_unix,expires_at_unix,revoked_at_unix
                 FROM privacy_sensitive_mappings WHERE mapping_id=?1",
                [mapping_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?
            .ok_or(LifecycleError::MappingNotAvailable)?;
        if row.0 != context.redaction_id {
            return Err(LifecycleError::MappingAccessDenied);
        }
        if row.10.is_some() {
            return Err(LifecycleError::MappingRevoked);
        }
        let expires_at = sql_u64(row.9)?;
        if context.now_unix >= expires_at {
            return Err(LifecycleError::MappingExpired);
        }
        if sha256_hex(&row.4) != row.6 {
            return Err(LifecycleError::Crypto);
        }
        let key_version = sql_u64(row.2)?;
        let key = load_mapping_key(connection, key_version)?;
        let sealed =
            AeadSealedV1::from_parts(&row.3, row.4, &row.5).map_err(|_| LifecycleError::Crypto)?;
        let aad = mapping_aad(
            &self.workspace_instance_id,
            mapping_id,
            context.redaction_id,
            sql_u64(row.1)?,
            key_version,
            sql_u64(row.8)?,
            expires_at,
        )?;
        let plaintext = ZeroizingBytes::new(open(&key, &sealed, &aad).map_err(map_crypto_error)?);
        if plaintext.len() > MAX_MAPPING_PLAINTEXT_BYTES || sha256_hex(&plaintext) != row.7 {
            return Err(LifecycleError::Crypto);
        }
        let payload: SensitiveMappingPayloadV1 =
            strict_json_v1_from_slice(&plaintext).map_err(|_| LifecycleError::Crypto)?;
        payload.validate().map_err(|_| LifecycleError::Crypto)?;
        Ok(payload)
    }

    pub fn revoke_mapping(
        &self,
        connection: &Connection,
        mapping_id: &str,
        revoked_at_unix: u64,
    ) -> Result<(), LifecycleError> {
        valid_opaque_id(mapping_id, "map_")?;
        if revoked_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let changed = connection
            .execute(
                "UPDATE privacy_sensitive_mappings SET revoked_at_unix=?2
                 WHERE mapping_id=?1 AND revoked_at_unix IS NULL",
                params![mapping_id, sql_i64(revoked_at_unix)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(LifecycleError::Conflict)
        }
    }

    pub fn rotate_mapping_key(
        &self,
        connection: &mut Connection,
        rotated_at_unix: u64,
    ) -> Result<u64, LifecycleError> {
        if rotated_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let key = SecretKey32::generate().map_err(map_crypto_error)?;
        let wrapped = wrap_case_key(&key).map_err(map_crypto_error)?;
        let wrapped_sha256 = sha256_hex(&wrapped);
        let transaction = connection
            .transaction()
            .map_err(|_| LifecycleError::Database)?;
        let (active, epoch): (i64, i64) = transaction
            .query_row(
                "SELECT active_mapping_key_version,key_epoch FROM privacy_lifecycle_meta
                 WHERE singleton=1 AND workspace_instance_id=?1",
                [self.workspace_instance_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| LifecycleError::EnvironmentMismatch)?;
        let next = active.checked_add(1).ok_or(LifecycleError::InvalidInput)?;
        let next_epoch = epoch.checked_add(1).ok_or(LifecycleError::InvalidInput)?;
        let changed = transaction
            .execute(
                "UPDATE privacy_mapping_keys SET state='retired',retired_at_unix=?2
                 WHERE key_version=?1 AND state='active'",
                params![active, sql_i64(rotated_at_unix)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed != 1 {
            return Err(LifecycleError::Conflict);
        }
        transaction
            .execute(
                "INSERT INTO privacy_mapping_keys(
                   key_version,protected_key,protected_key_sha256,state,created_at_unix
                 ) VALUES(?1,?2,?3,'active',?4)",
                params![next, wrapped, wrapped_sha256, sql_i64(rotated_at_unix)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        transaction
            .execute(
                "UPDATE privacy_lifecycle_meta SET active_mapping_key_version=?1,key_epoch=?2
                 WHERE singleton=1 AND active_mapping_key_version=?3 AND key_epoch=?4",
                params![next, next_epoch, active, epoch],
            )
            .map_err(|_| LifecycleError::Database)?;
        transaction.commit().map_err(|_| LifecycleError::Database)?;
        sql_u64(next)
    }

    pub fn revoke_mapping_key(
        &self,
        connection: &Connection,
        key_version: u64,
        revoked_at_unix: u64,
    ) -> Result<(), LifecycleError> {
        if key_version == 0 || revoked_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let changed = connection
            .execute(
                "UPDATE privacy_mapping_keys SET state='revoked',revoked_at_unix=?2
                 WHERE key_version=?1 AND state='retired'",
                params![sql_i64(key_version)?, sql_i64(revoked_at_unix)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(LifecycleError::Conflict)
        }
    }

    pub fn destroy_mapping_key(
        &self,
        connection: &Connection,
        key_version: u64,
        expected_protected_key_sha256: &str,
        destroyed_at_unix: u64,
    ) -> Result<(), LifecycleError> {
        if key_version == 0 || destroyed_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        valid_hash(expected_protected_key_sha256)?;
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let changed = connection
            .execute(
                "UPDATE privacy_mapping_keys SET
                   protected_key=NULL,state='destroyed',destroyed_at_unix=?3
                 WHERE key_version=?1 AND protected_key_sha256=?2
                   AND state IN('retired','revoked') AND protected_key IS NOT NULL",
                params![
                    sql_i64(key_version)?,
                    expected_protected_key_sha256,
                    sql_i64(destroyed_at_unix)?
                ],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed == 1 {
            Ok(())
        } else {
            Err(LifecycleError::Conflict)
        }
    }

    pub fn prepare_retention_sweep(
        &self,
        connection: &mut Connection,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<u64, LifecycleError> {
        valid_opaque_id(cleanup_id, "cln_")?;
        if now_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let policy = load_retention_policy(connection)?;
        let transaction = connection
            .transaction()
            .map_err(|_| LifecycleError::Database)?;
        transaction
            .execute(
                "INSERT INTO privacy_cleanup_journal(
                   cleanup_id,state,policy_revision,started_at_unix,previous_event_hash,event_hash,
                   erasure_disclosure
                 ) VALUES(?1,'prepared',?2,?3,'','',?4)",
                params![
                    cleanup_id,
                    sql_i64(policy.revision)?,
                    sql_i64(now_unix)?,
                    LOGICAL_ERASURE_DISCLOSURE
                ],
            )
            .map_err(|_| LifecycleError::Conflict)?;
        let mut candidates = 0_u64;
        {
            let mut statement = transaction
                .prepare(
                    "SELECT b.redaction_id,m.source_sha256,r.extraction_sha256
                     FROM privacy_retention_bindings b
                     JOIN privacy_redactions r ON r.redaction_id=b.redaction_id
                     JOIN privacy_materials m ON m.material_id=r.material_id
                     WHERE b.legal_hold=0 AND b.expires_at_unix<=?1
                     ORDER BY b.redaction_id",
                )
                .map_err(|_| LifecycleError::Database)?;
            let rows = statement
                .query_map([sql_i64(now_unix)?], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|_| LifecycleError::Database)?;
            for row in rows {
                let (redaction_id, source_sha256, extraction_sha256) =
                    row.map_err(|_| LifecycleError::Database)?;
                let expected = sha256_hex(
                    format!("redaction\0{redaction_id}\0{source_sha256}\0{extraction_sha256}")
                        .as_bytes(),
                );
                insert_cleanup_candidate(
                    &transaction,
                    cleanup_id,
                    "redaction",
                    &redaction_id,
                    &expected,
                )?;
                candidates = candidates.saturating_add(1);
            }
        }
        {
            let mut statement = transaction
                .prepare(
                    "SELECT s.mapping_id,s.ciphertext_sha256
                     FROM privacy_sensitive_mappings s
                     LEFT JOIN privacy_retention_bindings b ON b.redaction_id=s.redaction_id
                     WHERE s.expires_at_unix<=?1 AND COALESCE(b.legal_hold,0)=0
                     ORDER BY s.mapping_id",
                )
                .map_err(|_| LifecycleError::Database)?;
            let rows = statement
                .query_map([sql_i64(now_unix)?], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|_| LifecycleError::Database)?;
            for row in rows {
                let (mapping_id, expected) = row.map_err(|_| LifecycleError::Database)?;
                insert_cleanup_candidate(
                    &transaction,
                    cleanup_id,
                    "mapping",
                    &mapping_id,
                    &expected,
                )?;
                candidates = candidates.saturating_add(1);
            }
        }
        {
            let mut statement = transaction
                .prepare(
                    "SELECT o.output_id,o.protected_content
                     FROM privacy_approved_outputs o
                     LEFT JOIN privacy_retention_bindings b ON b.redaction_id=o.redaction_id
                     WHERE o.expires_at_unix<=?1 AND COALESCE(b.legal_hold,0)=0
                     ORDER BY o.output_id",
                )
                .map_err(|_| LifecycleError::Database)?;
            let rows = statement
                .query_map([sql_i64(now_unix)?], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|_| LifecycleError::Database)?;
            for row in rows {
                let (output_id, protected_content) = row.map_err(|_| LifecycleError::Database)?;
                insert_cleanup_candidate(
                    &transaction,
                    cleanup_id,
                    "approved_output",
                    &output_id,
                    &sha256_hex(&protected_content),
                )?;
                candidates = candidates.saturating_add(1);
            }
        }
        {
            let cutoff = now_unix.saturating_sub(policy.receipt_grace_seconds);
            let mut statement = transaction
                .prepare(
                    "SELECT p.receipt_id,p.signed_token
                     FROM privacy_receipts p
                     JOIN privacy_redactions r ON r.redaction_id=p.redaction_id
                     LEFT JOIN privacy_retention_bindings b ON b.redaction_id=r.redaction_id
                     WHERE p.expires_at_unix<=?1 AND COALESCE(b.legal_hold,0)=0
                     ORDER BY p.receipt_id",
                )
                .map_err(|_| LifecycleError::Database)?;
            let rows = statement
                .query_map([sql_i64(cutoff)?], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .map_err(|_| LifecycleError::Database)?;
            for row in rows {
                let (receipt_id, protected_token) = row.map_err(|_| LifecycleError::Database)?;
                insert_cleanup_candidate(
                    &transaction,
                    cleanup_id,
                    "receipt",
                    &receipt_id,
                    &sha256_hex(&protected_token),
                )?;
                candidates = candidates.saturating_add(1);
            }
        }
        transaction
            .execute(
                "UPDATE privacy_cleanup_journal SET candidate_count=?2
                 WHERE cleanup_id=?1 AND state='prepared'",
                params![cleanup_id, sql_i64(candidates)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        transaction.commit().map_err(|_| LifecycleError::Database)?;
        Ok(candidates)
    }

    pub fn commit_retention_sweep(
        &self,
        connection: &mut Connection,
        cleanup_id: &str,
        completed_at_unix: u64,
    ) -> Result<CleanupReportV1, LifecycleError> {
        valid_opaque_id(cleanup_id, "cln_")?;
        if completed_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        connection
            .pragma_update(None, "secure_delete", "ON")
            .map_err(|_| LifecycleError::Database)?;
        let secure_delete: i64 = connection
            .pragma_query_value(None, "secure_delete", |row| row.get(0))
            .map_err(|_| LifecycleError::Database)?;
        if secure_delete != 1 {
            return Err(LifecycleError::Database);
        }
        let result = commit_cleanup_transaction(connection, cleanup_id, completed_at_unix);
        if result.is_err() {
            let _ = mark_cleanup_failed(
                connection,
                cleanup_id,
                completed_at_unix,
                LifecycleError::CleanupIntegrity.code(),
            );
        }
        result
    }

    /// Revalidates a prepared retention sweep immediately before an external approved-workspace
    /// invalidator is allowed to revoke or physically clean derived artifacts.
    ///
    /// A legal hold or any other candidate precondition may change after the durable prepare
    /// phase (for example, after a crash or an invalidator failure). In that case the prepared
    /// journal is finalized as `failed` before this method returns `None`; callers must not invoke
    /// the external invalidator. This prevents stale cleanup candidates from overriding a newer
    /// legal hold and also keeps startup recovery deterministic.
    pub fn revalidate_prepared_retention_sweep_for_external_invalidation(
        &self,
        connection: &mut Connection,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<Option<BTreeSet<String>>, LifecycleError> {
        valid_opaque_id(cleanup_id, "cln_")?;
        if now_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        match preflight_cleanup_invalidation(connection, cleanup_id, now_unix) {
            Ok(bindings) => Ok(Some(bindings)),
            Err(LifecycleError::CleanupIntegrity) => {
                mark_cleanup_failed(
                    connection,
                    cleanup_id,
                    now_unix,
                    RETENTION_PRECONDITION_CHANGED_ERROR_CODE,
                )?;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub fn run_retention_sweep(
        &self,
        connection: &mut Connection,
        cleanup_id: &str,
        now_unix: u64,
    ) -> Result<CleanupReportV1, LifecycleError> {
        self.prepare_retention_sweep(connection, cleanup_id, now_unix)?;
        self.commit_retention_sweep(connection, cleanup_id, now_unix)
    }

    pub fn recover_prepared_sweeps(
        &self,
        connection: &mut Connection,
        recovered_at_unix: u64,
    ) -> Result<Vec<CleanupReportV1>, LifecycleError> {
        if recovered_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let cleanup_ids = {
            let mut statement = connection
                .prepare(
                    "SELECT cleanup_id FROM privacy_cleanup_journal
                     WHERE state='prepared' ORDER BY cleanup_id",
                )
                .map_err(|_| LifecycleError::Database)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(|_| LifecycleError::Database)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|_| LifecycleError::Database)?
        };
        let mut reports = Vec::with_capacity(cleanup_ids.len());
        for cleanup_id in cleanup_ids {
            reports.push(self.commit_retention_sweep(
                connection,
                &cleanup_id,
                recovered_at_unix,
            )?);
        }
        Ok(reports)
    }

    pub fn verify_cleanup_journal(&self, connection: &Connection) -> Result<u64, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        let mut statement = connection
            .prepare(
                "SELECT cleanup_id,state,policy_revision,started_at_unix,completed_at_unix,
                        candidate_count,removed_count,keys_destroyed,error_code,
                        previous_event_hash,event_hash,erasure_disclosure
                 FROM privacy_cleanup_journal WHERE state!='prepared'
                 ORDER BY rowid",
            )
            .map_err(|_| LifecycleError::Database)?;
        let rows = statement
            .query_map([], |row| {
                Ok(CleanupJournalRow {
                    cleanup_id: row.get(0)?,
                    state: row.get(1)?,
                    policy_revision: row.get(2)?,
                    started_at_unix: row.get(3)?,
                    completed_at_unix: row.get(4)?,
                    candidate_count: row.get(5)?,
                    removed_count: row.get(6)?,
                    keys_destroyed: row.get(7)?,
                    error_code: row.get(8)?,
                    previous_event_hash: row.get(9)?,
                    event_hash: row.get(10)?,
                    erasure_disclosure: row.get(11)?,
                })
            })
            .map_err(|_| LifecycleError::Database)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LifecycleError::Database)?;
        drop(statement);
        let expected_count =
            u64::try_from(rows.len()).map_err(|_| LifecycleError::CleanupIntegrity)?;
        let mut rows_by_previous = HashMap::with_capacity(rows.len());
        for row in &rows {
            if rows_by_previous
                .insert(row.previous_event_hash.as_str(), row)
                .is_some()
            {
                return Err(LifecycleError::CleanupIntegrity);
            }
        }
        let mut previous = String::new();
        let mut visited = BTreeSet::new();
        let mut count = 0_u64;
        while count < expected_count {
            let row = rows_by_previous
                .remove(previous.as_str())
                .ok_or(LifecycleError::CleanupIntegrity)?;
            if row.event_hash.len() != 64 || !visited.insert(row.event_hash.clone()) {
                return Err(LifecycleError::CleanupIntegrity);
            }
            let evidence_manifest_sha256 = cleanup_evidence_manifest(connection, &row.cleanup_id)?;
            let legacy_event_hash = cleanup_event_hash(row)?;
            let evidence_event_hash =
                cleanup_event_hash_with_evidence(row, &evidence_manifest_sha256)?;
            let (
                candidate_total,
                removed_total,
                redaction_candidate_total,
                redaction_evidence_total,
                invalid_redaction_evidence,
            ): (i64, i64, i64, i64, bool) = connection
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM privacy_cleanup_candidates
                        WHERE cleanup_id=?1),
                       (SELECT COUNT(*) FROM privacy_cleanup_candidates
                        WHERE cleanup_id=?1 AND state='removed'),
                       (SELECT COUNT(*) FROM privacy_cleanup_candidates
                        WHERE cleanup_id=?1 AND target_kind='redaction'),
                       (SELECT COUNT(*) FROM privacy_cleanup_redaction_evidence
                        WHERE cleanup_id=?1),
                       EXISTS(
                         SELECT 1
                         FROM privacy_cleanup_redaction_evidence AS evidence
                         LEFT JOIN privacy_cleanup_candidates AS candidate
                           ON candidate.cleanup_id=evidence.cleanup_id
                          AND candidate.target_kind='redaction'
                          AND candidate.target_id=evidence.redaction_id
                          AND candidate.expected_sha256=evidence.expected_sha256
                         WHERE evidence.cleanup_id=?1
                           AND candidate.target_id IS NULL
                       )",
                    [&row.cleanup_id],
                    |values| {
                        Ok((
                            values.get(0)?,
                            values.get(1)?,
                            values.get(2)?,
                            values.get(3)?,
                            values.get(4)?,
                        ))
                    },
                )
                .map_err(|_| LifecycleError::Database)?;
            let legacy_event = redaction_evidence_total == 0 && row.event_hash == legacy_event_hash;
            let inventory_valid = candidate_total == row.candidate_count
                && removed_total == row.removed_count
                && !invalid_redaction_evidence
                && match row.state.as_str() {
                    "committed" => {
                        removed_total == candidate_total
                            && (redaction_evidence_total == redaction_candidate_total
                                || legacy_event)
                    }
                    "failed" => removed_total == 0 && redaction_evidence_total == 0,
                    _ => false,
                };
            let event_valid = row.event_hash == evidence_event_hash || legacy_event;
            if row.erasure_disclosure != LOGICAL_ERASURE_DISCLOSURE
                || !inventory_valid
                || !event_valid
            {
                return Err(LifecycleError::CleanupIntegrity);
            }
            previous = row.event_hash.clone();
            count = count.saturating_add(1);
        }
        if !rows_by_previous.is_empty() {
            return Err(LifecycleError::CleanupIntegrity);
        }
        Ok(count)
    }

    /// Authenticates the complete cleanup chain once, then returns the exact v2 redaction
    /// erasures and retained final-material tombstones covered by that verified snapshot.
    pub fn cleanup_authorization_snapshot(
        &self,
        connection: &Connection,
    ) -> Result<CleanupAuthorizationSnapshotV1, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        self.verify_cleanup_journal(connection)?;
        let evidence = {
            let mut statement = connection
                .prepare(
                    "SELECT evidence.redaction_id,evidence.material_id,
                            evidence.generation_number,
                            evidence.material_provenance_sha256,
                            evidence.material_tombstoned
                     FROM privacy_cleanup_redaction_evidence AS evidence
                     JOIN privacy_cleanup_candidates AS candidate
                       ON candidate.cleanup_id=evidence.cleanup_id
                      AND candidate.target_kind='redaction'
                      AND candidate.target_id=evidence.redaction_id
                      AND candidate.expected_sha256=evidence.expected_sha256
                      AND candidate.state='removed'
                     JOIN privacy_cleanup_journal AS journal
                       ON journal.cleanup_id=evidence.cleanup_id
                      AND journal.state='committed'
                     ORDER BY evidence.rowid",
                )
                .map_err(|_| LifecycleError::Database)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                })
                .map_err(|_| LifecycleError::Database)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LifecycleError::Database)?;
            rows
        };
        let evidence_total: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_cleanup_redaction_evidence",
                [],
                |row| row.get(0),
            )
            .map_err(|_| LifecycleError::Database)?;
        if usize::try_from(evidence_total).ok() != Some(evidence.len()) {
            return Err(LifecycleError::CleanupIntegrity);
        }
        let mut redactions = Vec::with_capacity(evidence.len());
        let mut tombstoned_material_ids = BTreeSet::new();
        for (
            redaction_id,
            material_id,
            generation_number,
            material_provenance_sha256,
            material_tombstoned,
        ) in evidence
        {
            if material_tombstoned
                && (retention_material_provenance_sha256(connection, &material_id)?
                    != material_provenance_sha256
                    || !tombstoned_material_ids.insert(material_id.clone()))
            {
                return Err(LifecycleError::CleanupIntegrity);
            }
            redactions.push(RedactionCleanupAuthorizationV1 {
                redaction_id,
                material_id,
                generation_number,
            });
        }
        Ok(CleanupAuthorizationSnapshotV1 {
            redactions,
            tombstoned_material_ids: tombstoned_material_ids.into_iter().collect(),
        })
    }

    /// Returns `true` only when a physically absent redaction is covered by an exact,
    /// candidate-manifest-bound committed cleanup record. Legacy count-only cleanup events are
    /// deliberately insufficient authorization for migration-ledger target disappearance.
    pub fn redaction_cleanup_is_authorized(
        &self,
        connection: &Connection,
        redaction_id: &str,
        material_id: &str,
        generation_number: i64,
    ) -> Result<bool, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        if redaction_id.is_empty() || material_id.is_empty() || generation_number <= 0 {
            return Err(LifecycleError::InvalidInput);
        }
        Ok(self
            .cleanup_authorization_snapshot(connection)?
            .redactions
            .iter()
            .any(|entry| {
                entry.redaction_id == redaction_id
                    && entry.material_id == material_id
                    && entry.generation_number == generation_number
            }))
    }

    /// Identifies a final-generation retention tombstone without reconstructing erased review
    /// payloads. At least one exact v2 redaction-erasure record must name the retained material.
    pub fn material_cleanup_is_authorized(
        &self,
        connection: &Connection,
        material_id: &str,
    ) -> Result<bool, LifecycleError> {
        ensure_workspace(connection, &self.workspace_instance_id)?;
        if material_id.is_empty() {
            return Err(LifecycleError::InvalidInput);
        }
        Ok(self
            .cleanup_authorization_snapshot(connection)?
            .tombstoned_material_ids
            .iter()
            .any(|value| value == material_id))
    }
}

pub struct EncryptedPrivacyBackupStore {
    root: FixedLocalStorageRoot,
}

impl EncryptedPrivacyBackupStore {
    pub fn initialize(root: impl AsRef<Path>) -> Result<Self, LifecycleError> {
        let root = FixedLocalStorageRoot::initialize(root.as_ref()).map_err(map_vault_error)?;
        root.ensure_directory(Path::new(".staging"))
            .map_err(map_vault_error)?;
        root.ensure_directory(Path::new("backups"))
            .map_err(map_vault_error)?;
        cleanup_stale_backup_staging(&root)?;
        Ok(Self { root })
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self, LifecycleError> {
        let root = FixedLocalStorageRoot::open(root.as_ref()).map_err(map_vault_error)?;
        root.validate_existing_directory(Path::new(".staging"))
            .map_err(map_vault_error)?;
        root.validate_existing_directory(Path::new("backups"))
            .map_err(map_vault_error)?;
        cleanup_stale_backup_staging(&root)?;
        Ok(Self { root })
    }

    pub fn export_database(
        &self,
        connection: &mut Connection,
        lifecycle: &PrivacyLifecycle,
        request: &BackupExportRequestV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        self.export_database_with_schema_expectation(
            connection,
            lifecycle,
            request,
            BackupSchemaExpectation::Current,
        )
    }

    /// Creates a rollback backup before a v1-v5 privacy-store migration.
    ///
    /// This path is intentionally separate from `export_database`: callers must name the exact
    /// legacy schema they preflighted, and both the live database and the coherent snapshot must
    /// match it. Current or future schemas are never accepted through this API.
    pub fn export_pre_migration_database(
        &self,
        connection: &mut Connection,
        lifecycle: &PrivacyLifecycle,
        request: &BackupExportRequestV1<'_>,
        context: &PreMigrationBackupExportContextV1,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        self.export_database_with_schema_expectation(
            connection,
            lifecycle,
            request,
            BackupSchemaExpectation::PreMigration(context.expected_privacy_store_schema_version),
        )
    }

    fn export_database_with_schema_expectation(
        &self,
        connection: &mut Connection,
        lifecycle: &PrivacyLifecycle,
        request: &BackupExportRequestV1<'_>,
        schema_expectation: BackupSchemaExpectation,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        schema_expectation.expected_version()?;
        valid_opaque_id(request.backup_id, "bkp_")?;
        if request.created_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(connection, lifecycle.workspace_instance_id())?;
        let privacy_store_schema_version =
            schema_expectation.validate_actual(read_privacy_store_schema_version(connection)?)?;
        let maximum_database_bytes =
            max_backup_database_bytes_for_schema(privacy_store_schema_version)
                .ok_or(LifecycleError::InvalidInput)?;
        let maximum_envelope_bytes =
            max_backup_envelope_bytes_for_schema(privacy_store_schema_version)
                .ok_or(LifecycleError::InvalidInput)?;
        let policy = load_retention_policy(connection)?;
        let expires_at_unix = request.expires_at_unix.unwrap_or(
            request
                .created_at_unix
                .checked_add(policy.backup_retention_seconds)
                .ok_or(LifecycleError::InvalidInput)?,
        );
        if expires_at_unix <= request.created_at_unix
            || expires_at_unix - request.created_at_unix > MAX_RETENTION_SECONDS
        {
            return Err(LifecycleError::InvalidInput);
        }
        let key_epoch = lifecycle.current_key_epoch(connection)?;
        let snapshot_path = self.temporary_path(request.backup_id, "sqlite")?;
        let snapshot_result = snapshot_database(connection, &snapshot_path);
        let database_bytes = match snapshot_result {
            Ok(()) => {
                read_safe_file(&snapshot_path, maximum_database_bytes).map(ZeroizingBytes::new)
            }
            Err(error) => Err(error),
        };
        let database_bytes =
            finish_sensitive_temporary(&snapshot_path, self.root.canonical_root(), database_bytes)?;
        verify_sqlite_snapshot_bytes(
            &database_bytes,
            lifecycle.workspace_instance_id(),
            key_epoch,
            privacy_store_schema_version,
            &self.root,
            request.backup_id,
        )?;
        let database_sha256 = sha256_hex(&database_bytes);
        let data_key = SecretKey32::generate().map_err(map_crypto_error)?;
        let wrapped_data_key = wrap_case_key(&data_key).map_err(map_crypto_error)?;
        let wrapped_data_key_sha256 = sha256_hex(&wrapped_data_key);
        let database_length =
            u64::try_from(database_bytes.len()).map_err(|_| LifecycleError::InvalidInput)?;
        let aad = backup_aad(
            request.backup_id,
            lifecycle.workspace_instance_id(),
            privacy_store_schema_version,
            key_epoch,
            request.created_at_unix,
            expires_at_unix,
            database_length,
            &database_sha256,
            &wrapped_data_key_sha256,
        )?;
        let sealed = seal(&data_key, &database_bytes, &aad).map_err(map_crypto_error)?;
        let envelope = BackupEnvelopeV1 {
            schema_version: ENCRYPTED_BACKUP_SCHEMA_VERSION.to_owned(),
            crypto_suite: BACKUP_CRYPTO_SUITE.to_owned(),
            backup_id: request.backup_id.to_owned(),
            workspace_instance_id: lifecycle.workspace_instance_id().clone(),
            privacy_store_schema_version,
            lifecycle_schema_version: PRIVACY_LIFECYCLE_SCHEMA_VERSION,
            key_epoch,
            created_at_unix: request.created_at_unix,
            expires_at_unix,
            database_bytes: database_length,
            database_sha256: database_sha256.clone(),
            wrapped_data_key_base64: BASE64_STANDARD.encode(&wrapped_data_key),
            wrapped_data_key_sha256,
            nonce_base64: BASE64_STANDARD.encode(sealed.nonce()),
            ciphertext_base64: BASE64_STANDARD.encode(sealed.ciphertext()),
            ciphertext_sha256: sha256_hex(sealed.ciphertext()),
            tag_base64: BASE64_STANDARD.encode(sealed.tag()),
        };
        let envelope_bytes =
            canonical_json_v1(&envelope).map_err(|_| LifecycleError::BackupInvalid)?;
        if envelope_bytes.len() > maximum_envelope_bytes {
            return Err(LifecycleError::InvalidInput);
        }
        let envelope_sha256 = sha256_hex(&envelope_bytes);
        let final_path = self.backup_path(request.backup_id)?;
        write_atomic_new_file(
            self.root.canonical_root(),
            &self.root,
            &final_path,
            &envelope_bytes,
            request.backup_id,
        )?;
        let verified = VerifiedBackupV1 {
            backup_id: request.backup_id.to_owned(),
            workspace_instance_id: lifecycle.workspace_instance_id().clone(),
            privacy_store_schema_version,
            created_at_unix: request.created_at_unix,
            expires_at_unix,
            key_epoch,
            database_sha256,
            envelope_sha256,
        };
        if let Err(error) = self.write_initial_backup_state(&verified) {
            let _ = fs::remove_file(&final_path);
            return Err(error);
        }
        let insert = connection.execute(
            "INSERT INTO privacy_backup_registry(
               backup_id,envelope_sha256,created_at_unix,expires_at_unix,key_epoch,state
             ) VALUES(?1,?2,?3,?4,?5,'active')",
            params![
                request.backup_id,
                verified.envelope_sha256,
                sql_i64(request.created_at_unix)?,
                sql_i64(expires_at_unix)?,
                sql_i64(key_epoch)?
            ],
        );
        if insert.is_err() {
            let _ = fs::remove_file(&final_path);
            if let Ok(state_path) = self.backup_state_path(request.backup_id) {
                let _ = fs::remove_file(state_path);
            }
            return Err(LifecycleError::Conflict);
        }
        Ok(verified)
    }

    pub fn verify_backup(
        &self,
        registry_connection: &Connection,
        backup_id: &str,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let expectation = current_backup_verification_expectation(context);
        let (_, verified) =
            self.decrypt_and_verify(registry_connection, backup_id, &expectation)?;
        Ok(verified)
    }

    /// Verifies a backup created by `export_pre_migration_database`.
    ///
    /// The expected legacy schema is part of the authenticated envelope and AAD and must also
    /// match the decrypted SQLite snapshot. This does not make the normal verification path accept
    /// legacy schemas.
    pub fn verify_pre_migration_backup(
        &self,
        registry_connection: &Connection,
        backup_id: &str,
        context: &PreMigrationBackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let expectation = pre_migration_backup_verification_expectation(context)?;
        let (_, verified) =
            self.decrypt_and_verify(registry_connection, backup_id, &expectation)?;
        Ok(verified)
    }

    pub fn restore_into_empty_database(
        &self,
        registry_connection: &Connection,
        destination: &mut Connection,
        backup_id: &str,
        context: &BackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let expectation = current_backup_verification_expectation(context);
        self.restore_into_empty_database_with_expectation(
            registry_connection,
            destination,
            backup_id,
            &expectation,
        )
    }

    /// Restores an exact v1-v5 rollback snapshot without upgrading it.
    ///
    /// This is deliberately separate from the current-schema restore path. The caller must name
    /// the authenticated legacy schema exactly; future schemas and the current schema are rejected.
    pub fn restore_pre_migration_into_empty_database(
        &self,
        registry_connection: &Connection,
        destination: &mut Connection,
        backup_id: &str,
        context: &PreMigrationBackupVerificationContextV1<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        let expectation = pre_migration_backup_verification_expectation(context)?;
        self.restore_into_empty_database_with_expectation(
            registry_connection,
            destination,
            backup_id,
            &expectation,
        )
    }

    fn restore_into_empty_database_with_expectation(
        &self,
        registry_connection: &Connection,
        destination: &mut Connection,
        backup_id: &str,
        expectation: &BackupVerificationExpectation<'_>,
    ) -> Result<VerifiedBackupV1, LifecycleError> {
        ensure_empty_database(destination)?;
        let (database_bytes, verified) =
            self.decrypt_and_verify(registry_connection, backup_id, expectation)?;
        let snapshot_path = self.temporary_path(backup_id, "restore.sqlite")?;
        write_new_safe_file(&snapshot_path, &database_bytes)?;
        let restore_result = (|| {
            let source =
                Connection::open_with_flags(&snapshot_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                    .map_err(|_| LifecycleError::BackupInvalid)?;
            validate_sqlite_connection(
                &source,
                expectation.expected_workspace_instance_id,
                expectation.expected_key_epoch,
                expectation.expected_privacy_store_schema_version,
            )?;
            {
                let backup =
                    Backup::new(&source, destination).map_err(|_| LifecycleError::Database)?;
                backup
                    .run_to_completion(64, Duration::from_millis(1), None)
                    .map_err(|_| LifecycleError::Database)?;
            }
            validate_sqlite_connection(
                destination,
                expectation.expected_workspace_instance_id,
                expectation.expected_key_epoch,
                expectation.expected_privacy_store_schema_version,
            )
        })();
        finish_sensitive_temporary(&snapshot_path, self.root.canonical_root(), restore_result)?;
        Ok(verified)
    }

    pub fn revoke_backup(
        &self,
        connection: &Connection,
        backup_id: &str,
        revoked_at_unix: u64,
    ) -> Result<(), LifecycleError> {
        valid_opaque_id(backup_id, "bkp_")?;
        if revoked_at_unix == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        self.revoke_backup_state(backup_id, revoked_at_unix)?;
        let changed = connection
            .execute(
                "UPDATE privacy_backup_registry SET state='revoked',revoked_at_unix=?2
                 WHERE backup_id=?1 AND state='active'",
                params![backup_id, sql_i64(revoked_at_unix)?],
            )
            .map_err(|_| LifecycleError::Database)?;
        if changed == 1 {
            return Ok(());
        }
        let state = connection
            .query_row(
                "SELECT state FROM privacy_backup_registry WHERE backup_id=?1",
                [backup_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| LifecycleError::Database)?;
        if state.as_deref() == Some("revoked") {
            // Idempotent completion after the companion state was already persisted.
            return Ok(());
        }
        Err(LifecycleError::Conflict)
    }

    fn decrypt_and_verify(
        &self,
        registry_connection: &Connection,
        backup_id: &str,
        context: &BackupVerificationExpectation<'_>,
    ) -> Result<(ZeroizingBytes, VerifiedBackupV1), LifecycleError> {
        valid_opaque_id(backup_id, "bkp_")?;
        if context.now_unix == 0 || context.expected_key_epoch == 0 {
            return Err(LifecycleError::InvalidInput);
        }
        ensure_workspace(registry_connection, context.expected_workspace_instance_id)?;
        let registry: (String, i64, i64, i64, String) = registry_connection
            .query_row(
                "SELECT envelope_sha256,created_at_unix,expires_at_unix,key_epoch,state
                 FROM privacy_backup_registry WHERE backup_id=?1",
                [backup_id],
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
            .map_err(|_| LifecycleError::Database)?
            .ok_or(LifecycleError::BackupNotAvailable)?;
        if registry.4 == "revoked" {
            return Err(LifecycleError::BackupRevoked);
        }
        if registry.4 != "active" {
            return Err(LifecycleError::BackupInvalid);
        }
        let expires_at_unix = sql_u64(registry.2)?;
        if context.now_unix >= expires_at_unix {
            return Err(LifecycleError::BackupExpired);
        }
        if sql_u64(registry.3)? != context.expected_key_epoch {
            return Err(LifecycleError::EnvironmentMismatch);
        }
        let path = self.backup_path(backup_id)?;
        let envelope_bytes = read_safe_file(&path, MAX_BACKUP_ENVELOPE_BYTES)?;
        let envelope_sha256 = sha256_hex(&envelope_bytes);
        if envelope_sha256 != registry.0 {
            return Err(LifecycleError::BackupTampered);
        }
        let envelope: BackupEnvelopeV1 = strict_json_v1_from_slice(&envelope_bytes)
            .map_err(|_| LifecycleError::BackupInvalid)?;
        let maximum_envelope_bytes =
            max_backup_envelope_bytes_for_schema(envelope.privacy_store_schema_version)
                .ok_or(LifecycleError::BackupInvalid)?;
        let maximum_database_bytes =
            max_backup_database_bytes_for_schema(envelope.privacy_store_schema_version)
                .ok_or(LifecycleError::BackupInvalid)?;
        if envelope_bytes.len() > maximum_envelope_bytes {
            return Err(LifecycleError::BackupInvalid);
        }
        validate_backup_envelope(&envelope, backup_id, context, &registry)?;
        let wrapped = decode_bounded_base64(&envelope.wrapped_data_key_base64, 64 * 1024)?;
        if sha256_hex(&wrapped) != envelope.wrapped_data_key_sha256 {
            return Err(LifecycleError::BackupTampered);
        }
        let key = unwrap_case_key(&wrapped).map_err(map_crypto_error)?;
        let nonce = decode_bounded_base64(&envelope.nonce_base64, 64)?;
        let ciphertext =
            decode_bounded_base64(&envelope.ciphertext_base64, maximum_database_bytes)?;
        let tag = decode_bounded_base64(&envelope.tag_base64, 64)?;
        if sha256_hex(&ciphertext) != envelope.ciphertext_sha256 {
            return Err(LifecycleError::BackupTampered);
        }
        let sealed = AeadSealedV1::from_parts(&nonce, ciphertext, &tag)
            .map_err(|_| LifecycleError::BackupInvalid)?;
        let aad = backup_aad(
            backup_id,
            context.expected_workspace_instance_id,
            envelope.privacy_store_schema_version,
            envelope.key_epoch,
            envelope.created_at_unix,
            envelope.expires_at_unix,
            envelope.database_bytes,
            &envelope.database_sha256,
            &envelope.wrapped_data_key_sha256,
        )?;
        let database_bytes =
            ZeroizingBytes::new(open(&key, &sealed, &aad).map_err(map_crypto_error)?);
        if u64::try_from(database_bytes.len()).ok() != Some(envelope.database_bytes)
            || sha256_hex(&database_bytes) != envelope.database_sha256
        {
            return Err(LifecycleError::BackupTampered);
        }
        verify_sqlite_snapshot_bytes(
            &database_bytes,
            context.expected_workspace_instance_id,
            context.expected_key_epoch,
            context.expected_privacy_store_schema_version,
            &self.root,
            backup_id,
        )?;
        Ok((
            database_bytes,
            VerifiedBackupV1 {
                backup_id: backup_id.to_owned(),
                workspace_instance_id: envelope.workspace_instance_id,
                privacy_store_schema_version: envelope.privacy_store_schema_version,
                created_at_unix: envelope.created_at_unix,
                expires_at_unix: envelope.expires_at_unix,
                key_epoch: envelope.key_epoch,
                database_sha256: envelope.database_sha256,
                envelope_sha256,
            },
        ))
    }

    fn backup_path(&self, backup_id: &str) -> Result<PathBuf, LifecycleError> {
        valid_opaque_id(backup_id, "bkp_")?;
        Ok(self
            .root
            .canonical_root()
            .join("backups")
            .join(format!("{backup_id}.lavbackup")))
    }

    fn temporary_path(&self, backup_id: &str, suffix: &str) -> Result<PathBuf, LifecycleError> {
        valid_opaque_id(backup_id, "bkp_")?;
        if suffix.is_empty()
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.')
        {
            return Err(LifecycleError::InvalidInput);
        }
        let mut random = [0_u8; 8];
        crate::vault_crypto::fill_random(&mut random).map_err(map_crypto_error)?;
        Ok(self
            .root
            .canonical_root()
            .join(".staging")
            .join(format!("{backup_id}-{}-{suffix}", hex_lower(&random))))
    }
}

pub(crate) fn initialize_lifecycle_schema(
    connection: &Connection,
) -> Result<(), PrivacyStoreError> {
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS privacy_lifecycle_meta(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               schema_version INTEGER NOT NULL,
               workspace_instance_id TEXT NOT NULL,
               active_mapping_key_version INTEGER NOT NULL CHECK(active_mapping_key_version>0),
               key_epoch INTEGER NOT NULL CHECK(key_epoch>0),
               created_at_unix INTEGER NOT NULL CHECK(created_at_unix>0)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS privacy_mapping_keys(
               key_version INTEGER PRIMARY KEY CHECK(key_version>0),
               protected_key BLOB,
               protected_key_sha256 TEXT NOT NULL CHECK(length(protected_key_sha256)=64),
               state TEXT NOT NULL CHECK(state IN('active','retired','revoked','destroyed')),
               created_at_unix INTEGER NOT NULL CHECK(created_at_unix>0),
               retired_at_unix INTEGER,
               revoked_at_unix INTEGER,
               destroyed_at_unix INTEGER,
               CHECK((state='destroyed' AND protected_key IS NULL AND destroyed_at_unix IS NOT NULL)
                  OR (state!='destroyed' AND protected_key IS NOT NULL))
             ) STRICT;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_privacy_mapping_one_active_key
               ON privacy_mapping_keys(state) WHERE state='active';
             CREATE TABLE IF NOT EXISTS privacy_sensitive_mappings(
               mapping_id TEXT PRIMARY KEY,
               redaction_id TEXT NOT NULL,
               revision INTEGER NOT NULL CHECK(revision>0),
               key_version INTEGER NOT NULL,
               nonce BLOB NOT NULL CHECK(length(nonce)=12),
               ciphertext BLOB NOT NULL CHECK(length(ciphertext)>0),
               tag BLOB NOT NULL CHECK(length(tag)=16),
               ciphertext_sha256 TEXT NOT NULL CHECK(length(ciphertext_sha256)=64),
               mapping_revision_sha256 TEXT NOT NULL CHECK(length(mapping_revision_sha256)=64),
               created_at_unix INTEGER NOT NULL CHECK(created_at_unix>0),
               expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix>created_at_unix),
               revoked_at_unix INTEGER,
               UNIQUE(redaction_id,revision),
               FOREIGN KEY(redaction_id) REFERENCES privacy_redactions(redaction_id) ON DELETE CASCADE,
               FOREIGN KEY(key_version) REFERENCES privacy_mapping_keys(key_version)
             ) STRICT;
             CREATE INDEX IF NOT EXISTS idx_privacy_mapping_expiry
               ON privacy_sensitive_mappings(expires_at_unix,redaction_id);
             CREATE TABLE IF NOT EXISTS privacy_retention_policy(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               policy_id TEXT NOT NULL,
               review_retention_seconds INTEGER NOT NULL CHECK(review_retention_seconds>0),
               mapping_retention_seconds INTEGER NOT NULL CHECK(mapping_retention_seconds>0),
               receipt_grace_seconds INTEGER NOT NULL CHECK(receipt_grace_seconds>=0),
               backup_retention_seconds INTEGER NOT NULL CHECK(backup_retention_seconds>0),
               revision INTEGER NOT NULL CHECK(revision>0),
               updated_at_unix INTEGER NOT NULL CHECK(updated_at_unix>0)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS privacy_retention_bindings(
               redaction_id TEXT PRIMARY KEY,
               expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix>0),
               legal_hold INTEGER NOT NULL CHECK(legal_hold IN(0,1)),
               bound_at_unix INTEGER NOT NULL CHECK(bound_at_unix>0),
               policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
               hold_changed_at_unix INTEGER,
               FOREIGN KEY(redaction_id) REFERENCES privacy_redactions(redaction_id) ON DELETE CASCADE
             ) STRICT;
             CREATE TABLE IF NOT EXISTS privacy_cleanup_journal(
               cleanup_id TEXT PRIMARY KEY,
               state TEXT NOT NULL CHECK(state IN('prepared','committed','failed')),
               policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
               started_at_unix INTEGER NOT NULL CHECK(started_at_unix>0),
               completed_at_unix INTEGER,
               candidate_count INTEGER NOT NULL DEFAULT 0 CHECK(candidate_count>=0),
               removed_count INTEGER NOT NULL DEFAULT 0 CHECK(removed_count>=0),
               keys_destroyed INTEGER NOT NULL DEFAULT 0 CHECK(keys_destroyed>=0),
               error_code TEXT,
               previous_event_hash TEXT NOT NULL CHECK(length(previous_event_hash) IN(0,64)),
               event_hash TEXT NOT NULL CHECK(length(event_hash) IN(0,64)),
               erasure_disclosure TEXT NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS privacy_cleanup_candidates(
               cleanup_id TEXT NOT NULL,
               target_kind TEXT NOT NULL CHECK(target_kind IN('redaction','mapping','approved_output','receipt')),
               target_id TEXT NOT NULL,
               expected_sha256 TEXT NOT NULL CHECK(length(expected_sha256)=64),
               state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','removed')),
               PRIMARY KEY(cleanup_id,target_kind,target_id),
               FOREIGN KEY(cleanup_id) REFERENCES privacy_cleanup_journal(cleanup_id)
             ) STRICT;
             CREATE INDEX IF NOT EXISTS idx_privacy_cleanup_previous_event_hash
               ON privacy_cleanup_journal(state,previous_event_hash);
             CREATE TABLE IF NOT EXISTS privacy_cleanup_redaction_evidence(
               cleanup_id TEXT NOT NULL,
               redaction_id TEXT NOT NULL UNIQUE,
               material_id TEXT NOT NULL,
               generation_number INTEGER NOT NULL CHECK(generation_number>0),
               expected_sha256 TEXT NOT NULL CHECK(length(expected_sha256)=64),
               material_provenance_sha256 TEXT NOT NULL CHECK(
                 length(material_provenance_sha256)=64
               ),
               material_tombstoned INTEGER NOT NULL CHECK(material_tombstoned IN(0,1)),
               PRIMARY KEY(cleanup_id,redaction_id),
               FOREIGN KEY(cleanup_id) REFERENCES privacy_cleanup_journal(cleanup_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS privacy_mapping_access_audit(
               access_id TEXT PRIMARY KEY,
               mapping_id TEXT NOT NULL,
               redaction_id TEXT NOT NULL,
               purpose_sha256 TEXT NOT NULL CHECK(length(purpose_sha256)=64),
               occurred_at_unix INTEGER NOT NULL CHECK(occurred_at_unix>0),
               allowed INTEGER NOT NULL CHECK(allowed IN(0,1)),
               reason_code TEXT NOT NULL,
               previous_event_hash TEXT NOT NULL CHECK(length(previous_event_hash) IN(0,64)),
               event_hash TEXT NOT NULL UNIQUE CHECK(length(event_hash)=64)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS privacy_approved_outputs(
               output_id TEXT PRIMARY KEY,
               redaction_id TEXT NOT NULL,
               approval_generation_id TEXT NOT NULL CHECK(length(approval_generation_id) BETWEEN 1 AND 128),
               receipt_id TEXT NOT NULL,
               provider_sha256 TEXT NOT NULL CHECK(length(provider_sha256)=64),
               model_sha256 TEXT NOT NULL CHECK(length(model_sha256)=64),
               purpose_sha256 TEXT NOT NULL CHECK(length(purpose_sha256)=64),
               approved_payload_sha256 TEXT NOT NULL CHECK(length(approved_payload_sha256)=64),
               content_sha256 TEXT NOT NULL CHECK(length(content_sha256)=64),
               content_bytes INTEGER NOT NULL CHECK(content_bytes>0),
               protected_content BLOB NOT NULL CHECK(length(protected_content)>0),
               protection_scheme TEXT NOT NULL CHECK(protection_scheme='windows_dpapi_current_user_v1'),
               created_at_unix INTEGER NOT NULL CHECK(created_at_unix>0),
               expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix>created_at_unix),
               revoked_at_unix INTEGER,
               UNIQUE(redaction_id,approval_generation_id,provider_sha256,model_sha256,purpose_sha256),
               FOREIGN KEY(redaction_id) REFERENCES privacy_redactions(redaction_id) ON DELETE CASCADE,
               FOREIGN KEY(receipt_id) REFERENCES privacy_receipts(receipt_id) ON DELETE CASCADE
             ) STRICT;
             CREATE INDEX IF NOT EXISTS idx_privacy_approved_output_expiry
               ON privacy_approved_outputs(expires_at_unix,redaction_id);
             CREATE TABLE IF NOT EXISTS privacy_backup_registry(
               backup_id TEXT PRIMARY KEY,
               envelope_sha256 TEXT NOT NULL CHECK(length(envelope_sha256)=64),
               created_at_unix INTEGER NOT NULL CHECK(created_at_unix>0),
               expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix>created_at_unix),
               key_epoch INTEGER NOT NULL CHECK(key_epoch>0),
               state TEXT NOT NULL CHECK(state IN('active','revoked')),
               revoked_at_unix INTEGER
             ) STRICT;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_no_delete
               BEFORE DELETE ON privacy_cleanup_journal BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup journal is append only');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_no_replace
               BEFORE INSERT ON privacy_cleanup_journal
               WHEN EXISTS(
                 SELECT 1 FROM privacy_cleanup_journal AS existing
                 WHERE existing.cleanup_id=NEW.cleanup_id
               ) BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup journal is append only');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_final_no_update
               BEFORE UPDATE ON privacy_cleanup_journal
               WHEN OLD.state!='prepared' BEGIN
                 SELECT RAISE(ABORT,'final privacy cleanup journal is immutable');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_candidate_no_delete
               BEFORE DELETE ON privacy_cleanup_candidates BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup candidate is append preserving');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_candidate_no_replace
               BEFORE INSERT ON privacy_cleanup_candidates
               WHEN EXISTS(
                 SELECT 1 FROM privacy_cleanup_candidates AS existing
                 WHERE existing.cleanup_id=NEW.cleanup_id
                   AND existing.target_kind=NEW.target_kind
                   AND existing.target_id=NEW.target_id
               ) BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup candidate is append preserving');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_candidate_one_way
               BEFORE UPDATE ON privacy_cleanup_candidates
               WHEN NEW.cleanup_id IS NOT OLD.cleanup_id
                 OR NEW.target_kind IS NOT OLD.target_kind
                 OR NEW.target_id IS NOT OLD.target_id
                 OR NEW.expected_sha256 IS NOT OLD.expected_sha256
                 OR OLD.state<>'pending'
                 OR NEW.state<>'removed'
                 OR NOT EXISTS(
                   SELECT 1 FROM privacy_cleanup_journal AS journal
                   WHERE journal.cleanup_id=OLD.cleanup_id
                     AND journal.state='prepared'
                 )
               BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup candidate transition is invalid');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_redaction_evidence_no_update
               BEFORE UPDATE ON privacy_cleanup_redaction_evidence BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup redaction evidence is immutable');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_redaction_evidence_no_delete
               BEFORE DELETE ON privacy_cleanup_redaction_evidence BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup redaction evidence is append only');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_cleanup_redaction_evidence_no_replace
               BEFORE INSERT ON privacy_cleanup_redaction_evidence
               WHEN EXISTS(
                 SELECT 1 FROM privacy_cleanup_redaction_evidence AS existing
                 WHERE existing.redaction_id=NEW.redaction_id
                    OR (
                      NEW.material_tombstoned=1
                      AND existing.material_id=NEW.material_id
                      AND existing.material_tombstoned=1
                    )
               ) BEGIN
                 SELECT RAISE(ABORT,'privacy cleanup redaction evidence is append only');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_mapping_access_no_update
               BEFORE UPDATE ON privacy_mapping_access_audit BEGIN
                 SELECT RAISE(ABORT,'privacy mapping access audit is append only');
               END;
             CREATE TRIGGER IF NOT EXISTS trg_privacy_mapping_access_no_delete
               BEFORE DELETE ON privacy_mapping_access_audit BEGIN
                 SELECT RAISE(ABORT,'privacy mapping access audit is append only');
               END;",
        )
        .map_err(|_| PrivacyStoreError::Database)
}

include!("lifecycle_mapping_audit.rs");
include!("lifecycle_support.rs");
