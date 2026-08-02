//! Canonical, append-only receipts for the v0.3.1 to v0.4.0 upgrade.
//!
//! This module owns only the protected receipt wire and chain validation. It
//! deliberately does not enumerate directories, install files, replace files,
//! or compare a receipt with live component state. The desktop orchestrator
//! must pass every directory entry through this validator before performing a
//! target write and must install an authenticated `.incoming` artifact with
//! create-new/no-replacement semantics.

use crate::{
    protected_blob::{
        protect_local, unprotect_local, ProtectedBlobError, MAX_PROTECTED_PLAINTEXT_BYTES,
    },
    vnext::{canonical_json_v1, strict_json_v1_from_slice},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, error::Error, fmt};
use zeroize::{Zeroize, Zeroizing};

pub const V031_UPGRADE_RECEIPT_SCHEMA_VERSION: &str = "lawyer-assistance-v031-upgrade-receipt-v1";
pub const V031_UPGRADE_RECEIPT_MIGRATION_ID: &str = "v0.3.1-to-v0.4.0-user-schema-v1";
pub const V031_UPGRADE_RECEIPT_RESULT_CODE: &str = "ok";
pub const V031_UPGRADE_RECEIPT_STAGE_COUNT: usize = 10;
pub const MAX_V031_UPGRADE_RECEIPT_PLAINTEXT_BYTES: usize = 64 * 1024;
pub const MAX_V031_UPGRADE_RECEIPT_PROTECTED_BYTES: usize = 256 * 1024;
pub const MAX_V031_UPGRADE_RECEIPT_COUNT: u64 = i64::MAX as u64;
pub const MAX_V031_UPGRADE_RECEIPT_CREATED_AT_UNIX: u64 = 253_402_300_799;

// Receipt 8 authenticates the canonical full-v6 application manifest. Keep
// its exact count bound to the manifest's single table-name source so schema
// expansion cannot silently diverge from the protected receipt contract.
const V031_USER_V11_PRIVACY_MANIFEST_TABLE_COUNT: u64 =
    crate::current_manifest::PRIVACY_V6_APPLICATION_TABLES.len() as u64;

pub const V031_UPGRADE_RECEIPT_FINAL_BASENAMES: [&str; V031_UPGRADE_RECEIPT_STAGE_COUNT] = [
    "00-source_preflight_verified.receipt.dpapi",
    "01-original_rollback_verified.receipt.dpapi",
    "02-target_components_prepared.receipt.dpapi",
    "03-case_migration_backups_verified.receipt.dpapi",
    "04-privacy_v5_verified.receipt.dpapi",
    "05-binding_materials_verified.receipt.dpapi",
    "06-projection_backup_verified.receipt.dpapi",
    "07-privacy_v6_verified.receipt.dpapi",
    "08-user_v11_verified.receipt.dpapi",
    "09-upgrade_complete.receipt.dpapi",
];

pub const V031_UPGRADE_RECEIPT_INCOMING_BASENAMES: [&str; V031_UPGRADE_RECEIPT_STAGE_COUNT] = [
    "00-source_preflight_verified.receipt.dpapi.incoming",
    "01-original_rollback_verified.receipt.dpapi.incoming",
    "02-target_components_prepared.receipt.dpapi.incoming",
    "03-case_migration_backups_verified.receipt.dpapi.incoming",
    "04-privacy_v5_verified.receipt.dpapi.incoming",
    "05-binding_materials_verified.receipt.dpapi.incoming",
    "06-projection_backup_verified.receipt.dpapi.incoming",
    "07-privacy_v6_verified.receipt.dpapi.incoming",
    "08-user_v11_verified.receipt.dpapi.incoming",
    "09-upgrade_complete.receipt.dpapi.incoming",
];

const EVIDENCE_SOURCE_PREFLIGHT_V1: &str =
    "lawyer-assistance-v031-upgrade-evidence-source-preflight-v1";
const EVIDENCE_ORIGINAL_ROLLBACK_V1: &str =
    "lawyer-assistance-v031-upgrade-evidence-original-rollback-v1";
const EVIDENCE_TARGET_COMPONENTS_V1: &str =
    "lawyer-assistance-v031-upgrade-evidence-target-components-v1";
const EVIDENCE_CASE_MIGRATION_BACKUPS_V1: &str =
    "lawyer-assistance-v031-upgrade-evidence-case-migration-backups-v1";
const EVIDENCE_PRIVACY_V5_V1: &str = "lawyer-assistance-v031-upgrade-evidence-privacy-v5-v1";
const EVIDENCE_BINDING_MATERIALS_V1: &str =
    "lawyer-assistance-v031-upgrade-evidence-binding-materials-v1";
const EVIDENCE_PROJECTION_BACKUP_V1: &str =
    "lawyer-assistance-v031-upgrade-evidence-projection-backup-v1";
const EVIDENCE_PRIVACY_V6_V1: &str = "lawyer-assistance-v031-upgrade-evidence-privacy-v6-v1";
const EVIDENCE_USER_V11_V1: &str = "lawyer-assistance-v031-upgrade-evidence-user-v11-v1";
const EVIDENCE_UPGRADE_COMPLETE_V1: &str =
    "lawyer-assistance-v031-upgrade-evidence-upgrade-complete-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V031UpgradeReceiptError {
    InvalidContext,
    InvalidHash,
    InvalidTimestamp,
    InvalidCounts,
    CountOverflow,
    ArtifactTooLarge,
    PlatformUnavailable,
    ProtectionFailed,
    CurrentUserAuthenticationFailed,
    InvalidPlaintext,
    NonCanonicalPlaintext,
    ReceiptMismatch,
    UnknownArtifact,
    DuplicateArtifact,
    NonContiguousChain,
    BrokenChain,
    MultipleIncoming,
    UnexpectedIncoming,
    TimestampRegression,
}

impl V031UpgradeReceiptError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidContext => "v031_upgrade_receipt_context_invalid",
            Self::InvalidHash => "v031_upgrade_receipt_hash_invalid",
            Self::InvalidTimestamp => "v031_upgrade_receipt_timestamp_invalid",
            Self::InvalidCounts => "v031_upgrade_receipt_counts_invalid",
            Self::CountOverflow => "v031_upgrade_receipt_count_overflow",
            Self::ArtifactTooLarge => "v031_upgrade_receipt_artifact_too_large",
            Self::PlatformUnavailable => "v031_upgrade_receipt_platform_unavailable",
            Self::ProtectionFailed => "v031_upgrade_receipt_protection_failed",
            Self::CurrentUserAuthenticationFailed => {
                "v031_upgrade_receipt_current_user_authentication_failed"
            }
            Self::InvalidPlaintext => "v031_upgrade_receipt_plaintext_invalid",
            Self::NonCanonicalPlaintext => "v031_upgrade_receipt_plaintext_noncanonical",
            Self::ReceiptMismatch => "v031_upgrade_receipt_mismatch",
            Self::UnknownArtifact => "v031_upgrade_receipt_artifact_unknown",
            Self::DuplicateArtifact => "v031_upgrade_receipt_artifact_duplicate",
            Self::NonContiguousChain => "v031_upgrade_receipt_chain_noncontiguous",
            Self::BrokenChain => "v031_upgrade_receipt_chain_broken",
            Self::MultipleIncoming => "v031_upgrade_receipt_incoming_multiple",
            Self::UnexpectedIncoming => "v031_upgrade_receipt_incoming_unexpected",
            Self::TimestampRegression => "v031_upgrade_receipt_timestamp_regression",
        }
    }
}

impl fmt::Display for V031UpgradeReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for V031UpgradeReceiptError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V031UpgradeReceiptStage {
    SourcePreflightVerified,
    OriginalRollbackVerified,
    TargetComponentsPrepared,
    CaseMigrationBackupsVerified,
    PrivacyV5Verified,
    BindingMaterialsVerified,
    ProjectionBackupVerified,
    PrivacyV6Verified,
    UserV11Verified,
    UpgradeComplete,
}

impl V031UpgradeReceiptStage {
    pub const ALL: [Self; V031_UPGRADE_RECEIPT_STAGE_COUNT] = [
        Self::SourcePreflightVerified,
        Self::OriginalRollbackVerified,
        Self::TargetComponentsPrepared,
        Self::CaseMigrationBackupsVerified,
        Self::PrivacyV5Verified,
        Self::BindingMaterialsVerified,
        Self::ProjectionBackupVerified,
        Self::PrivacyV6Verified,
        Self::UserV11Verified,
        Self::UpgradeComplete,
    ];

    pub const fn ordinal(self) -> u8 {
        match self {
            Self::SourcePreflightVerified => 0,
            Self::OriginalRollbackVerified => 1,
            Self::TargetComponentsPrepared => 2,
            Self::CaseMigrationBackupsVerified => 3,
            Self::PrivacyV5Verified => 4,
            Self::BindingMaterialsVerified => 5,
            Self::ProjectionBackupVerified => 6,
            Self::PrivacyV6Verified => 7,
            Self::UserV11Verified => 8,
            Self::UpgradeComplete => 9,
        }
    }

    pub const fn from_ordinal(ordinal: u8) -> Option<Self> {
        match ordinal {
            0 => Some(Self::SourcePreflightVerified),
            1 => Some(Self::OriginalRollbackVerified),
            2 => Some(Self::TargetComponentsPrepared),
            3 => Some(Self::CaseMigrationBackupsVerified),
            4 => Some(Self::PrivacyV5Verified),
            5 => Some(Self::BindingMaterialsVerified),
            6 => Some(Self::ProjectionBackupVerified),
            7 => Some(Self::PrivacyV6Verified),
            8 => Some(Self::UserV11Verified),
            9 => Some(Self::UpgradeComplete),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourcePreflightVerified => "source_preflight_verified",
            Self::OriginalRollbackVerified => "original_rollback_verified",
            Self::TargetComponentsPrepared => "target_components_prepared",
            Self::CaseMigrationBackupsVerified => "case_migration_backups_verified",
            Self::PrivacyV5Verified => "privacy_v5_verified",
            Self::BindingMaterialsVerified => "binding_materials_verified",
            Self::ProjectionBackupVerified => "projection_backup_verified",
            Self::PrivacyV6Verified => "privacy_v6_verified",
            Self::UserV11Verified => "user_v11_verified",
            Self::UpgradeComplete => "upgrade_complete",
        }
    }

    pub const fn final_basename(self) -> &'static str {
        V031_UPGRADE_RECEIPT_FINAL_BASENAMES[self.ordinal() as usize]
    }

    pub const fn incoming_basename(self) -> &'static str {
        V031_UPGRADE_RECEIPT_INCOMING_BASENAMES[self.ordinal() as usize]
    }

    pub const fn evidence_schema_version(self) -> &'static str {
        match self {
            Self::SourcePreflightVerified => EVIDENCE_SOURCE_PREFLIGHT_V1,
            Self::OriginalRollbackVerified => EVIDENCE_ORIGINAL_ROLLBACK_V1,
            Self::TargetComponentsPrepared => EVIDENCE_TARGET_COMPONENTS_V1,
            Self::CaseMigrationBackupsVerified => EVIDENCE_CASE_MIGRATION_BACKUPS_V1,
            Self::PrivacyV5Verified => EVIDENCE_PRIVACY_V5_V1,
            Self::BindingMaterialsVerified => EVIDENCE_BINDING_MATERIALS_V1,
            Self::ProjectionBackupVerified => EVIDENCE_PROJECTION_BACKUP_V1,
            Self::PrivacyV6Verified => EVIDENCE_PRIVACY_V6_V1,
            Self::UserV11Verified => EVIDENCE_USER_V11_V1,
            Self::UpgradeComplete => EVIDENCE_UPGRADE_COMPLETE_V1,
        }
    }

    pub const fn count_keys(self) -> &'static [V031UpgradeReceiptCountKey] {
        match self {
            Self::SourcePreflightVerified => &SOURCE_PREFLIGHT_COUNT_KEYS,
            Self::OriginalRollbackVerified => &ORIGINAL_ROLLBACK_COUNT_KEYS,
            Self::TargetComponentsPrepared => &TARGET_COMPONENTS_COUNT_KEYS,
            Self::CaseMigrationBackupsVerified => &CASE_MIGRATION_BACKUPS_COUNT_KEYS,
            Self::PrivacyV5Verified => &PRIVACY_V5_COUNT_KEYS,
            Self::BindingMaterialsVerified => &BINDING_MATERIALS_COUNT_KEYS,
            Self::ProjectionBackupVerified => &PROJECTION_BACKUP_COUNT_KEYS,
            Self::PrivacyV6Verified => &PRIVACY_V6_COUNT_KEYS,
            Self::UserV11Verified => &USER_V11_COUNT_KEYS,
            Self::UpgradeComplete => &UPGRADE_COMPLETE_COUNT_KEYS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V031UpgradeReceiptCountKey {
    UserSchemaObjects,
    PrivacySchemaObjects,
    PresentSlots,
    AuthenticatedAbsentSlots,
    TargetAbsenceChecks,
    CapacityChecks,
    ProtectedPayloads,
    IdentityArtifacts,
    BundleArtifacts,
    RollbackSlots,
    SqliteImages,
    EncryptedChunks,
    SourceRevalidations,
    TargetCredentials,
    WorkspaceIdentities,
    EmptyTargetComponents,
    BindingCheckpoints,
    MaterialCheckpoints,
    CheckpointComponents,
    PrivacyMigrationBatches,
    BindingLedgerRows,
    MaterialLedgerRows,
    TerminalRows,
    BlockedRows,
    ProjectionCheckpoints,
    ApprovedGenerations,
    ProjectionRows,
    RiskHeads,
    RevocationRows,
    SecurityTriggers,
    BindingsVerified,
    UserAuditRows,
    PrivacyLineageRows,
    UserManifestTables,
    UserManifestRows,
    PrivacyManifestTables,
    PrivacyManifestRows,
    FinalComponentSlots,
    Restarts,
    NoopMigrations,
    FinalManifestEntries,
    MaintenanceActions,
}

const SOURCE_PREFLIGHT_COUNT_KEYS: [V031UpgradeReceiptCountKey; 7] = [
    V031UpgradeReceiptCountKey::UserSchemaObjects,
    V031UpgradeReceiptCountKey::PrivacySchemaObjects,
    V031UpgradeReceiptCountKey::PresentSlots,
    V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots,
    V031UpgradeReceiptCountKey::TargetAbsenceChecks,
    V031UpgradeReceiptCountKey::CapacityChecks,
    V031UpgradeReceiptCountKey::ProtectedPayloads,
];
const ORIGINAL_ROLLBACK_COUNT_KEYS: [V031UpgradeReceiptCountKey; 7] = [
    V031UpgradeReceiptCountKey::IdentityArtifacts,
    V031UpgradeReceiptCountKey::BundleArtifacts,
    V031UpgradeReceiptCountKey::RollbackSlots,
    V031UpgradeReceiptCountKey::SqliteImages,
    V031UpgradeReceiptCountKey::EncryptedChunks,
    V031UpgradeReceiptCountKey::SourceRevalidations,
    V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots,
];
const TARGET_COMPONENTS_COUNT_KEYS: [V031UpgradeReceiptCountKey; 3] = [
    V031UpgradeReceiptCountKey::TargetCredentials,
    V031UpgradeReceiptCountKey::WorkspaceIdentities,
    V031UpgradeReceiptCountKey::EmptyTargetComponents,
];
const CASE_MIGRATION_BACKUPS_COUNT_KEYS: [V031UpgradeReceiptCountKey; 3] = [
    V031UpgradeReceiptCountKey::BindingCheckpoints,
    V031UpgradeReceiptCountKey::MaterialCheckpoints,
    V031UpgradeReceiptCountKey::CheckpointComponents,
];
const PRIVACY_V5_COUNT_KEYS: [V031UpgradeReceiptCountKey; 2] = [
    V031UpgradeReceiptCountKey::PrivacySchemaObjects,
    V031UpgradeReceiptCountKey::PrivacyMigrationBatches,
];
const BINDING_MATERIALS_COUNT_KEYS: [V031UpgradeReceiptCountKey; 5] = [
    V031UpgradeReceiptCountKey::BindingLedgerRows,
    V031UpgradeReceiptCountKey::MaterialLedgerRows,
    V031UpgradeReceiptCountKey::TerminalRows,
    V031UpgradeReceiptCountKey::BlockedRows,
    V031UpgradeReceiptCountKey::PrivacyMigrationBatches,
];
const PROJECTION_BACKUP_COUNT_KEYS: [V031UpgradeReceiptCountKey; 4] = [
    V031UpgradeReceiptCountKey::ProjectionCheckpoints,
    V031UpgradeReceiptCountKey::CheckpointComponents,
    V031UpgradeReceiptCountKey::ApprovedGenerations,
    V031UpgradeReceiptCountKey::SourceRevalidations,
];
const PRIVACY_V6_COUNT_KEYS: [V031UpgradeReceiptCountKey; 6] = [
    V031UpgradeReceiptCountKey::PrivacySchemaObjects,
    V031UpgradeReceiptCountKey::ProjectionRows,
    V031UpgradeReceiptCountKey::RiskHeads,
    V031UpgradeReceiptCountKey::RevocationRows,
    V031UpgradeReceiptCountKey::SecurityTriggers,
    V031UpgradeReceiptCountKey::BindingsVerified,
];
const USER_V11_COUNT_KEYS: [V031UpgradeReceiptCountKey; 7] = [
    V031UpgradeReceiptCountKey::UserAuditRows,
    V031UpgradeReceiptCountKey::PrivacyLineageRows,
    V031UpgradeReceiptCountKey::UserManifestTables,
    V031UpgradeReceiptCountKey::UserManifestRows,
    V031UpgradeReceiptCountKey::PrivacyManifestTables,
    V031UpgradeReceiptCountKey::PrivacyManifestRows,
    V031UpgradeReceiptCountKey::FinalComponentSlots,
];
const UPGRADE_COMPLETE_COUNT_KEYS: [V031UpgradeReceiptCountKey; 5] = [
    V031UpgradeReceiptCountKey::Restarts,
    V031UpgradeReceiptCountKey::NoopMigrations,
    V031UpgradeReceiptCountKey::FinalComponentSlots,
    V031UpgradeReceiptCountKey::FinalManifestEntries,
    V031UpgradeReceiptCountKey::MaintenanceActions,
];

#[derive(Debug, Clone, Copy)]
pub struct V031UpgradeReceiptChainContext<'a> {
    pub lineage_id: &'a str,
    pub envelope_binding_id: &'a str,
    pub source_profile_proof_sha256: &'a str,
}

/// Authenticated context recovered from an ordinal-zero receipt after a crash
/// that happened before the V2 identity was installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredV031UpgradeReceiptChainContextV1 {
    lineage_id: String,
    envelope_binding_id: String,
    source_profile_proof_sha256: String,
}

impl DiscoveredV031UpgradeReceiptChainContextV1 {
    pub fn as_borrowed(&self) -> V031UpgradeReceiptChainContext<'_> {
        V031UpgradeReceiptChainContext {
            lineage_id: &self.lineage_id,
            envelope_binding_id: &self.envelope_binding_id,
            source_profile_proof_sha256: &self.source_profile_proof_sha256,
        }
    }
}

pub struct V031UpgradeReceiptCreateRequest<'a> {
    pub context: V031UpgradeReceiptChainContext<'a>,
    pub stage: V031UpgradeReceiptStage,
    pub previous_receipt_sha256: Option<&'a str>,
    pub evidence_sha256: &'a str,
    pub counts: &'a BTreeMap<V031UpgradeReceiptCountKey, u64>,
    pub created_at_unix: u64,
}

impl fmt::Debug for V031UpgradeReceiptCreateRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031UpgradeReceiptCreateRequest")
            .field("stage", &self.stage)
            .field("counts", &self.counts)
            .field("created_at_unix", &self.created_at_unix)
            .finish_non_exhaustive()
    }
}

pub struct ProtectedV031UpgradeReceiptV1 {
    protected_bytes: Vec<u8>,
    summary: ValidatedV031UpgradeReceiptV1,
}

impl fmt::Debug for ProtectedV031UpgradeReceiptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedV031UpgradeReceiptV1")
            .field("protected_bytes", &"[DPAPI protected]")
            .field("summary", &self.summary)
            .finish()
    }
}

impl ProtectedV031UpgradeReceiptV1 {
    pub fn protected_bytes(&self) -> &[u8] {
        &self.protected_bytes
    }

    pub fn into_protected_bytes(self) -> Vec<u8> {
        self.protected_bytes
    }

    pub const fn summary(&self) -> &ValidatedV031UpgradeReceiptV1 {
        &self.summary
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedV031UpgradeReceiptV1 {
    stage: V031UpgradeReceiptStage,
    previous_receipt_sha256: Option<String>,
    evidence_sha256: String,
    counts: BTreeMap<V031UpgradeReceiptCountKey, u64>,
    created_at_unix: u64,
    protected_sha256: String,
}

impl ValidatedV031UpgradeReceiptV1 {
    pub const fn stage(&self) -> V031UpgradeReceiptStage {
        self.stage
    }

    pub const fn ordinal(&self) -> u8 {
        self.stage.ordinal()
    }

    pub fn previous_receipt_sha256(&self) -> Option<&str> {
        self.previous_receipt_sha256.as_deref()
    }

    pub const fn evidence_schema_version(&self) -> &'static str {
        self.stage.evidence_schema_version()
    }

    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub const fn counts(&self) -> &BTreeMap<V031UpgradeReceiptCountKey, u64> {
        &self.counts
    }

    pub const fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    pub fn protected_sha256(&self) -> &str {
        &self.protected_sha256
    }
}

pub struct V031UpgradeReceiptChainArtifact<'a> {
    basename: &'a str,
    protected_bytes: &'a [u8],
}

impl<'a> V031UpgradeReceiptChainArtifact<'a> {
    pub const fn new(basename: &'a str, protected_bytes: &'a [u8]) -> Self {
        Self {
            basename,
            protected_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedV031UpgradeReceiptChainV1 {
    final_receipts: Vec<ValidatedV031UpgradeReceiptV1>,
    incoming_receipt: Option<ValidatedV031UpgradeReceiptV1>,
}

impl ValidatedV031UpgradeReceiptChainV1 {
    pub fn final_receipts(&self) -> &[ValidatedV031UpgradeReceiptV1] {
        &self.final_receipts
    }

    pub fn incoming_receipt(&self) -> Option<&ValidatedV031UpgradeReceiptV1> {
        self.incoming_receipt.as_ref()
    }

    pub fn last_final_receipt(&self) -> Option<&ValidatedV031UpgradeReceiptV1> {
        self.final_receipts.last()
    }

    pub fn next_stage(&self) -> Option<V031UpgradeReceiptStage> {
        u8::try_from(self.final_receipts.len())
            .ok()
            .and_then(V031UpgradeReceiptStage::from_ordinal)
    }

    pub const fn is_complete(&self) -> bool {
        self.final_receipts.len() == V031_UPGRADE_RECEIPT_STAGE_COUNT
            && self.incoming_receipt.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031UpgradeReceiptWireV1 {
    schema_version: String,
    migration_id: String,
    lineage_id: String,
    envelope_binding_id: String,
    ordinal: u8,
    stage: V031UpgradeReceiptStage,
    previous_receipt_sha256: Option<String>,
    source_profile_proof_sha256: String,
    evidence_schema_version: String,
    evidence_sha256: String,
    counts: BTreeMap<V031UpgradeReceiptCountKey, u64>,
    created_at_unix: u64,
    result_code: String,
}

impl Zeroize for V031UpgradeReceiptWireV1 {
    fn zeroize(&mut self) {
        self.schema_version.zeroize();
        self.migration_id.zeroize();
        self.lineage_id.zeroize();
        self.envelope_binding_id.zeroize();
        self.ordinal.zeroize();
        if let Some(previous) = &mut self.previous_receipt_sha256 {
            previous.zeroize();
        }
        self.previous_receipt_sha256 = None;
        self.source_profile_proof_sha256.zeroize();
        self.evidence_schema_version.zeroize();
        self.evidence_sha256.zeroize();
        for value in self.counts.values_mut() {
            value.zeroize();
        }
        self.counts.clear();
        self.created_at_unix.zeroize();
        self.result_code.zeroize();
    }
}

impl Drop for V031UpgradeReceiptWireV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

trait CurrentUserReceiptProtection {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, V031UpgradeReceiptError>;
    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, V031UpgradeReceiptError>;
}

struct WindowsCurrentUserDpapi;

impl CurrentUserReceiptProtection for WindowsCurrentUserDpapi {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, V031UpgradeReceiptError> {
        protect_local(plaintext).map_err(map_protect_error)
    }

    fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, V031UpgradeReceiptError> {
        unprotect_local(protected).map_err(map_unprotect_error)
    }
}

pub fn seal_v031_upgrade_receipt_v1(
    request: &V031UpgradeReceiptCreateRequest<'_>,
) -> Result<ProtectedV031UpgradeReceiptV1, V031UpgradeReceiptError> {
    seal_with_protection(request, &WindowsCurrentUserDpapi)
}

/// Discovers the non-secret chain context from an authenticated ordinal-zero
/// receipt. This is deliberately limited to stage zero: later receipts must be
/// opened through a context already established by receipt zero or the V2
/// identity, so an arbitrary artifact cannot select its own expected chain.
pub fn discover_v031_upgrade_receipt_chain_context_v1(
    protected_bytes: &[u8],
    expected_lineage_id: &str,
) -> Result<DiscoveredV031UpgradeReceiptChainContextV1, V031UpgradeReceiptError> {
    discover_context_with_protection(
        protected_bytes,
        expected_lineage_id,
        &WindowsCurrentUserDpapi,
    )
}

pub fn open_v031_upgrade_receipt_v1(
    protected_bytes: &[u8],
    context: V031UpgradeReceiptChainContext<'_>,
    expected_stage: V031UpgradeReceiptStage,
    expected_previous_receipt_sha256: Option<&str>,
) -> Result<ValidatedV031UpgradeReceiptV1, V031UpgradeReceiptError> {
    open_with_protection(
        protected_bytes,
        context,
        expected_stage,
        expected_previous_receipt_sha256,
        &WindowsCurrentUserDpapi,
    )
}

pub fn validate_v031_upgrade_receipt_chain_v1(
    artifacts: &[V031UpgradeReceiptChainArtifact<'_>],
    context: V031UpgradeReceiptChainContext<'_>,
) -> Result<ValidatedV031UpgradeReceiptChainV1, V031UpgradeReceiptError> {
    validate_chain_with_protection(artifacts, context, &WindowsCurrentUserDpapi)
}

fn seal_with_protection<P: CurrentUserReceiptProtection>(
    request: &V031UpgradeReceiptCreateRequest<'_>,
    protection: &P,
) -> Result<ProtectedV031UpgradeReceiptV1, V031UpgradeReceiptError> {
    validate_context(request.context)?;
    validate_hash(request.evidence_sha256)?;
    validate_previous_for_stage(request.stage, request.previous_receipt_sha256)?;
    validate_counts(request.stage, request.counts)?;
    validate_stage_semantics(
        request.stage,
        request.context.source_profile_proof_sha256,
        request.evidence_sha256,
    )?;
    validate_timestamp(request.created_at_unix)?;

    let wire = V031UpgradeReceiptWireV1 {
        schema_version: V031_UPGRADE_RECEIPT_SCHEMA_VERSION.to_owned(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID.to_owned(),
        lineage_id: request.context.lineage_id.to_owned(),
        envelope_binding_id: request.context.envelope_binding_id.to_owned(),
        ordinal: request.stage.ordinal(),
        stage: request.stage,
        previous_receipt_sha256: request.previous_receipt_sha256.map(str::to_owned),
        source_profile_proof_sha256: request.context.source_profile_proof_sha256.to_owned(),
        evidence_schema_version: request.stage.evidence_schema_version().to_owned(),
        evidence_sha256: request.evidence_sha256.to_owned(),
        counts: request.counts.clone(),
        created_at_unix: request.created_at_unix,
        result_code: V031_UPGRADE_RECEIPT_RESULT_CODE.to_owned(),
    };
    let plaintext = Zeroizing::new(
        canonical_json_v1(&wire).map_err(|_| V031UpgradeReceiptError::InvalidPlaintext)?,
    );
    if plaintext.is_empty() || plaintext.len() > MAX_V031_UPGRADE_RECEIPT_PLAINTEXT_BYTES {
        return Err(V031UpgradeReceiptError::ArtifactTooLarge);
    }
    let protected_bytes = protection.protect(&plaintext)?;
    if protected_bytes.is_empty()
        || protected_bytes.len() > MAX_V031_UPGRADE_RECEIPT_PROTECTED_BYTES
    {
        return Err(V031UpgradeReceiptError::ArtifactTooLarge);
    }
    let protected_sha256 = sha256_hex(&protected_bytes);
    let summary = summary_from_wire(&wire, protected_sha256);
    Ok(ProtectedV031UpgradeReceiptV1 {
        protected_bytes,
        summary,
    })
}

fn discover_context_with_protection<P: CurrentUserReceiptProtection>(
    protected_bytes: &[u8],
    expected_lineage_id: &str,
    protection: &P,
) -> Result<DiscoveredV031UpgradeReceiptChainContextV1, V031UpgradeReceiptError> {
    if !valid_lower_hex(expected_lineage_id, 64) {
        return Err(V031UpgradeReceiptError::InvalidContext);
    }
    if protected_bytes.is_empty()
        || protected_bytes.len() > MAX_V031_UPGRADE_RECEIPT_PROTECTED_BYTES
    {
        return Err(V031UpgradeReceiptError::ArtifactTooLarge);
    }
    let plaintext = Zeroizing::new(protection.unprotect(protected_bytes)?);
    if plaintext.is_empty()
        || plaintext.len() > MAX_V031_UPGRADE_RECEIPT_PLAINTEXT_BYTES
        || plaintext.len() > MAX_PROTECTED_PLAINTEXT_BYTES
    {
        return Err(V031UpgradeReceiptError::ArtifactTooLarge);
    }
    let wire = Zeroizing::new(
        strict_json_v1_from_slice::<V031UpgradeReceiptWireV1>(&plaintext)
            .map_err(|_| V031UpgradeReceiptError::InvalidPlaintext)?,
    );
    let canonical = Zeroizing::new(
        canonical_json_v1(&*wire).map_err(|_| V031UpgradeReceiptError::InvalidPlaintext)?,
    );
    if canonical.as_slice() != plaintext.as_slice() {
        return Err(V031UpgradeReceiptError::NonCanonicalPlaintext);
    }
    if wire.lineage_id != expected_lineage_id
        || wire.ordinal != V031UpgradeReceiptStage::SourcePreflightVerified.ordinal()
        || wire.stage != V031UpgradeReceiptStage::SourcePreflightVerified
    {
        return Err(V031UpgradeReceiptError::ReceiptMismatch);
    }
    let discovered = DiscoveredV031UpgradeReceiptChainContextV1 {
        lineage_id: wire.lineage_id.clone(),
        envelope_binding_id: wire.envelope_binding_id.clone(),
        source_profile_proof_sha256: wire.source_profile_proof_sha256.clone(),
    };
    validate_wire(
        &wire,
        discovered.as_borrowed(),
        V031UpgradeReceiptStage::SourcePreflightVerified,
        None,
    )?;
    Ok(discovered)
}

fn open_with_protection<P: CurrentUserReceiptProtection>(
    protected_bytes: &[u8],
    context: V031UpgradeReceiptChainContext<'_>,
    expected_stage: V031UpgradeReceiptStage,
    expected_previous_receipt_sha256: Option<&str>,
    protection: &P,
) -> Result<ValidatedV031UpgradeReceiptV1, V031UpgradeReceiptError> {
    validate_context(context)?;
    validate_previous_for_stage(expected_stage, expected_previous_receipt_sha256)?;
    if protected_bytes.is_empty()
        || protected_bytes.len() > MAX_V031_UPGRADE_RECEIPT_PROTECTED_BYTES
    {
        return Err(V031UpgradeReceiptError::ArtifactTooLarge);
    }

    let plaintext = Zeroizing::new(protection.unprotect(protected_bytes)?);
    if plaintext.is_empty()
        || plaintext.len() > MAX_V031_UPGRADE_RECEIPT_PLAINTEXT_BYTES
        || plaintext.len() > MAX_PROTECTED_PLAINTEXT_BYTES
    {
        return Err(V031UpgradeReceiptError::ArtifactTooLarge);
    }
    let wire = Zeroizing::new(
        strict_json_v1_from_slice::<V031UpgradeReceiptWireV1>(&plaintext)
            .map_err(|_| V031UpgradeReceiptError::InvalidPlaintext)?,
    );
    let canonical = Zeroizing::new(
        canonical_json_v1(&*wire).map_err(|_| V031UpgradeReceiptError::InvalidPlaintext)?,
    );
    if canonical.as_slice() != plaintext.as_slice() {
        return Err(V031UpgradeReceiptError::NonCanonicalPlaintext);
    }
    validate_wire(
        &wire,
        context,
        expected_stage,
        expected_previous_receipt_sha256,
    )?;
    Ok(summary_from_wire(&wire, sha256_hex(protected_bytes)))
}

fn validate_chain_with_protection<P: CurrentUserReceiptProtection>(
    artifacts: &[V031UpgradeReceiptChainArtifact<'_>],
    context: V031UpgradeReceiptChainContext<'_>,
    protection: &P,
) -> Result<ValidatedV031UpgradeReceiptChainV1, V031UpgradeReceiptError> {
    validate_context(context)?;
    let mut finals: [Option<&[u8]>; V031_UPGRADE_RECEIPT_STAGE_COUNT] =
        [None; V031_UPGRADE_RECEIPT_STAGE_COUNT];
    let mut incoming: [Option<&[u8]>; V031_UPGRADE_RECEIPT_STAGE_COUNT] =
        [None; V031_UPGRADE_RECEIPT_STAGE_COUNT];

    for artifact in artifacts {
        let (stage, is_incoming) = classify_basename(artifact.basename)?;
        let slot = if is_incoming {
            &mut incoming[stage.ordinal() as usize]
        } else {
            &mut finals[stage.ordinal() as usize]
        };
        if slot.replace(artifact.protected_bytes).is_some() {
            return Err(V031UpgradeReceiptError::DuplicateArtifact);
        }
    }

    let prefix_length = finals
        .iter()
        .position(Option::is_none)
        .unwrap_or(finals.len());
    if finals[prefix_length..].iter().any(Option::is_some) {
        return Err(V031UpgradeReceiptError::NonContiguousChain);
    }

    let incoming_ordinals = incoming
        .iter()
        .enumerate()
        .filter_map(|(ordinal, bytes)| bytes.map(|bytes| (ordinal, bytes)))
        .collect::<Vec<_>>();
    if incoming_ordinals.len() > 1 {
        return Err(V031UpgradeReceiptError::MultipleIncoming);
    }
    if let Some((ordinal, _)) = incoming_ordinals.first() {
        if *ordinal != prefix_length || prefix_length == V031_UPGRADE_RECEIPT_STAGE_COUNT {
            return Err(V031UpgradeReceiptError::UnexpectedIncoming);
        }
    }

    let mut final_receipts = Vec::with_capacity(prefix_length);
    let mut expected_previous: Option<String> = None;
    let mut previous_created_at = None;
    for (ordinal, protected_bytes) in finals.iter().take(prefix_length).enumerate() {
        let stage = V031UpgradeReceiptStage::from_ordinal(ordinal as u8)
            .ok_or(V031UpgradeReceiptError::NonContiguousChain)?;
        let protected_bytes = protected_bytes
            .as_ref()
            .ok_or(V031UpgradeReceiptError::NonContiguousChain)?;
        let receipt = open_with_protection(
            protected_bytes,
            context,
            stage,
            expected_previous.as_deref(),
            protection,
        )
        .map_err(|error| match error {
            V031UpgradeReceiptError::ReceiptMismatch => V031UpgradeReceiptError::BrokenChain,
            other => other,
        })?;
        if previous_created_at.is_some_and(|created_at| receipt.created_at_unix() < created_at) {
            return Err(V031UpgradeReceiptError::TimestampRegression);
        }
        previous_created_at = Some(receipt.created_at_unix());
        expected_previous = Some(receipt.protected_sha256().to_owned());
        final_receipts.push(receipt);
    }

    let incoming_receipt = if let Some((ordinal, protected_bytes)) = incoming_ordinals.first() {
        let stage = V031UpgradeReceiptStage::from_ordinal(*ordinal as u8)
            .ok_or(V031UpgradeReceiptError::UnexpectedIncoming)?;
        let receipt = open_with_protection(
            protected_bytes,
            context,
            stage,
            expected_previous.as_deref(),
            protection,
        )
        .map_err(|error| match error {
            V031UpgradeReceiptError::ReceiptMismatch => V031UpgradeReceiptError::BrokenChain,
            other => other,
        })?;
        if previous_created_at.is_some_and(|created_at| receipt.created_at_unix() < created_at) {
            return Err(V031UpgradeReceiptError::TimestampRegression);
        }
        Some(receipt)
    } else {
        None
    };

    Ok(ValidatedV031UpgradeReceiptChainV1 {
        final_receipts,
        incoming_receipt,
    })
}

fn validate_wire(
    wire: &V031UpgradeReceiptWireV1,
    context: V031UpgradeReceiptChainContext<'_>,
    expected_stage: V031UpgradeReceiptStage,
    expected_previous_receipt_sha256: Option<&str>,
) -> Result<(), V031UpgradeReceiptError> {
    if wire.schema_version != V031_UPGRADE_RECEIPT_SCHEMA_VERSION
        || wire.migration_id != V031_UPGRADE_RECEIPT_MIGRATION_ID
        || wire.lineage_id != context.lineage_id
        || wire.envelope_binding_id != context.envelope_binding_id
        || wire.source_profile_proof_sha256 != context.source_profile_proof_sha256
        || wire.ordinal != expected_stage.ordinal()
        || wire.stage != expected_stage
        || wire.evidence_schema_version != expected_stage.evidence_schema_version()
        || wire.result_code != V031_UPGRADE_RECEIPT_RESULT_CODE
        || wire.previous_receipt_sha256.as_deref() != expected_previous_receipt_sha256
    {
        return Err(V031UpgradeReceiptError::ReceiptMismatch);
    }
    validate_hash(&wire.evidence_sha256)?;
    validate_previous_for_stage(wire.stage, wire.previous_receipt_sha256.as_deref())?;
    validate_counts(wire.stage, &wire.counts)?;
    validate_stage_semantics(
        wire.stage,
        &wire.source_profile_proof_sha256,
        &wire.evidence_sha256,
    )?;
    validate_timestamp(wire.created_at_unix)
}

fn validate_stage_semantics(
    stage: V031UpgradeReceiptStage,
    source_profile_proof_sha256: &str,
    evidence_sha256: &str,
) -> Result<(), V031UpgradeReceiptError> {
    if stage == V031UpgradeReceiptStage::SourcePreflightVerified
        && evidence_sha256 != source_profile_proof_sha256
    {
        return Err(V031UpgradeReceiptError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_context(
    context: V031UpgradeReceiptChainContext<'_>,
) -> Result<(), V031UpgradeReceiptError> {
    if !valid_lower_hex(context.lineage_id, 64)
        || !valid_envelope_binding_id(context.envelope_binding_id)
        || !valid_lower_hex(context.source_profile_proof_sha256, 64)
    {
        return Err(V031UpgradeReceiptError::InvalidContext);
    }
    Ok(())
}

fn validate_previous_for_stage(
    stage: V031UpgradeReceiptStage,
    previous_receipt_sha256: Option<&str>,
) -> Result<(), V031UpgradeReceiptError> {
    match (stage.ordinal(), previous_receipt_sha256) {
        (0, None) => Ok(()),
        (0, Some(_)) | (_, None) => Err(V031UpgradeReceiptError::BrokenChain),
        (_, Some(hash)) => validate_hash(hash),
    }
}

fn validate_hash(value: &str) -> Result<(), V031UpgradeReceiptError> {
    if valid_lower_hex(value, 64) {
        Ok(())
    } else {
        Err(V031UpgradeReceiptError::InvalidHash)
    }
}

fn validate_counts(
    stage: V031UpgradeReceiptStage,
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
) -> Result<(), V031UpgradeReceiptError> {
    let expected = stage.count_keys();
    if counts.len() != expected.len() || expected.iter().any(|key| !counts.contains_key(key)) {
        return Err(V031UpgradeReceiptError::InvalidCounts);
    }
    let mut aggregate = 0_u64;
    for count in counts.values().copied() {
        if count > MAX_V031_UPGRADE_RECEIPT_COUNT {
            return Err(V031UpgradeReceiptError::CountOverflow);
        }
        aggregate = aggregate
            .checked_add(count)
            .filter(|sum| *sum <= MAX_V031_UPGRADE_RECEIPT_COUNT)
            .ok_or(V031UpgradeReceiptError::CountOverflow)?;
    }
    let exact = |key, expected| counts.get(&key).copied() == Some(expected);
    let semantics_match = match stage {
        V031UpgradeReceiptStage::SourcePreflightVerified => {
            exact(V031UpgradeReceiptCountKey::UserSchemaObjects, 74)
                && exact(V031UpgradeReceiptCountKey::PrivacySchemaObjects, 11)
                && exact(V031UpgradeReceiptCountKey::PresentSlots, 2)
                && exact(V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3)
                && exact(V031UpgradeReceiptCountKey::TargetAbsenceChecks, 26)
                && exact(V031UpgradeReceiptCountKey::CapacityChecks, 2)
        }
        V031UpgradeReceiptStage::OriginalRollbackVerified => {
            exact(V031UpgradeReceiptCountKey::IdentityArtifacts, 1)
                && exact(V031UpgradeReceiptCountKey::BundleArtifacts, 1)
                && exact(V031UpgradeReceiptCountKey::RollbackSlots, 5)
                && exact(V031UpgradeReceiptCountKey::SqliteImages, 2)
                && counts
                    .get(&V031UpgradeReceiptCountKey::EncryptedChunks)
                    .is_some_and(|count| *count >= 5)
                && exact(V031UpgradeReceiptCountKey::SourceRevalidations, 2)
                && exact(V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3)
        }
        V031UpgradeReceiptStage::TargetComponentsPrepared => {
            exact(V031UpgradeReceiptCountKey::TargetCredentials, 4)
                && exact(V031UpgradeReceiptCountKey::WorkspaceIdentities, 1)
                && exact(V031UpgradeReceiptCountKey::EmptyTargetComponents, 3)
        }
        V031UpgradeReceiptStage::CaseMigrationBackupsVerified => {
            exact(V031UpgradeReceiptCountKey::BindingCheckpoints, 1)
                && exact(V031UpgradeReceiptCountKey::MaterialCheckpoints, 1)
                && exact(V031UpgradeReceiptCountKey::CheckpointComponents, 10)
        }
        V031UpgradeReceiptStage::PrivacyV5Verified => {
            counts
                .get(&V031UpgradeReceiptCountKey::PrivacySchemaObjects)
                .is_some_and(|count| *count > 0)
                && exact(V031UpgradeReceiptCountKey::PrivacyMigrationBatches, 1)
        }
        V031UpgradeReceiptStage::BindingMaterialsVerified => {
            let material_rows = counts
                .get(&V031UpgradeReceiptCountKey::MaterialLedgerRows)
                .copied();
            let terminal_rows = counts
                .get(&V031UpgradeReceiptCountKey::TerminalRows)
                .copied();
            let blocked_rows = counts
                .get(&V031UpgradeReceiptCountKey::BlockedRows)
                .copied();
            exact(V031UpgradeReceiptCountKey::PrivacyMigrationBatches, 1)
                && material_rows == terminal_rows
                && blocked_rows
                    .zip(terminal_rows)
                    .is_some_and(|(blocked, terminal)| blocked <= terminal)
        }
        V031UpgradeReceiptStage::ProjectionBackupVerified => {
            exact(V031UpgradeReceiptCountKey::ProjectionCheckpoints, 1)
                && exact(V031UpgradeReceiptCountKey::CheckpointComponents, 5)
                && exact(V031UpgradeReceiptCountKey::SourceRevalidations, 2)
        }
        V031UpgradeReceiptStage::PrivacyV6Verified => {
            counts
                .get(&V031UpgradeReceiptCountKey::PrivacySchemaObjects)
                .is_some_and(|count| *count > 0)
                && counts
                    .get(&V031UpgradeReceiptCountKey::SecurityTriggers)
                    .is_some_and(|count| *count > 0)
        }
        V031UpgradeReceiptStage::UserV11Verified => {
            exact(V031UpgradeReceiptCountKey::UserAuditRows, 1)
                && exact(V031UpgradeReceiptCountKey::PrivacyLineageRows, 1)
                && exact(V031UpgradeReceiptCountKey::UserManifestTables, 29)
                && exact(
                    V031UpgradeReceiptCountKey::PrivacyManifestTables,
                    V031_USER_V11_PRIVACY_MANIFEST_TABLE_COUNT,
                )
                && exact(V031UpgradeReceiptCountKey::FinalComponentSlots, 5)
                && counts
                    .get(&V031UpgradeReceiptCountKey::UserManifestRows)
                    .is_some_and(|count| *count > 0)
                && counts
                    .get(&V031UpgradeReceiptCountKey::PrivacyManifestRows)
                    .is_some_and(|count| *count > 0)
        }
        V031UpgradeReceiptStage::UpgradeComplete => {
            exact(V031UpgradeReceiptCountKey::Restarts, 1)
                && exact(V031UpgradeReceiptCountKey::NoopMigrations, 4)
                && exact(V031UpgradeReceiptCountKey::FinalComponentSlots, 5)
                && exact(V031UpgradeReceiptCountKey::FinalManifestEntries, 5)
                && exact(V031UpgradeReceiptCountKey::MaintenanceActions, 5)
        }
    };
    if !semantics_match {
        return Err(V031UpgradeReceiptError::InvalidCounts);
    }
    Ok(())
}

fn validate_timestamp(created_at_unix: u64) -> Result<(), V031UpgradeReceiptError> {
    if (1..=MAX_V031_UPGRADE_RECEIPT_CREATED_AT_UNIX).contains(&created_at_unix) {
        Ok(())
    } else {
        Err(V031UpgradeReceiptError::InvalidTimestamp)
    }
}

fn classify_basename(
    basename: &str,
) -> Result<(V031UpgradeReceiptStage, bool), V031UpgradeReceiptError> {
    for stage in V031UpgradeReceiptStage::ALL {
        if basename == stage.final_basename() {
            return Ok((stage, false));
        }
        if basename == stage.incoming_basename() {
            return Ok((stage, true));
        }
    }
    Err(V031UpgradeReceiptError::UnknownArtifact)
}

fn summary_from_wire(
    wire: &V031UpgradeReceiptWireV1,
    protected_sha256: String,
) -> ValidatedV031UpgradeReceiptV1 {
    ValidatedV031UpgradeReceiptV1 {
        stage: wire.stage,
        previous_receipt_sha256: wire.previous_receipt_sha256.clone(),
        evidence_sha256: wire.evidence_sha256.clone(),
        counts: wire.counts.clone(),
        created_at_unix: wire.created_at_unix,
        protected_sha256,
    }
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_envelope_binding_id(value: &str) -> bool {
    value
        .strip_prefix("ws_")
        .is_some_and(|suffix| valid_lower_hex(suffix, 32))
}

fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}

fn map_protect_error(error: ProtectedBlobError) -> V031UpgradeReceiptError {
    match error {
        ProtectedBlobError::PlatformUnavailable => V031UpgradeReceiptError::PlatformUnavailable,
        ProtectedBlobError::InputTooLarge => V031UpgradeReceiptError::ArtifactTooLarge,
        ProtectedBlobError::EmptyInput
        | ProtectedBlobError::ProtectFailed
        | ProtectedBlobError::UnprotectFailed
        | ProtectedBlobError::InvalidOutput => V031UpgradeReceiptError::ProtectionFailed,
    }
}

fn map_unprotect_error(error: ProtectedBlobError) -> V031UpgradeReceiptError {
    match error {
        ProtectedBlobError::PlatformUnavailable => V031UpgradeReceiptError::PlatformUnavailable,
        ProtectedBlobError::InputTooLarge => V031UpgradeReceiptError::ArtifactTooLarge,
        ProtectedBlobError::EmptyInput => V031UpgradeReceiptError::InvalidPlaintext,
        ProtectedBlobError::ProtectFailed
        | ProtectedBlobError::UnprotectFailed
        | ProtectedBlobError::InvalidOutput => {
            V031UpgradeReceiptError::CurrentUserAuthenticationFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINEAGE_ID: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ENVELOPE_BINDING_ID: &str = "ws_22222222222222222222222222222222";
    const SOURCE_PROFILE_PROOF_SHA256: &str =
        "3333333333333333333333333333333333333333333333333333333333333333";
    const EVIDENCE_SHA256: &str =
        "4444444444444444444444444444444444444444444444444444444444444444";

    #[derive(Clone, Copy)]
    struct TestCurrentUserProtection {
        scope: u8,
    }

    impl CurrentUserReceiptProtection for TestCurrentUserProtection {
        fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, V031UpgradeReceiptError> {
            let mut protected = Vec::with_capacity(1 + plaintext.len() + 32);
            protected.push(self.scope);
            protected.extend(plaintext.iter().map(|byte| byte ^ 0xa5));
            let digest = Sha256::digest(&protected);
            protected.extend_from_slice(&digest);
            Ok(protected)
        }

        fn unprotect(&self, protected: &[u8]) -> Result<Vec<u8>, V031UpgradeReceiptError> {
            if protected.len() < 33 || protected[0] != self.scope {
                return Err(V031UpgradeReceiptError::CurrentUserAuthenticationFailed);
            }
            let (body, expected_digest) = protected.split_at(protected.len() - 32);
            if &Sha256::digest(body)[..] != expected_digest {
                return Err(V031UpgradeReceiptError::CurrentUserAuthenticationFailed);
            }
            Ok(body[1..].iter().map(|byte| byte ^ 0xa5).collect())
        }
    }

    fn context() -> V031UpgradeReceiptChainContext<'static> {
        V031UpgradeReceiptChainContext {
            lineage_id: LINEAGE_ID,
            envelope_binding_id: ENVELOPE_BINDING_ID,
            source_profile_proof_sha256: SOURCE_PROFILE_PROOF_SHA256,
        }
    }

    fn counts(stage: V031UpgradeReceiptStage) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
        let mut counts = stage
            .count_keys()
            .iter()
            .copied()
            .map(|key| (key, 1))
            .collect::<BTreeMap<_, _>>();
        match stage {
            V031UpgradeReceiptStage::SourcePreflightVerified => {
                counts.insert(V031UpgradeReceiptCountKey::UserSchemaObjects, 74);
                counts.insert(V031UpgradeReceiptCountKey::PrivacySchemaObjects, 11);
                counts.insert(V031UpgradeReceiptCountKey::PresentSlots, 2);
                counts.insert(V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3);
                counts.insert(V031UpgradeReceiptCountKey::TargetAbsenceChecks, 26);
                counts.insert(V031UpgradeReceiptCountKey::CapacityChecks, 2);
            }
            V031UpgradeReceiptStage::OriginalRollbackVerified => {
                counts.insert(V031UpgradeReceiptCountKey::IdentityArtifacts, 1);
                counts.insert(V031UpgradeReceiptCountKey::BundleArtifacts, 1);
                counts.insert(V031UpgradeReceiptCountKey::RollbackSlots, 5);
                counts.insert(V031UpgradeReceiptCountKey::SqliteImages, 2);
                counts.insert(V031UpgradeReceiptCountKey::EncryptedChunks, 5);
                counts.insert(V031UpgradeReceiptCountKey::SourceRevalidations, 2);
                counts.insert(V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3);
            }
            V031UpgradeReceiptStage::TargetComponentsPrepared => {
                counts.insert(V031UpgradeReceiptCountKey::TargetCredentials, 4);
                counts.insert(V031UpgradeReceiptCountKey::WorkspaceIdentities, 1);
                counts.insert(V031UpgradeReceiptCountKey::EmptyTargetComponents, 3);
            }
            V031UpgradeReceiptStage::CaseMigrationBackupsVerified => {
                counts.insert(V031UpgradeReceiptCountKey::BindingCheckpoints, 1);
                counts.insert(V031UpgradeReceiptCountKey::MaterialCheckpoints, 1);
                counts.insert(V031UpgradeReceiptCountKey::CheckpointComponents, 10);
            }
            V031UpgradeReceiptStage::PrivacyV5Verified => {
                counts.insert(V031UpgradeReceiptCountKey::PrivacySchemaObjects, 1);
                counts.insert(V031UpgradeReceiptCountKey::PrivacyMigrationBatches, 1);
            }
            V031UpgradeReceiptStage::BindingMaterialsVerified => {
                counts.insert(V031UpgradeReceiptCountKey::BindingLedgerRows, 1);
                counts.insert(V031UpgradeReceiptCountKey::MaterialLedgerRows, 1);
                counts.insert(V031UpgradeReceiptCountKey::TerminalRows, 1);
                counts.insert(V031UpgradeReceiptCountKey::BlockedRows, 0);
                counts.insert(V031UpgradeReceiptCountKey::PrivacyMigrationBatches, 1);
            }
            V031UpgradeReceiptStage::ProjectionBackupVerified => {
                counts.insert(V031UpgradeReceiptCountKey::ProjectionCheckpoints, 1);
                counts.insert(V031UpgradeReceiptCountKey::CheckpointComponents, 5);
                counts.insert(V031UpgradeReceiptCountKey::ApprovedGenerations, 1);
                counts.insert(V031UpgradeReceiptCountKey::SourceRevalidations, 2);
            }
            V031UpgradeReceiptStage::PrivacyV6Verified => {
                counts.insert(V031UpgradeReceiptCountKey::PrivacySchemaObjects, 1);
                counts.insert(V031UpgradeReceiptCountKey::ProjectionRows, 1);
                counts.insert(V031UpgradeReceiptCountKey::RiskHeads, 1);
                counts.insert(V031UpgradeReceiptCountKey::RevocationRows, 0);
                counts.insert(V031UpgradeReceiptCountKey::SecurityTriggers, 1);
                counts.insert(V031UpgradeReceiptCountKey::BindingsVerified, 1);
            }
            V031UpgradeReceiptStage::UserV11Verified => {
                counts.insert(V031UpgradeReceiptCountKey::UserAuditRows, 1);
                counts.insert(V031UpgradeReceiptCountKey::PrivacyLineageRows, 1);
                counts.insert(V031UpgradeReceiptCountKey::UserManifestTables, 29);
                counts.insert(V031UpgradeReceiptCountKey::UserManifestRows, 1);
                counts.insert(
                    V031UpgradeReceiptCountKey::PrivacyManifestTables,
                    V031_USER_V11_PRIVACY_MANIFEST_TABLE_COUNT,
                );
                counts.insert(V031UpgradeReceiptCountKey::PrivacyManifestRows, 1);
                counts.insert(V031UpgradeReceiptCountKey::FinalComponentSlots, 5);
            }
            V031UpgradeReceiptStage::UpgradeComplete => {
                counts.insert(V031UpgradeReceiptCountKey::Restarts, 1);
                counts.insert(V031UpgradeReceiptCountKey::NoopMigrations, 4);
                counts.insert(V031UpgradeReceiptCountKey::FinalComponentSlots, 5);
                counts.insert(V031UpgradeReceiptCountKey::FinalManifestEntries, 5);
                counts.insert(V031UpgradeReceiptCountKey::MaintenanceActions, 5);
            }
        }
        counts
    }

    fn evidence_sha256(stage: V031UpgradeReceiptStage) -> &'static str {
        if stage == V031UpgradeReceiptStage::SourcePreflightVerified {
            SOURCE_PROFILE_PROOF_SHA256
        } else {
            EVIDENCE_SHA256
        }
    }

    fn seal_for_test(
        stage: V031UpgradeReceiptStage,
        previous_receipt_sha256: Option<&str>,
        created_at_unix: u64,
        protection: TestCurrentUserProtection,
    ) -> ProtectedV031UpgradeReceiptV1 {
        let counts = counts(stage);
        seal_with_protection(
            &V031UpgradeReceiptCreateRequest {
                context: context(),
                stage,
                previous_receipt_sha256,
                evidence_sha256: evidence_sha256(stage),
                counts: &counts,
                created_at_unix,
            },
            &protection,
        )
        .expect("seal receipt")
    }

    fn reprotect_plaintext(
        protected: &[u8],
        transform: impl FnOnce(Vec<u8>) -> Vec<u8>,
        protection: TestCurrentUserProtection,
    ) -> Vec<u8> {
        let plaintext = protection
            .unprotect(protected)
            .expect("unprotect test wire");
        protection
            .protect(&transform(plaintext))
            .expect("protect modified test wire")
    }

    #[test]
    fn strict_receipt_round_trip_exposes_only_audit_summary() {
        let protection = TestCurrentUserProtection { scope: 7 };
        let sealed = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            100,
            protection,
        );
        let opened = open_with_protection(
            sealed.protected_bytes(),
            context(),
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            &protection,
        )
        .expect("open receipt");
        assert_eq!(
            opened.stage(),
            V031UpgradeReceiptStage::SourcePreflightVerified
        );
        assert_eq!(opened.ordinal(), 0);
        assert_eq!(opened.previous_receipt_sha256(), None);
        assert_eq!(opened.evidence_sha256(), SOURCE_PROFILE_PROOF_SHA256);
        assert_eq!(opened.counts(), &counts(opened.stage()));
        assert_eq!(
            opened.protected_sha256(),
            sha256_hex(sealed.protected_bytes())
        );
    }

    #[test]
    fn ordinal_zero_recovers_authenticated_context_after_pre_identity_crash() {
        let protection = TestCurrentUserProtection { scope: 17 };
        let sealed = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            101,
            protection,
        );
        let discovered =
            discover_context_with_protection(sealed.protected_bytes(), LINEAGE_ID, &protection)
                .expect("discover authenticated receipt-zero context");
        assert_eq!(discovered.as_borrowed().lineage_id, LINEAGE_ID);
        assert_eq!(
            discovered.as_borrowed().envelope_binding_id,
            ENVELOPE_BINDING_ID
        );
        assert_eq!(
            discovered.as_borrowed().source_profile_proof_sha256,
            SOURCE_PROFILE_PROOF_SHA256
        );
        assert_eq!(
            discover_context_with_protection(
                sealed.protected_bytes(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                &protection,
            ),
            Err(V031UpgradeReceiptError::ReceiptMismatch)
        );
    }

    #[test]
    fn ordinal_zero_binds_evidence_to_source_profile_on_seal_open_and_discovery() {
        let protection = TestCurrentUserProtection { scope: 23 };
        let source_counts = counts(V031UpgradeReceiptStage::SourcePreflightVerified);
        assert!(matches!(
            seal_with_protection(
                &V031UpgradeReceiptCreateRequest {
                    context: context(),
                    stage: V031UpgradeReceiptStage::SourcePreflightVerified,
                    previous_receipt_sha256: None,
                    evidence_sha256: EVIDENCE_SHA256,
                    counts: &source_counts,
                    created_at_unix: 101,
                },
                &protection,
            ),
            Err(V031UpgradeReceiptError::ReceiptMismatch)
        ));

        let sealed = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            101,
            protection,
        );
        let mismatched = reprotect_plaintext(
            sealed.protected_bytes(),
            |plaintext| {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&plaintext).expect("parse receipt");
                value["evidenceSha256"] = serde_json::json!(EVIDENCE_SHA256);
                canonical_json_v1(&value).expect("canonical mismatched receipt")
            },
            protection,
        );
        assert_eq!(
            open_with_protection(
                &mismatched,
                context(),
                V031UpgradeReceiptStage::SourcePreflightVerified,
                None,
                &protection,
            ),
            Err(V031UpgradeReceiptError::ReceiptMismatch)
        );
        assert_eq!(
            discover_context_with_protection(&mismatched, LINEAGE_ID, &protection),
            Err(V031UpgradeReceiptError::ReceiptMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_current_user_round_trip() {
        let counts = counts(V031UpgradeReceiptStage::SourcePreflightVerified);
        let sealed = seal_v031_upgrade_receipt_v1(&V031UpgradeReceiptCreateRequest {
            context: context(),
            stage: V031UpgradeReceiptStage::SourcePreflightVerified,
            previous_receipt_sha256: None,
            evidence_sha256: SOURCE_PROFILE_PROOF_SHA256,
            counts: &counts,
            created_at_unix: 100,
        })
        .expect("DPAPI protect");
        let opened = open_v031_upgrade_receipt_v1(
            sealed.protected_bytes(),
            context(),
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
        )
        .expect("same-user DPAPI unprotect");
        assert_eq!(
            opened.stage(),
            V031UpgradeReceiptStage::SourcePreflightVerified
        );
    }

    #[test]
    fn protected_bytes_tamper_and_wrong_user_scope_are_rejected() {
        let protection = TestCurrentUserProtection { scope: 7 };
        let sealed = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            100,
            protection,
        );
        let mut tampered = sealed.protected_bytes().to_vec();
        tampered[3] ^= 0x01;
        assert_eq!(
            open_with_protection(
                &tampered,
                context(),
                V031UpgradeReceiptStage::SourcePreflightVerified,
                None,
                &protection,
            ),
            Err(V031UpgradeReceiptError::CurrentUserAuthenticationFailed)
        );
        assert_eq!(
            open_with_protection(
                sealed.protected_bytes(),
                context(),
                V031UpgradeReceiptStage::SourcePreflightVerified,
                None,
                &TestCurrentUserProtection { scope: 8 },
            ),
            Err(V031UpgradeReceiptError::CurrentUserAuthenticationFailed)
        );
    }

    #[test]
    fn lineage_binding_and_source_profile_proof_are_reauthenticated() {
        let protection = TestCurrentUserProtection { scope: 7 };
        let sealed = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            100,
            protection,
        );
        for mismatched_context in [
            V031UpgradeReceiptChainContext {
                lineage_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ..context()
            },
            V031UpgradeReceiptChainContext {
                envelope_binding_id: "ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ..context()
            },
            V031UpgradeReceiptChainContext {
                source_profile_proof_sha256:
                    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                ..context()
            },
        ] {
            assert_eq!(
                open_with_protection(
                    sealed.protected_bytes(),
                    mismatched_context,
                    V031UpgradeReceiptStage::SourcePreflightVerified,
                    None,
                    &protection,
                ),
                Err(V031UpgradeReceiptError::ReceiptMismatch)
            );
        }
    }

    #[test]
    fn unknown_duplicate_and_noncanonical_plaintext_are_rejected() {
        let protection = TestCurrentUserProtection { scope: 7 };
        let sealed = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            100,
            protection,
        );
        let unknown = reprotect_plaintext(
            sealed.protected_bytes(),
            |plaintext| {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&plaintext).expect("parse canonical test receipt");
                value
                    .as_object_mut()
                    .expect("receipt object")
                    .insert("unknownField".to_owned(), serde_json::json!(true));
                canonical_json_v1(&value).expect("canonical unknown-field receipt")
            },
            protection,
        );
        assert_eq!(
            open_with_protection(
                &unknown,
                context(),
                V031UpgradeReceiptStage::SourcePreflightVerified,
                None,
                &protection,
            ),
            Err(V031UpgradeReceiptError::InvalidPlaintext)
        );

        let duplicate = reprotect_plaintext(
            sealed.protected_bytes(),
            |plaintext| {
                let text = String::from_utf8(plaintext).expect("UTF-8 receipt");
                format!("{{\"counts\":{{}},{}", &text[1..]).into_bytes()
            },
            protection,
        );
        assert_eq!(
            open_with_protection(
                &duplicate,
                context(),
                V031UpgradeReceiptStage::SourcePreflightVerified,
                None,
                &protection,
            ),
            Err(V031UpgradeReceiptError::InvalidPlaintext)
        );

        let noncanonical = reprotect_plaintext(
            sealed.protected_bytes(),
            |mut plaintext| {
                plaintext.push(b'\n');
                plaintext
            },
            protection,
        );
        assert_eq!(
            open_with_protection(
                &noncanonical,
                context(),
                V031UpgradeReceiptStage::SourcePreflightVerified,
                None,
                &protection,
            ),
            Err(V031UpgradeReceiptError::NonCanonicalPlaintext)
        );
    }

    #[test]
    fn count_key_and_overflow_are_rejected() {
        let protection = TestCurrentUserProtection { scope: 7 };
        let sealed = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            100,
            protection,
        );
        let wrong_key = reprotect_plaintext(
            sealed.protected_bytes(),
            |plaintext| {
                let mut value: serde_json::Value =
                    serde_json::from_slice(&plaintext).expect("parse receipt");
                let counts = value
                    .get_mut("counts")
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("counts object");
                counts.insert("unknown_count".to_owned(), serde_json::json!(1));
                canonical_json_v1(&value).expect("canonical wrong-key receipt")
            },
            protection,
        );
        assert_eq!(
            open_with_protection(
                &wrong_key,
                context(),
                V031UpgradeReceiptStage::SourcePreflightVerified,
                None,
                &protection,
            ),
            Err(V031UpgradeReceiptError::InvalidPlaintext)
        );

        let mut overflowing = counts(V031UpgradeReceiptStage::SourcePreflightVerified);
        overflowing.insert(
            V031UpgradeReceiptCountKey::UserSchemaObjects,
            MAX_V031_UPGRADE_RECEIPT_COUNT,
        );
        assert!(matches!(
            seal_with_protection(
                &V031UpgradeReceiptCreateRequest {
                    context: context(),
                    stage: V031UpgradeReceiptStage::SourcePreflightVerified,
                    previous_receipt_sha256: None,
                    evidence_sha256: SOURCE_PROFILE_PROOF_SHA256,
                    counts: &overflowing,
                    created_at_unix: 100,
                },
                &protection,
            ),
            Err(V031UpgradeReceiptError::CountOverflow)
        ));

        let mut wrong_source_semantics = counts(V031UpgradeReceiptStage::SourcePreflightVerified);
        wrong_source_semantics.insert(V031UpgradeReceiptCountKey::PresentSlots, 1);
        assert!(matches!(
            seal_with_protection(
                &V031UpgradeReceiptCreateRequest {
                    context: context(),
                    stage: V031UpgradeReceiptStage::SourcePreflightVerified,
                    previous_receipt_sha256: None,
                    evidence_sha256: SOURCE_PROFILE_PROOF_SHA256,
                    counts: &wrong_source_semantics,
                    created_at_unix: 100,
                },
                &protection,
            ),
            Err(V031UpgradeReceiptError::InvalidCounts)
        ));

        let mut wrong_rollback_semantics =
            counts(V031UpgradeReceiptStage::OriginalRollbackVerified);
        wrong_rollback_semantics.insert(V031UpgradeReceiptCountKey::RollbackSlots, 4);
        assert!(matches!(
            seal_with_protection(
                &V031UpgradeReceiptCreateRequest {
                    context: context(),
                    stage: V031UpgradeReceiptStage::OriginalRollbackVerified,
                    previous_receipt_sha256: Some(SOURCE_PROFILE_PROOF_SHA256),
                    evidence_sha256: EVIDENCE_SHA256,
                    counts: &wrong_rollback_semantics,
                    created_at_unix: 101,
                },
                &protection,
            ),
            Err(V031UpgradeReceiptError::InvalidCounts)
        ));
    }

    #[test]
    fn later_stage_fixed_count_semantics_cannot_be_weakened() {
        let protection = TestCurrentUserProtection { scope: 19 };
        for (stage, key, invalid) in [
            (
                V031UpgradeReceiptStage::TargetComponentsPrepared,
                V031UpgradeReceiptCountKey::TargetCredentials,
                3,
            ),
            (
                V031UpgradeReceiptStage::CaseMigrationBackupsVerified,
                V031UpgradeReceiptCountKey::CheckpointComponents,
                5,
            ),
            (
                V031UpgradeReceiptStage::PrivacyV5Verified,
                V031UpgradeReceiptCountKey::PrivacyMigrationBatches,
                0,
            ),
            (
                V031UpgradeReceiptStage::ProjectionBackupVerified,
                V031UpgradeReceiptCountKey::SourceRevalidations,
                1,
            ),
            (
                V031UpgradeReceiptStage::UserV11Verified,
                V031UpgradeReceiptCountKey::PrivacyManifestTables,
                V031_USER_V11_PRIVACY_MANIFEST_TABLE_COUNT - 1,
            ),
            (
                V031UpgradeReceiptStage::UserV11Verified,
                V031UpgradeReceiptCountKey::UserManifestTables,
                27,
            ),
            (
                V031UpgradeReceiptStage::UpgradeComplete,
                V031UpgradeReceiptCountKey::NoopMigrations,
                3,
            ),
        ] {
            let mut invalid_counts = counts(stage);
            invalid_counts.insert(key, invalid);
            assert!(
                matches!(
                    seal_with_protection(
                        &V031UpgradeReceiptCreateRequest {
                            context: context(),
                            stage,
                            previous_receipt_sha256: Some(SOURCE_PROFILE_PROOF_SHA256),
                            evidence_sha256: EVIDENCE_SHA256,
                            counts: &invalid_counts,
                            created_at_unix: 101 + u64::from(stage.ordinal()),
                        },
                        &protection,
                    ),
                    Err(V031UpgradeReceiptError::InvalidCounts)
                ),
                "stage {} accepted weakened fixed counts",
                stage.as_str()
            );
        }

        let mut partial_terminal = counts(V031UpgradeReceiptStage::BindingMaterialsVerified);
        partial_terminal.insert(V031UpgradeReceiptCountKey::MaterialLedgerRows, 2);
        assert!(matches!(
            seal_with_protection(
                &V031UpgradeReceiptCreateRequest {
                    context: context(),
                    stage: V031UpgradeReceiptStage::BindingMaterialsVerified,
                    previous_receipt_sha256: Some(SOURCE_PROFILE_PROOF_SHA256),
                    evidence_sha256: EVIDENCE_SHA256,
                    counts: &partial_terminal,
                    created_at_unix: 105,
                },
                &protection,
            ),
            Err(V031UpgradeReceiptError::InvalidCounts)
        ));
    }

    #[test]
    fn chain_rejects_unknown_duplicate_break_and_jump() {
        let protection = TestCurrentUserProtection { scope: 7 };
        let first = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            100,
            protection,
        );
        let wrong_previous = "5555555555555555555555555555555555555555555555555555555555555555";
        let broken_second = seal_for_test(
            V031UpgradeReceiptStage::OriginalRollbackVerified,
            Some(wrong_previous),
            101,
            protection,
        );

        let unknown = [V031UpgradeReceiptChainArtifact::new(
            "00-source_preflight_verified.receipt.dpapi.bak",
            first.protected_bytes(),
        )];
        assert_eq!(
            validate_chain_with_protection(&unknown, context(), &protection),
            Err(V031UpgradeReceiptError::UnknownArtifact)
        );

        let duplicate = [
            V031UpgradeReceiptChainArtifact::new(
                V031UpgradeReceiptStage::SourcePreflightVerified.final_basename(),
                first.protected_bytes(),
            ),
            V031UpgradeReceiptChainArtifact::new(
                V031UpgradeReceiptStage::SourcePreflightVerified.final_basename(),
                first.protected_bytes(),
            ),
        ];
        assert_eq!(
            validate_chain_with_protection(&duplicate, context(), &protection),
            Err(V031UpgradeReceiptError::DuplicateArtifact)
        );

        let broken = [
            V031UpgradeReceiptChainArtifact::new(
                V031UpgradeReceiptStage::SourcePreflightVerified.final_basename(),
                first.protected_bytes(),
            ),
            V031UpgradeReceiptChainArtifact::new(
                V031UpgradeReceiptStage::OriginalRollbackVerified.final_basename(),
                broken_second.protected_bytes(),
            ),
        ];
        assert_eq!(
            validate_chain_with_protection(&broken, context(), &protection),
            Err(V031UpgradeReceiptError::BrokenChain)
        );

        let jump = [V031UpgradeReceiptChainArtifact::new(
            V031UpgradeReceiptStage::OriginalRollbackVerified.final_basename(),
            broken_second.protected_bytes(),
        )];
        assert_eq!(
            validate_chain_with_protection(&jump, context(), &protection),
            Err(V031UpgradeReceiptError::NonContiguousChain)
        );
    }

    #[test]
    fn exact_next_stage_incoming_is_parsed_and_authenticated() {
        let protection = TestCurrentUserProtection { scope: 7 };
        let first = seal_for_test(
            V031UpgradeReceiptStage::SourcePreflightVerified,
            None,
            100,
            protection,
        );
        let second = seal_for_test(
            V031UpgradeReceiptStage::OriginalRollbackVerified,
            Some(first.summary().protected_sha256()),
            101,
            protection,
        );
        let artifacts = [
            V031UpgradeReceiptChainArtifact::new(
                V031UpgradeReceiptStage::SourcePreflightVerified.final_basename(),
                first.protected_bytes(),
            ),
            V031UpgradeReceiptChainArtifact::new(
                V031UpgradeReceiptStage::OriginalRollbackVerified.incoming_basename(),
                second.protected_bytes(),
            ),
        ];
        let chain = validate_chain_with_protection(&artifacts, context(), &protection)
            .expect("authenticated next-stage incoming");
        assert_eq!(chain.final_receipts().len(), 1);
        assert_eq!(
            chain.next_stage(),
            Some(V031UpgradeReceiptStage::OriginalRollbackVerified)
        );
        assert_eq!(
            chain
                .incoming_receipt()
                .map(ValidatedV031UpgradeReceiptV1::stage),
            Some(V031UpgradeReceiptStage::OriginalRollbackVerified)
        );
    }
}
