//! Step 1/2 of the frozen v0.3.1 -> v0.4.0 migration protocol.
//!
//! This module is deliberately not a Tauri command.  It is a startup-only
//! capability gate that must be called while the process-wide startup and
//! migration-operation guards are held.  Success proves that receipt zero and
//! receipt one are final, that the Original V2 five-slot rollback point is
//! installed and decryptable, and that both active source databases plus all
//! target-absence predicates still match their preflight proofs.

use crate::{
    approved_mcp::{ApprovedMcpWorkspace, V031ApprovedMcpCredentialProbe},
    commands::{
        v031_checkpoint_receipts::authenticate_v031_partial_v5_workspace_profile_read_only,
        v031_upgrade_complete::authenticate_v031_terminal_history_for_bootstrap_offline,
    },
    v031_upgrade_r2::{
        self, AuthenticatedLineageInventory, AuthenticatedMigrationBackupsInventory, DirectorySync,
        OriginalRollbackV2InstallRequest, PlatformDirectorySync, ReceiptZeroBootstrap,
        ReceiptZeroNamespaceInventory, V2EvidenceInventory, VerifiedOriginalRollbackV2,
        PRIVACY_SNAPSHOT_INCOMING, USER_SNAPSHOT_INCOMING,
    },
    v031_upgrade_receipts::{
        load_authenticated_v031_lineage, persist_v031_receipt, OwnedV031ReceiptContext,
        PrivacyReceiptAuthenticationBridge, V031ReceiptPersistenceError,
    },
    v031_upgrade_source::{
        build_v031_source_profile_proof, generate_v031_upgrade_identity,
        recover_v031_source_profile_from_authenticated_original_v2,
        run_v031_local_protection_preflight, target_absence_evidence_from_verified,
        v031_target_absence_policy_sha256, verify_v031_backup_capacity, V031BackupCapacityEvidence,
        V031SourceProfileProof, V031TargetAbsenceEvidence, V031UpgradeSourceError,
    },
};
use database::{
    validate_v031_user_sqlite_image_read_only,
    with_validated_user_database_migration_source_read_only, UserMigrationSourceFileProof,
    UserMigrationSourceProof, ValidatedUserSourceSchema, V031_USER_SCHEMA_OBJECT_COUNT,
};
use privacy::{
    classify_privacy_v5_partial_read_only, compute_privacy_v5_manifests_read_only,
    compute_privacy_v6_manifests_read_only,
    lifecycle::max_backup_database_bytes_for_schema,
    original_rollback_v2::{
        open_v031_original_rollback_identity_v2, open_v031_original_rollback_v2_for_identity,
        MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES, MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
    },
    upgrade_receipt_v1::{V031UpgradeReceiptCountKey, V031UpgradeReceiptStage},
    validate_privacy_v1_sqlite_image_read_only,
    verify_initial_privacy_v5_before_receipt4_read_only,
    vnext::canonical_json_v1,
    with_validated_privacy_v1_migration_source_read_only, PrivacyStore, PrivacyStoreSchemaStatus,
    PrivacyV1SourceFileProof, PrivacyV5InitialFullExpectation, ValidatedPrivacyV1Source,
    PRIVACY_V1_SCHEMA_OBJECT_COUNT, PRIVACY_V1_SCHEMA_VERSION,
};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io,
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;

#[cfg(windows)]
use std::os::windows::{
    fs::OpenOptionsExt,
    io::{AsRawHandle, RawHandle},
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};

const ORIGINAL_ROLLBACK_EVIDENCE_SCHEMA: &str =
    "lawyer-assistance-v031-original-rollback-live-evidence-v1";
const PRESENT_SLOT_COUNT: u64 = 2;
const AUTHENTICATED_ABSENT_SLOT_COUNT: u64 = 3;
const ROLLBACK_SLOT_COUNT: u64 = 5;
const CAPACITY_CHECK_COUNT: u64 = 2;
const SOURCE_REVALIDATION_COUNT: u64 = 2;
const SOURCE_PHYSICAL_FILE_SET_SCHEMA: &str = "lawyer-assistance-v031-source-physical-file-set-v1";

/// Capability token returned only after the complete Step 1/2 gate succeeds.
///
/// Fields stay private so later migration stages cannot manufacture this token
/// with a struct literal.  The narrow hash/id accessors expose only the audit
/// anchors required to bind subsequent append-only receipts.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct OriginalRollbackVerifiedGate {
    receipt_context: OwnedV031ReceiptContext,
    original_identity_sha256: String,
    original_bundle_sha256: String,
    original_rollback_receipt_sha256: String,
    original_user_physical_file_set_sha256: String,
    original_privacy_physical_file_set_sha256: String,
    original_user_source_proof: UserMigrationSourceProof,
    original_privacy_logical_manifest_sha256: String,
    original_privacy_business_manifest_sha256: String,
    original_privacy_table_count: u64,
    original_privacy_total_rows: u64,
    original_privacy_protected_review_payload_count: u64,
}

impl fmt::Debug for OriginalRollbackVerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginalRollbackVerifiedGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field(
                "source_profile_proof_sha256",
                &self.receipt_context.source_profile_proof_sha256,
            )
            .field("original_identity_sha256", &self.original_identity_sha256)
            .field("original_bundle_sha256", &self.original_bundle_sha256)
            .field(
                "original_rollback_receipt_sha256",
                &self.original_rollback_receipt_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl OriginalRollbackVerifiedGate {
    pub(crate) fn lineage_id(&self) -> &str {
        &self.receipt_context.lineage_id
    }

    pub(crate) fn envelope_binding_id(&self) -> &str {
        &self.receipt_context.envelope_binding_id
    }

    pub(crate) fn source_profile_proof_sha256(&self) -> &str {
        &self.receipt_context.source_profile_proof_sha256
    }

    pub(crate) fn original_identity_sha256(&self) -> &str {
        &self.original_identity_sha256
    }

    pub(crate) fn original_bundle_sha256(&self) -> &str {
        &self.original_bundle_sha256
    }

    pub(crate) fn original_rollback_receipt_sha256(&self) -> &str {
        &self.original_rollback_receipt_sha256
    }

    pub(crate) fn original_user_physical_file_set_sha256(&self) -> &str {
        &self.original_user_physical_file_set_sha256
    }

    pub(crate) fn original_privacy_physical_file_set_sha256(&self) -> &str {
        &self.original_privacy_physical_file_set_sha256
    }

    pub(crate) fn authenticates_user_physical_file_set(
        &self,
        source: &UserMigrationSourceProof,
    ) -> bool {
        user_physical_file_set_sha256(source)
            .is_ok_and(|observed| observed == self.original_user_physical_file_set_sha256)
    }

    pub(crate) fn authenticates_privacy_physical_file_set(
        &self,
        source: &ValidatedPrivacyV1Source,
    ) -> bool {
        privacy_physical_file_set_sha256(source)
            .is_ok_and(|observed| observed == self.original_privacy_physical_file_set_sha256)
    }

    pub(crate) fn receipt_context(&self) -> OwnedV031ReceiptContext {
        self.receipt_context.clone()
    }

    /// Exact user source revalidated while the authenticated original rollback
    /// bundle and receipt were still live. Later migration stages may compare
    /// semantic proof fields but cannot manufacture or replace this gate.
    pub(crate) fn original_user_source_proof(&self) -> &UserMigrationSourceProof {
        &self.original_user_source_proof
    }

    pub(crate) fn original_privacy_logical_manifest_sha256(&self) -> &str {
        &self.original_privacy_logical_manifest_sha256
    }

    pub(crate) fn original_privacy_business_manifest_sha256(&self) -> &str {
        &self.original_privacy_business_manifest_sha256
    }

    pub(crate) const fn original_privacy_table_count(&self) -> u64 {
        self.original_privacy_table_count
    }

    pub(crate) const fn original_privacy_total_rows(&self) -> u64 {
        self.original_privacy_total_rows
    }

    pub(crate) const fn original_privacy_protected_review_payload_count(&self) -> u64 {
        self.original_privacy_protected_review_payload_count
    }

    /// Compares only stable, independently authenticated rollback anchors and
    /// semantic source evidence. Active-source file metadata deliberately does
    /// not participate because a gate reloaded from the immutable V2 SQLite
    /// images has different in-memory file proofs by construction.
    pub(crate) fn authenticates_same_original_rollback(&self, observed: &Self) -> bool {
        self.receipt_context == observed.receipt_context
            && self.original_identity_sha256 == observed.original_identity_sha256
            && self.original_bundle_sha256 == observed.original_bundle_sha256
            && self.original_rollback_receipt_sha256 == observed.original_rollback_receipt_sha256
            && self.original_user_physical_file_set_sha256
                == observed.original_user_physical_file_set_sha256
            && self.original_privacy_physical_file_set_sha256
                == observed.original_privacy_physical_file_set_sha256
            && same_user_source_content(
                &self.original_user_source_proof,
                &observed.original_user_source_proof,
            )
            && self.original_privacy_logical_manifest_sha256
                == observed.original_privacy_logical_manifest_sha256
            && self.original_privacy_business_manifest_sha256
                == observed.original_privacy_business_manifest_sha256
            && self.original_privacy_table_count == observed.original_privacy_table_count
            && self.original_privacy_total_rows == observed.original_privacy_total_rows
            && self.original_privacy_protected_review_payload_count
                == observed.original_privacy_protected_review_payload_count
    }

    #[cfg(test)]
    pub(crate) fn from_user_source_for_test(
        original_user_source_proof: UserMigrationSourceProof,
    ) -> Self {
        let original_user_physical_file_set_sha256 =
            user_physical_file_set_sha256(&original_user_source_proof)
                .expect("test user physical file-set evidence");
        Self {
            receipt_context: OwnedV031ReceiptContext {
                lineage_id: "a".repeat(64),
                envelope_binding_id: format!("ws_{}", "b".repeat(32)),
                source_profile_proof_sha256: "c".repeat(64),
            },
            original_identity_sha256: "d".repeat(64),
            original_bundle_sha256: "e".repeat(64),
            original_rollback_receipt_sha256: "f".repeat(64),
            original_user_physical_file_set_sha256,
            original_privacy_physical_file_set_sha256: "7".repeat(64),
            original_user_source_proof,
            original_privacy_logical_manifest_sha256: "1".repeat(64),
            original_privacy_business_manifest_sha256: "2".repeat(64),
            original_privacy_table_count: 5,
            original_privacy_total_rows: 0,
            original_privacy_protected_review_payload_count: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_privacy_source_for_checkpoint_test(
        mut self,
        original_privacy_source: ValidatedPrivacyV1Source,
    ) -> Self {
        self.original_privacy_physical_file_set_sha256 =
            privacy_physical_file_set_sha256(&original_privacy_source)
                .expect("test Privacy physical file-set evidence");
        self.original_privacy_logical_manifest_sha256 =
            original_privacy_source.logical_manifest.sha256.clone();
        self.original_privacy_business_manifest_sha256 =
            original_privacy_source.business_manifest.sha256.clone();
        self.original_privacy_table_count =
            u64::try_from(original_privacy_source.logical_manifest.tables.len())
                .expect("test Privacy table count fits u64");
        self.original_privacy_total_rows = original_privacy_source.logical_manifest.total_row_count;
        self.original_privacy_protected_review_payload_count =
            original_privacy_source.protected_review_payload_count;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_original_rollback_receipt_sha256_for_test(
        mut self,
        original_rollback_receipt_sha256: String,
    ) -> Self {
        self.original_rollback_receipt_sha256 = original_rollback_receipt_sha256;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginalMigrationBackupError {
    InvalidInput,
    ExistingLineageConflict,
    TargetAbsence,
    LocalProtection,
    CapacityProbe,
    InsufficientCapacity,
    UserSource,
    PrivacySource,
    SourceDrift,
    Receipt,
    Filesystem,
    Snapshot,
    RollbackCodec,
    EvidenceEncoding,
}

impl OriginalMigrationBackupError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "v031_original_backup_invalid_input",
            Self::ExistingLineageConflict => "v031_original_backup_lineage_conflict",
            Self::TargetAbsence => "v031_original_backup_target_absence_failed",
            Self::LocalProtection => "v031_original_backup_dpapi_preflight_failed",
            Self::CapacityProbe => "v031_original_backup_capacity_probe_failed",
            Self::InsufficientCapacity => "v031_original_backup_insufficient_capacity",
            Self::UserSource => "v031_original_backup_user_source_failed",
            Self::PrivacySource => "v031_original_backup_privacy_source_failed",
            Self::SourceDrift => "v031_original_backup_source_drift",
            Self::Receipt => "v031_original_backup_receipt_failed",
            Self::Filesystem => "v031_original_backup_filesystem_failed",
            Self::Snapshot => "v031_original_backup_snapshot_failed",
            Self::RollbackCodec => "v031_original_backup_codec_failed",
            Self::EvidenceEncoding => "v031_original_backup_evidence_encoding_failed",
        }
    }
}

impl fmt::Display for OriginalMigrationBackupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for OriginalMigrationBackupError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LineagePreflight {
    Fresh,
    Resume { lineage_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CapacityPreflight {
    user_bytes: u64,
    privacy_bytes: u64,
    evidence: V031BackupCapacityEvidence,
}

#[derive(Debug, Clone)]
struct Step12NamespacePreflight {
    lineage: LineagePreflight,
    receipt_zero_namespace: ReceiptZeroNamespaceInventory,
}

#[derive(Debug, Clone)]
struct InSessionResult {
    source_profile: V031SourceProfileProof,
    initial_user: UserMigrationSourceProof,
    initial_privacy: ValidatedPrivacyV1Source,
    receipt_context: OwnedV031ReceiptContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedV2 {
    protected_identity_sha256: String,
    bundle_sha256: String,
    source_user_physical_file_set_sha256: String,
    source_privacy_physical_file_set_sha256: String,
    user_snapshot_sha256: String,
    privacy_snapshot_sha256: String,
    bundle_bytes: u64,
    total_chunk_count: u64,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct OriginalRollbackReceiptEvidenceV1<'a> {
    schema_version: &'static str,
    source_profile_proof_sha256: &'a str,
    source_revalidation_sha256: &'a str,
    target_absence_policy_sha256: &'a str,
    protected_identity_sha256: &'a str,
    bundle_sha256: &'a str,
    source_user_physical_file_set_sha256: &'a str,
    source_privacy_physical_file_set_sha256: &'a str,
    user_snapshot_sha256: &'a str,
    privacy_snapshot_sha256: &'a str,
    identity_artifacts: u64,
    bundle_artifacts: u64,
    bundle_bytes: u64,
    rollback_slots: u64,
    sqlite_images: u64,
    encrypted_chunks: u64,
    source_revalidations: u64,
    authenticated_absent_slots: u64,
    target_absence_checks: u64,
}

/// Establishes the frozen Step 1/2 migration gate.
///
/// The caller must hold the application startup/single-instance guard and the
/// migration operation gate.  This function does not create any target
/// credential, workspace identity, Vault, approved-workspace, work-product, or
/// current-schema manager state.
pub(crate) fn establish_original_migration_backup(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
) -> Result<OriginalRollbackVerifiedGate, OriginalMigrationBackupError> {
    let credential_probe = V031ApprovedMcpCredentialProbe::new();
    establish_original_migration_backup_with_probe(
        app_local_data_dir,
        user_database_path,
        privacy_database_path,
        &credential_probe,
    )
}

/// Test-only dependency-injection boundary for an ephemeral credential
/// provider. The rollback bundle, identity, receipts, DPAPI and source
/// validators remain the production implementations; only the read-only
/// Credential Manager presence probe is supplied by the fixture so tests never
/// create or delete the fixed production credential names.
#[cfg(test)]
pub(crate) fn establish_original_migration_backup_with_credential_probe_for_test<
    P: v031_upgrade_r2::CredentialPresenceProbe,
>(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
    credential_probe: &P,
) -> Result<OriginalRollbackVerifiedGate, OriginalMigrationBackupError> {
    establish_original_migration_backup_with_probe(
        app_local_data_dir,
        user_database_path,
        privacy_database_path,
        credential_probe,
    )
}

fn establish_original_migration_backup_with_probe<P: v031_upgrade_r2::CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
    credential_probe: &P,
) -> Result<OriginalRollbackVerifiedGate, OriginalMigrationBackupError> {
    validate_absolute_path(app_local_data_dir)?;
    validate_absolute_path(user_database_path)?;
    validate_absolute_path(privacy_database_path)?;
    if user_database_path == privacy_database_path {
        return Err(OriginalMigrationBackupError::InvalidInput);
    }

    // Every non-empty lineage is authenticated before `migration-backups` is
    // admitted as the sole target-absence exception.  Any number of terminal
    // ten-receipt histories may coexist with at most one active Step 1/2
    // lineage (or one empty receipt-zero crash residue).
    let namespace_preflight = inspect_existing_step12_lineage(app_local_data_dir)?;
    let initial_absence = prove_target_absence_with_namespace(
        app_local_data_dir,
        &namespace_preflight.receipt_zero_namespace,
        credential_probe,
    )?;
    let local_protection_preflight_sha256 = run_v031_local_protection_preflight()
        .map_err(|_| OriginalMigrationBackupError::LocalProtection)?;
    let capacity = run_capacity_preflight(
        app_local_data_dir,
        user_database_path,
        privacy_database_path,
    )?;

    let target_absence_evidence = target_absence_evidence_from_verified(&initial_absence)
        .map_err(|_| OriginalMigrationBackupError::TargetAbsence)?;
    let (post_user, nested_result) = with_validated_user_database_migration_source_read_only(
        user_database_path,
        |user_session| {
            let initial_user = user_session.proof().clone();
            with_validated_privacy_v1_migration_source_read_only(
                privacy_database_path,
                |privacy_session| {
                    let initial_privacy = privacy_session.proof().clone();
                    establish_inside_simultaneous_source_sessions(
                        app_local_data_dir,
                        user_session,
                        privacy_session,
                        initial_user,
                        initial_privacy,
                        &target_absence_evidence,
                        &local_protection_preflight_sha256,
                        &capacity,
                        &namespace_preflight,
                        &initial_absence,
                        credential_probe,
                    )
                },
            )
            .map_err(|_| OriginalMigrationBackupError::PrivacySource)
            .and_then(|(post_privacy, inner_result)| {
                let result = inner_result?;
                if !same_privacy_source_content(&result.initial_privacy, &post_privacy) {
                    return Err(OriginalMigrationBackupError::SourceDrift);
                }
                Ok((post_privacy, result))
            })
        },
    )
    .map_err(|_| OriginalMigrationBackupError::UserSource)?;
    let (post_privacy, in_session) = nested_result?;
    if !same_user_source_content(&in_session.initial_user, &post_user) {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }

    // Both callback-scoped deferred/query-only sessions have now exited and
    // each validator has repeated its filesystem, sidecar, schema, logical,
    // business, data-version, and protected-payload proof.
    let live_namespace = inspect_existing_step12_lineage(app_local_data_dir)?;
    verify_terminal_history_lineages(
        app_local_data_dir,
        live_namespace
            .receipt_zero_namespace
            .authenticated_lineages(),
    )?;
    require_same_lineage(
        &live_namespace.lineage,
        &in_session.receipt_context.lineage_id,
    )?;
    let authenticated_backups = authenticate_complete_migration_backups(app_local_data_dir)?;
    let final_absence = prove_target_absence_with_authenticated_backups(
        app_local_data_dir,
        &authenticated_backups,
        credential_probe,
    )?;
    let final_absence_evidence = target_absence_evidence_from_verified(&final_absence)
        .map_err(|_| OriginalMigrationBackupError::TargetAbsence)?;
    if target_absence_evidence != final_absence_evidence {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }

    let final_local_protection_preflight_sha256 = run_v031_local_protection_preflight()
        .map_err(|_| OriginalMigrationBackupError::LocalProtection)?;
    if final_local_protection_preflight_sha256 != local_protection_preflight_sha256 {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    let final_capacity = verify_v031_backup_capacity(
        app_local_data_dir,
        post_user.database_file.length,
        post_privacy.database_file.length,
    )
    .map_err(|error| match error {
        V031UpgradeSourceError::InsufficientCapacity => {
            OriginalMigrationBackupError::InsufficientCapacity
        }
        _ => OriginalMigrationBackupError::CapacityProbe,
    })?;

    let revalidated_source_profile = build_v031_source_profile_proof(
        &post_user,
        &post_privacy,
        &final_absence_evidence,
        &final_capacity,
        &final_local_protection_preflight_sha256,
    )
    .map_err(|_| OriginalMigrationBackupError::SourceDrift)?;
    if revalidated_source_profile != in_session.source_profile
        || revalidated_source_profile.sha256()
            != in_session.receipt_context.source_profile_proof_sha256
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }

    // Re-open every live evidence artifact after leaving both source sessions.
    // This is also required for an existing receipt1 no-op: a protected receipt
    // never substitutes for current disk-state verification.
    let verified_v2 = verify_installed_v2_from_disk(
        app_local_data_dir,
        &in_session.receipt_context,
        &post_user,
        &post_privacy,
        &revalidated_source_profile,
    )?;
    let receipt_one_evidence_sha256 = original_rollback_evidence_sha256(
        &in_session.source_profile,
        &revalidated_source_profile,
        &verified_v2,
    )?;
    let receipt_one_counts = original_rollback_counts(verified_v2.total_chunk_count);
    let persisted_receipt_one = persist_v031_receipt(
        app_local_data_dir,
        &in_session.receipt_context,
        V031UpgradeReceiptStage::OriginalRollbackVerified,
        &receipt_one_evidence_sha256,
        &receipt_one_counts,
        || {
            verify_receipt_one_live_state(
                app_local_data_dir,
                user_database_path,
                privacy_database_path,
                &in_session.receipt_context,
                &in_session.source_profile,
                &receipt_one_evidence_sha256,
                &verified_v2,
                credential_probe,
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
        },
    )
    .map_err(|_| OriginalMigrationBackupError::Receipt)?;

    let bridge = PrivacyReceiptAuthenticationBridge::new(in_session.receipt_context.clone());
    let inventory = load_authenticated_v031_lineage(
        app_local_data_dir,
        &in_session.receipt_context.lineage_id,
        &bridge,
    )
    .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    validate_terminal_step12_inventory(&inventory)?;
    let final_verified_v2 = verify_installed_v2_from_disk(
        app_local_data_dir,
        &in_session.receipt_context,
        &post_user,
        &post_privacy,
        &revalidated_source_profile,
    )?;
    if final_verified_v2 != verified_v2
        || persisted_receipt_one.receipt.metadata.evidence_sha256 != receipt_one_evidence_sha256
        || persisted_receipt_one.receipt.metadata.counts != count_map_as_wire(&receipt_one_counts)?
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }

    Ok(OriginalRollbackVerifiedGate {
        receipt_context: in_session.receipt_context,
        original_identity_sha256: final_verified_v2.protected_identity_sha256,
        original_bundle_sha256: final_verified_v2.bundle_sha256,
        original_rollback_receipt_sha256: persisted_receipt_one.receipt.protected_file_sha256,
        original_user_physical_file_set_sha256: final_verified_v2
            .source_user_physical_file_set_sha256,
        original_privacy_physical_file_set_sha256: final_verified_v2
            .source_privacy_physical_file_set_sha256,
        original_user_source_proof: post_user,
        original_privacy_logical_manifest_sha256: post_privacy.logical_manifest.sha256.clone(),
        original_privacy_business_manifest_sha256: post_privacy.business_manifest.sha256.clone(),
        original_privacy_table_count: u64::try_from(post_privacy.logical_manifest.tables.len())
            .map_err(|_| OriginalMigrationBackupError::SourceDrift)?,
        original_privacy_total_rows: post_privacy.logical_manifest.total_row_count,
        original_privacy_protected_review_payload_count: post_privacy
            .protected_review_payload_count,
    })
}

/// Re-authenticates the immutable Step 1/2 capability after the active Privacy
/// or user stores have advanced beyond the v0.3.1 source schemas.
///
/// The original SQLite images are opened only from the DPAPI/AEAD-authenticated
/// V2 envelope and validated in SQLite-owned read-only memory. No plaintext
/// recovery image is written to disk and no current-schema validator is
/// relaxed. The ordinal-one evidence is recomputed from the installed bytes so
/// an authenticated receipt cannot substitute for the live rollback point.
pub(crate) fn load_original_migration_backup_gate(
    app_local_data_dir: &Path,
    lineage_id: &str,
) -> Result<OriginalRollbackVerifiedGate, OriginalMigrationBackupError> {
    let approved_workspace = ApprovedMcpWorkspace::new(app_local_data_dir.to_path_buf());
    load_original_migration_backup_gate_with_approved_workspace(
        app_local_data_dir,
        lineage_id,
        &approved_workspace,
    )
}

#[cfg(test)]
pub(crate) fn load_original_migration_backup_gate_with_approved_workspace_for_test(
    app_local_data_dir: &Path,
    lineage_id: &str,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<OriginalRollbackVerifiedGate, OriginalMigrationBackupError> {
    load_original_migration_backup_gate_with_approved_workspace(
        app_local_data_dir,
        lineage_id,
        approved_workspace,
    )
}

fn load_original_migration_backup_gate_with_approved_workspace(
    app_local_data_dir: &Path,
    lineage_id: &str,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<OriginalRollbackVerifiedGate, OriginalMigrationBackupError> {
    validate_absolute_path(app_local_data_dir)?;
    v031_upgrade_r2::validate_lineage_id(lineage_id)
        .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;

    let bridge = PrivacyReceiptAuthenticationBridge::discovering();
    let inventory = load_authenticated_v031_lineage(app_local_data_dir, lineage_id, &bridge)
        .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    if inventory.final_receipts.len() < 2
        || !inventory.v2.identity_final
        || inventory.v2.identity_incoming
        || !inventory.v2.bundle_final
        || inventory.v2.bundle_incoming
        || inventory.v2.user_snapshot_incoming
        || inventory.v2.privacy_snapshot_incoming
    {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let context = bridge
        .context()
        .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    if context.lineage_id != lineage_id {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }

    let lineage_directory =
        v031_upgrade_r2::canonical_lineage_directory(app_local_data_dir, lineage_id)
            .map_err(|_| OriginalMigrationBackupError::Filesystem)?;
    let protected_identity = v031_upgrade_r2::read_bounded_file(
        &lineage_directory.join(v031_upgrade_r2::V2_IDENTITY_FINAL),
        MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
    )
    .map_err(|_| OriginalMigrationBackupError::Filesystem)?;
    let bundle = v031_upgrade_r2::read_bounded_file(
        &lineage_directory.join(v031_upgrade_r2::V2_BUNDLE_FINAL),
        MAX_V031_ORIGINAL_ROLLBACK_BUNDLE_BYTES,
    )
    .map_err(|_| OriginalMigrationBackupError::Filesystem)?;
    let protected_identity_sha256 = sha256_hex(&protected_identity);
    let bundle_sha256 = sha256_hex(&bundle);
    let identity = open_v031_original_rollback_identity_v2(&protected_identity)
        .map_err(|_| OriginalMigrationBackupError::RollbackCodec)?;
    if identity.lineage_id != context.lineage_id
        || identity.envelope_binding_id != context.envelope_binding_id
        || identity.source_profile_proof_sha256 != context.source_profile_proof_sha256
        || identity.bundle_sha256 != bundle_sha256
        || identity.bundle_bytes != bundle.len() as u64
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    let opened = open_v031_original_rollback_v2_for_identity(&bundle, &identity)
        .map_err(|_| OriginalMigrationBackupError::RollbackCodec)?;
    let user_source = validate_v031_user_sqlite_image_read_only(&opened.user_database)
        .map_err(|_| OriginalMigrationBackupError::UserSource)?;
    let privacy_source = validate_privacy_v1_sqlite_image_read_only(&opened.privacy_store)
        .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
    let source_profile = recover_v031_source_profile_from_authenticated_original_v2(
        &identity,
        &user_source,
        &privacy_source,
    )
    .map_err(|_| OriginalMigrationBackupError::SourceDrift)?;
    if source_profile.sha256() != context.source_profile_proof_sha256 {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }

    let verified_v2 = VerifiedV2 {
        protected_identity_sha256: protected_identity_sha256.clone(),
        bundle_sha256: bundle_sha256.clone(),
        source_user_physical_file_set_sha256: identity.source_user_physical_file_set_sha256.clone(),
        source_privacy_physical_file_set_sha256: identity
            .source_privacy_physical_file_set_sha256
            .clone(),
        user_snapshot_sha256: sha256_hex(&opened.user_database),
        privacy_snapshot_sha256: sha256_hex(&opened.privacy_store),
        bundle_bytes: bundle.len() as u64,
        total_chunk_count: u64::from(identity.total_chunk_count),
    };
    let expected_evidence =
        original_rollback_evidence_sha256(&source_profile, &source_profile, &verified_v2)?;
    let expected_counts =
        count_map_as_wire(&original_rollback_counts(verified_v2.total_chunk_count))?;
    let receipt_one = inventory
        .final_receipts
        .get(1)
        .ok_or(OriginalMigrationBackupError::Receipt)?;
    if receipt_one.ordinal != V031UpgradeReceiptStage::OriginalRollbackVerified.ordinal()
        || receipt_one.metadata.evidence_sha256 != expected_evidence
        || receipt_one.metadata.counts != expected_counts
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    let gate = OriginalRollbackVerifiedGate {
        receipt_context: context.clone(),
        original_identity_sha256: protected_identity_sha256.clone(),
        original_bundle_sha256: bundle_sha256.clone(),
        original_rollback_receipt_sha256: receipt_one.protected_file_sha256.clone(),
        original_user_physical_file_set_sha256: identity
            .source_user_physical_file_set_sha256
            .clone(),
        original_privacy_physical_file_set_sha256: identity
            .source_privacy_physical_file_set_sha256
            .clone(),
        original_user_source_proof: user_source.clone(),
        original_privacy_logical_manifest_sha256: privacy_source.logical_manifest.sha256.clone(),
        original_privacy_business_manifest_sha256: privacy_source.business_manifest.sha256.clone(),
        original_privacy_table_count: u64::try_from(privacy_source.logical_manifest.tables.len())
            .map_err(|_| OriginalMigrationBackupError::SourceDrift)?,
        original_privacy_total_rows: privacy_source.logical_manifest.total_row_count,
        original_privacy_protected_review_payload_count: privacy_source
            .protected_review_payload_count,
    };
    validate_active_sources_for_reloaded_gate(
        app_local_data_dir,
        &inventory,
        approved_workspace,
        &gate,
        &identity,
        &user_source,
        &privacy_source,
    )?;
    Ok(gate)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadedPrivacySourceState {
    OriginalV1,
    PartialV5,
    MigratedV5,
    CurrentV6,
}

fn validate_active_sources_for_reloaded_gate(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
    rollback_gate: &OriginalRollbackVerifiedGate,
    identity: &privacy::original_rollback_v2::V031OriginalRollbackIdentityV2,
    original_user: &UserMigrationSourceProof,
    original_privacy: &ValidatedPrivacyV1Source,
) -> Result<(), OriginalMigrationBackupError> {
    let user_database_path = app_local_data_dir.join("user.sqlite");
    let (active_user, ()) =
        with_validated_user_database_migration_source_read_only(&user_database_path, |_| ())
            .map_err(|_| OriginalMigrationBackupError::UserSource)?;
    match active_user.schema {
        ValidatedUserSourceSchema::V031V10 => {
            validate_original_user_v10_physical_anchor(
                &active_user,
                original_user,
                &identity.source_user_physical_file_set_sha256,
            )?;
        }
        ValidatedUserSourceSchema::CurrentV11 => {
            if !receipt_prefix_reaches(inventory, V031UpgradeReceiptStage::PrivacyV6Verified)
                || !inventory.checkpoints.binding.is_exact_final()
                || !inventory.checkpoints.materials.is_exact_final()
                || !inventory.checkpoints.projection.is_exact_final()
            {
                return Err(OriginalMigrationBackupError::SourceDrift);
            }
        }
    }

    let privacy_state = validate_active_privacy_source_for_reloaded_gate(
        app_local_data_dir,
        inventory,
        approved_workspace,
        rollback_gate,
        identity,
        original_privacy,
    )?;
    if active_user.schema == ValidatedUserSourceSchema::CurrentV11
        && privacy_state != ReloadedPrivacySourceState::CurrentV6
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    Ok(())
}

fn validate_original_user_v10_physical_anchor(
    active_user: &UserMigrationSourceProof,
    original_user: &UserMigrationSourceProof,
    expected_physical_file_set_sha256: &str,
) -> Result<(), OriginalMigrationBackupError> {
    if active_user.schema != ValidatedUserSourceSchema::V031V10
        || !same_user_source_content(original_user, active_user)
        || user_physical_file_set_sha256(active_user)? != expected_physical_file_set_sha256
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    Ok(())
}

fn validate_active_privacy_source_for_reloaded_gate(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
    rollback_gate: &OriginalRollbackVerifiedGate,
    identity: &privacy::original_rollback_v2::V031OriginalRollbackIdentityV2,
    original_privacy: &ValidatedPrivacyV1Source,
) -> Result<ReloadedPrivacySourceState, OriginalMigrationBackupError> {
    let privacy_database_path = app_local_data_dir
        .join("privacy")
        .join("privacy-workflow.sqlite");
    let _plain_file = open_plain_file_read_only(&privacy_database_path)
        .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
    let connection = Connection::open_with_flags(
        &privacy_database_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
    let status = PrivacyStore::preflight_schema(&connection)
        .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;

    match status {
        PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 1 } => {
            drop(connection);
            let active_privacy =
                privacy::validate_privacy_v1_migration_source_read_only(&privacy_database_path)
                    .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
            if !same_privacy_source_content(original_privacy, &active_privacy)
                || privacy_physical_file_set_sha256(&active_privacy)?
                    != identity.source_privacy_physical_file_set_sha256
            {
                return Err(OriginalMigrationBackupError::SourceDrift);
            }
            Ok(ReloadedPrivacySourceState::OriginalV1)
        }
        PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 } => {
            if !receipt_prefix_reaches(
                inventory,
                V031UpgradeReceiptStage::CaseMigrationBackupsVerified,
            ) || !inventory.checkpoints.binding.is_exact_final()
                || !inventory.checkpoints.materials.is_exact_final()
            {
                return Err(OriginalMigrationBackupError::SourceDrift);
            }

            // Once Receipt 4 is final, later authorized binding/material rows
            // make the general canonical v5 manifest the correct live proof.
            if receipt_prefix_reaches(inventory, V031UpgradeReceiptStage::PrivacyV5Verified) {
                compute_privacy_v5_manifests_read_only(&connection)
                    .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
                return Ok(ReloadedPrivacySourceState::MigratedV5);
            }

            // Before Receipt 4, both a recoverable partial prefix and a fully
            // committed v5 crash residue require the same authenticated
            // Receipt-3 workspace/checkpoint profile. Receipt-4 incoming is
            // allowed only as the next authenticated file; the strict full
            // proof below still has to match Original V2 exactly.
            let workspace = authenticate_v031_partial_v5_workspace_profile_read_only(
                app_local_data_dir,
                approved_workspace,
                rollback_gate,
                inventory,
            )
            .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
            let initial_expectation = PrivacyV5InitialFullExpectation {
                expected_workspace_instance_id: workspace.workspace_instance_id(),
                expected_source_business_manifest_sha256: original_privacy
                    .business_manifest
                    .sha256
                    .as_str(),
                expected_source_total_row_count: original_privacy.logical_manifest.total_row_count,
                expected_protected_review_payload_count: original_privacy
                    .protected_review_payload_count,
            };
            if verify_initial_privacy_v5_before_receipt4_read_only(
                &connection,
                &initial_expectation,
            )
            .is_ok()
            {
                return Ok(ReloadedPrivacySourceState::MigratedV5);
            }

            let partial = classify_privacy_v5_partial_read_only(
                &connection,
                workspace.workspace_instance_id(),
            )
            .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
            if partial.source_business_manifest_sha256()
                != original_privacy.business_manifest.sha256.as_str()
                || partial.source_total_row_count()
                    != original_privacy.logical_manifest.total_row_count
                || partial.protected_review_payload_count()
                    != original_privacy.protected_review_payload_count
            {
                return Err(OriginalMigrationBackupError::SourceDrift);
            }
            Ok(ReloadedPrivacySourceState::PartialV5)
        }
        PrivacyStoreSchemaStatus::Current => {
            compute_privacy_v6_manifests_read_only(&connection)
                .map_err(|_| OriginalMigrationBackupError::PrivacySource)?;
            if !receipt_prefix_reaches(inventory, V031UpgradeReceiptStage::ProjectionBackupVerified)
                || !inventory.checkpoints.binding.is_exact_final()
                || !inventory.checkpoints.materials.is_exact_final()
                || !inventory.checkpoints.projection.is_exact_final()
            {
                return Err(OriginalMigrationBackupError::SourceDrift);
            }
            Ok(ReloadedPrivacySourceState::CurrentV6)
        }
        PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
            Err(OriginalMigrationBackupError::PrivacySource)
        }
    }
}

fn receipt_prefix_reaches(
    inventory: &AuthenticatedLineageInventory,
    stage: V031UpgradeReceiptStage,
) -> bool {
    inventory.final_receipts.len() > usize::from(stage.ordinal())
}

#[allow(clippy::too_many_arguments)]
fn verify_receipt_one_live_state<P: v031_upgrade_r2::CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
    context: &OwnedV031ReceiptContext,
    expected_source_profile: &V031SourceProfileProof,
    expected_evidence_sha256: &str,
    expected_v2: &VerifiedV2,
    credential_probe: &P,
) -> Result<(), OriginalMigrationBackupError> {
    let local_protection_preflight_sha256 = run_v031_local_protection_preflight()
        .map_err(|_| OriginalMigrationBackupError::LocalProtection)?;
    let (post_user, nested) = with_validated_user_database_migration_source_read_only(
        user_database_path,
        |user_session| {
            let initial_user = user_session.proof().clone();
            with_validated_privacy_v1_migration_source_read_only(
                privacy_database_path,
                |privacy_session| {
                    let initial_privacy = privacy_session.proof().clone();
                    let namespace = inspect_existing_step12_lineage(app_local_data_dir)?;
                    require_same_lineage(&namespace.lineage, &context.lineage_id)?;
                    verify_terminal_history_lineages(
                        app_local_data_dir,
                        namespace.receipt_zero_namespace.authenticated_lineages(),
                    )?;
                    let authenticated_backups =
                        authenticate_complete_migration_backups(app_local_data_dir)?;
                    let absence = prove_target_absence_with_authenticated_backups(
                        app_local_data_dir,
                        &authenticated_backups,
                        credential_probe,
                    )?;
                    let absence_evidence = target_absence_evidence_from_verified(&absence)
                        .map_err(|_| OriginalMigrationBackupError::TargetAbsence)?;
                    let capacity = verify_v031_backup_capacity(
                        app_local_data_dir,
                        initial_user.database_file.length,
                        initial_privacy.database_file.length,
                    )
                    .map_err(|_| OriginalMigrationBackupError::CapacityProbe)?;
                    let source_profile = build_v031_source_profile_proof(
                        &initial_user,
                        &initial_privacy,
                        &absence_evidence,
                        &capacity,
                        &local_protection_preflight_sha256,
                    )
                    .map_err(|_| OriginalMigrationBackupError::SourceDrift)?;
                    if &source_profile != expected_source_profile
                        || source_profile.sha256() != context.source_profile_proof_sha256
                    {
                        return Err(OriginalMigrationBackupError::SourceDrift);
                    }
                    let live_v2 = verify_installed_v2_from_disk(
                        app_local_data_dir,
                        context,
                        &initial_user,
                        &initial_privacy,
                        &source_profile,
                    )?;
                    let evidence_sha256 = original_rollback_evidence_sha256(
                        &source_profile,
                        &source_profile,
                        &live_v2,
                    )?;
                    if &live_v2 != expected_v2 || evidence_sha256 != expected_evidence_sha256 {
                        return Err(OriginalMigrationBackupError::SourceDrift);
                    }
                    Ok::<_, OriginalMigrationBackupError>((initial_user, initial_privacy))
                },
            )
            .map_err(|_| OriginalMigrationBackupError::PrivacySource)
            .and_then(|(post_privacy, result)| {
                let (initial_user, initial_privacy) = result?;
                if !same_privacy_source_content(&initial_privacy, &post_privacy) {
                    return Err(OriginalMigrationBackupError::SourceDrift);
                }
                Ok((initial_user, initial_privacy))
            })
        },
    )
    .map_err(|_| OriginalMigrationBackupError::UserSource)?;
    let (initial_user, _initial_privacy) = nested?;
    if !same_user_source_content(&initial_user, &post_user) {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    Ok(())
}

fn verify_receipt_zero_live_state<P: v031_upgrade_r2::CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    user_session: &database::ValidatedUserMigrationSourceSession<'_>,
    privacy_session: &privacy::ValidatedPrivacyV1ReadOnlySession<'_>,
    context: &OwnedV031ReceiptContext,
    expected_source_profile: &V031SourceProfileProof,
    receipt_zero_bootstrap: Option<&ReceiptZeroBootstrap>,
    credential_probe: &P,
) -> Result<(), OriginalMigrationBackupError> {
    let capacity = verify_v031_backup_capacity(
        app_local_data_dir,
        user_session.proof().database_file.length,
        privacy_session.proof().database_file.length,
    )
    .map_err(|_| OriginalMigrationBackupError::CapacityProbe)?;
    let local_protection_preflight_sha256 = run_v031_local_protection_preflight()
        .map_err(|_| OriginalMigrationBackupError::LocalProtection)?;

    let namespace = v031_upgrade_r2::inspect_receipt_zero_namespace(app_local_data_dir, |_| {
        PrivacyReceiptAuthenticationBridge::discovering()
    })
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    verify_terminal_history_lineages(app_local_data_dir, namespace.authenticated_lineages())?;
    let absence = if namespace.empty_lineage_id() == Some(context.lineage_id.as_str()) {
        let bootstrap = receipt_zero_bootstrap
            .filter(|bootstrap| bootstrap.lineage_id() == context.lineage_id)
            .ok_or(OriginalMigrationBackupError::ExistingLineageConflict)?;
        prove_target_absence_with_bootstrap(app_local_data_dir, bootstrap, credential_probe)?
    } else {
        if namespace.empty_lineage_id().is_some() {
            return Err(OriginalMigrationBackupError::ExistingLineageConflict);
        }
        let authenticated = authenticate_complete_migration_backups(app_local_data_dir)?;
        let active = active_step12_lineage(&authenticated.lineages)?
            .ok_or(OriginalMigrationBackupError::ExistingLineageConflict)?;
        if active.lineage_id != context.lineage_id {
            return Err(OriginalMigrationBackupError::ExistingLineageConflict);
        }
        prove_target_absence_with_authenticated_backups(
            app_local_data_dir,
            &authenticated,
            credential_probe,
        )?
    };
    let absence_evidence = target_absence_evidence_from_verified(&absence)
        .map_err(|_| OriginalMigrationBackupError::TargetAbsence)?;
    let current_source_profile = build_v031_source_profile_proof(
        user_session.proof(),
        privacy_session.proof(),
        &absence_evidence,
        &capacity,
        &local_protection_preflight_sha256,
    )
    .map_err(|_| OriginalMigrationBackupError::SourceDrift)?;
    if &current_source_profile != expected_source_profile
        || current_source_profile.sha256() != context.source_profile_proof_sha256
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn establish_inside_simultaneous_source_sessions<P: v031_upgrade_r2::CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    user_session: &database::ValidatedUserMigrationSourceSession<'_>,
    privacy_session: &privacy::ValidatedPrivacyV1ReadOnlySession<'_>,
    initial_user: UserMigrationSourceProof,
    initial_privacy: ValidatedPrivacyV1Source,
    target_absence: &V031TargetAbsenceEvidence,
    local_protection_preflight_sha256: &str,
    capacity: &CapacityPreflight,
    namespace_preflight: &Step12NamespacePreflight,
    initial_target_absence: &v031_upgrade_r2::TargetAbsenceProof,
    credential_probe: &P,
) -> Result<InSessionResult, OriginalMigrationBackupError> {
    if initial_user.schema != ValidatedUserSourceSchema::V031V10
        || initial_privacy.schema_version != PRIVACY_V1_SCHEMA_VERSION
        || initial_user.database_file.length != capacity.user_bytes
        || initial_privacy.database_file.length != capacity.privacy_bytes
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    let source_profile = build_v031_source_profile_proof(
        &initial_user,
        &initial_privacy,
        target_absence,
        &capacity.evidence,
        local_protection_preflight_sha256,
    )
    .map_err(|_| OriginalMigrationBackupError::SourceDrift)?;

    let (receipt_context, receipt_zero_bootstrap) = match &namespace_preflight.lineage {
        LineagePreflight::Fresh => {
            let generated = generate_v031_upgrade_identity(&source_profile)
                .map_err(|_| OriginalMigrationBackupError::LocalProtection)?;
            let context = OwnedV031ReceiptContext {
                lineage_id: generated.lineage_id().to_owned(),
                envelope_binding_id: generated.envelope_binding_id().to_owned(),
                source_profile_proof_sha256: source_profile.sha256().to_owned(),
            };
            let verified_terminal_lineages = verify_terminal_lineages_for_bootstrap(
                app_local_data_dir,
                &namespace_preflight.receipt_zero_namespace,
            )?;
            let bootstrap = v031_upgrade_r2::prepare_receipt_zero_bootstrap(
                app_local_data_dir,
                &context.lineage_id,
                &namespace_preflight.receipt_zero_namespace,
                initial_target_absence,
                &verified_terminal_lineages,
                &PlatformDirectorySync,
            )
            .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
            if bootstrap.lineage_id() != context.lineage_id {
                return Err(OriginalMigrationBackupError::ExistingLineageConflict);
            }
            (context, Some(bootstrap))
        }
        LineagePreflight::Resume { lineage_id } => {
            let bridge = PrivacyReceiptAuthenticationBridge::discovering();
            let inventory =
                load_authenticated_v031_lineage(app_local_data_dir, lineage_id, &bridge)
                    .map_err(|_| OriginalMigrationBackupError::Receipt)?;
            validate_resumable_step12_inventory(&inventory)?;
            let context = bridge
                .context()
                .map_err(|_| OriginalMigrationBackupError::Receipt)?;
            if context.lineage_id != *lineage_id
                || context.source_profile_proof_sha256 != source_profile.sha256()
            {
                return Err(OriginalMigrationBackupError::SourceDrift);
            }
            if receipt_zero(&inventory)?.metadata.evidence_sha256 != source_profile.sha256() {
                return Err(OriginalMigrationBackupError::SourceDrift);
            }
            (context, None)
        }
    };

    let receipt_zero_counts = source_preflight_counts(
        source_profile.target_absence_checks(),
        source_profile.privacy_protected_payloads(),
    );
    let persisted_receipt_zero = persist_v031_receipt(
        app_local_data_dir,
        &receipt_context,
        V031UpgradeReceiptStage::SourcePreflightVerified,
        source_profile.sha256(),
        &receipt_zero_counts,
        || {
            verify_receipt_zero_live_state(
                app_local_data_dir,
                user_session,
                privacy_session,
                &receipt_context,
                &source_profile,
                receipt_zero_bootstrap.as_ref(),
                credential_probe,
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
        },
    )
    .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    if persisted_receipt_zero.receipt.metadata.evidence_sha256 != source_profile.sha256() {
        return Err(OriginalMigrationBackupError::Receipt);
    }

    let bridge = PrivacyReceiptAuthenticationBridge::new(receipt_context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, &receipt_context.lineage_id, &bridge)
            .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    validate_receipt0_final_before_v2(&inventory)?;

    let lineage_directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &receipt_context.lineage_id,
    )
    .map_err(|_| OriginalMigrationBackupError::Filesystem)?;
    let user_snapshot_path = lineage_directory.join(USER_SNAPSHOT_INCOMING);
    let privacy_snapshot_path = lineage_directory.join(PRIVACY_SNAPSHOT_INCOMING);
    if inventory.v2.identity_final
        && inventory.v2.bundle_final
        && !inventory.v2.identity_incoming
        && !inventory.v2.bundle_incoming
    {
        let verified = verify_installed_v2_before_snapshot_cleanup(
            app_local_data_dir,
            &receipt_context,
            &initial_user,
            &initial_privacy,
            &source_profile,
        )?;
        cleanup_plaintext_snapshots(
            app_local_data_dir,
            &receipt_context,
            &source_profile,
            &initial_user,
            &initial_privacy,
            &verified,
        )?;
    } else {
        ensure_user_snapshot(&user_snapshot_path, user_session, &initial_user)?;
        ensure_privacy_snapshot(&privacy_snapshot_path, privacy_session, &initial_privacy)?;

        let user_snapshot = Zeroizing::new(read_user_snapshot(&user_snapshot_path)?);
        let privacy_snapshot = Zeroizing::new(read_privacy_snapshot(&privacy_snapshot_path)?);
        let verified = establish_or_resume_v2(
            app_local_data_dir,
            &receipt_context,
            &source_profile,
            &initial_user,
            &initial_privacy,
            &user_snapshot,
            &privacy_snapshot,
        )?;
        cleanup_plaintext_snapshots(
            app_local_data_dir,
            &receipt_context,
            &source_profile,
            &initial_user,
            &initial_privacy,
            &verified,
        )?;
    }

    let cleaned_inventory =
        load_authenticated_v031_lineage(app_local_data_dir, &receipt_context.lineage_id, &bridge)
            .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    if !complete_v2_evidence(cleaned_inventory.v2) {
        return Err(OriginalMigrationBackupError::Snapshot);
    }

    Ok(InSessionResult {
        source_profile,
        initial_user,
        initial_privacy,
        receipt_context,
    })
}

fn inspect_existing_step12_lineage(
    app_local_data_dir: &Path,
) -> Result<Step12NamespacePreflight, OriginalMigrationBackupError> {
    let namespace = v031_upgrade_r2::inspect_receipt_zero_namespace(app_local_data_dir, |_| {
        PrivacyReceiptAuthenticationBridge::discovering()
    })
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    let active = active_step12_lineage(namespace.authenticated_lineages())?;
    if namespace.empty_lineage_id().is_some() && active.is_some() {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let lineage = match active {
        Some(inventory) => {
            validate_resumable_step12_inventory(inventory)?;
            LineagePreflight::Resume {
                lineage_id: inventory.lineage_id.clone(),
            }
        }
        None => LineagePreflight::Fresh,
    };
    Ok(Step12NamespacePreflight {
        lineage,
        receipt_zero_namespace: namespace,
    })
}

fn active_step12_lineage(
    lineages: &[AuthenticatedLineageInventory],
) -> Result<Option<&AuthenticatedLineageInventory>, OriginalMigrationBackupError> {
    let mut active = lineages
        .iter()
        .filter(|lineage| !is_terminal_historical_lineage(lineage));
    let result = active.next();
    if active.next().is_some() {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    Ok(result)
}

fn verify_terminal_lineages_for_bootstrap(
    app_local_data_dir: &Path,
    namespace: &ReceiptZeroNamespaceInventory,
) -> Result<Vec<VerifiedOriginalRollbackV2>, OriginalMigrationBackupError> {
    let verified =
        verify_terminal_history_lineages(app_local_data_dir, namespace.authenticated_lineages())?;
    if verified.len() != namespace.authenticated_lineages().len() {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    Ok(verified)
}

/// Exercises the exact terminal-history gate consumed by the fresh-lineage
/// receipt-zero bootstrap, without preparing a new lineage or writing any
/// receipt.  This is intentionally test-only so production callers cannot
/// split authentication from the bootstrap operation.
#[cfg(test)]
pub(crate) fn verify_terminal_history_for_receipt_zero_bootstrap_for_test(
    app_local_data_dir: &Path,
) -> Result<usize, OriginalMigrationBackupError> {
    let namespace = v031_upgrade_r2::inspect_receipt_zero_namespace(app_local_data_dir, |_| {
        PrivacyReceiptAuthenticationBridge::discovering()
    })
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    verify_terminal_lineages_for_bootstrap(app_local_data_dir, &namespace)
        .map(|verified| verified.len())
}

fn verify_terminal_history_lineages(
    app_local_data_dir: &Path,
    lineages: &[AuthenticatedLineageInventory],
) -> Result<Vec<VerifiedOriginalRollbackV2>, OriginalMigrationBackupError> {
    let terminal_count = lineages
        .iter()
        .filter(|inventory| is_terminal_historical_lineage(inventory))
        .count();
    let mut verified = Vec::with_capacity(terminal_count);
    for expected_inventory in lineages
        .iter()
        .filter(|inventory| is_terminal_historical_lineage(inventory))
    {
        verified.push(verify_one_v031_terminal_history_lineage_read_only(
            app_local_data_dir,
            expected_inventory,
        )?);
    }
    if verified.len() != terminal_count {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    Ok(verified)
}

/// Re-authenticates one terminal historical lineage from disk, including both
/// DPAPI evidence sidecars and the complete encrypted Original-V2 payload.
/// The returned token exists only after the V2 identity, bundle, and all five
/// slots agree with the receipt-bound frozen source manifests.
pub(crate) fn verify_one_v031_terminal_history_lineage_read_only(
    app_local_data_dir: &Path,
    expected_inventory: &AuthenticatedLineageInventory,
) -> Result<VerifiedOriginalRollbackV2, OriginalMigrationBackupError> {
    if !is_terminal_historical_lineage(expected_inventory) {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let bridge = PrivacyReceiptAuthenticationBridge::discovering();
    let inventory = load_authenticated_v031_lineage(
        app_local_data_dir,
        &expected_inventory.lineage_id,
        &bridge,
    )
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    if &inventory != expected_inventory {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let historical_context = bridge
        .context()
        .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    if historical_context.lineage_id != inventory.lineage_id {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let terminal = authenticate_v031_terminal_history_for_bootstrap_offline(
        app_local_data_dir,
        &inventory,
        &historical_context,
    )
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    let predecessor = terminal.predecessor();
    let lineage_directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &historical_context.lineage_id,
    )
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    let protected_identity = v031_upgrade_r2::read_bounded_file(
        &lineage_directory.join(v031_upgrade_r2::V2_IDENTITY_FINAL),
        MAX_V031_ORIGINAL_ROLLBACK_IDENTITY_BYTES,
    )
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    let identity = open_v031_original_rollback_identity_v2(&protected_identity)
        .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    if identity.lineage_id != historical_context.lineage_id
        || identity.envelope_binding_id != historical_context.envelope_binding_id
        || identity.source_profile_proof_sha256 != historical_context.source_profile_proof_sha256
        || sha256_hex(&protected_identity)
            != predecessor
                .receipt_eight_evidence()
                .original_rollback_identity_sha256()
        || identity.source_user_physical_file_set_sha256
            != predecessor
                .receipt_eight_evidence()
                .source_user_physical_file_set_sha256()
        || identity.source_privacy_physical_file_set_sha256
            != predecessor
                .receipt_eight_evidence()
                .source_privacy_physical_file_set_sha256()
    {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let request = v031_upgrade_r2::OriginalRollbackV2VerificationRequest {
        source_profile_proof_sha256: &historical_context.source_profile_proof_sha256,
        source_user_physical_file_set_sha256: &identity.source_user_physical_file_set_sha256,
        source_privacy_physical_file_set_sha256: &identity.source_privacy_physical_file_set_sha256,
        source_user_logical_manifest_sha256: predecessor
            .receipt_eight_evidence()
            .source_user_logical_manifest_sha256(),
        source_user_business_manifest_sha256: predecessor
            .receipt_eight_evidence()
            .source_user_business_manifest_sha256(),
        source_privacy_logical_manifest_sha256: predecessor
            .receipt_eight_evidence()
            .source_privacy_logical_manifest_sha256(),
        source_privacy_business_manifest_sha256: predecessor
            .receipt_eight_evidence()
            .source_privacy_business_manifest_sha256(),
        envelope_binding_id: &historical_context.envelope_binding_id,
        lineage_id: &historical_context.lineage_id,
    };
    let token = v031_upgrade_r2::verify_installed_original_rollback_v2(
        app_local_data_dir,
        &inventory,
        &request,
        &bridge,
    )
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)?;
    if token.lineage_id() != historical_context.lineage_id {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let mut terminal_evidence_sha256 = BTreeMap::new();
    for record in predecessor.checkpoint_files() {
        if terminal_evidence_sha256
            .insert(record.basename().to_owned(), record.sha256().to_owned())
            .is_some()
        {
            return Err(OriginalMigrationBackupError::ExistingLineageConflict);
        }
    }
    terminal_evidence_sha256.insert(
        v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_FINAL.to_owned(),
        predecessor.protected_sha256().to_owned(),
    );
    terminal_evidence_sha256.insert(
        v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_FINAL.to_owned(),
        terminal.upgrade_complete_protected_sha256().to_owned(),
    );
    v031_upgrade_r2::bind_authenticated_terminal_evidence_files(
        app_local_data_dir,
        &inventory,
        token,
        &terminal_evidence_sha256,
    )
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)
}

fn is_terminal_historical_lineage(inventory: &AuthenticatedLineageInventory) -> bool {
    inventory.final_receipts.len() == 10
        && inventory
            .final_receipts
            .iter()
            .enumerate()
            .all(|(ordinal, receipt)| usize::from(receipt.ordinal) == ordinal)
        && inventory.next_incoming_receipt.is_none()
        && inventory.v2.identity_final
        && !inventory.v2.identity_incoming
        && inventory.v2.bundle_final
        && !inventory.v2.bundle_incoming
        && !inventory.v2.user_snapshot_incoming
        && !inventory.v2.privacy_snapshot_incoming
        && inventory.checkpoints.binding.is_exact_final()
        && inventory.checkpoints.materials.is_exact_final()
        && inventory.checkpoints.projection.is_exact_final()
        && inventory.step8_predecessor.is_exact_final()
        && inventory.upgrade_complete_evidence.is_exact_final()
}

fn validate_resumable_step12_inventory(
    inventory: &AuthenticatedLineageInventory,
) -> Result<(), OriginalMigrationBackupError> {
    if inventory.final_receipts.len() > 2 {
        return Err(OriginalMigrationBackupError::ExistingLineageConflict);
    }
    let next_ordinal = inventory
        .next_incoming_receipt
        .as_ref()
        .map(|receipt| receipt.ordinal);
    match inventory.final_receipts.len() {
        0 => {
            if next_ordinal != Some(0) || any_v2_evidence(inventory.v2) {
                return Err(OriginalMigrationBackupError::ExistingLineageConflict);
            }
        }
        1 => {
            if inventory.final_receipts[0].ordinal != 0 || !matches!(next_ordinal, None | Some(1)) {
                return Err(OriginalMigrationBackupError::ExistingLineageConflict);
            }
            if next_ordinal == Some(1) && !complete_v2_evidence(inventory.v2) {
                return Err(OriginalMigrationBackupError::ExistingLineageConflict);
            }
        }
        2 => {
            if inventory.final_receipts[0].ordinal != 0
                || inventory.final_receipts[1].ordinal != 1
                || next_ordinal.is_some()
                || !complete_v2_evidence(inventory.v2)
            {
                return Err(OriginalMigrationBackupError::ExistingLineageConflict);
            }
        }
        _ => return Err(OriginalMigrationBackupError::ExistingLineageConflict),
    }
    Ok(())
}

fn validate_receipt0_final_before_v2(
    inventory: &AuthenticatedLineageInventory,
) -> Result<(), OriginalMigrationBackupError> {
    if inventory
        .final_receipts
        .first()
        .map(|receipt| receipt.ordinal)
        != Some(0)
    {
        return Err(OriginalMigrationBackupError::Receipt);
    }
    validate_resumable_step12_inventory(inventory)
}

fn validate_terminal_step12_inventory(
    inventory: &AuthenticatedLineageInventory,
) -> Result<(), OriginalMigrationBackupError> {
    if inventory.final_receipts.len() != 2
        || inventory.final_receipts[0].ordinal != 0
        || inventory.final_receipts[1].ordinal != 1
        || inventory.next_incoming_receipt.is_some()
        || !complete_v2_evidence(inventory.v2)
    {
        return Err(OriginalMigrationBackupError::Receipt);
    }
    Ok(())
}

fn receipt_zero(
    inventory: &AuthenticatedLineageInventory,
) -> Result<&v031_upgrade_r2::AuthenticatedReceiptFile, OriginalMigrationBackupError> {
    inventory
        .final_receipts
        .first()
        .filter(|receipt| receipt.ordinal == 0)
        .or_else(|| {
            inventory
                .next_incoming_receipt
                .as_ref()
                .filter(|receipt| receipt.ordinal == 0)
        })
        .ok_or(OriginalMigrationBackupError::Receipt)
}

fn any_v2_evidence(evidence: V2EvidenceInventory) -> bool {
    evidence.identity_final
        || evidence.identity_incoming
        || evidence.bundle_final
        || evidence.bundle_incoming
        || evidence.user_snapshot_incoming
        || evidence.privacy_snapshot_incoming
}

fn complete_v2_evidence(evidence: V2EvidenceInventory) -> bool {
    evidence.identity_final
        && !evidence.identity_incoming
        && evidence.bundle_final
        && !evidence.bundle_incoming
        && !evidence.user_snapshot_incoming
        && !evidence.privacy_snapshot_incoming
}

fn require_same_lineage(
    preflight: &LineagePreflight,
    expected_lineage_id: &str,
) -> Result<(), OriginalMigrationBackupError> {
    match preflight {
        LineagePreflight::Resume { lineage_id } if lineage_id == expected_lineage_id => Ok(()),
        _ => Err(OriginalMigrationBackupError::ExistingLineageConflict),
    }
}

fn prove_target_absence_with_namespace<P: v031_upgrade_r2::CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    namespace: &ReceiptZeroNamespaceInventory,
    credential_probe: &P,
) -> Result<v031_upgrade_r2::TargetAbsenceProof, OriginalMigrationBackupError> {
    v031_upgrade_r2::verify_exact_target_absence_with_receipt_zero_namespace(
        app_local_data_dir,
        credential_probe,
        namespace,
    )
    .map_err(|_| OriginalMigrationBackupError::TargetAbsence)
}

fn prove_target_absence_with_bootstrap<P: v031_upgrade_r2::CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    bootstrap: &ReceiptZeroBootstrap,
    credential_probe: &P,
) -> Result<v031_upgrade_r2::TargetAbsenceProof, OriginalMigrationBackupError> {
    v031_upgrade_r2::verify_exact_target_absence_with_receipt_zero_bootstrap(
        app_local_data_dir,
        credential_probe,
        bootstrap,
    )
    .map_err(|_| OriginalMigrationBackupError::TargetAbsence)
}

fn prove_target_absence_with_authenticated_backups<P: v031_upgrade_r2::CredentialPresenceProbe>(
    app_local_data_dir: &Path,
    authenticated_backups: &AuthenticatedMigrationBackupsInventory,
    credential_probe: &P,
) -> Result<v031_upgrade_r2::TargetAbsenceProof, OriginalMigrationBackupError> {
    v031_upgrade_r2::verify_exact_target_absence_with_authenticated_migration_backups(
        app_local_data_dir,
        credential_probe,
        authenticated_backups,
    )
    .map_err(|_| OriginalMigrationBackupError::TargetAbsence)
}

fn authenticate_complete_migration_backups(
    app_local_data_dir: &Path,
) -> Result<AuthenticatedMigrationBackupsInventory, OriginalMigrationBackupError> {
    v031_upgrade_r2::authenticate_migration_backups(app_local_data_dir, |_| {
        PrivacyReceiptAuthenticationBridge::discovering()
    })
    .map_err(|_| OriginalMigrationBackupError::ExistingLineageConflict)
}

fn run_capacity_preflight(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
) -> Result<CapacityPreflight, OriginalMigrationBackupError> {
    let user_bytes = guarded_source_file_length(user_database_path)?;
    let privacy_bytes = guarded_source_file_length(privacy_database_path)?;
    let evidence = verify_v031_backup_capacity(app_local_data_dir, user_bytes, privacy_bytes)
        .map_err(|error| match error {
            V031UpgradeSourceError::InsufficientCapacity => {
                OriginalMigrationBackupError::InsufficientCapacity
            }
            _ => OriginalMigrationBackupError::CapacityProbe,
        })?;
    Ok(CapacityPreflight {
        user_bytes,
        privacy_bytes,
        evidence,
    })
}

fn guarded_source_file_length(path: &Path) -> Result<u64, OriginalMigrationBackupError> {
    validate_absolute_path(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|_| OriginalMigrationBackupError::CapacityProbe)?;
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(OriginalMigrationBackupError::CapacityProbe);
    }
    let file =
        open_plain_file_read_only(path).map_err(|_| OriginalMigrationBackupError::CapacityProbe)?;
    verify_single_link_handle(&file).map_err(|_| OriginalMigrationBackupError::CapacityProbe)?;
    file.metadata()
        .map(|metadata| metadata.len())
        .map_err(|_| OriginalMigrationBackupError::CapacityProbe)
}

fn ensure_user_snapshot(
    path: &Path,
    source: &database::ValidatedUserMigrationSourceSession<'_>,
    expected: &UserMigrationSourceProof,
) -> Result<(), OriginalMigrationBackupError> {
    if path_exists(path)? {
        validate_user_snapshot(path, expected)?;
        return Ok(());
    }
    let mut destination = create_new_snapshot_connection(path)?;
    source
        .backup_to(destination.connection_mut_for_backup()?)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    close_snapshot_connection(destination)?;
    validate_user_snapshot(path, expected)
}

fn ensure_privacy_snapshot(
    path: &Path,
    source: &privacy::ValidatedPrivacyV1ReadOnlySession<'_>,
    expected: &ValidatedPrivacyV1Source,
) -> Result<(), OriginalMigrationBackupError> {
    if path_exists(path)? {
        validate_privacy_snapshot(path, expected)?;
        return Ok(());
    }
    let mut destination = create_new_snapshot_connection(path)?;
    source
        .backup_to(destination.connection_mut_for_backup()?)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    close_snapshot_connection(destination)?;
    validate_privacy_snapshot(path, expected)
}

/// Owns every capability that binds a SQLite snapshot connection to the exact
/// create-new file.  The parent and file handles deliberately omit delete
/// sharing and remain live for the complete Backup API write and durable close.
/// Callers therefore cannot accidentally regress to "verify, close, reopen by
/// pathname, write".
struct BoundSnapshotConnection {
    connection: Connection,
    create_new_file: File,
    parent_directory: File,
    path: PathBuf,
}

impl BoundSnapshotConnection {
    fn connection_mut_for_backup(
        &mut self,
    ) -> Result<&mut Connection, OriginalMigrationBackupError> {
        verify_snapshot_connection_binding(
            &self.connection,
            &self.create_new_file,
            &self.parent_directory,
            &self.path,
        )
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
        Ok(&mut self.connection)
    }
}

fn create_new_snapshot_connection(
    path: &Path,
) -> Result<BoundSnapshotConnection, OriginalMigrationBackupError> {
    create_new_snapshot_connection_with_preopen_hook(path, |_| Ok(()))
}

fn create_new_snapshot_connection_with_preopen_hook<F>(
    path: &Path,
    before_sqlite_open: F,
) -> Result<BoundSnapshotConnection, OriginalMigrationBackupError>
where
    F: FnOnce(&Path) -> Result<(), OriginalMigrationBackupError>,
{
    let parent = path
        .parent()
        .ok_or(OriginalMigrationBackupError::Snapshot)?;
    ensure_plain_directory(parent)?;
    let parent_directory = pin_snapshot_parent_directory(parent)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    verify_snapshot_parent_path_binding(parent, &parent_directory)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(windows)]
    options
        // SQLite must be able to acquire its own read/write handle, while the
        // missing FILE_SHARE_DELETE keeps this exact create-new file pinned.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options
        .open(path)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    verify_single_link_handle(&file).map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    file.sync_all()
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    verify_snapshot_file_path_binding(path, &file, &parent_directory)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;

    // Test fault injection runs while both no-delete-sharing handles are live.
    // Production supplies a no-op closure and exposes no callback boundary.
    before_sqlite_open(path)?;
    verify_snapshot_file_path_binding(path, &file, &parent_directory)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;

    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    verify_snapshot_connection_binding(&connection, &file, &parent_directory, path)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    Ok(BoundSnapshotConnection {
        connection,
        create_new_file: file,
        parent_directory,
        path: path.to_path_buf(),
    })
}

fn close_snapshot_connection(
    snapshot: BoundSnapshotConnection,
) -> Result<(), OriginalMigrationBackupError> {
    verify_snapshot_connection_binding(
        &snapshot.connection,
        &snapshot.create_new_file,
        &snapshot.parent_directory,
        &snapshot.path,
    )
    .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    let BoundSnapshotConnection {
        connection,
        create_new_file,
        parent_directory,
        path,
    } = snapshot;
    connection
        .close()
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    ensure_snapshot_has_no_sidecars(&path)?;
    verify_snapshot_file_path_binding(&path, &create_new_file, &parent_directory)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    verify_single_link_handle(&create_new_file)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    create_new_file
        .sync_all()
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    let parent = path
        .parent()
        .ok_or(OriginalMigrationBackupError::Snapshot)?;
    PlatformDirectorySync
        .sync_directory(parent)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    verify_snapshot_file_path_binding(&path, &create_new_file, &parent_directory)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)
}

#[cfg(windows)]
fn pin_snapshot_parent_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        // Deliberately omit FILE_SHARE_DELETE.  This handle pins the exact
        // parent directory while SQLite resolves and writes the snapshot path.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    verify_windows_plain_directory_handle(&directory)?;
    Ok(directory)
}

#[cfg(not(windows))]
fn pin_snapshot_parent_directory(path: &Path) -> io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn verify_snapshot_parent_path_binding(path: &Path, pinned_parent: &File) -> io::Result<()> {
    let pinned_information = windows_handle_information(pinned_parent.as_raw_handle())?;
    verify_windows_plain_directory_information(&pinned_information)?;
    let path_check = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let path_information = windows_handle_information(path_check.as_raw_handle())?;
    verify_windows_plain_directory_information(&path_information)?;
    if windows_file_identity(&pinned_information) != windows_file_identity(&path_information) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot parent path identity changed",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_snapshot_parent_path_binding(path: &Path, pinned_parent: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let pinned = pinned_parent.metadata()?;
    let path_check = File::open(path)?;
    let observed = path_check.metadata()?;
    if !pinned.is_dir()
        || !observed.is_dir()
        || (pinned.dev(), pinned.ino()) != (observed.dev(), observed.ino())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot parent path identity changed",
        ));
    }
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn verify_snapshot_parent_path_binding(_path: &Path, _pinned_parent: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "snapshot parent identity proof unavailable",
    ))
}

#[cfg(windows)]
fn verify_snapshot_file_path_binding(
    path: &Path,
    create_new_file: &File,
    pinned_parent: &File,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "snapshot has no parent"))?;
    verify_snapshot_parent_path_binding(parent, pinned_parent)?;
    let created_information = windows_handle_information(create_new_file.as_raw_handle())?;
    verify_windows_plain_single_link_information(&created_information)?;
    let path_check = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let path_information = windows_handle_information(path_check.as_raw_handle())?;
    verify_windows_plain_single_link_information(&path_information)?;
    if windows_file_identity(&created_information) != windows_file_identity(&path_information) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot file path identity changed",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_snapshot_file_path_binding(
    path: &Path,
    create_new_file: &File,
    pinned_parent: &File,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "snapshot has no parent"))?;
    verify_snapshot_parent_path_binding(parent, pinned_parent)?;
    verify_single_link_handle(create_new_file)?;
    let created = create_new_file.metadata()?;
    let path_check = OpenOptions::new().read(true).open(path)?;
    verify_single_link_handle(&path_check)?;
    let observed = path_check.metadata()?;
    if (created.dev(), created.ino()) != (observed.dev(), observed.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "snapshot file path identity changed",
        ));
    }
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn verify_snapshot_file_path_binding(
    _path: &Path,
    _create_new_file: &File,
    _pinned_parent: &File,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "snapshot file identity proof unavailable",
    ))
}

#[cfg(windows)]
fn verify_snapshot_connection_binding(
    connection: &Connection,
    create_new_file: &File,
    pinned_parent: &File,
    path: &Path,
) -> io::Result<()> {
    verify_snapshot_file_path_binding(path, create_new_file, pinned_parent)?;
    let created_information = windows_handle_information(create_new_file.as_raw_handle())?;
    let mut sqlite_handle: RawHandle = std::ptr::null_mut();
    // SAFETY: `connection` owns a live sqlite3 handle, "main" is NUL
    // terminated, and `sqlite_handle` is writable for the duration of the
    // read-only SQLITE_FCNTL_WIN32_GET_HANDLE call.
    let result = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_WIN32_GET_HANDLE,
            (&raw mut sqlite_handle).cast(),
        )
    };
    if result != rusqlite::ffi::SQLITE_OK || sqlite_handle.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SQLite did not expose its Windows snapshot handle",
        ));
    }
    let sqlite_information = windows_handle_information(sqlite_handle)?;
    verify_windows_plain_single_link_information(&sqlite_information)?;
    if windows_file_identity(&created_information) != windows_file_identity(&sqlite_information) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SQLite snapshot handle differs from the create-new handle",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_snapshot_connection_binding(
    _connection: &Connection,
    _create_new_file: &File,
    _pinned_parent: &File,
    _path: &Path,
) -> io::Result<()> {
    // The v0.3.1 rollback codec is Windows-only.  Do not silently weaken the
    // write-before-identity gate on a VFS where the native SQLite handle cannot
    // be compared with the create-new handle.
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native SQLite snapshot handle identity proof unavailable",
    ))
}

fn ensure_snapshot_has_no_sidecars(path: &Path) -> Result<(), OriginalMigrationBackupError> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match fs::symlink_metadata(PathBuf::from(name)) {
            Ok(_) => return Err(OriginalMigrationBackupError::Snapshot),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(OriginalMigrationBackupError::Snapshot),
        }
    }
    Ok(())
}

fn validate_user_snapshot(
    path: &Path,
    expected: &UserMigrationSourceProof,
) -> Result<(), OriginalMigrationBackupError> {
    ensure_snapshot_has_no_sidecars(path)?;
    let (proof, ()) = with_validated_user_database_migration_source_read_only(path, |_| ())
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    if !same_user_source_content(expected, &proof) {
        return Err(OriginalMigrationBackupError::Snapshot);
    }
    Ok(())
}

fn validate_privacy_snapshot(
    path: &Path,
    expected: &ValidatedPrivacyV1Source,
) -> Result<(), OriginalMigrationBackupError> {
    ensure_snapshot_has_no_sidecars(path)?;
    let proof = privacy::validate_privacy_v1_migration_source_read_only(path)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    if !same_privacy_source_content(expected, &proof) {
        return Err(OriginalMigrationBackupError::Snapshot);
    }
    Ok(())
}

fn read_user_snapshot(path: &Path) -> Result<Vec<u8>, OriginalMigrationBackupError> {
    v031_upgrade_r2::read_bounded_file(path, privacy::MAX_USER_DATABASE_BACKUP_BYTES)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)
}

fn read_privacy_snapshot(path: &Path) -> Result<Vec<u8>, OriginalMigrationBackupError> {
    let maximum = max_backup_database_bytes_for_schema(PRIVACY_V1_SCHEMA_VERSION)
        .ok_or(OriginalMigrationBackupError::Snapshot)?;
    v031_upgrade_r2::read_bounded_file(path, maximum)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)
}

fn establish_or_resume_v2(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    source_profile: &V031SourceProfileProof,
    user_source: &UserMigrationSourceProof,
    privacy_source: &ValidatedPrivacyV1Source,
    user_snapshot: &[u8],
    privacy_snapshot: &[u8],
) -> Result<VerifiedV2, OriginalMigrationBackupError> {
    validate_source_profile_context(context, source_profile)?;
    validate_profile_against_sources(source_profile, user_source, privacy_source)?;
    let user_physical_file_set_sha256 = user_physical_file_set_sha256(user_source)?;
    let privacy_physical_file_set_sha256 = privacy_physical_file_set_sha256(privacy_source)?;
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, &context.lineage_id, &bridge)
            .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    validate_receipt0_final_before_v2(&inventory)?;
    let request = OriginalRollbackV2InstallRequest {
        source_profile_proof_sha256: source_profile.sha256(),
        source_user_physical_file_set_sha256: &user_physical_file_set_sha256,
        source_privacy_physical_file_set_sha256: &privacy_physical_file_set_sha256,
        source_user_logical_manifest_sha256: source_profile.user_logical_sha256(),
        source_user_business_manifest_sha256: source_profile.user_business_sha256(),
        source_privacy_logical_manifest_sha256: source_profile.privacy_logical_sha256(),
        source_privacy_business_manifest_sha256: source_profile.privacy_business_sha256(),
        envelope_binding_id: &context.envelope_binding_id,
        lineage_id: &context.lineage_id,
        user_database_snapshot: user_snapshot,
        privacy_store_snapshot: privacy_snapshot,
    };
    let verified = v031_upgrade_r2::install_or_resume_original_rollback_v2(
        app_local_data_dir,
        &inventory,
        &request,
        &bridge,
        &PlatformDirectorySync,
    )
    .map_err(|_| OriginalMigrationBackupError::RollbackCodec)?;
    verified_v2_from_token(
        &verified,
        &user_physical_file_set_sha256,
        &privacy_physical_file_set_sha256,
    )
}

fn verify_installed_v2_before_snapshot_cleanup(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    user_source: &UserMigrationSourceProof,
    privacy_source: &ValidatedPrivacyV1Source,
    source_profile: &V031SourceProfileProof,
) -> Result<VerifiedV2, OriginalMigrationBackupError> {
    validate_profile_against_sources(source_profile, user_source, privacy_source)?;
    let user_physical_file_set_sha256 = user_physical_file_set_sha256(user_source)?;
    let privacy_physical_file_set_sha256 = privacy_physical_file_set_sha256(privacy_source)?;
    verify_installed_v2_with_snapshot_policy(
        app_local_data_dir,
        context,
        source_profile,
        &user_physical_file_set_sha256,
        &privacy_physical_file_set_sha256,
        false,
    )
}

fn verify_installed_v2_from_disk(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    user_source: &UserMigrationSourceProof,
    privacy_source: &ValidatedPrivacyV1Source,
    source_profile: &V031SourceProfileProof,
) -> Result<VerifiedV2, OriginalMigrationBackupError> {
    validate_profile_against_sources(source_profile, user_source, privacy_source)?;
    let user_physical_file_set_sha256 = user_physical_file_set_sha256(user_source)?;
    let privacy_physical_file_set_sha256 = privacy_physical_file_set_sha256(privacy_source)?;
    verify_installed_v2_with_snapshot_policy(
        app_local_data_dir,
        context,
        source_profile,
        &user_physical_file_set_sha256,
        &privacy_physical_file_set_sha256,
        true,
    )
}

fn verify_installed_v2_with_snapshot_policy(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    source_profile: &V031SourceProfileProof,
    user_physical_file_set_sha256: &str,
    privacy_physical_file_set_sha256: &str,
    require_snapshots_absent: bool,
) -> Result<VerifiedV2, OriginalMigrationBackupError> {
    validate_source_profile_context(context, source_profile)?;
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, &context.lineage_id, &bridge)
            .map_err(|_| OriginalMigrationBackupError::Receipt)?;
    if require_snapshots_absent && !complete_v2_evidence(inventory.v2) {
        return Err(OriginalMigrationBackupError::RollbackCodec);
    }
    if !inventory.v2.identity_final
        || inventory.v2.identity_incoming
        || !inventory.v2.bundle_final
        || inventory.v2.bundle_incoming
        || inventory
            .final_receipts
            .first()
            .map(|receipt| receipt.ordinal)
            != Some(0)
    {
        return Err(OriginalMigrationBackupError::RollbackCodec);
    }
    let request = v031_upgrade_r2::OriginalRollbackV2VerificationRequest {
        source_profile_proof_sha256: source_profile.sha256(),
        source_user_physical_file_set_sha256: user_physical_file_set_sha256,
        source_privacy_physical_file_set_sha256: privacy_physical_file_set_sha256,
        source_user_logical_manifest_sha256: source_profile.user_logical_sha256(),
        source_user_business_manifest_sha256: source_profile.user_business_sha256(),
        source_privacy_logical_manifest_sha256: source_profile.privacy_logical_sha256(),
        source_privacy_business_manifest_sha256: source_profile.privacy_business_sha256(),
        envelope_binding_id: &context.envelope_binding_id,
        lineage_id: &context.lineage_id,
    };
    let verified = if require_snapshots_absent {
        v031_upgrade_r2::verify_installed_original_rollback_v2(
            app_local_data_dir,
            &inventory,
            &request,
            &bridge,
        )
    } else {
        v031_upgrade_r2::verify_installed_original_rollback_v2_for_snapshot_cleanup(
            app_local_data_dir,
            &inventory,
            &request,
            &bridge,
        )
    }
    .map_err(|_| OriginalMigrationBackupError::RollbackCodec)?;
    verified_v2_from_token(
        &verified,
        user_physical_file_set_sha256,
        privacy_physical_file_set_sha256,
    )
}

fn verified_v2_from_token(
    verified: &VerifiedOriginalRollbackV2,
    source_user_physical_file_set_sha256: &str,
    source_privacy_physical_file_set_sha256: &str,
) -> Result<VerifiedV2, OriginalMigrationBackupError> {
    if verified.bundle_bytes() == 0 || verified.encrypted_chunks() == 0 {
        return Err(OriginalMigrationBackupError::RollbackCodec);
    }
    Ok(VerifiedV2 {
        protected_identity_sha256: verified.identity_protected_sha256().to_owned(),
        bundle_sha256: verified.bundle_sha256().to_owned(),
        source_user_physical_file_set_sha256: source_user_physical_file_set_sha256.to_owned(),
        source_privacy_physical_file_set_sha256: source_privacy_physical_file_set_sha256.to_owned(),
        user_snapshot_sha256: verified.user_database_snapshot_sha256().to_owned(),
        privacy_snapshot_sha256: verified.privacy_store_snapshot_sha256().to_owned(),
        bundle_bytes: verified.bundle_bytes(),
        total_chunk_count: verified.encrypted_chunks(),
    })
}

fn validate_source_profile_context(
    context: &OwnedV031ReceiptContext,
    source_profile: &V031SourceProfileProof,
) -> Result<(), OriginalMigrationBackupError> {
    if context.source_profile_proof_sha256 != source_profile.sha256() {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    Ok(())
}

fn validate_profile_against_sources(
    source_profile: &V031SourceProfileProof,
    user_source: &UserMigrationSourceProof,
    privacy_source: &ValidatedPrivacyV1Source,
) -> Result<(), OriginalMigrationBackupError> {
    if source_profile.user_logical_sha256() != user_source.logical_database_manifest_sha256
        || source_profile.user_business_sha256() != user_source.business_manifest_sha256
        || source_profile.user_total_rows() != user_source.total_rows
        || source_profile.privacy_logical_sha256() != privacy_source.logical_manifest.sha256
        || source_profile.privacy_business_sha256() != privacy_source.business_manifest.sha256
        || source_profile.privacy_total_rows() != privacy_source.logical_manifest.total_row_count
        || source_profile.privacy_protected_payloads()
            != privacy_source.protected_review_payload_count
    {
        return Err(OriginalMigrationBackupError::SourceDrift);
    }
    Ok(())
}

fn cleanup_plaintext_snapshots(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    source_profile: &V031SourceProfileProof,
    user_source: &UserMigrationSourceProof,
    privacy_source: &ValidatedPrivacyV1Source,
    verified_before_cleanup: &VerifiedV2,
) -> Result<(), OriginalMigrationBackupError> {
    validate_profile_against_sources(source_profile, user_source, privacy_source)?;
    let independently_verified = verify_installed_v2_before_snapshot_cleanup(
        app_local_data_dir,
        context,
        user_source,
        privacy_source,
        source_profile,
    )?;
    if &independently_verified != verified_before_cleanup {
        return Err(OriginalMigrationBackupError::RollbackCodec);
    }

    let lineage_directory =
        v031_upgrade_r2::canonical_lineage_directory(app_local_data_dir, &context.lineage_id)
            .map_err(|_| OriginalMigrationBackupError::Filesystem)?;
    ensure_plain_directory(&lineage_directory)?;
    remove_user_snapshot_after_v2(
        &lineage_directory.join(USER_SNAPSHOT_INCOMING),
        user_source,
        &independently_verified.user_snapshot_sha256,
        &lineage_directory,
    )?;
    remove_privacy_snapshot_after_v2(
        &lineage_directory.join(PRIVACY_SNAPSHOT_INCOMING),
        privacy_source,
        &independently_verified.privacy_snapshot_sha256,
        &lineage_directory,
    )?;

    let verified_after_cleanup = verify_installed_v2_from_disk(
        app_local_data_dir,
        context,
        user_source,
        privacy_source,
        source_profile,
    )?;
    if verified_after_cleanup != independently_verified {
        return Err(OriginalMigrationBackupError::RollbackCodec);
    }
    Ok(())
}

fn remove_user_snapshot_after_v2(
    path: &Path,
    expected_source: &UserMigrationSourceProof,
    expected_sha256: &str,
    lineage_directory: &Path,
) -> Result<(), OriginalMigrationBackupError> {
    if !path_exists(path)? {
        ensure_snapshot_has_no_sidecars(path)?;
        return Ok(());
    }
    validate_user_snapshot(path, expected_source)?;
    let bytes = Zeroizing::new(read_user_snapshot(path)?);
    if sha256_hex(&bytes) != expected_sha256 {
        return Err(OriginalMigrationBackupError::Snapshot);
    }
    revalidate_removal_candidate(path, bytes.len())?;
    drop(bytes);
    validate_user_snapshot(path, expected_source)?;
    remove_exact_snapshot_and_sync(path, lineage_directory)
}

fn remove_privacy_snapshot_after_v2(
    path: &Path,
    expected_source: &ValidatedPrivacyV1Source,
    expected_sha256: &str,
    lineage_directory: &Path,
) -> Result<(), OriginalMigrationBackupError> {
    if !path_exists(path)? {
        ensure_snapshot_has_no_sidecars(path)?;
        return Ok(());
    }
    validate_privacy_snapshot(path, expected_source)?;
    let bytes = Zeroizing::new(read_privacy_snapshot(path)?);
    if sha256_hex(&bytes) != expected_sha256 {
        return Err(OriginalMigrationBackupError::Snapshot);
    }
    revalidate_removal_candidate(path, bytes.len())?;
    drop(bytes);
    validate_privacy_snapshot(path, expected_source)?;
    remove_exact_snapshot_and_sync(path, lineage_directory)
}

fn revalidate_removal_candidate(
    path: &Path,
    expected_bytes: usize,
) -> Result<(), OriginalMigrationBackupError> {
    ensure_snapshot_has_no_sidecars(path)?;
    let file =
        open_plain_file_read_only(path).map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    verify_single_link_handle(&file).map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    if file
        .metadata()
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?
        .len()
        != u64::try_from(expected_bytes).map_err(|_| OriginalMigrationBackupError::Snapshot)?
    {
        return Err(OriginalMigrationBackupError::Snapshot);
    }
    Ok(())
}

fn remove_exact_snapshot_and_sync(
    path: &Path,
    lineage_directory: &Path,
) -> Result<(), OriginalMigrationBackupError> {
    fs::remove_file(path).map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    PlatformDirectorySync
        .sync_directory(lineage_directory)
        .map_err(|_| OriginalMigrationBackupError::Snapshot)?;
    if path_exists(path)? {
        return Err(OriginalMigrationBackupError::Snapshot);
    }
    ensure_snapshot_has_no_sidecars(path)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SourcePhysicalFileSetEvidence<'a> {
    schema_version: &'static str,
    source_kind: &'static str,
    database: SourcePhysicalFileEvidence<'a>,
    wal: Option<SourcePhysicalFileEvidence<'a>>,
    shm: Option<SourcePhysicalFileEvidence<'a>>,
    journal: Option<SourcePhysicalFileEvidence<'a>>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "camelCase")]
struct SourcePhysicalFileEvidence<'a> {
    identity_sha256: &'a str,
    length: u64,
    modified_unix_nanos: Option<u128>,
    sha256: &'a str,
}

fn user_physical_file_set_sha256(
    source: &UserMigrationSourceProof,
) -> Result<String, OriginalMigrationBackupError> {
    canonical_evidence_sha256(&SourcePhysicalFileSetEvidence {
        schema_version: SOURCE_PHYSICAL_FILE_SET_SCHEMA,
        source_kind: "user-v10",
        database: user_physical_file_evidence(&source.database_file),
        wal: source.wal.as_ref().map(user_physical_file_evidence),
        shm: source.shm.as_ref().map(user_physical_file_evidence),
        journal: source.journal.as_ref().map(user_physical_file_evidence),
    })
}

fn privacy_physical_file_set_sha256(
    source: &ValidatedPrivacyV1Source,
) -> Result<String, OriginalMigrationBackupError> {
    canonical_evidence_sha256(&SourcePhysicalFileSetEvidence {
        schema_version: SOURCE_PHYSICAL_FILE_SET_SCHEMA,
        source_kind: "privacy-v1",
        database: privacy_physical_file_evidence(&source.database_file),
        wal: source.wal.as_ref().map(privacy_physical_file_evidence),
        shm: source.shm.as_ref().map(privacy_physical_file_evidence),
        journal: source.journal.as_ref().map(privacy_physical_file_evidence),
    })
}

fn user_physical_file_evidence(
    file: &UserMigrationSourceFileProof,
) -> SourcePhysicalFileEvidence<'_> {
    SourcePhysicalFileEvidence {
        identity_sha256: &file.identity_sha256,
        length: file.length,
        modified_unix_nanos: file.modified_unix_nanos,
        sha256: &file.sha256,
    }
}

fn privacy_physical_file_evidence(
    file: &PrivacyV1SourceFileProof,
) -> SourcePhysicalFileEvidence<'_> {
    SourcePhysicalFileEvidence {
        identity_sha256: &file.identity_sha256,
        length: file.length,
        modified_unix_nanos: file.modified_unix_nanos,
        sha256: &file.sha256,
    }
}

fn same_user_source_content(
    expected: &UserMigrationSourceProof,
    actual: &UserMigrationSourceProof,
) -> bool {
    actual.schema == ValidatedUserSourceSchema::V031V10
        && expected.schema == actual.schema
        && expected.schema_manifest_sha256 == actual.schema_manifest_sha256
        && expected.logical_database_manifest_sha256 == actual.logical_database_manifest_sha256
        && expected.business_manifest_sha256 == actual.business_manifest_sha256
        && expected.business_primary_key_manifest_sha256
            == actual.business_primary_key_manifest_sha256
        && expected.business_row_manifest_sha256 == actual.business_row_manifest_sha256
        && expected.tables == actual.tables
        && expected.total_rows == actual.total_rows
}

fn same_privacy_source_content(
    expected: &ValidatedPrivacyV1Source,
    actual: &ValidatedPrivacyV1Source,
) -> bool {
    expected.schema_version == PRIVACY_V1_SCHEMA_VERSION
        && expected.schema_version == actual.schema_version
        && expected.schema_object_count == actual.schema_object_count
        && expected.protected_review_payload_count == actual.protected_review_payload_count
        && expected.normalized_sqlite_master_sha256 == actual.normalized_sqlite_master_sha256
        && expected.logical_manifest == actual.logical_manifest
        && expected.business_manifest == actual.business_manifest
}

fn source_preflight_counts(
    target_absence_checks: u64,
    protected_payloads: u64,
) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (
            V031UpgradeReceiptCountKey::UserSchemaObjects,
            V031_USER_SCHEMA_OBJECT_COUNT as u64,
        ),
        (
            V031UpgradeReceiptCountKey::PrivacySchemaObjects,
            PRIVACY_V1_SCHEMA_OBJECT_COUNT as u64,
        ),
        (V031UpgradeReceiptCountKey::PresentSlots, PRESENT_SLOT_COUNT),
        (
            V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots,
            AUTHENTICATED_ABSENT_SLOT_COUNT,
        ),
        (
            V031UpgradeReceiptCountKey::TargetAbsenceChecks,
            target_absence_checks,
        ),
        (
            V031UpgradeReceiptCountKey::CapacityChecks,
            CAPACITY_CHECK_COUNT,
        ),
        (
            V031UpgradeReceiptCountKey::ProtectedPayloads,
            protected_payloads,
        ),
    ])
}

fn original_rollback_counts(encrypted_chunks: u64) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (V031UpgradeReceiptCountKey::IdentityArtifacts, 1),
        (V031UpgradeReceiptCountKey::BundleArtifacts, 1),
        (
            V031UpgradeReceiptCountKey::RollbackSlots,
            ROLLBACK_SLOT_COUNT,
        ),
        (V031UpgradeReceiptCountKey::SqliteImages, PRESENT_SLOT_COUNT),
        (
            V031UpgradeReceiptCountKey::EncryptedChunks,
            encrypted_chunks,
        ),
        (
            V031UpgradeReceiptCountKey::SourceRevalidations,
            SOURCE_REVALIDATION_COUNT,
        ),
        (
            V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots,
            AUTHENTICATED_ABSENT_SLOT_COUNT,
        ),
    ])
}

fn original_rollback_evidence_sha256(
    source_profile: &V031SourceProfileProof,
    revalidated_source_profile: &V031SourceProfileProof,
    verified: &VerifiedV2,
) -> Result<String, OriginalMigrationBackupError> {
    canonical_evidence_sha256(&OriginalRollbackReceiptEvidenceV1 {
        schema_version: ORIGINAL_ROLLBACK_EVIDENCE_SCHEMA,
        source_profile_proof_sha256: source_profile.sha256(),
        source_revalidation_sha256: revalidated_source_profile.sha256(),
        target_absence_policy_sha256: &v031_target_absence_policy_sha256(),
        protected_identity_sha256: &verified.protected_identity_sha256,
        bundle_sha256: &verified.bundle_sha256,
        source_user_physical_file_set_sha256: &verified.source_user_physical_file_set_sha256,
        source_privacy_physical_file_set_sha256: &verified.source_privacy_physical_file_set_sha256,
        user_snapshot_sha256: &verified.user_snapshot_sha256,
        privacy_snapshot_sha256: &verified.privacy_snapshot_sha256,
        identity_artifacts: 1,
        bundle_artifacts: 1,
        bundle_bytes: verified.bundle_bytes,
        rollback_slots: ROLLBACK_SLOT_COUNT,
        sqlite_images: PRESENT_SLOT_COUNT,
        encrypted_chunks: verified.total_chunk_count,
        source_revalidations: SOURCE_REVALIDATION_COUNT,
        authenticated_absent_slots: AUTHENTICATED_ABSENT_SLOT_COUNT,
        target_absence_checks: revalidated_source_profile.target_absence_checks(),
    })
}

fn canonical_evidence_sha256(
    evidence: &impl Serialize,
) -> Result<String, OriginalMigrationBackupError> {
    let bytes =
        canonical_json_v1(evidence).map_err(|_| OriginalMigrationBackupError::EvidenceEncoding)?;
    Ok(sha256_hex(&bytes))
}

fn count_map_as_wire(
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
) -> Result<BTreeMap<String, u64>, OriginalMigrationBackupError> {
    counts
        .iter()
        .map(|(key, value)| {
            let key = match serde_json::to_value(key)
                .map_err(|_| OriginalMigrationBackupError::EvidenceEncoding)?
            {
                serde_json::Value::String(value) => value,
                _ => return Err(OriginalMigrationBackupError::EvidenceEncoding),
            };
            Ok((key, *value))
        })
        .collect()
}

fn path_exists(path: &Path) -> Result<bool, OriginalMigrationBackupError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(OriginalMigrationBackupError::Filesystem),
    }
}

fn validate_absolute_path(path: &Path) -> Result<(), OriginalMigrationBackupError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(OriginalMigrationBackupError::InvalidInput);
    }
    Ok(())
}

fn ensure_plain_directory(path: &Path) -> Result<(), OriginalMigrationBackupError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| OriginalMigrationBackupError::Filesystem)?;
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
        || !metadata.is_dir()
    {
        return Err(OriginalMigrationBackupError::Filesystem);
    }
    Ok(())
}

#[cfg(windows)]
fn open_plain_file_read_only(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
fn open_plain_file_read_only(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(windows)]
fn verify_single_link_handle(file: &File) -> io::Result<()> {
    let information = windows_handle_information(file.as_raw_handle())?;
    verify_windows_plain_single_link_information(&information)
}

#[cfg(windows)]
fn windows_handle_information(handle: RawHandle) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the caller supplies a live Windows handle and `information` is
    // writable for the duration of the call.
    let succeeded = unsafe { GetFileInformationByHandle(handle, &raw mut information) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(information)
}

#[cfg(windows)]
fn verify_windows_plain_single_link_information(
    information: &BY_HANDLE_FILE_INFORMATION,
) -> io::Result<()> {
    if information.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
        || information.nNumberOfLinks != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "migration evidence file is not a plain single-link file",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn verify_windows_plain_directory_handle(file: &File) -> io::Result<()> {
    let information = windows_handle_information(file.as_raw_handle())?;
    verify_windows_plain_directory_information(&information)
}

#[cfg(windows)]
fn verify_windows_plain_directory_information(
    information: &BY_HANDLE_FILE_INFORMATION,
) -> io::Result<()> {
    if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "migration snapshot parent is not a plain directory",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_file_identity(information: &BY_HANDLE_FILE_INFORMATION) -> (u32, u64) {
    (
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    )
}

#[cfg(unix)]
fn verify_single_link_handle(file: &File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if file.metadata()?.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "migration evidence file is not single-link",
        ));
    }
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn verify_single_link_handle(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "single-link proof unavailable",
    ))
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::{fs::FileTimes, time::Duration};

    #[cfg(windows)]
    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    #[cfg(windows)]
    use privacy::{
        original_rollback_v2::{
            V031OriginalRollbackIdentityV2, V031OriginalRollbackSlotIdentityV2,
        },
        protected_blob::{protect_local, unprotect_local},
    };
    #[cfg(windows)]
    use serde_json::Value;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Deserialize)]
    struct FrozenUserSchemaObject {
        object_type: String,
        sql: String,
    }

    #[cfg(windows)]
    struct AlwaysAbsentCredentialProbe;

    #[cfg(windows)]
    impl v031_upgrade_r2::CredentialPresenceProbe for AlwaysAbsentCredentialProbe {
        type Error = ();

        fn credential_exists_read_only(
            &self,
            _query: v031_upgrade_r2::CredentialAbsenceQuery,
        ) -> Result<bool, Self::Error> {
            Ok(false)
        }
    }

    #[cfg(windows)]
    struct RealOriginalRollbackFixture {
        directory: tempfile::TempDir,
        user_database_path: PathBuf,
        privacy_database_path: PathBuf,
    }

    #[cfg(windows)]
    impl RealOriginalRollbackFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("original rollback fixture root");
            let root = directory.path();
            let user_database_path = database::user_database_path(root);
            let connection = Connection::open(&user_database_path).expect("user fixture opens");
            let objects =
                include_str!("../../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
                    .lines()
                    .map(|line| {
                        serde_json::from_str::<FrozenUserSchemaObject>(line)
                            .expect("frozen user schema object parses")
                    })
                    .collect::<Vec<_>>();
            for object_type in ["table", "index", "trigger", "view"] {
                for object in objects
                    .iter()
                    .filter(|object| object.object_type == object_type)
                {
                    connection
                        .execute_batch(&object.sql)
                        .expect("frozen user schema DDL executes");
                }
            }
            connection
                .execute(
                    "INSERT INTO user_database_metadata(key,value,updated_at)
                     VALUES('schema_version',?1,'2026-07-19 15:41:29')",
                    [database::V031_USER_SCHEMA_VERSION.to_string()],
                )
                .expect("user schema version inserts");
            connection
                .execute(
                    "INSERT INTO user_database_metadata(key,value,updated_at)
                     VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
                    [database::V031_USER_CANONICAL_SCHEMA_MARKER],
                )
                .expect("user canonical marker inserts");
            drop(connection);

            let privacy_root = root.join("privacy");
            fs::create_dir(&privacy_root).expect("Privacy fixture directory creates");
            let privacy_database_path = privacy_root.join("privacy-workflow.sqlite");
            let connection =
                Connection::open(&privacy_database_path).expect("Privacy fixture opens");
            connection
                .execute_batch(privacy::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
                .expect("frozen Privacy-v1 schema executes");
            connection
                .execute(
                    "INSERT INTO privacy_schema_metadata(key,value,updated_at)
                     VALUES('schema_version','1','2026-07-19 15:41:29')",
                    [],
                )
                .expect("Privacy schema version inserts");
            drop(connection);

            Self {
                directory,
                user_database_path,
                privacy_database_path,
            }
        }

        fn root(&self) -> &Path {
            self.directory.path()
        }
    }

    #[cfg(windows)]
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct V2TreeEntryObservation {
        kind: &'static str,
        bytes: u64,
        modified_unix_nanos: Option<u128>,
        sha256: Option<String>,
    }

    #[cfg(windows)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum V2SlotTamperKind {
        Ciphertext,
        ComponentHash,
        Presence,
        Ordinal,
        AuthenticatedAbsentSentinel,
        BundleFilename,
    }

    #[cfg(windows)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct V2SlotTamperCase {
        slot_ordinal: Option<usize>,
        kind: V2SlotTamperKind,
    }

    #[cfg(windows)]
    impl V2SlotTamperCase {
        fn label(self) -> String {
            let slot = self.slot_ordinal.map_or_else(
                || "identity".to_owned(),
                |ordinal| format!("slot-{ordinal}"),
            );
            format!("{slot}-{:?}", self.kind)
        }

        fn identity_must_remain_structurally_valid(self) -> bool {
            matches!(
                self.kind,
                V2SlotTamperKind::Ciphertext | V2SlotTamperKind::AuthenticatedAbsentSentinel
            ) || matches!(
                (self.slot_ordinal, self.kind),
                (Some(0 | 1), V2SlotTamperKind::ComponentHash)
            )
        }
    }

    #[cfg(windows)]
    fn v2_slot_tamper_matrix() -> Vec<V2SlotTamperCase> {
        let mut cases = Vec::with_capacity(24);
        for slot_ordinal in 0..5 {
            for kind in [
                V2SlotTamperKind::Ciphertext,
                V2SlotTamperKind::ComponentHash,
                V2SlotTamperKind::Presence,
                V2SlotTamperKind::Ordinal,
            ] {
                cases.push(V2SlotTamperCase {
                    slot_ordinal: Some(slot_ordinal),
                    kind,
                });
            }
        }
        for slot_ordinal in 2..5 {
            cases.push(V2SlotTamperCase {
                slot_ordinal: Some(slot_ordinal),
                kind: V2SlotTamperKind::AuthenticatedAbsentSentinel,
            });
        }
        cases.push(V2SlotTamperCase {
            slot_ordinal: None,
            kind: V2SlotTamperKind::BundleFilename,
        });
        cases
    }

    #[cfg(windows)]
    fn observe_v2_tree(root: &Path) -> BTreeMap<String, V2TreeEntryObservation> {
        fn observe(
            root: &Path,
            current: &Path,
            observations: &mut BTreeMap<String, V2TreeEntryObservation>,
        ) {
            let mut entries = fs::read_dir(current)
                .expect("V2 tree directory enumerates")
                .map(|entry| entry.expect("V2 tree entry enumerates"))
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("V2 tree metadata reads");
                let relative = path
                    .strip_prefix(root)
                    .expect("V2 tree path stays below root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let file_type = metadata.file_type();
                let kind = if file_type.is_file() {
                    "file"
                } else if file_type.is_dir() {
                    "directory"
                } else if file_type.is_symlink() {
                    "symlink"
                } else {
                    "other"
                };
                let modified_unix_nanos = metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|duration| duration.as_nanos());
                let sha256 = file_type
                    .is_file()
                    .then(|| sha256_hex(&fs::read(&path).expect("V2 tree file reads")));
                observations.insert(
                    relative,
                    V2TreeEntryObservation {
                        kind,
                        bytes: metadata.len(),
                        modified_unix_nanos,
                        sha256,
                    },
                );
                if file_type.is_dir() {
                    observe(root, &path, observations);
                }
            }
        }

        let mut observations = BTreeMap::new();
        let root_metadata = fs::symlink_metadata(root).expect("V2 tree root metadata reads");
        assert!(
            root_metadata.is_dir(),
            "V2 tree root must remain a directory"
        );
        observations.insert(
            ".".to_owned(),
            V2TreeEntryObservation {
                kind: "directory",
                bytes: root_metadata.len(),
                modified_unix_nanos: root_metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|duration| duration.as_nanos()),
                sha256: None,
            },
        );
        observe(root, root, &mut observations);
        observations
    }

    #[cfg(windows)]
    fn assert_v2_active_five_slots_and_evidence_complete(
        fixture: &RealOriginalRollbackFixture,
        lineage_id: &str,
    ) {
        for present in [
            fixture.user_database_path.as_path(),
            fixture.privacy_database_path.as_path(),
        ] {
            let metadata = fs::symlink_metadata(present).expect("present active slot exists");
            assert!(metadata.is_file());
            assert!(!metadata_is_reparse_point(&metadata));
            assert!(metadata.len() > 0);
        }
        for absent in [
            fixture.root().join("case-vault-v2"),
            fixture
                .root()
                .join("privacy/approved-mcp/approved-generations"),
            fixture.root().join("privacy/approved-mcp/work-products"),
        ] {
            assert!(
                matches!(
                    fs::symlink_metadata(&absent),
                    Err(error) if error.kind() == io::ErrorKind::NotFound
                ),
                "target-only active slot must remain absent: {}",
                absent.display()
            );
        }

        let lineage_directory =
            v031_upgrade_r2::canonical_lineage_directory(fixture.root(), lineage_id)
                .expect("V2 lineage path resolves");
        for final_name in [
            v031_upgrade_r2::V2_IDENTITY_FINAL,
            v031_upgrade_r2::V2_BUNDLE_FINAL,
            v031_upgrade_r2::V031_RECEIPTS[0].final_basename,
            v031_upgrade_r2::V031_RECEIPTS[1].final_basename,
        ] {
            let metadata = fs::symlink_metadata(lineage_directory.join(final_name))
                .expect("required V2 evidence is final");
            assert!(metadata.is_file());
            assert!(!metadata_is_reparse_point(&metadata));
            assert!(metadata.len() > 0);
        }
        for residue_name in [
            v031_upgrade_r2::V2_IDENTITY_INCOMING,
            v031_upgrade_r2::V2_BUNDLE_INCOMING,
            v031_upgrade_r2::USER_SNAPSHOT_INCOMING,
            v031_upgrade_r2::PRIVACY_SNAPSHOT_INCOMING,
        ] {
            assert!(!lineage_directory.join(residue_name).exists());
        }
        for descriptor in &v031_upgrade_r2::V031_RECEIPTS[2..] {
            assert!(!lineage_directory.join(descriptor.final_basename).exists());
            assert!(!lineage_directory
                .join(format!("{}.incoming", descriptor.final_basename))
                .exists());
        }
    }

    #[cfg(windows)]
    fn tampered_v2_pair(
        original_bundle: &[u8],
        original_identity: &V031OriginalRollbackIdentityV2,
        case: V2SlotTamperCase,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut bundle: Value =
            serde_json::from_slice(original_bundle).expect("canonical V2 bundle parses");
        let mut identity = original_identity.clone();

        match case.kind {
            V2SlotTamperKind::Ciphertext => {
                let slot_ordinal = case.slot_ordinal.expect("ciphertext case has slot");
                let chunk = bundle["slotChunks"]
                    .as_array_mut()
                    .expect("slot chunks are an array")
                    .iter_mut()
                    .find(|chunk| chunk["slotOrdinal"].as_u64() == Some(slot_ordinal as u64))
                    .expect("slot has an encrypted chunk");
                let mut ciphertext = BASE64_STANDARD
                    .decode(
                        chunk["ciphertextBase64"]
                            .as_str()
                            .expect("ciphertext is base64"),
                    )
                    .expect("ciphertext base64 decodes");
                ciphertext[0] ^= 0x01;
                chunk["ciphertextBase64"] = Value::String(BASE64_STANDARD.encode(&ciphertext));
                chunk["ciphertextSha256"] = Value::String(sha256_hex(&ciphertext));
            }
            V2SlotTamperKind::ComponentHash => {
                let slot_ordinal = case.slot_ordinal.expect("component-hash case has slot");
                let current = bundle["slots"][slot_ordinal]["plaintextSha256"]
                    .as_str()
                    .expect("component hash is a string");
                let replacement = if current
                    != "1111111111111111111111111111111111111111111111111111111111111111"
                {
                    "1".repeat(64)
                } else {
                    "2".repeat(64)
                };
                bundle["slots"][slot_ordinal]["plaintextSha256"] = Value::String(replacement);
            }
            V2SlotTamperKind::Presence => {
                let slot_ordinal = case.slot_ordinal.expect("presence case has slot");
                let replacement = if slot_ordinal < 2 {
                    "authenticated_absent"
                } else {
                    "present"
                };
                bundle["slots"][slot_ordinal]["presence"] = Value::String(replacement.to_owned());
            }
            V2SlotTamperKind::Ordinal => {
                let slot_ordinal = case.slot_ordinal.expect("ordinal case has slot");
                let replacement = (slot_ordinal + 1) % 5;
                bundle["slots"][slot_ordinal]["ordinal"] = Value::from(replacement as u64);
                for chunk in bundle["slotChunks"]
                    .as_array_mut()
                    .expect("slot chunks are an array")
                    .iter_mut()
                    .filter(|chunk| chunk["slotOrdinal"].as_u64() == Some(slot_ordinal as u64))
                {
                    chunk["slotOrdinal"] = Value::from(replacement as u64);
                }
            }
            V2SlotTamperKind::AuthenticatedAbsentSentinel => {
                let slot_ordinal = case.slot_ordinal.expect("sentinel case has slot");
                assert!((2..5).contains(&slot_ordinal));
                let donor = 2 + ((slot_ordinal - 2 + 1) % 3);
                let chunks = bundle["slotChunks"]
                    .as_array_mut()
                    .expect("slot chunks are an array");
                let donor_chunk = chunks
                    .iter()
                    .find(|chunk| chunk["slotOrdinal"].as_u64() == Some(donor as u64))
                    .expect("donor authenticated-absent sentinel chunk exists")
                    .clone();
                let target = chunks
                    .iter_mut()
                    .find(|chunk| chunk["slotOrdinal"].as_u64() == Some(slot_ordinal as u64))
                    .expect("target authenticated-absent sentinel chunk exists");
                *target = donor_chunk;
                target["slotOrdinal"] = Value::from(slot_ordinal as u64);
            }
            V2SlotTamperKind::BundleFilename => {
                identity.bundle_file_name = "renamed-v031-original-rollback-v2.bundle".to_owned();
            }
        }

        let tampered_bundle = canonical_json_v1(&bundle).expect("tampered V2 bundle canonicalizes");
        if case.kind != V2SlotTamperKind::BundleFilename {
            identity.slots = serde_json::from_value::<Vec<V031OriginalRollbackSlotIdentityV2>>(
                bundle["slots"].clone(),
            )
            .expect("tampered slot identities deserialize");
            identity.bundle_bytes =
                u64::try_from(tampered_bundle.len()).expect("tampered bundle length fits u64");
            identity.bundle_sha256 = sha256_hex(&tampered_bundle);
        }
        let tampered_identity_plaintext =
            canonical_json_v1(&identity).expect("tampered V2 identity canonicalizes");
        let tampered_identity_protected = protect_local(&tampered_identity_plaintext)
            .expect("tampered identity uses real CurrentUser DPAPI");
        assert_eq!(
            unprotect_local(&tampered_identity_protected)
                .expect("real CurrentUser DPAPI opens tampered test identity"),
            tampered_identity_plaintext
        );
        (tampered_bundle, tampered_identity_protected)
    }

    #[cfg(windows)]
    fn set_modified_time(path: &Path, modified: std::time::SystemTime) {
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .expect("fixture file opens for timestamp update");
        file.set_times(FileTimes::new().set_modified(modified))
            .expect("fixture modified time updates");
    }

    #[cfg(windows)]
    fn bump_modified_time(path: &Path) -> std::time::SystemTime {
        let original = fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .expect("fixture modified time reads");
        let bumped = original
            .checked_add(Duration::from_secs(7))
            .expect("fixture modified time advances");
        set_modified_time(path, bumped);
        original
    }

    #[test]
    fn receipt_count_maps_use_only_the_frozen_stage_keys_and_values() {
        let source_counts = source_preflight_counts(26, 3);
        assert_eq!(source_counts.len(), 7);
        assert_eq!(
            source_counts[&V031UpgradeReceiptCountKey::UserSchemaObjects],
            V031_USER_SCHEMA_OBJECT_COUNT as u64
        );
        assert_eq!(
            source_counts[&V031UpgradeReceiptCountKey::PrivacySchemaObjects],
            PRIVACY_V1_SCHEMA_OBJECT_COUNT as u64
        );
        assert_eq!(source_counts[&V031UpgradeReceiptCountKey::PresentSlots], 2);
        assert_eq!(
            source_counts[&V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots],
            3
        );
        assert_eq!(
            source_counts[&V031UpgradeReceiptCountKey::TargetAbsenceChecks],
            26
        );
        assert_eq!(
            source_counts[&V031UpgradeReceiptCountKey::CapacityChecks],
            2
        );
        assert_eq!(
            source_counts[&V031UpgradeReceiptCountKey::ProtectedPayloads],
            3
        );

        let rollback_counts = original_rollback_counts(9);
        assert_eq!(rollback_counts.len(), 7);
        assert_eq!(
            rollback_counts[&V031UpgradeReceiptCountKey::IdentityArtifacts],
            1
        );
        assert_eq!(
            rollback_counts[&V031UpgradeReceiptCountKey::BundleArtifacts],
            1
        );
        assert_eq!(
            rollback_counts[&V031UpgradeReceiptCountKey::RollbackSlots],
            5
        );
        assert_eq!(
            rollback_counts[&V031UpgradeReceiptCountKey::SqliteImages],
            2
        );
    }

    #[test]
    fn rollback_evidence_is_canonical_and_contains_no_location_or_secret_fields() {
        let evidence = OriginalRollbackReceiptEvidenceV1 {
            schema_version: ORIGINAL_ROLLBACK_EVIDENCE_SCHEMA,
            source_profile_proof_sha256: HASH,
            source_revalidation_sha256: HASH,
            target_absence_policy_sha256: HASH,
            protected_identity_sha256: HASH,
            bundle_sha256: HASH,
            source_user_physical_file_set_sha256: HASH,
            source_privacy_physical_file_set_sha256: HASH,
            user_snapshot_sha256: HASH,
            privacy_snapshot_sha256: HASH,
            identity_artifacts: 1,
            bundle_artifacts: 1,
            bundle_bytes: 1024,
            rollback_slots: 5,
            sqlite_images: 2,
            encrypted_chunks: 7,
            source_revalidations: 2,
            authenticated_absent_slots: 3,
            target_absence_checks: 26,
        };
        let first = canonical_json_v1(&evidence).expect("canonical evidence");
        let second = canonical_json_v1(&evidence).expect("canonical evidence");
        assert_eq!(first, second);
        let text = String::from_utf8(first).expect("UTF-8 canonical JSON");
        assert!(text.contains("\"bundleBytes\":1024"));
        assert!(text.contains("\"sourceUserPhysicalFileSetSha256\""));
        assert!(text.contains("\"sourcePrivacyPhysicalFileSetSha256\""));
        assert!(!text.contains("slotIdentity"));
        for forbidden in [
            "path",
            "filename",
            "privacyCaseId",
            "credential",
            "token",
            "ticket",
            "secret",
        ] {
            assert!(!text.contains(forbidden));
        }
    }

    #[test]
    fn receipt_one_canonical_evidence_binds_both_physical_file_set_anchors() {
        let baseline = OriginalRollbackReceiptEvidenceV1 {
            schema_version: ORIGINAL_ROLLBACK_EVIDENCE_SCHEMA,
            source_profile_proof_sha256: HASH,
            source_revalidation_sha256: HASH,
            target_absence_policy_sha256: HASH,
            protected_identity_sha256: HASH,
            bundle_sha256: HASH,
            source_user_physical_file_set_sha256: HASH,
            source_privacy_physical_file_set_sha256: HASH,
            user_snapshot_sha256: HASH,
            privacy_snapshot_sha256: HASH,
            identity_artifacts: 1,
            bundle_artifacts: 1,
            bundle_bytes: 1024,
            rollback_slots: 5,
            sqlite_images: 2,
            encrypted_chunks: 7,
            source_revalidations: 2,
            authenticated_absent_slots: 3,
            target_absence_checks: 26,
        };
        let baseline_sha256 = canonical_evidence_sha256(&baseline).expect("baseline evidence");
        let other_hash = "b".repeat(64);

        let changed_user = OriginalRollbackReceiptEvidenceV1 {
            source_user_physical_file_set_sha256: &other_hash,
            ..baseline
        };
        let changed_privacy = OriginalRollbackReceiptEvidenceV1 {
            source_privacy_physical_file_set_sha256: &other_hash,
            ..baseline
        };

        assert_ne!(
            canonical_evidence_sha256(&changed_user).expect("user-anchor evidence"),
            baseline_sha256
        );
        assert_ne!(
            canonical_evidence_sha256(&changed_privacy).expect("Privacy-anchor evidence"),
            baseline_sha256
        );
    }

    #[cfg(windows)]
    #[test]
    fn receipt_one_restart_revalidates_active_user_v10_and_privacy_v1_physical_anchors() {
        let fixture = RealOriginalRollbackFixture::new();
        let established = establish_original_migration_backup_with_probe(
            fixture.root(),
            &fixture.user_database_path,
            &fixture.privacy_database_path,
            &AlwaysAbsentCredentialProbe,
        )
        .expect("receipt-one gate establishes");
        let loaded = load_original_migration_backup_gate(fixture.root(), established.lineage_id())
            .expect("receipt-one gate reloads");
        assert!(established.authenticates_same_original_rollback(&loaded));
        assert!(loaded.authenticates_same_original_rollback(&established));
        assert_eq!(
            loaded.original_user_physical_file_set_sha256(),
            established.original_user_physical_file_set_sha256()
        );
        assert_eq!(
            loaded.original_privacy_physical_file_set_sha256(),
            established.original_privacy_physical_file_set_sha256()
        );

        let original_user_modified = bump_modified_time(&fixture.user_database_path);
        database::validate_user_database_migration_source_read_only(&fixture.user_database_path)
            .expect("mtime-only user change preserves exact v10 semantics");
        assert_eq!(
            load_original_migration_backup_gate(fixture.root(), established.lineage_id()),
            Err(OriginalMigrationBackupError::SourceDrift)
        );
        set_modified_time(&fixture.user_database_path, original_user_modified);
        load_original_migration_backup_gate(fixture.root(), established.lineage_id())
            .expect("restored user physical anchor reloads");

        let original_privacy_modified = bump_modified_time(&fixture.privacy_database_path);
        privacy::validate_privacy_v1_migration_source_read_only(&fixture.privacy_database_path)
            .expect("mtime-only Privacy change preserves exact v1 semantics");
        assert_eq!(
            load_original_migration_backup_gate(fixture.root(), established.lineage_id()),
            Err(OriginalMigrationBackupError::SourceDrift)
        );
        set_modified_time(&fixture.privacy_database_path, original_privacy_modified);
        load_original_migration_backup_gate(fixture.root(), established.lineage_id())
            .expect("restored Privacy physical anchor reloads");
    }

    #[cfg(windows)]
    #[test]
    fn privacy_v5_restart_path_does_not_skip_the_active_user_v10_physical_anchor() {
        let fixture = RealOriginalRollbackFixture::new();
        let (original_user, ()) = with_validated_user_database_migration_source_read_only(
            &fixture.user_database_path,
            |_| (),
        )
        .expect("original user-v10 proof");
        let expected_physical =
            user_physical_file_set_sha256(&original_user).expect("original user physical anchor");

        let mut privacy_connection =
            Connection::open(&fixture.privacy_database_path).expect("Privacy-v1 fixture reopens");
        PrivacyStore::upgrade_exact_v031_schema_to_v5_after_backup(&privacy_connection)
            .expect("Privacy fixture advances to strict v5");
        privacy::PrivacyLifecycle::initialize(
            &mut privacy_connection,
            privacy::vnext::WorkspaceInstanceId::parse("ws_0123456789abcdef0123456789abcdef")
                .expect("fixture workspace id"),
            1_784_476_800,
        )
        .expect("Privacy lifecycle v5 initializes");
        privacy::ProjectPrivacyCaseBindingStore::initialize(&mut privacy_connection)
            .expect("project-case binding v5 initializes");
        compute_privacy_v5_manifests_read_only(&privacy_connection)
            .expect("advanced Privacy-v5 state is exact");
        drop(privacy_connection);

        bump_modified_time(&fixture.user_database_path);
        let (active_user, ()) = with_validated_user_database_migration_source_read_only(
            &fixture.user_database_path,
            |_| (),
        )
        .expect("mtime-only user change remains exact v10");
        assert!(same_user_source_content(&original_user, &active_user));
        assert_eq!(
            validate_original_user_v10_physical_anchor(
                &active_user,
                &original_user,
                &expected_physical,
            ),
            Err(OriginalMigrationBackupError::SourceDrift)
        );
    }

    #[cfg(windows)]
    #[test]
    fn original_v2_five_slot_tamper_matrix_fails_closed_before_any_process_start_write() {
        let fixture = RealOriginalRollbackFixture::new();
        let mut isolated_credentials =
            crate::approved_mcp::V031CrossProcessCredentialHarness::create_parent(
                fixture.root().to_path_buf(),
            )
            .expect("V2 matrix allocates an isolated real Credential Manager namespace");
        let credential_probe = isolated_credentials.credential_probe();
        let established = establish_original_migration_backup_with_probe(
            fixture.root(),
            &fixture.user_database_path,
            &fixture.privacy_database_path,
            &credential_probe,
        )
        .expect("real Original-V2 five-slot gate establishes");
        let lineage_id = established.lineage_id().to_owned();
        let lineage_directory =
            v031_upgrade_r2::canonical_lineage_directory(fixture.root(), &lineage_id)
                .expect("V2 lineage path resolves");
        let identity_path = lineage_directory.join(v031_upgrade_r2::V2_IDENTITY_FINAL);
        let bundle_path = lineage_directory.join(v031_upgrade_r2::V2_BUNDLE_FINAL);
        let original_identity_protected = fs::read(&identity_path).expect("V2 identity reads");
        let original_identity =
            open_v031_original_rollback_identity_v2(&original_identity_protected)
                .expect("real DPAPI identity opens before tamper matrix");
        let original_bundle = fs::read(&bundle_path).expect("V2 bundle reads");
        open_v031_original_rollback_v2_for_identity(&original_bundle, &original_identity)
            .expect("real AES-GCM five-slot bundle opens before tamper matrix");

        let cases = v2_slot_tamper_matrix();
        assert_eq!(cases.len(), 24);
        for case in cases {
            let label = case.label();
            let (tampered_bundle, tampered_identity_protected) =
                tampered_v2_pair(&original_bundle, &original_identity, case);

            match open_v031_original_rollback_identity_v2(&tampered_identity_protected) {
                Ok(tampered_identity) => {
                    assert!(
                        case.identity_must_remain_structurally_valid(),
                        "{label}: only ciphertext or present-component-hash tamper may pass identity shape"
                    );
                    assert!(
                        open_v031_original_rollback_v2_for_identity(
                            &tampered_bundle,
                            &tampered_identity
                        )
                        .is_err(),
                        "{label}: isolated Original-V2 AES-GCM verifier must reject"
                    );
                }
                Err(_) => assert!(
                    !case.identity_must_remain_structurally_valid(),
                    "{label}: structurally valid identity unexpectedly failed before bundle verification"
                ),
            }

            fs::write(&bundle_path, &tampered_bundle)
                .expect("tampered final bundle writes before observation");
            fs::write(&identity_path, &tampered_identity_protected)
                .expect("tampered final identity writes before observation");
            assert_v2_active_five_slots_and_evidence_complete(&fixture, &lineage_id);
            let before = observe_v2_tree(fixture.root());

            let startup = crate::v031_startup::
                observe_production_startup_with_credential_probe_for_test(
                    fixture.root(),
                    &credential_probe,
                )
                .expect(
                    "the production startup common-inner classifies the receipt-1 source profile with isolated real credentials",
                );
            assert_eq!(
                crate::v031_startup::classify_startup(startup.summary()),
                Ok(crate::v031_startup::StartupRoute::AdvanceUpgradeThroughReceiptEight {
                    next_ordinal: 2,
                }),
                "{label}: production startup arbitration must select the unique receipt-2 transition"
            );
            assert_eq!(
                observe_v2_tree(fixture.root()),
                before,
                "{label}: production startup observation and arbitration must be read-only"
            );
            assert_eq!(
                crate::v031_startup::advance_v031_upgrade_through_receipt_eight(
                    fixture.root(),
                    startup.process_start_upgrade(),
                    startup.exact_v031_source_gate(),
                ),
                Err(crate::v031_startup::V031StartupTransitionError::OriginalRollback),
                "{label}: the production transition must reject the tampered V2 before target initialization"
            );
            assert_eq!(
                observe_v2_tree(fixture.root()),
                before,
                "{label}: failed production startup transition must not alter any active slot or migration evidence"
            );

            // Keep the narrow loader assertion as secondary codec evidence. The
            // production observation above intentionally classifies the exact
            // receipt-1 source profile; the transition is the first boundary
            // that may authorize target writes and therefore must independently
            // authenticate the complete V2 payload before doing so.
            assert_eq!(
                load_original_migration_backup_gate(fixture.root(), &lineage_id),
                Err(OriginalMigrationBackupError::RollbackCodec),
                "{label}: the isolated Original-V2 loader must also fail closed"
            );

            let after = observe_v2_tree(fixture.root());
            assert_eq!(
                after, before,
                "{label}: failed isolated verification must not alter active slots, identity, bundle, or receipt tree"
            );
            assert_v2_active_five_slots_and_evidence_complete(&fixture, &lineage_id);
        }

        fs::write(&bundle_path, &original_bundle).expect("original V2 bundle restores");
        fs::write(&identity_path, &original_identity_protected)
            .expect("original V2 identity restores");
        isolated_credentials
            .verify_all_credentials_absent_read_only_for_test()
            .expect("V2 tamper observation never creates an isolated target credential");
        isolated_credentials
            .cleanup()
            .expect("V2 matrix explicitly cleans its isolated Credential Manager namespace");
        let before_valid_reload = observe_v2_tree(fixture.root());
        let reloaded = load_original_migration_backup_gate(fixture.root(), &lineage_id)
            .expect("untampered Original-V2 loader reloads after the complete matrix");
        assert!(established.authenticates_same_original_rollback(&reloaded));
        assert_eq!(observe_v2_tree(fixture.root()), before_valid_reload);
        assert_v2_active_five_slots_and_evidence_complete(&fixture, &lineage_id);
    }

    #[cfg(windows)]
    #[test]
    fn snapshot_sqlite_open_keeps_create_new_file_and_parent_bound_before_write() {
        let directory = tempfile::tempdir().expect("snapshot binding fixture root");
        let lineage_directory = directory.path().join("lineage");
        fs::create_dir(&lineage_directory).expect("snapshot lineage directory creates");
        let snapshot_path = lineage_directory.join("user-snapshot.sqlite.incoming");
        let displaced_path = lineage_directory.join("displaced.sqlite");
        let replacement_path = lineage_directory.join("replacement.sqlite");
        let displaced_parent = directory.path().join("displaced-lineage");
        fs::write(&replacement_path, b"attacker replacement")
            .expect("replacement candidate creates");

        let mut replacement_attempted = false;
        let mut snapshot =
            create_new_snapshot_connection_with_preopen_hook(&snapshot_path, |create_new_path| {
                replacement_attempted = true;
                assert!(
                    fs::rename(create_new_path, &displaced_path).is_err(),
                    "the live create-new handle must deny moving the verified file"
                );
                assert!(
                    fs::rename(&replacement_path, create_new_path).is_err(),
                    "the live create-new handle must deny replacement before SQLite opens"
                );
                assert!(
                    fs::rename(&lineage_directory, &displaced_parent).is_err(),
                    "the live parent handle must deny replacing the exact directory"
                );
                Ok(())
            })
            .expect("SQLite opens the exact still-pinned create-new file");
        assert!(replacement_attempted);

        snapshot
            .connection_mut_for_backup()
            .expect("SQLite handle still matches create-new handle before the first write")
            .execute_batch(
                "CREATE TABLE snapshot_binding_probe(value TEXT NOT NULL);
                 INSERT INTO snapshot_binding_probe(value) VALUES('bound');",
            )
            .expect("bound SQLite connection writes");
        close_snapshot_connection(snapshot).expect("bound snapshot closes durably");

        assert!(snapshot_path.is_file());
        assert!(!displaced_path.exists());
        assert!(!displaced_parent.exists());
        assert_eq!(
            fs::read(&replacement_path).expect("unused replacement remains readable"),
            b"attacker replacement"
        );
        let connection = Connection::open_with_flags(
            &snapshot_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("completed snapshot reopens read-only");
        let observed: String = connection
            .query_row("SELECT value FROM snapshot_binding_probe", [], |row| {
                row.get(0)
            })
            .expect("bound snapshot row reads");
        assert_eq!(observed, "bound");
    }

    #[test]
    fn receipt_one_requires_final_v2_and_both_plaintext_snapshots_absent() {
        let complete = V2EvidenceInventory {
            identity_final: true,
            bundle_final: true,
            ..V2EvidenceInventory::default()
        };
        assert!(complete_v2_evidence(complete));

        for incomplete in [
            V2EvidenceInventory {
                user_snapshot_incoming: true,
                ..complete
            },
            V2EvidenceInventory {
                privacy_snapshot_incoming: true,
                ..complete
            },
            V2EvidenceInventory {
                identity_incoming: true,
                ..complete
            },
            V2EvidenceInventory {
                bundle_incoming: true,
                ..complete
            },
        ] {
            assert!(!complete_v2_evidence(incomplete));
        }
    }
}
