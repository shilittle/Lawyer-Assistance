//! Final v0.3.1 user-database migration and ordinal-8 receipt.
//!
//! This is the only desktop orchestration path allowed to write user schema 11.
//! The immutable Privacy-v6 predecessor is reloaded before the writer, the two
//! database audit rows are completed in their frozen crash-resumable order, and
//! the post-audit five-component manifest is bound only by the DPAPI receipt.

use crate::{
    approved_mcp::{
        ApprovedMcpWorkspace, CurrentApprovedComponentsLifecycle,
        CurrentApprovedComponentsObservation, V031_APPROVED_WORKSPACE_SCHEMA_SHA256,
        V031_WORK_PRODUCTS_SCHEMA_SHA256,
    },
    commands::{
        original_migration_backup::{
            load_original_migration_backup_gate, OriginalRollbackVerifiedGate,
        },
        v031_checkpoint_receipts::load_v031_projection_backup_verified_gate_read_only,
        v031_migration_checkpoint::load_v031_historical_target_components_from_checkpoint_read_only,
        v031_privacy_migration::{
            load_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only,
            load_v031_privacy_v6_verified_gate_read_only,
            verify_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only,
            verify_v031_privacy_v6_verified_gate_read_only, V031PrivacyV6VerifiedGate,
        },
        v031_upgrade_complete::AuthenticatedV031Step8PredecessorEvidence,
    },
    privacy_workflow::{
        observe_current_vault_read_only, CurrentVaultObservation, PrivacyWorkflowManager,
    },
    v031_upgrade_r2::V031CheckpointKind,
    v031_upgrade_receipts::{
        load_authenticated_v031_lineage, persist_v031_receipt, OwnedV031ReceiptContext,
        PrivacyReceiptAuthenticationBridge, V031ReceiptPersistenceError,
    },
};
use database::{
    migrate_exact_v031_user_to_v11_with_upgrade_audit, open_existing_user_database,
    verify_exact_v031_user_v11_upgrade_audit,
    with_validated_user_database_migration_source_read_only, OperationAuditRow,
    UserMigrationSourceProof, V031UserPreAuditManifest, V031UserUpgradeAuditEvidence,
    V031UserUpgradeResult, ValidatedUserSourceSchema, USER_SCHEMA_VERSION,
    V031_TO_V040_USER_MIGRATION_ID, V031_USER_SCHEMA_VERSION,
};
use privacy::{
    append_application_upgrade_lineage, compute_privacy_v6_manifests_read_only,
    compute_privacy_v6_pre_audit_manifests_read_only, load_application_upgrade_lineage,
    ApplicationUpgradeLineageAppendOutcome, ApplicationUpgradeLineageRecord,
    PrivacyV6ManifestProof, APPLICATION_UPGRADE_RESULT_OK, PRIVACY_STORE_SCHEMA_VERSION,
    PRIVACY_V6_APPLICATION_TABLES,
};
use privacy::{
    upgrade_receipt_v1::{V031UpgradeReceiptCountKey, V031UpgradeReceiptStage},
    vnext::canonical_json_v1,
};
use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, path::Path, sync::Mutex};

const PRIVACY_DATABASE_RELATIVE: &str = "privacy/privacy-workflow.sqlite";
const FINAL_COMPONENT_MANIFEST_SCHEMA: &str =
    "lawyer-assistance-v031-final-five-component-manifest-v1";
const EXPECTED_SOURCE_USER_TABLE_COUNT: u64 = 27;
const EXPECTED_TARGET_USER_TABLE_COUNT: u64 = 29;
const EXPECTED_SOURCE_PRIVACY_TABLE_COUNT: u64 = 5;
const EXPECTED_PRIVACY_TABLE_COUNT: u64 = PRIVACY_V6_APPLICATION_TABLES.len() as u64;
const FINAL_COMPONENT_SLOT_COUNT: u64 = 5;
const HISTORICAL_CHECKPOINT_FILE_COUNT: usize = 6;
const MAX_HISTORICAL_CHECKPOINT_FILE_BYTES: usize =
    privacy::MAX_APPLICATION_BACKUP_BYTES + 64 * 1024;
const FINAL_COMPONENT_SLOT_NAMES: [&str; 5] = [
    "user_database",
    "privacy_database",
    "vault",
    "approved_workspace",
    "work_products",
];
static V031_USER_UPGRADE_OPERATION: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031UserUpgradeError {
    InvalidInput,
    Predecessor,
    ReceiptPrefix,
    UserDatabase,
    PrivacyDatabase,
    AuditTimestamp,
    LedgerConflict,
    SourceDrift,
    FinalComponents,
    EvidenceEncoding,
    Receipt,
}

impl V031UserUpgradeError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "v031_user_upgrade_input_invalid",
            Self::Predecessor => "v031_user_upgrade_predecessor_invalid",
            Self::ReceiptPrefix => "v031_user_upgrade_receipt_prefix_invalid",
            Self::UserDatabase => "v031_user_upgrade_user_database_failed",
            Self::PrivacyDatabase => "v031_user_upgrade_privacy_database_failed",
            Self::AuditTimestamp => "v031_user_upgrade_audit_timestamp_invalid",
            Self::LedgerConflict => "v031_user_upgrade_ledger_conflict",
            Self::SourceDrift => "v031_user_upgrade_source_drift",
            Self::FinalComponents => "v031_user_upgrade_final_components_invalid",
            Self::EvidenceEncoding => "v031_user_upgrade_evidence_encoding_failed",
            Self::Receipt => "v031_user_upgrade_receipt_failed",
        }
    }
}

impl fmt::Display for V031UserUpgradeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031UserUpgradeError {}

/// Opaque capability handed to Step 8 only after the ordinal-8 receipt and all
/// five live component slots have been revalidated.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031UserV11VerifiedGate {
    original_rollback_gate: OriginalRollbackVerifiedGate,
    receipt_context: OwnedV031ReceiptContext,
    privacy_v6_receipt_sha256: String,
    user_v11_receipt_sha256: String,
    evidence_sha256: String,
    evidence_record: V031UserV11ReceiptEvidenceRecordV1,
    final_component_manifest: V031FinalComponentManifestProof,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
}

/// Opaque historical authorization for receipt 8. Unlike
/// [`V031UserV11VerifiedGate`], this gate deliberately does not claim that the
/// five live component manifests still equal their pre-Step-8 values. It is
/// returned only after the authenticated receipt/checkpoint chain, the full
/// sidecar evidence records, and the immutable database ledgers agree.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031HistoricalReceipt8VerifiedGate {
    original_rollback_gate: OriginalRollbackVerifiedGate,
    receipt_context: OwnedV031ReceiptContext,
    privacy_v6_receipt_sha256: String,
    user_v11_receipt_sha256: String,
    evidence_sha256: String,
    evidence_record: V031UserV11ReceiptEvidenceRecordV1,
    final_component_manifest: V031FinalComponentManifestProof,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
}

/// Borrowed, untrusted values obtained by opening the Step-8 DPAPI sidecar.
/// This is data, not a capability: constructing it grants nothing. The only
/// capability constructor is the read-only verifier below, which rebinds every
/// field to authenticated disk state.
struct V031HistoricalReceipt8SidecarView<'a> {
    receipt_context: &'a OwnedV031ReceiptContext,
    receipt_seven_sha256: &'a str,
    receipt_eight_sha256: &'a str,
    receipt_eight_evidence_schema_version: &'a str,
    receipt_eight_evidence_sha256: &'a str,
    receipt_eight_counts: &'a BTreeMap<String, u64>,
    predecessor_manifest_sha256: &'a str,
    predecessor_manifest: &'a V031FinalComponentManifestRecordV1,
    receipt_eight_evidence: &'a V031UserV11ReceiptEvidenceRecordV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct V031HistoricalCheckpointFileRecordV1 {
    basename: String,
    file_bytes: u64,
    sha256: String,
}

impl V031HistoricalCheckpointFileRecordV1 {
    pub(crate) fn basename(&self) -> &str {
        &self.basename
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }
}

/// Opaque proof that all six immutable V3 checkpoint files still match the
/// exact size/hash set captured by the authenticated Step-8 sidecar.
#[derive(Clone, PartialEq, Eq)]
struct V031HistoricalCheckpointFilesVerifiedGate {
    lineage_id: String,
    files: Vec<V031HistoricalCheckpointFileRecordV1>,
    projection_identity_sha256: String,
    projection_bundle_sha256: String,
}

impl fmt::Debug for V031HistoricalCheckpointFilesVerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031HistoricalCheckpointFilesVerifiedGate")
            .field("lineage_id", &self.lineage_id)
            .field("checkpoint_file_count", &self.files.len())
            .field(
                "projection_identity_sha256",
                &self.projection_identity_sha256,
            )
            .field("projection_bundle_sha256", &self.projection_bundle_sha256)
            .finish_non_exhaustive()
    }
}

/// Narrow authorization for the one restart state in which the user
/// transaction is committed but ordinal 8 is not. It is built before Gate 7 is
/// reconstructed, from authenticated receipt-7/V2/checkpoint state plus the
/// exact immutable user audit. It never depends on receipt 8.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031CommittedUserV11ResumeProof {
    rollback_gate: OriginalRollbackVerifiedGate,
    receipt_context: OwnedV031ReceiptContext,
    privacy_v6_receipt_sha256: String,
    privacy_v6_evidence_sha256: String,
    target_user_pre_audit: V031UserPreAuditManifest,
    target_privacy_pre_audit_logical_manifest_sha256: String,
    target_privacy_pre_audit_business_manifest_sha256: String,
    target_privacy_pre_audit_table_count: u64,
    target_privacy_pre_audit_total_rows: u64,
    audit_created_at_unix: i64,
    user_audit_sha256: String,
    privacy_lineage_sha256: Option<String>,
}

impl fmt::Debug for V031CommittedUserV11ResumeProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031CommittedUserV11ResumeProof")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field("privacy_v6_receipt_sha256", &self.privacy_v6_receipt_sha256)
            .field(
                "privacy_v6_evidence_sha256",
                &self.privacy_v6_evidence_sha256,
            )
            .field("user_audit_sha256", &self.user_audit_sha256)
            .field(
                "privacy_lineage_present",
                &self.privacy_lineage_sha256.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl V031CommittedUserV11ResumeProof {
    pub(crate) fn rollback_gate(&self) -> &OriginalRollbackVerifiedGate {
        &self.rollback_gate
    }

    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn privacy_v6_receipt_sha256(&self) -> &str {
        &self.privacy_v6_receipt_sha256
    }

    pub(crate) fn privacy_v6_evidence_sha256(&self) -> &str {
        &self.privacy_v6_evidence_sha256
    }

    pub(crate) fn target_privacy_pre_audit_logical_manifest_sha256(&self) -> &str {
        &self.target_privacy_pre_audit_logical_manifest_sha256
    }

    pub(crate) fn target_privacy_pre_audit_business_manifest_sha256(&self) -> &str {
        &self.target_privacy_pre_audit_business_manifest_sha256
    }

    pub(crate) const fn target_privacy_pre_audit_table_count(&self) -> u64 {
        self.target_privacy_pre_audit_table_count
    }

    pub(crate) const fn target_privacy_pre_audit_total_rows(&self) -> u64 {
        self.target_privacy_pre_audit_total_rows
    }

    pub(crate) fn privacy_lineage_sha256(&self) -> Option<&str> {
        self.privacy_lineage_sha256.as_deref()
    }
}

impl fmt::Debug for V031UserV11VerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031UserV11VerifiedGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field("privacy_v6_receipt_sha256", &self.privacy_v6_receipt_sha256)
            .field("user_v11_receipt_sha256", &self.user_v11_receipt_sha256)
            .field("evidence_sha256", &self.evidence_sha256)
            .field(
                "final_component_manifest_sha256",
                &self.final_component_manifest.sha256,
            )
            .finish_non_exhaustive()
    }
}

impl V031UserV11VerifiedGate {
    pub(crate) fn original_rollback_gate(&self) -> &OriginalRollbackVerifiedGate {
        &self.original_rollback_gate
    }

    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn privacy_v6_receipt_sha256(&self) -> &str {
        &self.privacy_v6_receipt_sha256
    }

    pub(crate) fn user_v11_receipt_sha256(&self) -> &str {
        &self.user_v11_receipt_sha256
    }

    pub(crate) fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub(crate) fn evidence_record(&self) -> &V031UserV11ReceiptEvidenceRecordV1 {
        &self.evidence_record
    }

    pub(crate) fn final_component_manifest(&self) -> &V031FinalComponentManifestProof {
        &self.final_component_manifest
    }

    pub(crate) fn user_audit_sha256(&self) -> &str {
        &self.user_audit_sha256
    }

    pub(crate) fn privacy_lineage_sha256(&self) -> &str {
        &self.privacy_lineage_sha256
    }
}

impl fmt::Debug for V031HistoricalReceipt8VerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031HistoricalReceipt8VerifiedGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field("privacy_v6_receipt_sha256", &self.privacy_v6_receipt_sha256)
            .field("user_v11_receipt_sha256", &self.user_v11_receipt_sha256)
            .field("evidence_sha256", &self.evidence_sha256)
            .field(
                "historical_final_component_manifest_sha256",
                &self.final_component_manifest.sha256,
            )
            .finish_non_exhaustive()
    }
}

impl V031HistoricalReceipt8VerifiedGate {
    pub(crate) fn original_rollback_gate(&self) -> &OriginalRollbackVerifiedGate {
        &self.original_rollback_gate
    }

    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    #[cfg(test)]
    pub(crate) fn user_v11_receipt_sha256(&self) -> &str {
        &self.user_v11_receipt_sha256
    }

    pub(crate) fn final_component_manifest(&self) -> &V031FinalComponentManifestProof {
        &self.final_component_manifest
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct V031UserV11ReceiptEvidenceRecordV1 {
    schema_version: String,
    migration_id: String,
    lineage_id: String,
    source_profile_proof_sha256: String,
    original_rollback_identity_sha256: String,
    previous_receipt_sha256: String,
    privacy_v6_evidence_sha256: String,
    projection_checkpoint_identity_sha256: String,
    projection_checkpoint_bundle_sha256: String,
    source_user_physical_file_set_sha256: String,
    source_privacy_physical_file_set_sha256: String,
    source_user_logical_manifest_sha256: String,
    source_user_business_manifest_sha256: String,
    source_privacy_logical_manifest_sha256: String,
    source_privacy_business_manifest_sha256: String,
    target_user_pre_audit_logical_manifest_sha256: String,
    target_user_pre_audit_business_manifest_sha256: String,
    target_privacy_pre_audit_logical_manifest_sha256: String,
    target_privacy_pre_audit_business_manifest_sha256: String,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
    ledger_created_at_unix: i64,
    final_component_manifest_sha256: String,
}

impl V031UserV11ReceiptEvidenceRecordV1 {
    pub(crate) fn canonical_sha256(&self) -> Result<String, V031UserUpgradeError> {
        validate_user_v11_receipt_evidence_record(self)?;
        canonical_sha256(self)
    }

    pub(crate) fn lineage_id(&self) -> &str {
        &self.lineage_id
    }

    pub(crate) fn source_profile_proof_sha256(&self) -> &str {
        &self.source_profile_proof_sha256
    }

    pub(crate) fn original_rollback_identity_sha256(&self) -> &str {
        &self.original_rollback_identity_sha256
    }

    pub(crate) fn previous_receipt_sha256(&self) -> &str {
        &self.previous_receipt_sha256
    }

    pub(crate) fn privacy_v6_evidence_sha256(&self) -> &str {
        &self.privacy_v6_evidence_sha256
    }

    pub(crate) fn projection_checkpoint_identity_sha256(&self) -> &str {
        &self.projection_checkpoint_identity_sha256
    }

    pub(crate) fn projection_checkpoint_bundle_sha256(&self) -> &str {
        &self.projection_checkpoint_bundle_sha256
    }

    pub(crate) fn source_user_physical_file_set_sha256(&self) -> &str {
        &self.source_user_physical_file_set_sha256
    }

    pub(crate) fn source_privacy_physical_file_set_sha256(&self) -> &str {
        &self.source_privacy_physical_file_set_sha256
    }

    pub(crate) fn source_user_logical_manifest_sha256(&self) -> &str {
        &self.source_user_logical_manifest_sha256
    }

    pub(crate) fn source_user_business_manifest_sha256(&self) -> &str {
        &self.source_user_business_manifest_sha256
    }

    pub(crate) fn source_privacy_logical_manifest_sha256(&self) -> &str {
        &self.source_privacy_logical_manifest_sha256
    }

    pub(crate) fn source_privacy_business_manifest_sha256(&self) -> &str {
        &self.source_privacy_business_manifest_sha256
    }

    pub(crate) fn user_audit_sha256(&self) -> &str {
        &self.user_audit_sha256
    }

    pub(crate) fn privacy_lineage_sha256(&self) -> &str {
        &self.privacy_lineage_sha256
    }

    pub(crate) const fn ledger_created_at_unix(&self) -> i64 {
        self.ledger_created_at_unix
    }

    pub(crate) fn final_component_manifest_sha256(&self) -> &str {
        &self.final_component_manifest_sha256
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_v031_user_v11_receipt_evidence_record_anchors(
    record: &V031UserV11ReceiptEvidenceRecordV1,
    rollback: &OriginalRollbackVerifiedGate,
    receipt_context: &OwnedV031ReceiptContext,
    receipt_seven_sha256: &str,
    receipt_seven_evidence_sha256: &str,
    projection_checkpoint_identity_sha256: &str,
    projection_checkpoint_bundle_sha256: &str,
    final_component_manifest_sha256: &str,
) -> Result<String, V031UserUpgradeError> {
    let canonical_sha256 = record.canonical_sha256()?;
    for hash in [
        receipt_seven_sha256,
        receipt_seven_evidence_sha256,
        projection_checkpoint_identity_sha256,
        projection_checkpoint_bundle_sha256,
        final_component_manifest_sha256,
    ] {
        require_hash(hash)?;
    }
    if rollback.receipt_context() != *receipt_context
        || record.lineage_id != rollback.lineage_id()
        || record.source_profile_proof_sha256 != rollback.source_profile_proof_sha256()
        || record.original_rollback_identity_sha256 != rollback.original_identity_sha256()
        || record.previous_receipt_sha256 != receipt_seven_sha256
        || record.privacy_v6_evidence_sha256 != receipt_seven_evidence_sha256
        || record.projection_checkpoint_identity_sha256 != projection_checkpoint_identity_sha256
        || record.projection_checkpoint_bundle_sha256 != projection_checkpoint_bundle_sha256
        || record.source_user_physical_file_set_sha256
            != rollback.original_user_physical_file_set_sha256()
        || record.source_privacy_physical_file_set_sha256
            != rollback.original_privacy_physical_file_set_sha256()
        || record.source_user_logical_manifest_sha256
            != rollback
                .original_user_source_proof()
                .logical_database_manifest_sha256
        || record.source_user_business_manifest_sha256
            != rollback
                .original_user_source_proof()
                .business_manifest_sha256
        || record.source_privacy_logical_manifest_sha256
            != rollback.original_privacy_logical_manifest_sha256()
        || record.source_privacy_business_manifest_sha256
            != rollback.original_privacy_business_manifest_sha256()
        || record.final_component_manifest_sha256 != final_component_manifest_sha256
    {
        return Err(V031UserUpgradeError::SourceDrift);
    }
    Ok(canonical_sha256)
}

pub(crate) fn capture_v031_historical_checkpoint_file_records_read_only(
    app_local_data_dir: &Path,
    lineage_id: &str,
) -> Result<Vec<V031HistoricalCheckpointFileRecordV1>, V031UserUpgradeError> {
    validate_app_root(app_local_data_dir)?;
    crate::v031_upgrade_r2::validate_lineage_id(lineage_id)
        .map_err(|_| V031UserUpgradeError::InvalidInput)?;
    let directory =
        crate::v031_upgrade_r2::canonical_lineage_directory(app_local_data_dir, lineage_id)
            .map_err(|_| V031UserUpgradeError::ReceiptPrefix)?;
    let mut records = Vec::with_capacity(HISTORICAL_CHECKPOINT_FILE_COUNT);
    for kind in V031CheckpointKind::ALL {
        for basename in [kind.identity_final_basename(), kind.bundle_final_basename()] {
            let path = directory.join(basename);
            crate::v031_upgrade_r2::verify_plain_single_link_file(&path)
                .map_err(|_| V031UserUpgradeError::ReceiptPrefix)?;
            let bytes = crate::v031_upgrade_r2::read_bounded_file(
                &path,
                MAX_HISTORICAL_CHECKPOINT_FILE_BYTES,
            )
            .map_err(|_| V031UserUpgradeError::ReceiptPrefix)?;
            if bytes.is_empty() {
                return Err(V031UserUpgradeError::ReceiptPrefix);
            }
            records.push(V031HistoricalCheckpointFileRecordV1 {
                basename: basename.to_owned(),
                file_bytes: u64::try_from(bytes.len())
                    .map_err(|_| V031UserUpgradeError::ReceiptPrefix)?,
                sha256: sha256_hex(&bytes),
            });
        }
    }
    validate_historical_checkpoint_file_records(&records)?;
    Ok(records)
}

fn verify_v031_historical_checkpoint_files_read_only(
    app_local_data_dir: &Path,
    lineage_id: &str,
    expected_files: &[V031HistoricalCheckpointFileRecordV1],
    receipt_eight_evidence: &V031UserV11ReceiptEvidenceRecordV1,
) -> Result<V031HistoricalCheckpointFilesVerifiedGate, V031UserUpgradeError> {
    validate_historical_checkpoint_file_records(expected_files)?;
    if receipt_eight_evidence.lineage_id() != lineage_id {
        return Err(V031UserUpgradeError::Predecessor);
    }
    receipt_eight_evidence.canonical_sha256()?;
    let observed =
        capture_v031_historical_checkpoint_file_records_read_only(app_local_data_dir, lineage_id)?;
    if observed != expected_files {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    let projection_identity_sha256 = observed[4].sha256.clone();
    let projection_bundle_sha256 = observed[5].sha256.clone();
    if projection_identity_sha256 != receipt_eight_evidence.projection_checkpoint_identity_sha256()
        || projection_bundle_sha256 != receipt_eight_evidence.projection_checkpoint_bundle_sha256()
    {
        return Err(V031UserUpgradeError::Predecessor);
    }
    Ok(V031HistoricalCheckpointFilesVerifiedGate {
        lineage_id: lineage_id.to_owned(),
        files: observed,
        projection_identity_sha256,
        projection_bundle_sha256,
    })
}

fn validate_historical_checkpoint_file_records(
    records: &[V031HistoricalCheckpointFileRecordV1],
) -> Result<(), V031UserUpgradeError> {
    let expected_basenames = V031CheckpointKind::ALL
        .into_iter()
        .flat_map(|kind| [kind.identity_final_basename(), kind.bundle_final_basename()])
        .collect::<Vec<_>>();
    if records.len() != HISTORICAL_CHECKPOINT_FILE_COUNT
        || records
            .iter()
            .zip(expected_basenames)
            .any(|(record, expected_basename)| {
                record.basename != expected_basename
                    || record.file_bytes == 0
                    || record.file_bytes > MAX_HISTORICAL_CHECKPOINT_FILE_BYTES as u64
                    || require_hash(&record.sha256).is_err()
            })
    {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    Ok(())
}

fn validate_user_v11_receipt_evidence_record(
    record: &V031UserV11ReceiptEvidenceRecordV1,
) -> Result<(), V031UserUpgradeError> {
    if record.schema_version != V031UpgradeReceiptStage::UserV11Verified.evidence_schema_version()
        || record.migration_id != V031_TO_V040_USER_MIGRATION_ID
        || record.ledger_created_at_unix <= 0
    {
        return Err(V031UserUpgradeError::EvidenceEncoding);
    }
    for hash in [
        record.lineage_id.as_str(),
        record.source_profile_proof_sha256.as_str(),
        record.original_rollback_identity_sha256.as_str(),
        record.previous_receipt_sha256.as_str(),
        record.privacy_v6_evidence_sha256.as_str(),
        record.projection_checkpoint_identity_sha256.as_str(),
        record.projection_checkpoint_bundle_sha256.as_str(),
        record.source_user_physical_file_set_sha256.as_str(),
        record.source_privacy_physical_file_set_sha256.as_str(),
        record.source_user_logical_manifest_sha256.as_str(),
        record.source_user_business_manifest_sha256.as_str(),
        record.source_privacy_logical_manifest_sha256.as_str(),
        record.source_privacy_business_manifest_sha256.as_str(),
        record
            .target_user_pre_audit_logical_manifest_sha256
            .as_str(),
        record
            .target_user_pre_audit_business_manifest_sha256
            .as_str(),
        record
            .target_privacy_pre_audit_logical_manifest_sha256
            .as_str(),
        record
            .target_privacy_pre_audit_business_manifest_sha256
            .as_str(),
        record.user_audit_sha256.as_str(),
        record.privacy_lineage_sha256.as_str(),
        record.final_component_manifest_sha256.as_str(),
    ] {
        require_hash(hash)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031FinalComponentManifestProof {
    sha256: String,
    canonical_record: V031FinalComponentManifestRecordV1,
    user_logical_manifest_sha256: String,
    user_business_manifest_sha256: String,
    user_table_count: u64,
    user_total_rows: u64,
    privacy_logical_manifest_sha256: String,
    privacy_business_manifest_sha256: String,
    privacy_table_count: u64,
    privacy_total_rows: u64,
    vault_component_manifest_sha256: String,
    approved_workspace_bundle_sha256: String,
    work_products_bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct V031FinalComponentManifestRecordV1 {
    schema_version: String,
    migration_id: String,
    lineage_id: String,
    workspace_instance_id: String,
    slots: Vec<V031FinalComponentSlotRecordV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "slotName", content = "evidence", deny_unknown_fields)]
enum V031FinalComponentSlotRecordV1 {
    #[serde(rename = "user_database")]
    UserDatabase(V031UserDatabaseSlotRecordV1),
    #[serde(rename = "privacy_database")]
    PrivacyDatabase(V031PrivacyDatabaseSlotRecordV1),
    #[serde(rename = "vault")]
    Vault(V031VaultSlotRecordV1),
    #[serde(rename = "approved_workspace")]
    ApprovedWorkspace(V031ArchiveSlotRecordV1),
    #[serde(rename = "work_products")]
    WorkProducts(V031ArchiveSlotRecordV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031UserDatabaseSlotRecordV1 {
    schema_version: i64,
    schema_manifest_sha256: String,
    logical_manifest_sha256: String,
    business_manifest_sha256: String,
    business_primary_key_manifest_sha256: String,
    business_row_manifest_sha256: String,
    table_count: u64,
    total_rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031PrivacyDatabaseSlotRecordV1 {
    schema_version: i64,
    schema_object_count: u64,
    logical_manifest_sha256: String,
    business_manifest_sha256: String,
    business_primary_key_manifest_sha256: String,
    business_row_manifest_sha256: String,
    table_count: u64,
    total_rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031VaultSlotRecordV1 {
    workspace_instance_id: String,
    component_manifest_sha256: String,
    schema_sha256: String,
    database_sha256: String,
    layout_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031ArchiveSlotRecordV1 {
    workspace_instance_id: String,
    bundle_sha256: String,
    manifest_sha256: String,
    schema_sha256: String,
}

impl V031FinalComponentManifestProof {
    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn canonical_record(&self) -> &V031FinalComponentManifestRecordV1 {
        &self.canonical_record
    }

    pub(crate) fn workspace_instance_id(&self) -> &str {
        self.canonical_record.workspace_instance_id()
    }

    pub(crate) fn user_logical_manifest_sha256(&self) -> &str {
        &self.user_logical_manifest_sha256
    }

    #[cfg(test)]
    pub(crate) const fn user_table_count(&self) -> u64 {
        self.user_table_count
    }

    pub(crate) fn privacy_logical_manifest_sha256(&self) -> &str {
        &self.privacy_logical_manifest_sha256
    }

    pub(crate) fn privacy_business_manifest_sha256(&self) -> &str {
        &self.privacy_business_manifest_sha256
    }

    #[cfg(test)]
    pub(crate) const fn privacy_table_count(&self) -> u64 {
        self.privacy_table_count
    }

    pub(crate) fn approved_workspace_bundle_sha256(&self) -> &str {
        &self.approved_workspace_bundle_sha256
    }
}

impl V031FinalComponentManifestRecordV1 {
    pub(crate) fn canonical_sha256(&self) -> Result<String, V031UserUpgradeError> {
        validate_final_component_manifest_record(self)?;
        canonical_sha256(self)
    }

    pub(crate) fn lineage_id(&self) -> &str {
        &self.lineage_id
    }

    pub(crate) fn workspace_instance_id(&self) -> &str {
        &self.workspace_instance_id
    }

    pub(crate) fn database_manifest_counts(&self) -> Option<((u64, u64), (u64, u64))> {
        match self.slots.as_slice() {
            [V031FinalComponentSlotRecordV1::UserDatabase(user), V031FinalComponentSlotRecordV1::PrivacyDatabase(privacy), V031FinalComponentSlotRecordV1::Vault(_), V031FinalComponentSlotRecordV1::ApprovedWorkspace(_), V031FinalComponentSlotRecordV1::WorkProducts(_)] => {
                Some((
                    (user.table_count, user.total_rows),
                    (privacy.table_count, privacy.total_rows),
                ))
            }
            _ => None,
        }
    }
}

fn validate_final_component_manifest_record(
    record: &V031FinalComponentManifestRecordV1,
) -> Result<(), V031UserUpgradeError> {
    require_hash(&record.lineage_id)?;
    if record.schema_version != FINAL_COMPONENT_MANIFEST_SCHEMA
        || record.migration_id != V031_TO_V040_USER_MIGRATION_ID
        || record.workspace_instance_id.len() != 35
        || !record.workspace_instance_id.starts_with("ws_")
        || !record.workspace_instance_id[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || record.slots.len() != FINAL_COMPONENT_SLOT_COUNT as usize
    {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    let expected_names = FINAL_COMPONENT_SLOT_NAMES;
    for (slot, expected_name) in record.slots.iter().zip(expected_names) {
        let (name, hashes, valid_counts, workspace) = match slot {
            V031FinalComponentSlotRecordV1::UserDatabase(value) => (
                "user_database",
                vec![
                    value.schema_manifest_sha256.as_str(),
                    value.logical_manifest_sha256.as_str(),
                    value.business_manifest_sha256.as_str(),
                    value.business_primary_key_manifest_sha256.as_str(),
                    value.business_row_manifest_sha256.as_str(),
                ],
                value.schema_version == USER_SCHEMA_VERSION
                    && value.table_count == EXPECTED_TARGET_USER_TABLE_COUNT
                    && value.total_rows > 0,
                None,
            ),
            V031FinalComponentSlotRecordV1::PrivacyDatabase(value) => (
                "privacy_database",
                vec![
                    value.logical_manifest_sha256.as_str(),
                    value.business_manifest_sha256.as_str(),
                    value.business_primary_key_manifest_sha256.as_str(),
                    value.business_row_manifest_sha256.as_str(),
                ],
                value.schema_version == PRIVACY_STORE_SCHEMA_VERSION
                    && value.schema_object_count > 0
                    && value.table_count == PRIVACY_V6_APPLICATION_TABLES.len() as u64
                    && value.total_rows > 0,
                None,
            ),
            V031FinalComponentSlotRecordV1::Vault(value) => (
                "vault",
                vec![
                    value.component_manifest_sha256.as_str(),
                    value.schema_sha256.as_str(),
                    value.database_sha256.as_str(),
                    value.layout_sha256.as_str(),
                ],
                true,
                Some(value.workspace_instance_id.as_str()),
            ),
            V031FinalComponentSlotRecordV1::ApprovedWorkspace(value) => (
                "approved_workspace",
                vec![
                    value.bundle_sha256.as_str(),
                    value.manifest_sha256.as_str(),
                    value.schema_sha256.as_str(),
                ],
                true,
                Some(value.workspace_instance_id.as_str()),
            ),
            V031FinalComponentSlotRecordV1::WorkProducts(value) => (
                "work_products",
                vec![
                    value.bundle_sha256.as_str(),
                    value.manifest_sha256.as_str(),
                    value.schema_sha256.as_str(),
                ],
                true,
                Some(value.workspace_instance_id.as_str()),
            ),
        };
        if name != expected_name
            || !valid_counts
            || workspace.is_some_and(|value| value != record.workspace_instance_id)
            || hashes.into_iter().any(|hash| require_hash(hash).is_err())
        {
            return Err(V031UserUpgradeError::FinalComponents);
        }
    }
    Ok(())
}

fn final_component_manifest_from_record(
    record: &V031FinalComponentManifestRecordV1,
) -> Result<V031FinalComponentManifestProof, V031UserUpgradeError> {
    let sha256 = record.canonical_sha256()?;
    let [V031FinalComponentSlotRecordV1::UserDatabase(user), V031FinalComponentSlotRecordV1::PrivacyDatabase(privacy), V031FinalComponentSlotRecordV1::Vault(vault), V031FinalComponentSlotRecordV1::ApprovedWorkspace(approved), V031FinalComponentSlotRecordV1::WorkProducts(work_products)] =
        record.slots.as_slice()
    else {
        return Err(V031UserUpgradeError::FinalComponents);
    };
    Ok(V031FinalComponentManifestProof {
        sha256,
        canonical_record: record.clone(),
        user_logical_manifest_sha256: user.logical_manifest_sha256.clone(),
        user_business_manifest_sha256: user.business_manifest_sha256.clone(),
        user_table_count: user.table_count,
        user_total_rows: user.total_rows,
        privacy_logical_manifest_sha256: privacy.logical_manifest_sha256.clone(),
        privacy_business_manifest_sha256: privacy.business_manifest_sha256.clone(),
        privacy_table_count: privacy.table_count,
        privacy_total_rows: privacy.total_rows,
        vault_component_manifest_sha256: vault.component_manifest_sha256.clone(),
        approved_workspace_bundle_sha256: approved.bundle_sha256.clone(),
        work_products_bundle_sha256: work_products.bundle_sha256.clone(),
    })
}

#[derive(Clone)]
struct LedgerPrerequisites<'a> {
    rollback: &'a OriginalRollbackVerifiedGate,
    previous_receipt_sha256: &'a str,
}

struct LedgerResult {
    user: V031UserUpgradeResult,
    privacy_pre_audit: PrivacyV6ManifestProof,
    privacy_post_audit: PrivacyV6ManifestProof,
    lineage: ApplicationUpgradeLineageRecord,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
}

struct HistoricalLedgerResult {
    target_user_pre_audit_logical_manifest_sha256: String,
    target_user_pre_audit_business_manifest_sha256: String,
    target_privacy_pre_audit_logical_manifest_sha256: String,
    target_privacy_pre_audit_business_manifest_sha256: String,
    created_at_unix: i64,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerFailurePoint {
    BeforeUserTransaction,
    AfterUserTransactionCommit,
    BeforePrivacyLineageAppend,
    AfterPrivacyLineageAppend,
}

#[derive(Debug)]
struct FinalNonDatabaseComponents {
    workspace_instance_id: String,
    vault_component_manifest_sha256: String,
    vault_schema_sha256: String,
    vault_database_sha256: String,
    vault_layout_sha256: String,
    approved_workspace_bundle_sha256: String,
    approved_workspace_manifest_sha256: String,
    approved_workspace_schema_sha256: String,
    work_products_bundle_sha256: String,
    work_products_manifest_sha256: String,
    work_products_schema_sha256: String,
}

struct ReceiptEightNamespaceState {
    final_receipt_sha256: Option<String>,
    next_incoming_ordinal: Option<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FinalFiveComponentManifestV1<'a> {
    schema_version: &'static str,
    migration_id: &'static str,
    lineage_id: &'a str,
    workspace_instance_id: &'a str,
    slots: Vec<FinalComponentSlotV1<'a>>,
}

#[derive(Serialize)]
#[serde(tag = "slotName", content = "evidence")]
enum FinalComponentSlotV1<'a> {
    #[serde(rename = "user_database")]
    UserDatabase(UserDatabaseSlotV1<'a>),
    #[serde(rename = "privacy_database")]
    PrivacyDatabase(PrivacyDatabaseSlotV1<'a>),
    #[serde(rename = "vault")]
    Vault(VaultSlotV1<'a>),
    #[serde(rename = "approved_workspace")]
    ApprovedWorkspace(ArchiveSlotV1<'a>),
    #[serde(rename = "work_products")]
    WorkProducts(ArchiveSlotV1<'a>),
}

impl FinalComponentSlotV1<'_> {
    const fn name(&self) -> &'static str {
        match self {
            Self::UserDatabase(_) => "user_database",
            Self::PrivacyDatabase(_) => "privacy_database",
            Self::Vault(_) => "vault",
            Self::ApprovedWorkspace(_) => "approved_workspace",
            Self::WorkProducts(_) => "work_products",
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserDatabaseSlotV1<'a> {
    schema_version: i64,
    schema_manifest_sha256: &'a str,
    logical_manifest_sha256: &'a str,
    business_manifest_sha256: &'a str,
    business_primary_key_manifest_sha256: &'a str,
    business_row_manifest_sha256: &'a str,
    table_count: u64,
    total_rows: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyDatabaseSlotV1<'a> {
    schema_version: i64,
    schema_object_count: u64,
    logical_manifest_sha256: &'a str,
    business_manifest_sha256: &'a str,
    business_primary_key_manifest_sha256: &'a str,
    business_row_manifest_sha256: &'a str,
    table_count: u64,
    total_rows: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultSlotV1<'a> {
    workspace_instance_id: &'a str,
    component_manifest_sha256: &'a str,
    schema_sha256: &'a str,
    database_sha256: &'a str,
    layout_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ArchiveSlotV1<'a> {
    workspace_instance_id: &'a str,
    bundle_sha256: &'a str,
    manifest_sha256: &'a str,
    schema_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UserAuditCanonicalV1<'a> {
    audit_id: &'a str,
    origin: &'a str,
    operation: &'a str,
    project_id: Option<&'a str>,
    request_hash: &'a str,
    idempotency_key_hash: Option<&'a str>,
    status: &'a str,
    details_json: &'a str,
    created_at: &'a str,
    finished_at: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyLineageCanonicalV1<'a> {
    lineage_id: &'a str,
    migration_id: &'a str,
    source_profile_proof_sha256: &'a str,
    source_user_logical_manifest_sha256: &'a str,
    source_privacy_logical_manifest_sha256: &'a str,
    original_rollback_identity_sha256: &'a str,
    target_user_pre_audit_logical_manifest_sha256: &'a str,
    target_user_pre_audit_business_manifest_sha256: &'a str,
    target_privacy_pre_audit_logical_manifest_sha256: &'a str,
    target_privacy_pre_audit_business_manifest_sha256: &'a str,
    previous_receipt_sha256: &'a str,
    result_code: &'a str,
    created_at_unix: i64,
}

/// Proves the committed-user/no-receipt restart state without calling a Gate-7
/// loader whose normal path requires an active physical v10 source. The
/// original V2 loader still requires receipt 7, all three exact-final
/// checkpoints, current Privacy 6, and a canonical current user database before
/// returning the semantic v10 proof used here.
pub(crate) fn load_v031_committed_user_v11_resume_proof_read_only(
    app_local_data_dir: &Path,
    lineage_id: &str,
) -> Result<V031CommittedUserV11ResumeProof, V031UserUpgradeError> {
    validate_app_root(app_local_data_dir)?;
    require_hash(lineage_id)?;
    let rollback = load_original_migration_backup_gate(app_local_data_dir, lineage_id)
        .map_err(|_| V031UserUpgradeError::Predecessor)?;
    if rollback.lineage_id() != lineage_id {
        return Err(V031UserUpgradeError::Predecessor);
    }
    let context = rollback.receipt_context();
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let inventory = load_authenticated_v031_lineage(app_local_data_dir, lineage_id, &bridge)
        .map_err(|_| V031UserUpgradeError::ReceiptPrefix)?;
    if inventory.final_receipts.len() < 8 || inventory.final_receipts.len() > 10 {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    let receipt_seven = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::PrivacyV6Verified.ordinal(),
        ))
        .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
    if receipt_seven.ordinal != V031UpgradeReceiptStage::PrivacyV6Verified.ordinal()
        || receipt_seven.stage != V031UpgradeReceiptStage::PrivacyV6Verified.as_str()
        || receipt_seven.metadata.evidence_schema_version
            != V031UpgradeReceiptStage::PrivacyV6Verified.evidence_schema_version()
        || receipt_seven.metadata.lineage_id != lineage_id
        || receipt_seven.metadata.envelope_binding_id != context.envelope_binding_id
        || receipt_seven.metadata.source_profile_proof_sha256 != context.source_profile_proof_sha256
    {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    require_hash(&receipt_seven.protected_file_sha256)?;
    require_hash(&receipt_seven.metadata.evidence_sha256)?;
    let final_count = inventory.final_receipts.len();
    if let Some(incoming) = inventory.next_incoming_receipt.as_ref() {
        let expected_stage = V031UpgradeReceiptStage::from_ordinal(
            u8::try_from(final_count).map_err(|_| V031UserUpgradeError::ReceiptPrefix)?,
        )
        .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
        let expected_previous = inventory
            .final_receipts
            .last()
            .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
        if incoming.ordinal != expected_stage.ordinal()
            || incoming.stage != expected_stage.as_str()
            || incoming.metadata.previous_receipt_sha256.as_deref()
                != Some(expected_previous.protected_file_sha256.as_str())
        {
            return Err(V031UserUpgradeError::ReceiptPrefix);
        }
    } else if final_count == 10 {
        // A completed ordinal-9 chain has no next stage.
    }
    if final_count == 10 && inventory.next_incoming_receipt.is_some() {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }

    let user_path = database::user_database_path(app_local_data_dir);
    let privacy_path = app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE);
    let user = database::open_user_database_read_only(&user_path)
        .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    if exact_user_schema_version(&user)? != USER_SCHEMA_VERSION {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    let privacy = open_existing_privacy_database(&privacy_path, false)?;
    let installed_lineage = load_application_upgrade_lineage(&privacy, lineage_id)
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    validate_committed_resume_lineage_presence(
        final_count,
        inventory
            .next_incoming_receipt
            .as_ref()
            .map(|receipt| receipt.ordinal),
        installed_lineage.is_some(),
    )?;
    let privacy_pre_audit = if installed_lineage.is_some() {
        compute_privacy_v6_pre_audit_manifests_read_only(&privacy, lineage_id)
    } else {
        compute_privacy_v6_manifests_read_only(&privacy)
    }
    .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    validate_target_privacy_manifest(&privacy_pre_audit)?;
    let prerequisites = LedgerPrerequisites {
        rollback: &rollback,
        previous_receipt_sha256: &receipt_seven.protected_file_sha256,
    };
    let audit_evidence = build_user_audit_evidence(&prerequisites, &privacy_pre_audit)?;
    let user_result = verify_exact_v031_user_v11_upgrade_audit(
        &user,
        rollback.original_user_source_proof(),
        &audit_evidence,
    )
    .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    validate_user_pre_audit_manifest(&user_result.target_pre_audit_manifest)?;
    let audit_created_at_unix = canonical_audit_timestamp_unix(&user, &user_result.audit)?;
    let expected_lineage = build_privacy_lineage_record(
        &prerequisites,
        &privacy_pre_audit,
        &user_result,
        audit_created_at_unix,
    );
    let privacy_lineage_sha256 = match installed_lineage {
        Some(installed) if installed == expected_lineage => {
            Some(canonical_privacy_lineage_sha256(&installed)?)
        }
        Some(_) => return Err(V031UserUpgradeError::LedgerConflict),
        None => None,
    };
    let user_audit_sha256 = canonical_user_audit_sha256(&user_result.audit)?;
    drop(privacy);
    drop(user);

    Ok(V031CommittedUserV11ResumeProof {
        rollback_gate: rollback,
        receipt_context: context,
        privacy_v6_receipt_sha256: receipt_seven.protected_file_sha256.clone(),
        privacy_v6_evidence_sha256: receipt_seven.metadata.evidence_sha256.clone(),
        target_user_pre_audit: user_result.target_pre_audit_manifest,
        target_privacy_pre_audit_logical_manifest_sha256: privacy_pre_audit.logical_manifest.sha256,
        target_privacy_pre_audit_business_manifest_sha256: privacy_pre_audit
            .business_manifest
            .sha256,
        target_privacy_pre_audit_table_count: u64::try_from(
            privacy_pre_audit.logical_manifest.tables.len(),
        )
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?,
        target_privacy_pre_audit_total_rows: privacy_pre_audit.logical_manifest.total_row_count,
        audit_created_at_unix,
        user_audit_sha256,
        privacy_lineage_sha256,
    })
}

/// Completes or resumes Step 7 and commits ordinal 8. The supplied predecessor
/// is never trusted as an in-process capability: it is verified and rebuilt
/// from authenticated disk state both before the database writer and after the
/// two database ledgers have committed.
pub(crate) fn ensure_v031_user_v11_verified(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    lineage_id: &str,
) -> Result<V031UserV11VerifiedGate, V031UserUpgradeError> {
    let _operation = V031_USER_UPGRADE_OPERATION
        .lock()
        .map_err(|_| V031UserUpgradeError::InvalidInput)?;
    ensure_v031_user_v11_verified_inner(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        lineage_id,
        None,
    )
}

/// Runs the same Step-7 coordinator as production and interrupts one real
/// cross-database durable boundary. This wrapper owns the operation mutex and
/// calls the common inner directly; it must never call the public wrapper while
/// the lock is held.
#[cfg(test)]
fn ensure_v031_user_v11_verified_with_failure_for_test(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    lineage_id: &str,
    failure_point: LedgerFailurePoint,
) -> Result<V031UserV11VerifiedGate, V031UserUpgradeError> {
    let _operation = V031_USER_UPGRADE_OPERATION
        .lock()
        .map_err(|_| V031UserUpgradeError::InvalidInput)?;
    ensure_v031_user_v11_verified_inner(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        lineage_id,
        Some(failure_point),
    )
}

fn ensure_v031_user_v11_verified_inner(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    lineage_id: &str,
    failure_point: Option<LedgerFailurePoint>,
) -> Result<V031UserV11VerifiedGate, V031UserUpgradeError> {
    validate_app_root(app_local_data_dir)?;

    let predecessor = reload_exact_privacy_v6_predecessor(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        lineage_id,
    )?;
    let receipt_state = validate_receipt_eight_namespace(
        app_local_data_dir,
        predecessor.receipt_context(),
        predecessor.privacy_v6_receipt_sha256(),
        None,
        None,
    )?;

    let user_database_path = database::user_database_path(app_local_data_dir);
    let (active_user, ()) =
        with_validated_user_database_migration_source_read_only(&user_database_path, |_| ())
            .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    if active_user.schema == ValidatedUserSourceSchema::V031V10
        && (receipt_state.final_receipt_sha256.is_some()
            || receipt_state.next_incoming_ordinal.is_some())
    {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    let privacy_database_path = app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE);
    let mut user = open_existing_user_database(&user_database_path)
        .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    let privacy = open_existing_privacy_database(&privacy_database_path, true)?;
    let prerequisites = LedgerPrerequisites {
        rollback: predecessor.rollback_gate(),
        previous_receipt_sha256: predecessor.privacy_v6_receipt_sha256(),
    };
    let ledgers =
        ensure_user_and_privacy_ledgers(&mut user, &privacy, &prerequisites, failure_point)?;
    drop(privacy);
    drop(user);

    let post_ledger_predecessor = reload_exact_privacy_v6_predecessor(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        lineage_id,
    )?;
    if post_ledger_predecessor != predecessor {
        return Err(V031UserUpgradeError::Predecessor);
    }

    let (post_user, ()) =
        with_validated_user_database_migration_source_read_only(&user_database_path, |_| ())
            .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    if post_user.schema != ValidatedUserSourceSchema::CurrentV11 {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    let privacy = open_existing_privacy_database(&privacy_database_path, false)?;
    let post_privacy = compute_privacy_v6_manifests_read_only(&privacy)
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    drop(privacy);
    if !same_privacy_manifest(&post_privacy, &ledgers.privacy_post_audit) {
        return Err(V031UserUpgradeError::SourceDrift);
    }

    let final_non_database = capture_final_non_database_components(
        app_local_data_dir,
        approved_workspace,
        predecessor.target_gate().workspace_instance_id().as_str(),
    )?;
    let final_component_manifest = build_final_component_manifest(
        predecessor.receipt_context().lineage_id.as_str(),
        &post_user,
        &post_privacy,
        &final_non_database,
    )?;
    let evidence_record =
        user_v11_evidence_record(&predecessor, &ledgers, &final_component_manifest)?;
    let evidence_sha256 = evidence_record.canonical_sha256()?;
    let counts = user_v11_counts(&post_user, &post_privacy)?;

    let verify_live_state = || {
        verify_receipt_eight_live_state(
            app_local_data_dir,
            privacy_manager,
            approved_workspace,
            &predecessor,
            &ledgers,
            &final_component_manifest,
            &evidence_sha256,
            &counts,
        )
        .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
    };
    let persisted = persist_v031_receipt(
        app_local_data_dir,
        predecessor.receipt_context(),
        V031UpgradeReceiptStage::UserV11Verified,
        &evidence_sha256,
        &counts,
        verify_live_state,
    )
    .map_err(|_| V031UserUpgradeError::Receipt)?;

    verify_receipt_eight_live_state(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        &predecessor,
        &ledgers,
        &final_component_manifest,
        &evidence_sha256,
        &counts,
    )?;
    committed_gate(
        &predecessor,
        persisted.receipt.protected_file_sha256,
        evidence_sha256,
        evidence_record,
        final_component_manifest,
        ledgers.user_audit_sha256,
        ledgers.privacy_lineage_sha256,
    )
}

/// Reconstructs the ordinal-8 capability without invoking a database writer,
/// target initializer, Credential mutation, or receipt installer.
pub(crate) fn load_v031_user_v11_verified_gate_read_only(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    lineage_id: &str,
) -> Result<V031UserV11VerifiedGate, V031UserUpgradeError> {
    let _operation = V031_USER_UPGRADE_OPERATION
        .lock()
        .map_err(|_| V031UserUpgradeError::InvalidInput)?;
    validate_app_root(app_local_data_dir)?;
    let predecessor = reload_exact_privacy_v6_predecessor(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        lineage_id,
    )?;
    let user_database_path = database::user_database_path(app_local_data_dir);
    let privacy_database_path = app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE);
    let user = database::open_user_database_read_only(&user_database_path)
        .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    let privacy = open_existing_privacy_database(&privacy_database_path, false)?;
    let prerequisites = LedgerPrerequisites {
        rollback: predecessor.rollback_gate(),
        previous_receipt_sha256: predecessor.privacy_v6_receipt_sha256(),
    };
    let ledgers = verify_user_and_privacy_ledgers(&user, &privacy, &prerequisites)?;
    drop(privacy);
    drop(user);

    let (post_user, ()) =
        with_validated_user_database_migration_source_read_only(&user_database_path, |_| ())
            .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    if post_user.schema != ValidatedUserSourceSchema::CurrentV11 {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    let privacy = open_existing_privacy_database(&privacy_database_path, false)?;
    let post_privacy = compute_privacy_v6_manifests_read_only(&privacy)
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    drop(privacy);
    if !same_privacy_manifest(&post_privacy, &ledgers.privacy_post_audit) {
        return Err(V031UserUpgradeError::SourceDrift);
    }
    let final_non_database = capture_final_non_database_components(
        app_local_data_dir,
        approved_workspace,
        predecessor.target_gate().workspace_instance_id().as_str(),
    )?;
    let final_component_manifest = build_final_component_manifest(
        predecessor.receipt_context().lineage_id.as_str(),
        &post_user,
        &post_privacy,
        &final_non_database,
    )?;
    let evidence_record =
        user_v11_evidence_record(&predecessor, &ledgers, &final_component_manifest)?;
    let evidence_sha256 = evidence_record.canonical_sha256()?;
    let counts = user_v11_counts(&post_user, &post_privacy)?;
    let receipt = validate_receipt_eight_namespace(
        app_local_data_dir,
        predecessor.receipt_context(),
        predecessor.privacy_v6_receipt_sha256(),
        Some(&evidence_sha256),
        Some(&counts),
    )?
    .final_receipt_sha256
    .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
    committed_gate(
        &predecessor,
        receipt,
        evidence_sha256,
        evidence_record,
        final_component_manifest,
        ledgers.user_audit_sha256,
        ledgers.privacy_lineage_sha256,
    )
}

/// Reconstructs the historical receipt-8 authorization from the authenticated
/// Step-8 sidecar without comparing today's business manifests to the frozen
/// pre-maintenance manifest. All immutable receipt, V2, V3 checkpoint, user
/// audit, and Privacy-lineage anchors are nevertheless reloaded from disk.
pub(crate) fn load_v031_historical_receipt_eight_verified_gate_read_only(
    app_local_data_dir: &Path,
    predecessor: &AuthenticatedV031Step8PredecessorEvidence,
) -> Result<V031HistoricalReceipt8VerifiedGate, V031UserUpgradeError> {
    let sidecar = V031HistoricalReceipt8SidecarView {
        receipt_context: predecessor.receipt_context(),
        receipt_seven_sha256: predecessor.receipt_seven_sha256(),
        receipt_eight_sha256: predecessor.receipt_eight_sha256(),
        receipt_eight_evidence_schema_version: predecessor.receipt_eight_evidence_schema_version(),
        receipt_eight_evidence_sha256: predecessor.receipt_eight_evidence_sha256(),
        receipt_eight_counts: predecessor.receipt_eight_counts(),
        predecessor_manifest_sha256: predecessor.predecessor_manifest_sha256(),
        predecessor_manifest: predecessor.predecessor_manifest(),
        receipt_eight_evidence: predecessor.receipt_eight_evidence(),
    };
    load_v031_historical_receipt_eight_from_authenticated_sidecar_read_only(
        app_local_data_dir,
        &sidecar,
        predecessor.checkpoint_files(),
    )
}

fn load_v031_historical_receipt_eight_from_authenticated_sidecar_read_only(
    app_local_data_dir: &Path,
    sidecar: &V031HistoricalReceipt8SidecarView<'_>,
    expected_checkpoint_files: &[V031HistoricalCheckpointFileRecordV1],
) -> Result<V031HistoricalReceipt8VerifiedGate, V031UserUpgradeError> {
    let _operation = V031_USER_UPGRADE_OPERATION
        .lock()
        .map_err(|_| V031UserUpgradeError::InvalidInput)?;
    validate_app_root(app_local_data_dir)?;
    let checkpoint_files = verify_v031_historical_checkpoint_files_read_only(
        app_local_data_dir,
        &sidecar.receipt_context.lineage_id,
        expected_checkpoint_files,
        sidecar.receipt_eight_evidence,
    )?;
    for hash in [
        sidecar.receipt_seven_sha256,
        sidecar.receipt_eight_sha256,
        sidecar.receipt_eight_evidence_sha256,
        sidecar.predecessor_manifest_sha256,
    ] {
        require_hash(hash)?;
    }
    if sidecar.receipt_eight_evidence_schema_version
        != V031UpgradeReceiptStage::UserV11Verified.evidence_schema_version()
    {
        return Err(V031UserUpgradeError::EvidenceEncoding);
    }

    let rollback = load_original_migration_backup_gate(
        app_local_data_dir,
        &sidecar.receipt_context.lineage_id,
    )
    .map_err(|_| V031UserUpgradeError::Predecessor)?;
    if rollback.receipt_context() != *sidecar.receipt_context {
        return Err(V031UserUpgradeError::Predecessor);
    }
    validate_historical_receipt_eight_from_sidecar(
        app_local_data_dir,
        sidecar,
        rollback,
        &checkpoint_files,
    )
}

fn validate_historical_receipt_eight_from_sidecar(
    app_local_data_dir: &Path,
    sidecar: &V031HistoricalReceipt8SidecarView<'_>,
    rollback: OriginalRollbackVerifiedGate,
    checkpoint_files: &V031HistoricalCheckpointFilesVerifiedGate,
) -> Result<V031HistoricalReceipt8VerifiedGate, V031UserUpgradeError> {
    if checkpoint_files.lineage_id != sidecar.receipt_context.lineage_id
        || checkpoint_files.projection_identity_sha256
            != sidecar
                .receipt_eight_evidence
                .projection_checkpoint_identity_sha256()
        || checkpoint_files.projection_bundle_sha256
            != sidecar
                .receipt_eight_evidence
                .projection_checkpoint_bundle_sha256()
    {
        return Err(V031UserUpgradeError::Predecessor);
    }
    let bridge = PrivacyReceiptAuthenticationBridge::new(sidecar.receipt_context.clone());
    let inventory = load_authenticated_v031_lineage(
        app_local_data_dir,
        &sidecar.receipt_context.lineage_id,
        &bridge,
    )
    .map_err(|_| V031UserUpgradeError::ReceiptPrefix)?;
    if !(9..=10).contains(&inventory.final_receipts.len()) {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    let receipt_seven = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::PrivacyV6Verified.ordinal(),
        ))
        .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
    let receipt_eight = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::UserV11Verified.ordinal(),
        ))
        .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
    if receipt_seven.ordinal != V031UpgradeReceiptStage::PrivacyV6Verified.ordinal()
        || receipt_seven.stage != V031UpgradeReceiptStage::PrivacyV6Verified.as_str()
        || receipt_seven.protected_file_sha256 != sidecar.receipt_seven_sha256
        || receipt_eight.ordinal != V031UpgradeReceiptStage::UserV11Verified.ordinal()
        || receipt_eight.stage != V031UpgradeReceiptStage::UserV11Verified.as_str()
        || receipt_eight.protected_file_sha256 != sidecar.receipt_eight_sha256
        || receipt_eight.metadata.evidence_schema_version
            != sidecar.receipt_eight_evidence_schema_version
        || receipt_eight.metadata.evidence_sha256 != sidecar.receipt_eight_evidence_sha256
        || receipt_eight.metadata.counts != *sidecar.receipt_eight_counts
    {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }

    let historical_manifest = final_component_manifest_from_record(sidecar.predecessor_manifest)?;
    if historical_manifest.sha256() != sidecar.predecessor_manifest_sha256 {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    let evidence_sha256 = verify_v031_user_v11_receipt_evidence_record_anchors(
        sidecar.receipt_eight_evidence,
        &rollback,
        sidecar.receipt_context,
        sidecar.receipt_seven_sha256,
        &receipt_seven.metadata.evidence_sha256,
        &checkpoint_files.projection_identity_sha256,
        &checkpoint_files.projection_bundle_sha256,
        historical_manifest.sha256(),
    )?;
    if evidence_sha256 != sidecar.receipt_eight_evidence_sha256 {
        return Err(V031UserUpgradeError::SourceDrift);
    }

    let ledgers = load_v031_historical_user_and_privacy_ledgers_read_only(
        app_local_data_dir,
        &rollback,
        sidecar.receipt_seven_sha256,
        sidecar.receipt_eight_evidence.user_audit_sha256(),
        sidecar.receipt_eight_evidence.privacy_lineage_sha256(),
    )?;
    let evidence = sidecar.receipt_eight_evidence;
    if evidence.target_user_pre_audit_logical_manifest_sha256
        != ledgers.target_user_pre_audit_logical_manifest_sha256
        || evidence.target_user_pre_audit_business_manifest_sha256
            != ledgers.target_user_pre_audit_business_manifest_sha256
        || evidence.target_privacy_pre_audit_logical_manifest_sha256
            != ledgers.target_privacy_pre_audit_logical_manifest_sha256
        || evidence.target_privacy_pre_audit_business_manifest_sha256
            != ledgers.target_privacy_pre_audit_business_manifest_sha256
        || evidence.ledger_created_at_unix != ledgers.created_at_unix
        || evidence.user_audit_sha256 != ledgers.user_audit_sha256
        || evidence.privacy_lineage_sha256 != ledgers.privacy_lineage_sha256
    {
        return Err(V031UserUpgradeError::LedgerConflict);
    }

    let counts = user_v11_counts_from_historical_manifest(&historical_manifest)?;
    if receipt_count_wire_map(&counts)? != *sidecar.receipt_eight_counts {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    let receipt_state = validate_receipt_eight_namespace(
        app_local_data_dir,
        sidecar.receipt_context,
        sidecar.receipt_seven_sha256,
        Some(&evidence_sha256),
        Some(&counts),
    )?;
    if receipt_state.final_receipt_sha256.as_deref() != Some(sidecar.receipt_eight_sha256) {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }

    Ok(V031HistoricalReceipt8VerifiedGate {
        original_rollback_gate: rollback,
        receipt_context: sidecar.receipt_context.clone(),
        privacy_v6_receipt_sha256: sidecar.receipt_seven_sha256.to_owned(),
        user_v11_receipt_sha256: sidecar.receipt_eight_sha256.to_owned(),
        evidence_sha256,
        evidence_record: sidecar.receipt_eight_evidence.clone(),
        final_component_manifest: historical_manifest,
        user_audit_sha256: ledgers.user_audit_sha256,
        privacy_lineage_sha256: ledgers.privacy_lineage_sha256,
    })
}

fn reload_exact_privacy_v6_predecessor(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    lineage_id: &str,
) -> Result<V031PrivacyV6VerifiedGate, V031UserUpgradeError> {
    require_hash(lineage_id)?;
    let user_path = database::user_database_path(app_local_data_dir);
    let (active_user, ()) =
        with_validated_user_database_migration_source_read_only(&user_path, |_| ())
            .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    match active_user.schema {
        ValidatedUserSourceSchema::V031V10 => {
            let rollback = load_original_migration_backup_gate(app_local_data_dir, lineage_id)
                .map_err(|_| V031UserUpgradeError::Predecessor)?;
            let target = load_v031_historical_target_components_from_checkpoint_read_only(
                app_local_data_dir,
                &rollback,
                approved_workspace,
            )
            .map_err(|_| V031UserUpgradeError::Predecessor)?;
            let projection = load_v031_projection_backup_verified_gate_read_only(
                app_local_data_dir,
                privacy_manager,
                approved_workspace,
                &target,
            )
            .map_err(|_| V031UserUpgradeError::Predecessor)?;
            let observed = load_v031_privacy_v6_verified_gate_read_only(
                app_local_data_dir,
                privacy_manager,
                approved_workspace,
                &projection,
            )
            .map_err(|_| V031UserUpgradeError::Predecessor)?;
            verify_v031_privacy_v6_verified_gate_read_only(
                app_local_data_dir,
                privacy_manager,
                approved_workspace,
                &observed,
            )
            .map_err(|_| V031UserUpgradeError::Predecessor)?;
            Ok(observed)
        }
        ValidatedUserSourceSchema::CurrentV11 => {
            let resume = load_v031_committed_user_v11_resume_proof_read_only(
                app_local_data_dir,
                lineage_id,
            )?;
            let target = load_v031_historical_target_components_from_checkpoint_read_only(
                app_local_data_dir,
                resume.rollback_gate(),
                approved_workspace,
            )
            .map_err(|_| V031UserUpgradeError::Predecessor)?;
            let projection = load_v031_projection_backup_verified_gate_read_only(
                app_local_data_dir,
                privacy_manager,
                approved_workspace,
                &target,
            )
            .map_err(|_| V031UserUpgradeError::Predecessor)?;
            let observed =
                load_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
                    app_local_data_dir,
                    privacy_manager,
                    approved_workspace,
                    &projection,
                    &resume,
                )
                .map_err(|_| V031UserUpgradeError::Predecessor)?;
            verify_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
                app_local_data_dir,
                privacy_manager,
                approved_workspace,
                &observed,
                &resume,
            )
            .map_err(|_| V031UserUpgradeError::Predecessor)?;
            Ok(observed)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_receipt_eight_live_state(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected_predecessor: &V031PrivacyV6VerifiedGate,
    expected_ledgers: &LedgerResult,
    expected_final_manifest: &V031FinalComponentManifestProof,
    expected_evidence_sha256: &str,
    expected_counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
) -> Result<(), V031UserUpgradeError> {
    let predecessor = reload_exact_privacy_v6_predecessor(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        &expected_predecessor.receipt_context().lineage_id,
    )?;
    if &predecessor != expected_predecessor {
        return Err(V031UserUpgradeError::Predecessor);
    }

    let user_path = database::user_database_path(app_local_data_dir);
    let privacy_path = app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE);
    let user = database::open_user_database_read_only(&user_path)
        .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    let privacy = open_existing_privacy_database(&privacy_path, false)?;
    let prerequisites = LedgerPrerequisites {
        rollback: predecessor.rollback_gate(),
        previous_receipt_sha256: predecessor.privacy_v6_receipt_sha256(),
    };
    let observed_ledgers = verify_user_and_privacy_ledgers(&user, &privacy, &prerequisites)?;
    drop(privacy);
    drop(user);
    if !same_ledger_result(&observed_ledgers, expected_ledgers) {
        return Err(V031UserUpgradeError::SourceDrift);
    }

    let (post_user, ()) =
        with_validated_user_database_migration_source_read_only(&user_path, |_| ())
            .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    if post_user.schema != ValidatedUserSourceSchema::CurrentV11 {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    let privacy = open_existing_privacy_database(&privacy_path, false)?;
    let post_privacy = compute_privacy_v6_manifests_read_only(&privacy)
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    drop(privacy);
    if !same_privacy_manifest(&post_privacy, &expected_ledgers.privacy_post_audit) {
        return Err(V031UserUpgradeError::SourceDrift);
    }
    let non_database = capture_final_non_database_components(
        app_local_data_dir,
        approved_workspace,
        predecessor.target_gate().workspace_instance_id().as_str(),
    )?;
    let final_manifest = build_final_component_manifest(
        predecessor.receipt_context().lineage_id.as_str(),
        &post_user,
        &post_privacy,
        &non_database,
    )?;
    if &final_manifest != expected_final_manifest {
        return Err(V031UserUpgradeError::SourceDrift);
    }
    let evidence_sha256 =
        user_v11_evidence_record(&predecessor, &observed_ledgers, &final_manifest)?
            .canonical_sha256()?;
    let counts = user_v11_counts(&post_user, &post_privacy)?;
    if evidence_sha256 != expected_evidence_sha256 || &counts != expected_counts {
        return Err(V031UserUpgradeError::SourceDrift);
    }
    validate_receipt_eight_namespace(
        app_local_data_dir,
        predecessor.receipt_context(),
        predecessor.privacy_v6_receipt_sha256(),
        Some(expected_evidence_sha256),
        Some(expected_counts),
    )?;
    Ok(())
}

fn same_ledger_result(left: &LedgerResult, right: &LedgerResult) -> bool {
    left.user == right.user
        && same_privacy_manifest(&left.privacy_pre_audit, &right.privacy_pre_audit)
        && same_privacy_manifest(&left.privacy_post_audit, &right.privacy_post_audit)
        && left.lineage == right.lineage
        && left.user_audit_sha256 == right.user_audit_sha256
        && left.privacy_lineage_sha256 == right.privacy_lineage_sha256
}

fn committed_gate(
    predecessor: &V031PrivacyV6VerifiedGate,
    user_v11_receipt_sha256: String,
    evidence_sha256: String,
    evidence_record: V031UserV11ReceiptEvidenceRecordV1,
    final_component_manifest: V031FinalComponentManifestProof,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
) -> Result<V031UserV11VerifiedGate, V031UserUpgradeError> {
    for hash in [
        predecessor.privacy_v6_receipt_sha256(),
        user_v11_receipt_sha256.as_str(),
        evidence_sha256.as_str(),
        final_component_manifest.sha256(),
        user_audit_sha256.as_str(),
        privacy_lineage_sha256.as_str(),
    ] {
        require_hash(hash)?;
    }
    if evidence_record.canonical_sha256()? != evidence_sha256
        || evidence_record.previous_receipt_sha256() != predecessor.privacy_v6_receipt_sha256()
        || evidence_record.privacy_v6_evidence_sha256() != predecessor.privacy_v6_evidence_sha256()
        || evidence_record.final_component_manifest_sha256() != final_component_manifest.sha256()
        || evidence_record.user_audit_sha256() != user_audit_sha256
        || evidence_record.privacy_lineage_sha256() != privacy_lineage_sha256
    {
        return Err(V031UserUpgradeError::SourceDrift);
    }
    Ok(V031UserV11VerifiedGate {
        original_rollback_gate: predecessor.rollback_gate().clone(),
        receipt_context: predecessor.receipt_context().clone(),
        privacy_v6_receipt_sha256: predecessor.privacy_v6_receipt_sha256().to_owned(),
        user_v11_receipt_sha256,
        evidence_sha256,
        evidence_record,
        final_component_manifest,
        user_audit_sha256,
        privacy_lineage_sha256,
    })
}

pub(crate) fn capture_v031_fresh_final_component_manifest_with_rollback_read_only(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
    rollback_gate: &OriginalRollbackVerifiedGate,
    lineage_id: &str,
    expected_workspace_instance_id: &str,
) -> Result<V031FinalComponentManifestProof, V031UserUpgradeError> {
    validate_app_root(app_local_data_dir)?;
    if rollback_gate.lineage_id() != lineage_id {
        return Err(V031UserUpgradeError::Predecessor);
    }
    let user_path = database::user_database_path(app_local_data_dir);
    let (user, ()) = with_validated_user_database_migration_source_read_only(&user_path, |_| ())
        .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    if user.schema != ValidatedUserSourceSchema::CurrentV11 {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    let privacy_path = app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE);
    let privacy = open_existing_privacy_database(&privacy_path, false)?;
    let privacy_manifest = compute_privacy_v6_manifests_read_only(&privacy)
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    drop(privacy);
    let non_database = capture_final_non_database_components(
        app_local_data_dir,
        approved_workspace,
        expected_workspace_instance_id,
    )?;
    build_final_component_manifest(lineage_id, &user, &privacy_manifest, &non_database)
}

/// Verifies the immutable Step-7 audit anchors after later ordinary business
/// rows or Step-8 recovery have changed the live component manifests.  This
/// deliberately does not recompute the historical pre-maintenance manifest;
/// that value is authenticated by the append-only Step-8 DPAPI sidecar.
pub(crate) fn verify_v031_historical_user_and_privacy_ledgers_read_only(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    receipt_seven_sha256: &str,
    expected_user_audit_sha256: &str,
    expected_privacy_lineage_sha256: &str,
) -> Result<(), V031UserUpgradeError> {
    load_v031_historical_user_and_privacy_ledgers_read_only(
        app_local_data_dir,
        rollback_gate,
        receipt_seven_sha256,
        expected_user_audit_sha256,
        expected_privacy_lineage_sha256,
    )
    .map(|_| ())
}

fn load_v031_historical_user_and_privacy_ledgers_read_only(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    receipt_seven_sha256: &str,
    expected_user_audit_sha256: &str,
    expected_privacy_lineage_sha256: &str,
) -> Result<HistoricalLedgerResult, V031UserUpgradeError> {
    validate_app_root(app_local_data_dir)?;
    for hash in [
        receipt_seven_sha256,
        expected_user_audit_sha256,
        expected_privacy_lineage_sha256,
    ] {
        require_hash(hash)?;
    }
    let user_path = database::user_database_path(app_local_data_dir);
    let user = database::open_user_database_read_only(&user_path)
        .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    database::validate_open_user_database(&user).map_err(|_| V031UserUpgradeError::UserDatabase)?;
    let audit = database::get_operation_audit_by_idempotency_key_hash(
        &user,
        "desktop",
        database::V031_TO_V040_USER_AUDIT_OPERATION,
        rollback_gate.lineage_id(),
    )
    .map_err(|_| V031UserUpgradeError::UserDatabase)?
    .ok_or(V031UserUpgradeError::LedgerConflict)?;
    let exact_audit_count: i64 = user
        .query_row(
            "SELECT COUNT(*) FROM operation_audit
             WHERE origin='desktop' AND operation=?1 AND idempotency_key_hash=?2",
            (
                database::V031_TO_V040_USER_AUDIT_OPERATION,
                rollback_gate.lineage_id(),
            ),
            |row| row.get(0),
        )
        .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    let audit_created_at_unix = canonical_audit_timestamp_unix(&user, &audit)?;
    let user_audit_sha256 = canonical_user_audit_sha256(&audit)?;
    if exact_audit_count != 1
        || audit.origin != "desktop"
        || audit.operation != database::V031_TO_V040_USER_AUDIT_OPERATION
        || audit.project_id.is_some()
        || audit.request_hash != rollback_gate.source_profile_proof_sha256()
        || audit.idempotency_key_hash.as_deref() != Some(rollback_gate.lineage_id())
        || audit.status != "succeeded"
        || audit.finished_at.as_deref() != Some(audit.created_at.as_str())
        || user_audit_sha256 != expected_user_audit_sha256
    {
        return Err(V031UserUpgradeError::LedgerConflict);
    }
    drop(user);

    let privacy_path = app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE);
    let privacy = open_existing_privacy_database(&privacy_path, false)?;
    let lineage = load_application_upgrade_lineage(&privacy, rollback_gate.lineage_id())
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?
        .ok_or(V031UserUpgradeError::LedgerConflict)?;
    let privacy_lineage_sha256 = canonical_privacy_lineage_sha256(&lineage)?;
    if lineage.lineage_id != rollback_gate.lineage_id()
        || lineage.migration_id != V031_TO_V040_USER_MIGRATION_ID
        || lineage.source_profile_proof_sha256 != rollback_gate.source_profile_proof_sha256()
        || lineage.source_user_logical_manifest_sha256
            != rollback_gate
                .original_user_source_proof()
                .logical_database_manifest_sha256
        || lineage.source_privacy_logical_manifest_sha256
            != rollback_gate.original_privacy_logical_manifest_sha256()
        || lineage.original_rollback_identity_sha256 != rollback_gate.original_identity_sha256()
        || lineage.previous_receipt_sha256 != receipt_seven_sha256
        || lineage.result_code != APPLICATION_UPGRADE_RESULT_OK
        || lineage.created_at_unix != audit_created_at_unix
        || privacy_lineage_sha256 != expected_privacy_lineage_sha256
    {
        return Err(V031UserUpgradeError::LedgerConflict);
    }
    for hash in [
        lineage
            .target_user_pre_audit_logical_manifest_sha256
            .as_str(),
        lineage
            .target_user_pre_audit_business_manifest_sha256
            .as_str(),
        lineage
            .target_privacy_pre_audit_logical_manifest_sha256
            .as_str(),
        lineage
            .target_privacy_pre_audit_business_manifest_sha256
            .as_str(),
    ] {
        require_hash(hash)?;
    }
    Ok(HistoricalLedgerResult {
        target_user_pre_audit_logical_manifest_sha256: lineage
            .target_user_pre_audit_logical_manifest_sha256,
        target_user_pre_audit_business_manifest_sha256: lineage
            .target_user_pre_audit_business_manifest_sha256,
        target_privacy_pre_audit_logical_manifest_sha256: lineage
            .target_privacy_pre_audit_logical_manifest_sha256,
        target_privacy_pre_audit_business_manifest_sha256: lineage
            .target_privacy_pre_audit_business_manifest_sha256,
        created_at_unix: lineage.created_at_unix,
        user_audit_sha256,
        privacy_lineage_sha256,
    })
}

fn ensure_user_and_privacy_ledgers(
    user: &mut Connection,
    privacy: &Connection,
    prerequisites: &LedgerPrerequisites<'_>,
    failure_point: Option<LedgerFailurePoint>,
) -> Result<LedgerResult, V031UserUpgradeError> {
    validate_ledger_prerequisites(prerequisites)?;
    let existing_lineage =
        load_application_upgrade_lineage(privacy, prerequisites.rollback.lineage_id())
            .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    let user_schema = exact_user_schema_version(user)?;
    if user_schema == V031_USER_SCHEMA_VERSION && existing_lineage.is_some() {
        return Err(V031UserUpgradeError::LedgerConflict);
    }
    if !matches!(user_schema, V031_USER_SCHEMA_VERSION | USER_SCHEMA_VERSION) {
        return Err(V031UserUpgradeError::UserDatabase);
    }

    let privacy_pre_audit = match existing_lineage.as_ref() {
        Some(_) => compute_privacy_v6_pre_audit_manifests_read_only(
            privacy,
            prerequisites.rollback.lineage_id(),
        ),
        None => compute_privacy_v6_manifests_read_only(privacy),
    }
    .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    validate_target_privacy_manifest(&privacy_pre_audit)?;
    let audit_evidence = build_user_audit_evidence(prerequisites, &privacy_pre_audit)?;

    if failure_point == Some(LedgerFailurePoint::BeforeUserTransaction) {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    let user_result = if user_schema == V031_USER_SCHEMA_VERSION {
        migrate_exact_v031_user_to_v11_with_upgrade_audit(
            user,
            prerequisites.rollback.original_user_source_proof(),
            &audit_evidence,
        )
        .map_err(|_| V031UserUpgradeError::UserDatabase)?
    } else {
        verify_exact_v031_user_v11_upgrade_audit(
            user,
            prerequisites.rollback.original_user_source_proof(),
            &audit_evidence,
        )
        .map_err(|_| V031UserUpgradeError::UserDatabase)?
    };
    validate_user_pre_audit_manifest(&user_result.target_pre_audit_manifest)?;
    if failure_point == Some(LedgerFailurePoint::AfterUserTransactionCommit) {
        return Err(V031UserUpgradeError::UserDatabase);
    }

    let created_at_unix = canonical_audit_timestamp_unix(user, &user_result.audit)?;
    let expected_lineage = build_privacy_lineage_record(
        prerequisites,
        &privacy_pre_audit,
        &user_result,
        created_at_unix,
    );
    if let Some(existing) = existing_lineage {
        if existing != expected_lineage {
            return Err(V031UserUpgradeError::LedgerConflict);
        }
    } else {
        if failure_point == Some(LedgerFailurePoint::BeforePrivacyLineageAppend) {
            return Err(V031UserUpgradeError::PrivacyDatabase);
        }
        match append_application_upgrade_lineage(privacy, &expected_lineage)
            .map_err(|_| V031UserUpgradeError::LedgerConflict)?
        {
            ApplicationUpgradeLineageAppendOutcome::Inserted
            | ApplicationUpgradeLineageAppendOutcome::AlreadyPresent => {}
        }
        if failure_point == Some(LedgerFailurePoint::AfterPrivacyLineageAppend) {
            return Err(V031UserUpgradeError::PrivacyDatabase);
        }
    }

    verify_user_and_privacy_ledgers(user, privacy, prerequisites)
}

fn verify_user_and_privacy_ledgers(
    user: &Connection,
    privacy: &Connection,
    prerequisites: &LedgerPrerequisites<'_>,
) -> Result<LedgerResult, V031UserUpgradeError> {
    validate_ledger_prerequisites(prerequisites)?;
    if exact_user_schema_version(user)? != USER_SCHEMA_VERSION {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    let installed_lineage =
        load_application_upgrade_lineage(privacy, prerequisites.rollback.lineage_id())
            .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?
            .ok_or(V031UserUpgradeError::LedgerConflict)?;
    let privacy_pre_audit = compute_privacy_v6_pre_audit_manifests_read_only(
        privacy,
        prerequisites.rollback.lineage_id(),
    )
    .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    validate_target_privacy_manifest(&privacy_pre_audit)?;
    let audit_evidence = build_user_audit_evidence(prerequisites, &privacy_pre_audit)?;
    let user_result = verify_exact_v031_user_v11_upgrade_audit(
        user,
        prerequisites.rollback.original_user_source_proof(),
        &audit_evidence,
    )
    .map_err(|_| V031UserUpgradeError::UserDatabase)?;
    validate_user_pre_audit_manifest(&user_result.target_pre_audit_manifest)?;
    let created_at_unix = canonical_audit_timestamp_unix(user, &user_result.audit)?;
    let expected_lineage = build_privacy_lineage_record(
        prerequisites,
        &privacy_pre_audit,
        &user_result,
        created_at_unix,
    );
    if installed_lineage != expected_lineage {
        return Err(V031UserUpgradeError::LedgerConflict);
    }
    let privacy_post_audit = compute_privacy_v6_manifests_read_only(privacy)
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    validate_target_privacy_manifest(&privacy_post_audit)?;
    if privacy_post_audit.logical_manifest.total_row_count
        != privacy_pre_audit
            .logical_manifest
            .total_row_count
            .checked_add(1)
            .ok_or(V031UserUpgradeError::PrivacyDatabase)?
        || privacy_post_audit.business_manifest != privacy_pre_audit.business_manifest
    {
        return Err(V031UserUpgradeError::LedgerConflict);
    }

    let user_audit_sha256 = canonical_user_audit_sha256(&user_result.audit)?;
    let privacy_lineage_sha256 = canonical_privacy_lineage_sha256(&installed_lineage)?;
    Ok(LedgerResult {
        user: user_result,
        privacy_pre_audit,
        privacy_post_audit,
        lineage: installed_lineage,
        user_audit_sha256,
        privacy_lineage_sha256,
    })
}

fn validate_ledger_prerequisites(
    prerequisites: &LedgerPrerequisites<'_>,
) -> Result<(), V031UserUpgradeError> {
    if prerequisites.rollback.original_user_source_proof().schema
        != ValidatedUserSourceSchema::V031V10
        || prerequisites
            .rollback
            .original_user_source_proof()
            .tables
            .len()
            != EXPECTED_SOURCE_USER_TABLE_COUNT as usize
        || prerequisites.rollback.original_privacy_table_count()
            != EXPECTED_SOURCE_PRIVACY_TABLE_COUNT
    {
        return Err(V031UserUpgradeError::InvalidInput);
    }
    for hash in [
        prerequisites.rollback.lineage_id(),
        prerequisites.rollback.source_profile_proof_sha256(),
        prerequisites.rollback.original_identity_sha256(),
        prerequisites
            .rollback
            .original_user_source_proof()
            .logical_database_manifest_sha256
            .as_str(),
        prerequisites
            .rollback
            .original_user_source_proof()
            .business_manifest_sha256
            .as_str(),
        prerequisites
            .rollback
            .original_privacy_logical_manifest_sha256(),
        prerequisites
            .rollback
            .original_privacy_business_manifest_sha256(),
        prerequisites.previous_receipt_sha256,
    ] {
        require_hash(hash)?;
    }
    Ok(())
}

fn build_user_audit_evidence(
    prerequisites: &LedgerPrerequisites<'_>,
    privacy_pre_audit: &PrivacyV6ManifestProof,
) -> Result<V031UserUpgradeAuditEvidence, V031UserUpgradeError> {
    validate_target_privacy_manifest(privacy_pre_audit)?;
    Ok(V031UserUpgradeAuditEvidence {
        lineage_id: prerequisites.rollback.lineage_id().to_owned(),
        source_profile_proof_sha256: prerequisites
            .rollback
            .source_profile_proof_sha256()
            .to_owned(),
        source_privacy_logical_manifest_sha256: prerequisites
            .rollback
            .original_privacy_logical_manifest_sha256()
            .to_owned(),
        source_privacy_business_manifest_sha256: prerequisites
            .rollback
            .original_privacy_business_manifest_sha256()
            .to_owned(),
        original_rollback_identity_sha256: prerequisites
            .rollback
            .original_identity_sha256()
            .to_owned(),
        target_privacy_pre_audit_logical_manifest_sha256: privacy_pre_audit
            .logical_manifest
            .sha256
            .clone(),
        target_privacy_pre_audit_business_manifest_sha256: privacy_pre_audit
            .business_manifest
            .sha256
            .clone(),
        previous_receipt_sha256: prerequisites.previous_receipt_sha256.to_owned(),
        source_privacy_table_count: prerequisites.rollback.original_privacy_table_count(),
        source_privacy_total_rows: prerequisites.rollback.original_privacy_total_rows(),
        target_privacy_table_count: u64::try_from(privacy_pre_audit.logical_manifest.tables.len())
            .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?,
        target_privacy_total_rows: privacy_pre_audit.logical_manifest.total_row_count,
        original_rollback_slot_count: FINAL_COMPONENT_SLOT_COUNT,
    })
}

fn build_privacy_lineage_record(
    prerequisites: &LedgerPrerequisites<'_>,
    privacy_pre_audit: &PrivacyV6ManifestProof,
    user_result: &V031UserUpgradeResult,
    created_at_unix: i64,
) -> ApplicationUpgradeLineageRecord {
    ApplicationUpgradeLineageRecord {
        lineage_id: prerequisites.rollback.lineage_id().to_owned(),
        migration_id: V031_TO_V040_USER_MIGRATION_ID.to_owned(),
        source_profile_proof_sha256: prerequisites
            .rollback
            .source_profile_proof_sha256()
            .to_owned(),
        source_user_logical_manifest_sha256: prerequisites
            .rollback
            .original_user_source_proof()
            .logical_database_manifest_sha256
            .clone(),
        source_privacy_logical_manifest_sha256: prerequisites
            .rollback
            .original_privacy_logical_manifest_sha256()
            .to_owned(),
        original_rollback_identity_sha256: prerequisites
            .rollback
            .original_identity_sha256()
            .to_owned(),
        target_user_pre_audit_logical_manifest_sha256: user_result
            .target_pre_audit_manifest
            .logical_manifest_sha256
            .clone(),
        target_user_pre_audit_business_manifest_sha256: user_result
            .target_pre_audit_manifest
            .business_manifest_sha256
            .clone(),
        target_privacy_pre_audit_logical_manifest_sha256: privacy_pre_audit
            .logical_manifest
            .sha256
            .clone(),
        target_privacy_pre_audit_business_manifest_sha256: privacy_pre_audit
            .business_manifest
            .sha256
            .clone(),
        previous_receipt_sha256: prerequisites.previous_receipt_sha256.to_owned(),
        result_code: APPLICATION_UPGRADE_RESULT_OK.to_owned(),
        created_at_unix,
    }
}

fn exact_user_schema_version(connection: &Connection) -> Result<i64, V031UserUpgradeError> {
    let version = connection
        .query_row(
            "SELECT value FROM user_database_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| V031UserUpgradeError::UserDatabase)?
        .ok_or(V031UserUpgradeError::UserDatabase)?;
    match version.as_str() {
        "10" => Ok(V031_USER_SCHEMA_VERSION),
        "11" => Ok(USER_SCHEMA_VERSION),
        _ => Err(V031UserUpgradeError::UserDatabase),
    }
}

fn canonical_audit_timestamp_unix(
    connection: &Connection,
    audit: &OperationAuditRow,
) -> Result<i64, V031UserUpgradeError> {
    let finished_at = audit
        .finished_at
        .as_deref()
        .ok_or(V031UserUpgradeError::AuditTimestamp)?;
    if audit.created_at != finished_at || !is_canonical_sqlite_utc(&audit.created_at) {
        return Err(V031UserUpgradeError::AuditTimestamp);
    }
    let (unix, round_trip): (Option<i64>, Option<String>) = connection
        .query_row(
            "SELECT unixepoch(?1),
                    strftime('%Y-%m-%d %H:%M:%S', unixepoch(?1), 'unixepoch')",
            [audit.created_at.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| V031UserUpgradeError::AuditTimestamp)?;
    let unix = unix
        .filter(|value| *value > 0 && *value <= privacy::MAX_APPLICATION_UPGRADE_CREATED_AT_UNIX)
        .ok_or(V031UserUpgradeError::AuditTimestamp)?;
    if round_trip.as_deref() != Some(audit.created_at.as_str()) {
        return Err(V031UserUpgradeError::AuditTimestamp);
    }
    Ok(unix)
}

fn is_canonical_sqlite_utc(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 19
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b' ',
            13 | 16 => *byte == b':',
            _ => byte.is_ascii_digit(),
        })
}

fn validate_user_pre_audit_manifest(
    manifest: &V031UserPreAuditManifest,
) -> Result<(), V031UserUpgradeError> {
    if manifest.table_count != EXPECTED_TARGET_USER_TABLE_COUNT {
        return Err(V031UserUpgradeError::UserDatabase);
    }
    for hash in [
        manifest.schema_manifest_sha256.as_str(),
        manifest.logical_manifest_sha256.as_str(),
        manifest.business_manifest_sha256.as_str(),
        manifest.business_primary_key_manifest_sha256.as_str(),
        manifest.business_row_manifest_sha256.as_str(),
    ] {
        require_hash(hash)?;
    }
    Ok(())
}

fn validate_target_privacy_manifest(
    manifest: &PrivacyV6ManifestProof,
) -> Result<(), V031UserUpgradeError> {
    if manifest.schema_version != PRIVACY_STORE_SCHEMA_VERSION
        || manifest.logical_manifest.tables.len() != EXPECTED_PRIVACY_TABLE_COUNT as usize
        || manifest.business_manifest.tables.len() != EXPECTED_PRIVACY_TABLE_COUNT as usize - 2
        || manifest.logical_manifest.total_row_count == 0
    {
        return Err(V031UserUpgradeError::PrivacyDatabase);
    }
    for hash in [
        manifest.logical_manifest.sha256.as_str(),
        manifest.business_manifest.sha256.as_str(),
        manifest.business_manifest.primary_key_sha256.as_str(),
        manifest.business_manifest.row_sha256.as_str(),
    ] {
        require_hash(hash)?;
    }
    Ok(())
}

fn same_privacy_manifest(left: &PrivacyV6ManifestProof, right: &PrivacyV6ManifestProof) -> bool {
    left.schema_version == right.schema_version
        && left.schema_object_count == right.schema_object_count
        && left.logical_manifest == right.logical_manifest
        && left.business_manifest == right.business_manifest
}

fn capture_final_non_database_components(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
    expected_workspace_instance_id: &str,
) -> Result<FinalNonDatabaseComponents, V031UserUpgradeError> {
    let current_approved = match approved_workspace
        .observe_current_components_read_only()
        .map_err(|_| V031UserUpgradeError::FinalComponents)?
    {
        CurrentApprovedComponentsObservation::Exact(proof) => proof,
        CurrentApprovedComponentsObservation::Absent => {
            return Err(V031UserUpgradeError::FinalComponents)
        }
    };
    if current_approved.lifecycle() != CurrentApprovedComponentsLifecycle::ApprovedAndWorkProducts
        || current_approved.workspace_instance_id().as_str() != expected_workspace_instance_id
        || current_approved.approved_archive_sha256().is_none()
        || current_approved.approved_manifest_sha256().is_none()
        || current_approved.work_products_archive_sha256().is_none()
        || current_approved.work_products_manifest_sha256().is_none()
    {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    let current_vault = match observe_current_vault_read_only(
        app_local_data_dir,
        current_approved.workspace_instance_id(),
    )
    .map_err(|_| V031UserUpgradeError::FinalComponents)?
    {
        CurrentVaultObservation::Exact(proof) => proof,
        CurrentVaultObservation::Absent => return Err(V031UserUpgradeError::FinalComponents),
    };
    let current_approved_after = approved_workspace
        .observe_current_components_read_only()
        .map_err(|_| V031UserUpgradeError::FinalComponents)?;
    let current_vault_after = match observe_current_vault_read_only(
        app_local_data_dir,
        current_approved.workspace_instance_id(),
    )
    .map_err(|_| V031UserUpgradeError::FinalComponents)?
    {
        CurrentVaultObservation::Exact(proof) => proof,
        CurrentVaultObservation::Absent => return Err(V031UserUpgradeError::FinalComponents),
    };
    if current_approved_after
        != CurrentApprovedComponentsObservation::Exact(current_approved.clone())
        || current_vault_after != current_vault
    {
        return Err(V031UserUpgradeError::SourceDrift);
    }

    let approved_workspace_bundle_sha256 = current_approved
        .approved_archive_sha256()
        .ok_or(V031UserUpgradeError::FinalComponents)?
        .to_owned();
    let approved_workspace_manifest_sha256 = current_approved
        .approved_manifest_sha256()
        .ok_or(V031UserUpgradeError::FinalComponents)?
        .to_owned();
    let work_products_bundle_sha256 = current_approved
        .work_products_archive_sha256()
        .ok_or(V031UserUpgradeError::FinalComponents)?
        .to_owned();
    let work_products_manifest_sha256 = current_approved
        .work_products_manifest_sha256()
        .ok_or(V031UserUpgradeError::FinalComponents)?
        .to_owned();
    let result = FinalNonDatabaseComponents {
        workspace_instance_id: expected_workspace_instance_id.to_owned(),
        vault_component_manifest_sha256: current_vault.component_manifest_sha256().to_owned(),
        vault_schema_sha256: current_vault.schema_sha256().to_owned(),
        vault_database_sha256: current_vault.database_sha256().to_owned(),
        vault_layout_sha256: current_vault.layout_sha256().to_owned(),
        approved_workspace_bundle_sha256,
        approved_workspace_manifest_sha256,
        approved_workspace_schema_sha256: V031_APPROVED_WORKSPACE_SCHEMA_SHA256.to_owned(),
        work_products_bundle_sha256,
        work_products_manifest_sha256,
        work_products_schema_sha256: V031_WORK_PRODUCTS_SCHEMA_SHA256.to_owned(),
    };
    validate_final_non_database_components(&result)?;
    Ok(result)
}

fn validate_final_non_database_components(
    components: &FinalNonDatabaseComponents,
) -> Result<(), V031UserUpgradeError> {
    if components.workspace_instance_id.len() != 35
        || !components.workspace_instance_id.starts_with("ws_")
        || !components.workspace_instance_id[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    for hash in [
        components.vault_component_manifest_sha256.as_str(),
        components.vault_schema_sha256.as_str(),
        components.vault_database_sha256.as_str(),
        components.vault_layout_sha256.as_str(),
        components.approved_workspace_bundle_sha256.as_str(),
        components.approved_workspace_manifest_sha256.as_str(),
        components.approved_workspace_schema_sha256.as_str(),
        components.work_products_bundle_sha256.as_str(),
        components.work_products_manifest_sha256.as_str(),
        components.work_products_schema_sha256.as_str(),
    ] {
        require_hash(hash)?;
    }
    Ok(())
}

fn build_final_component_manifest(
    lineage_id: &str,
    user: &UserMigrationSourceProof,
    privacy: &PrivacyV6ManifestProof,
    non_database: &FinalNonDatabaseComponents,
) -> Result<V031FinalComponentManifestProof, V031UserUpgradeError> {
    require_hash(lineage_id)?;
    if user.schema != ValidatedUserSourceSchema::CurrentV11
        || user.tables.len() != EXPECTED_TARGET_USER_TABLE_COUNT as usize
        || user.total_rows == 0
    {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    validate_target_privacy_manifest(privacy)?;
    validate_final_non_database_components(non_database)?;
    for hash in [
        user.schema_manifest_sha256.as_str(),
        user.logical_database_manifest_sha256.as_str(),
        user.business_manifest_sha256.as_str(),
        user.business_primary_key_manifest_sha256.as_str(),
        user.business_row_manifest_sha256.as_str(),
    ] {
        require_hash(hash)?;
    }
    let user_table_count =
        u64::try_from(user.tables.len()).map_err(|_| V031UserUpgradeError::FinalComponents)?;
    let privacy_table_count = u64::try_from(privacy.logical_manifest.tables.len())
        .map_err(|_| V031UserUpgradeError::FinalComponents)?;
    let slots = vec![
        FinalComponentSlotV1::UserDatabase(UserDatabaseSlotV1 {
            schema_version: USER_SCHEMA_VERSION,
            schema_manifest_sha256: &user.schema_manifest_sha256,
            logical_manifest_sha256: &user.logical_database_manifest_sha256,
            business_manifest_sha256: &user.business_manifest_sha256,
            business_primary_key_manifest_sha256: &user.business_primary_key_manifest_sha256,
            business_row_manifest_sha256: &user.business_row_manifest_sha256,
            table_count: user_table_count,
            total_rows: user.total_rows,
        }),
        FinalComponentSlotV1::PrivacyDatabase(PrivacyDatabaseSlotV1 {
            schema_version: privacy.schema_version,
            schema_object_count: u64::try_from(privacy.schema_object_count)
                .map_err(|_| V031UserUpgradeError::FinalComponents)?,
            logical_manifest_sha256: &privacy.logical_manifest.sha256,
            business_manifest_sha256: &privacy.business_manifest.sha256,
            business_primary_key_manifest_sha256: &privacy.business_manifest.primary_key_sha256,
            business_row_manifest_sha256: &privacy.business_manifest.row_sha256,
            table_count: privacy_table_count,
            total_rows: privacy.logical_manifest.total_row_count,
        }),
        FinalComponentSlotV1::Vault(VaultSlotV1 {
            workspace_instance_id: &non_database.workspace_instance_id,
            component_manifest_sha256: &non_database.vault_component_manifest_sha256,
            schema_sha256: &non_database.vault_schema_sha256,
            database_sha256: &non_database.vault_database_sha256,
            layout_sha256: &non_database.vault_layout_sha256,
        }),
        FinalComponentSlotV1::ApprovedWorkspace(ArchiveSlotV1 {
            workspace_instance_id: &non_database.workspace_instance_id,
            bundle_sha256: &non_database.approved_workspace_bundle_sha256,
            manifest_sha256: &non_database.approved_workspace_manifest_sha256,
            schema_sha256: &non_database.approved_workspace_schema_sha256,
        }),
        FinalComponentSlotV1::WorkProducts(ArchiveSlotV1 {
            workspace_instance_id: &non_database.workspace_instance_id,
            bundle_sha256: &non_database.work_products_bundle_sha256,
            manifest_sha256: &non_database.work_products_manifest_sha256,
            schema_sha256: &non_database.work_products_schema_sha256,
        }),
    ];
    if slots.len() != FINAL_COMPONENT_SLOT_COUNT as usize
        || slots
            .iter()
            .zip(FINAL_COMPONENT_SLOT_NAMES)
            .any(|(slot, expected)| slot.name() != expected)
    {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    let canonical_record = V031FinalComponentManifestRecordV1 {
        schema_version: FINAL_COMPONENT_MANIFEST_SCHEMA.to_owned(),
        migration_id: V031_TO_V040_USER_MIGRATION_ID.to_owned(),
        lineage_id: lineage_id.to_owned(),
        workspace_instance_id: non_database.workspace_instance_id.clone(),
        slots: vec![
            V031FinalComponentSlotRecordV1::UserDatabase(V031UserDatabaseSlotRecordV1 {
                schema_version: USER_SCHEMA_VERSION,
                schema_manifest_sha256: user.schema_manifest_sha256.clone(),
                logical_manifest_sha256: user.logical_database_manifest_sha256.clone(),
                business_manifest_sha256: user.business_manifest_sha256.clone(),
                business_primary_key_manifest_sha256: user
                    .business_primary_key_manifest_sha256
                    .clone(),
                business_row_manifest_sha256: user.business_row_manifest_sha256.clone(),
                table_count: user_table_count,
                total_rows: user.total_rows,
            }),
            V031FinalComponentSlotRecordV1::PrivacyDatabase(V031PrivacyDatabaseSlotRecordV1 {
                schema_version: privacy.schema_version,
                schema_object_count: u64::try_from(privacy.schema_object_count)
                    .map_err(|_| V031UserUpgradeError::FinalComponents)?,
                logical_manifest_sha256: privacy.logical_manifest.sha256.clone(),
                business_manifest_sha256: privacy.business_manifest.sha256.clone(),
                business_primary_key_manifest_sha256: privacy
                    .business_manifest
                    .primary_key_sha256
                    .clone(),
                business_row_manifest_sha256: privacy.business_manifest.row_sha256.clone(),
                table_count: privacy_table_count,
                total_rows: privacy.logical_manifest.total_row_count,
            }),
            V031FinalComponentSlotRecordV1::Vault(V031VaultSlotRecordV1 {
                workspace_instance_id: non_database.workspace_instance_id.clone(),
                component_manifest_sha256: non_database.vault_component_manifest_sha256.clone(),
                schema_sha256: non_database.vault_schema_sha256.clone(),
                database_sha256: non_database.vault_database_sha256.clone(),
                layout_sha256: non_database.vault_layout_sha256.clone(),
            }),
            V031FinalComponentSlotRecordV1::ApprovedWorkspace(V031ArchiveSlotRecordV1 {
                workspace_instance_id: non_database.workspace_instance_id.clone(),
                bundle_sha256: non_database.approved_workspace_bundle_sha256.clone(),
                manifest_sha256: non_database.approved_workspace_manifest_sha256.clone(),
                schema_sha256: non_database.approved_workspace_schema_sha256.clone(),
            }),
            V031FinalComponentSlotRecordV1::WorkProducts(V031ArchiveSlotRecordV1 {
                workspace_instance_id: non_database.workspace_instance_id.clone(),
                bundle_sha256: non_database.work_products_bundle_sha256.clone(),
                manifest_sha256: non_database.work_products_manifest_sha256.clone(),
                schema_sha256: non_database.work_products_schema_sha256.clone(),
            }),
        ],
    };
    let record_sha256 = canonical_record.canonical_sha256()?;
    let manifest = FinalFiveComponentManifestV1 {
        schema_version: FINAL_COMPONENT_MANIFEST_SCHEMA,
        migration_id: V031_TO_V040_USER_MIGRATION_ID,
        lineage_id,
        workspace_instance_id: &non_database.workspace_instance_id,
        slots,
    };
    let sha256 = canonical_sha256(&manifest)?;
    if sha256 != record_sha256 {
        return Err(V031UserUpgradeError::EvidenceEncoding);
    }
    Ok(V031FinalComponentManifestProof {
        sha256,
        canonical_record,
        user_logical_manifest_sha256: user.logical_database_manifest_sha256.clone(),
        user_business_manifest_sha256: user.business_manifest_sha256.clone(),
        user_table_count,
        user_total_rows: user.total_rows,
        privacy_logical_manifest_sha256: privacy.logical_manifest.sha256.clone(),
        privacy_business_manifest_sha256: privacy.business_manifest.sha256.clone(),
        privacy_table_count,
        privacy_total_rows: privacy.logical_manifest.total_row_count,
        vault_component_manifest_sha256: non_database.vault_component_manifest_sha256.clone(),
        approved_workspace_bundle_sha256: non_database.approved_workspace_bundle_sha256.clone(),
        work_products_bundle_sha256: non_database.work_products_bundle_sha256.clone(),
    })
}

fn user_v11_evidence_record(
    predecessor: &V031PrivacyV6VerifiedGate,
    ledgers: &LedgerResult,
    final_component_manifest: &V031FinalComponentManifestProof,
) -> Result<V031UserV11ReceiptEvidenceRecordV1, V031UserUpgradeError> {
    let rollback = predecessor.rollback_gate();
    let projection = predecessor.projection_checkpoint();
    for hash in [
        predecessor.privacy_v6_evidence_sha256(),
        projection.identity_protected_sha256(),
        projection.bundle_sha256(),
        ledgers.user_audit_sha256.as_str(),
        ledgers.privacy_lineage_sha256.as_str(),
        final_component_manifest.sha256(),
    ] {
        require_hash(hash)?;
    }
    let record = V031UserV11ReceiptEvidenceRecordV1 {
        schema_version: V031UpgradeReceiptStage::UserV11Verified
            .evidence_schema_version()
            .to_owned(),
        migration_id: V031_TO_V040_USER_MIGRATION_ID.to_owned(),
        lineage_id: rollback.lineage_id().to_owned(),
        source_profile_proof_sha256: rollback.source_profile_proof_sha256().to_owned(),
        original_rollback_identity_sha256: rollback.original_identity_sha256().to_owned(),
        previous_receipt_sha256: predecessor.privacy_v6_receipt_sha256().to_owned(),
        privacy_v6_evidence_sha256: predecessor.privacy_v6_evidence_sha256().to_owned(),
        projection_checkpoint_identity_sha256: projection.identity_protected_sha256().to_owned(),
        projection_checkpoint_bundle_sha256: projection.bundle_sha256().to_owned(),
        source_user_physical_file_set_sha256: rollback
            .original_user_physical_file_set_sha256()
            .to_owned(),
        source_privacy_physical_file_set_sha256: rollback
            .original_privacy_physical_file_set_sha256()
            .to_owned(),
        source_user_logical_manifest_sha256: rollback
            .original_user_source_proof()
            .logical_database_manifest_sha256
            .clone(),
        source_user_business_manifest_sha256: rollback
            .original_user_source_proof()
            .business_manifest_sha256
            .clone(),
        source_privacy_logical_manifest_sha256: rollback
            .original_privacy_logical_manifest_sha256()
            .to_owned(),
        source_privacy_business_manifest_sha256: rollback
            .original_privacy_business_manifest_sha256()
            .to_owned(),
        target_user_pre_audit_logical_manifest_sha256: ledgers
            .user
            .target_pre_audit_manifest
            .logical_manifest_sha256
            .clone(),
        target_user_pre_audit_business_manifest_sha256: ledgers
            .user
            .target_pre_audit_manifest
            .business_manifest_sha256
            .clone(),
        target_privacy_pre_audit_logical_manifest_sha256: ledgers
            .privacy_pre_audit
            .logical_manifest
            .sha256
            .clone(),
        target_privacy_pre_audit_business_manifest_sha256: ledgers
            .privacy_pre_audit
            .business_manifest
            .sha256
            .clone(),
        user_audit_sha256: ledgers.user_audit_sha256.clone(),
        privacy_lineage_sha256: ledgers.privacy_lineage_sha256.clone(),
        ledger_created_at_unix: ledgers.lineage.created_at_unix,
        final_component_manifest_sha256: final_component_manifest.sha256().to_owned(),
    };
    validate_user_v11_receipt_evidence_record(&record)?;
    Ok(record)
}

fn user_v11_counts(
    user: &UserMigrationSourceProof,
    privacy: &PrivacyV6ManifestProof,
) -> Result<BTreeMap<V031UpgradeReceiptCountKey, u64>, V031UserUpgradeError> {
    let user_tables =
        u64::try_from(user.tables.len()).map_err(|_| V031UserUpgradeError::FinalComponents)?;
    let privacy_tables = u64::try_from(privacy.logical_manifest.tables.len())
        .map_err(|_| V031UserUpgradeError::FinalComponents)?;
    if user.schema != ValidatedUserSourceSchema::CurrentV11
        || user_tables != EXPECTED_TARGET_USER_TABLE_COUNT
        || user.total_rows == 0
        || privacy.schema_version != PRIVACY_STORE_SCHEMA_VERSION
        || privacy_tables != EXPECTED_PRIVACY_TABLE_COUNT
        || privacy.logical_manifest.total_row_count == 0
    {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    Ok(BTreeMap::from([
        (V031UpgradeReceiptCountKey::UserAuditRows, 1),
        (V031UpgradeReceiptCountKey::PrivacyLineageRows, 1),
        (V031UpgradeReceiptCountKey::UserManifestTables, user_tables),
        (
            V031UpgradeReceiptCountKey::UserManifestRows,
            user.total_rows,
        ),
        (
            V031UpgradeReceiptCountKey::PrivacyManifestTables,
            privacy_tables,
        ),
        (
            V031UpgradeReceiptCountKey::PrivacyManifestRows,
            privacy.logical_manifest.total_row_count,
        ),
        (
            V031UpgradeReceiptCountKey::FinalComponentSlots,
            FINAL_COMPONENT_SLOT_COUNT,
        ),
    ]))
}

fn user_v11_counts_from_historical_manifest(
    manifest: &V031FinalComponentManifestProof,
) -> Result<BTreeMap<V031UpgradeReceiptCountKey, u64>, V031UserUpgradeError> {
    if manifest.user_table_count != EXPECTED_TARGET_USER_TABLE_COUNT
        || manifest.user_total_rows == 0
        || manifest.privacy_table_count != EXPECTED_PRIVACY_TABLE_COUNT
        || manifest.privacy_total_rows == 0
    {
        return Err(V031UserUpgradeError::FinalComponents);
    }
    Ok(BTreeMap::from([
        (V031UpgradeReceiptCountKey::UserAuditRows, 1),
        (V031UpgradeReceiptCountKey::PrivacyLineageRows, 1),
        (
            V031UpgradeReceiptCountKey::UserManifestTables,
            manifest.user_table_count,
        ),
        (
            V031UpgradeReceiptCountKey::UserManifestRows,
            manifest.user_total_rows,
        ),
        (
            V031UpgradeReceiptCountKey::PrivacyManifestTables,
            manifest.privacy_table_count,
        ),
        (
            V031UpgradeReceiptCountKey::PrivacyManifestRows,
            manifest.privacy_total_rows,
        ),
        (
            V031UpgradeReceiptCountKey::FinalComponentSlots,
            FINAL_COMPONENT_SLOT_COUNT,
        ),
    ]))
}

fn validate_receipt_eight_namespace(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    previous_receipt_sha256: &str,
    expected_evidence_sha256: Option<&str>,
    expected_counts: Option<&BTreeMap<V031UpgradeReceiptCountKey, u64>>,
) -> Result<ReceiptEightNamespaceState, V031UserUpgradeError> {
    require_hash(previous_receipt_sha256)?;
    if expected_evidence_sha256.is_some() != expected_counts.is_some() {
        return Err(V031UserUpgradeError::InvalidInput);
    }
    if let Some(hash) = expected_evidence_sha256 {
        require_hash(hash)?;
    }
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, &context.lineage_id, &bridge)
            .map_err(|_| V031UserUpgradeError::ReceiptPrefix)?;
    if inventory.final_receipts.len() < 8 || inventory.final_receipts.len() > 10 {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }
    let receipt_seven = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::PrivacyV6Verified.ordinal(),
        ))
        .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
    if receipt_seven.protected_file_sha256 != previous_receipt_sha256
        || receipt_seven.ordinal != V031UpgradeReceiptStage::PrivacyV6Verified.ordinal()
        || receipt_seven.stage != V031UpgradeReceiptStage::PrivacyV6Verified.as_str()
        || receipt_seven.metadata.evidence_schema_version
            != V031UpgradeReceiptStage::PrivacyV6Verified.evidence_schema_version()
    {
        return Err(V031UserUpgradeError::ReceiptPrefix);
    }

    let expected_wire_counts = expected_counts.map(receipt_count_wire_map).transpose()?;
    let validate_eight = |receipt: &crate::v031_upgrade_r2::AuthenticatedReceiptFile| {
        if receipt.ordinal != V031UpgradeReceiptStage::UserV11Verified.ordinal()
            || receipt.stage != V031UpgradeReceiptStage::UserV11Verified.as_str()
            || receipt.metadata.lineage_id != context.lineage_id
            || receipt.metadata.envelope_binding_id != context.envelope_binding_id
            || receipt.metadata.source_profile_proof_sha256 != context.source_profile_proof_sha256
            || receipt.metadata.previous_receipt_sha256.as_deref() != Some(previous_receipt_sha256)
            || receipt.metadata.evidence_schema_version
                != V031UpgradeReceiptStage::UserV11Verified.evidence_schema_version()
            || expected_evidence_sha256
                .is_some_and(|expected| receipt.metadata.evidence_sha256 != expected)
            || expected_wire_counts
                .as_ref()
                .is_some_and(|expected| &receipt.metadata.counts != expected)
        {
            Err(V031UserUpgradeError::ReceiptPrefix)
        } else {
            Ok(())
        }
    };

    match inventory.final_receipts.len() {
        8 => {
            if let Some(incoming) = inventory.next_incoming_receipt.as_ref() {
                validate_eight(incoming)?;
            }
            Ok(ReceiptEightNamespaceState {
                final_receipt_sha256: None,
                next_incoming_ordinal: inventory
                    .next_incoming_receipt
                    .as_ref()
                    .map(|receipt| receipt.ordinal),
            })
        }
        9 => {
            let receipt = inventory
                .final_receipts
                .get(usize::from(
                    V031UpgradeReceiptStage::UserV11Verified.ordinal(),
                ))
                .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
            validate_eight(receipt)?;
            if let Some(incoming) = inventory.next_incoming_receipt.as_ref() {
                if incoming.ordinal != V031UpgradeReceiptStage::UpgradeComplete.ordinal()
                    || incoming.stage != V031UpgradeReceiptStage::UpgradeComplete.as_str()
                    || incoming.metadata.previous_receipt_sha256.as_deref()
                        != Some(receipt.protected_file_sha256.as_str())
                {
                    return Err(V031UserUpgradeError::ReceiptPrefix);
                }
            }
            Ok(ReceiptEightNamespaceState {
                final_receipt_sha256: Some(receipt.protected_file_sha256.clone()),
                next_incoming_ordinal: inventory
                    .next_incoming_receipt
                    .as_ref()
                    .map(|incoming| incoming.ordinal),
            })
        }
        10 => {
            if inventory.next_incoming_receipt.is_some() {
                return Err(V031UserUpgradeError::ReceiptPrefix);
            }
            let receipt = inventory
                .final_receipts
                .get(usize::from(
                    V031UpgradeReceiptStage::UserV11Verified.ordinal(),
                ))
                .ok_or(V031UserUpgradeError::ReceiptPrefix)?;
            validate_eight(receipt)?;
            Ok(ReceiptEightNamespaceState {
                final_receipt_sha256: Some(receipt.protected_file_sha256.clone()),
                next_incoming_ordinal: None,
            })
        }
        _ => Err(V031UserUpgradeError::ReceiptPrefix),
    }
}

fn validate_committed_resume_lineage_presence(
    final_receipt_count: usize,
    next_incoming_ordinal: Option<u8>,
    privacy_lineage_present: bool,
) -> Result<(), V031UserUpgradeError> {
    let receipt_eight_started = final_receipt_count
        > usize::from(V031UpgradeReceiptStage::UserV11Verified.ordinal())
        || next_incoming_ordinal
            .is_some_and(|ordinal| ordinal >= V031UpgradeReceiptStage::UserV11Verified.ordinal());
    if receipt_eight_started && !privacy_lineage_present {
        return Err(V031UserUpgradeError::LedgerConflict);
    }
    Ok(())
}

fn receipt_count_wire_map(
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
) -> Result<BTreeMap<String, u64>, V031UserUpgradeError> {
    if counts.len() != V031UpgradeReceiptStage::UserV11Verified.count_keys().len()
        || V031UpgradeReceiptStage::UserV11Verified
            .count_keys()
            .iter()
            .any(|key| !counts.contains_key(key))
    {
        return Err(V031UserUpgradeError::InvalidInput);
    }
    counts
        .iter()
        .map(|(key, value)| {
            let name = serde_json::to_value(key)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or(V031UserUpgradeError::EvidenceEncoding)?;
            Ok((name, *value))
        })
        .collect()
}

fn canonical_user_audit_sha256(audit: &OperationAuditRow) -> Result<String, V031UserUpgradeError> {
    canonical_sha256(&UserAuditCanonicalV1 {
        audit_id: &audit.audit_id,
        origin: &audit.origin,
        operation: &audit.operation,
        project_id: audit.project_id.as_deref(),
        request_hash: &audit.request_hash,
        idempotency_key_hash: audit.idempotency_key_hash.as_deref(),
        status: &audit.status,
        details_json: &audit.details_json,
        created_at: &audit.created_at,
        finished_at: audit.finished_at.as_deref(),
    })
}

fn canonical_privacy_lineage_sha256(
    lineage: &ApplicationUpgradeLineageRecord,
) -> Result<String, V031UserUpgradeError> {
    canonical_sha256(&PrivacyLineageCanonicalV1 {
        lineage_id: &lineage.lineage_id,
        migration_id: &lineage.migration_id,
        source_profile_proof_sha256: &lineage.source_profile_proof_sha256,
        source_user_logical_manifest_sha256: &lineage.source_user_logical_manifest_sha256,
        source_privacy_logical_manifest_sha256: &lineage.source_privacy_logical_manifest_sha256,
        original_rollback_identity_sha256: &lineage.original_rollback_identity_sha256,
        target_user_pre_audit_logical_manifest_sha256: &lineage
            .target_user_pre_audit_logical_manifest_sha256,
        target_user_pre_audit_business_manifest_sha256: &lineage
            .target_user_pre_audit_business_manifest_sha256,
        target_privacy_pre_audit_logical_manifest_sha256: &lineage
            .target_privacy_pre_audit_logical_manifest_sha256,
        target_privacy_pre_audit_business_manifest_sha256: &lineage
            .target_privacy_pre_audit_business_manifest_sha256,
        previous_receipt_sha256: &lineage.previous_receipt_sha256,
        result_code: &lineage.result_code,
        created_at_unix: lineage.created_at_unix,
    })
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, V031UserUpgradeError> {
    canonical_json_v1(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| V031UserUpgradeError::EvidenceEncoding)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let value = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing into a String cannot fail");
    }
    encoded
}

fn require_hash(value: &str) -> Result<(), V031UserUpgradeError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(V031UserUpgradeError::InvalidInput)
    }
}

fn validate_app_root(app_local_data_dir: &Path) -> Result<(), V031UserUpgradeError> {
    if !app_local_data_dir.is_absolute() {
        return Err(V031UserUpgradeError::InvalidInput);
    }
    let metadata = std::fs::symlink_metadata(app_local_data_dir)
        .map_err(|_| V031UserUpgradeError::InvalidInput)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(V031UserUpgradeError::InvalidInput);
    }
    Ok(())
}

fn open_existing_privacy_database(
    path: &Path,
    writable: bool,
) -> Result<Connection, V031UserUpgradeError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(V031UserUpgradeError::PrivacyDatabase);
    }
    let flags = if writable {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
    } | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let connection = Connection::open_with_flags(path, flags)
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    connection
        .pragma_update(None, "trusted_schema", "OFF")
        .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    if !writable {
        connection
            .pragma_update(None, "query_only", "ON")
            .map_err(|_| V031UserUpgradeError::PrivacyDatabase)?;
    }
    Ok(connection)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::commands::{
        v031_checkpoint_receipts::{
            load_v031_case_migration_backups_verified_gate_read_only,
            verify_v031_case_migration_backups_verified_gate_read_only,
            verify_v031_projection_backup_verified_gate_read_only,
            V031CaseMigrationBackupsVerifiedGate, V031ProjectionBackupVerifiedGate,
        },
        v031_migration_checkpoint::V031MigrationCheckpointProof,
        v031_privacy_migration::{
            load_v031_binding_materials_verified_gate_read_only,
            load_v031_privacy_v5_verified_gate_read_only,
            verify_v031_binding_materials_verified_gate_read_only,
            verify_v031_privacy_v5_verified_gate_read_only,
            verify_v031_privacy_v6_verified_gate_read_only, V031BindingMaterialsVerifiedGate,
            V031PrivacyV5VerifiedGate,
        },
        v031_target_components::{
            load_v031_target_components_prepared_gate_read_only,
            verify_v031_target_components_prepared_gate_read_only,
            V031TargetComponentsPreparedGate,
        },
    };
    use privacy::{
        upgrade_receipt_v1::{seal_v031_upgrade_receipt_v1, V031UpgradeReceiptCreateRequest},
        vnext::CaseId,
        PrivacyStore, ProjectPrivacyCaseBindingStore,
    };
    use serde::Deserialize;
    #[cfg(windows)]
    use std::process::Command;
    use std::{
        collections::BTreeMap,
        fs,
        path::PathBuf,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    #[cfg(windows)]
    use zeroize::Zeroize;

    #[cfg(windows)]
    const V031_RESTART_CHILD_MODE_ENV: &str = "LAWYER_ASSISTANCE_V031_RESTART_CHILD_MODE";
    #[cfg(windows)]
    const V031_RESTART_ROOT_ENV: &str = "LAWYER_ASSISTANCE_V031_RESTART_ROOT";
    #[cfg(windows)]
    const V031_RESTART_CREDENTIAL_PREFIX_ENV: &str =
        "LAWYER_ASSISTANCE_V031_RESTART_CREDENTIAL_PREFIX";
    #[cfg(windows)]
    const V031_RESTART_WORKSPACE_ENV: &str = "LAWYER_ASSISTANCE_V031_RESTART_WORKSPACE";
    #[cfg(windows)]
    const V031_RESTART_LINEAGE_ENV: &str = "LAWYER_ASSISTANCE_V031_RESTART_LINEAGE";
    #[cfg(windows)]
    const V031_RESTART_CHILD_TEST: &str =
        "commands::v031_user_upgrade::tests::v031_real_restart_child_process";

    #[derive(Deserialize)]
    struct FrozenUserSchemaObject {
        object_type: String,
        sql: String,
    }

    struct LedgerFixture {
        _directory: tempfile::TempDir,
        user_path: PathBuf,
        privacy_path: PathBuf,
        rollback: OriginalRollbackVerifiedGate,
        previous_receipt_sha256: String,
    }

    impl LedgerFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("ledger fixture root");
            let user_path = database::user_database_path(directory.path());
            create_exact_v031_user_database(&user_path);
            let (source, ()) =
                with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                    .expect("exact user-v10 proof");
            let rollback = OriginalRollbackVerifiedGate::from_user_source_for_test(source);

            let privacy_root = directory.path().join("privacy");
            fs::create_dir(&privacy_root).expect("Privacy root creates");
            let privacy_path = privacy_root.join("privacy-workflow.sqlite");
            let mut privacy = Connection::open(&privacy_path).expect("Privacy fixture opens");
            PrivacyStore::initialize(&privacy).expect("Privacy-v6 schema initializes");
            ProjectPrivacyCaseBindingStore::initialize(&mut privacy)
                .expect("binding schema initializes");
            privacy::initialize_privacy_v6_application_extensions(&privacy)
                .expect("canonical Privacy-v6 application extensions initialize");
            compute_privacy_v6_manifests_read_only(&privacy).expect("Privacy-v6 fixture is exact");
            drop(privacy);

            Self {
                _directory: directory,
                user_path,
                privacy_path,
                rollback,
                previous_receipt_sha256: "8".repeat(64),
            }
        }

        fn prerequisites(&self) -> LedgerPrerequisites<'_> {
            LedgerPrerequisites {
                rollback: &self.rollback,
                previous_receipt_sha256: &self.previous_receipt_sha256,
            }
        }

        fn open(&self) -> (Connection, Connection) {
            (
                open_existing_user_database(&self.user_path).expect("user fixture opens"),
                Connection::open(&self.privacy_path).expect("Privacy fixture reopens"),
            )
        }
    }

    #[cfg(windows)]
    struct ProductionStepSevenFixture {
        _directory: tempfile::TempDir,
        approved: crate::approved_mcp::ApplicationBackupTestHarness,
        manager: PrivacyWorkflowManager,
        privacy_v6: V031PrivacyV6VerifiedGate,
        user_path: PathBuf,
        privacy_path: PathBuf,
    }

    #[cfg(windows)]
    impl ProductionStepSevenFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("production Step-7 fixture root");
            let root = directory.path();
            let user_path = database::user_database_path(root);
            let privacy_path = root.join(PRIVACY_DATABASE_RELATIVE);
            create_exact_v031_user_database(&user_path);
            create_exact_privacy_v1_database(&privacy_path);

            let approved =
                crate::approved_mcp::ApplicationBackupTestHarness::new_for_v031_migration(
                    root.to_path_buf(),
                );
            let credential_probe = approved.workspace.v031_credential_probe_for_test();
            crate::v031_upgrade_r2::verify_exact_target_absence(root, &credential_probe)
                .expect("fresh Step-7 fixture has exact target absence");
            let rollback = crate::commands::original_migration_backup::establish_original_migration_backup_with_credential_probe_for_test(
                root,
                &user_path,
                &privacy_path,
                &credential_probe,
            )
            .expect("real V2 and receipts zero/one commit");
            let target = crate::commands::v031_target_components::prepare_v031_target_components_with_ephemeral_workspace_for_test(
                root,
                &rollback,
                &approved.workspace,
            )
            .expect("real target components and receipt two commit");
            let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
                root.to_path_buf(),
                target.workspace_instance_id().clone(),
                Arc::new(approved.workspace.clone()),
            )
            .expect("Step-7 migration manager opens");
            manager.set_test_runtime(
                privacy::ReceiptSigner::new(
                    approved
                        .ephemeral_secret_key()
                        .expect("one-fixture CSPRNG receipt key"),
                )
                .expect("one-fixture receipt signer constructs"),
                receipt_timestamp_for_test(),
            );
            let case_backups = crate::commands::v031_checkpoint_receipts::ensure_v031_case_migration_backups_verified_gate(
                root,
                &manager,
                &approved.workspace,
                &target,
            )
            .expect("real Step-4 checkpoints and receipt three commit");
            let privacy_v5 =
                crate::commands::v031_privacy_migration::ensure_v031_privacy_v5_verified(
                    root,
                    &manager,
                    &approved.workspace,
                    &case_backups,
                )
                .expect("real Privacy-v5 and receipt four commit");
            let binding_materials =
                crate::commands::v031_privacy_migration::ensure_v031_binding_materials_verified(
                    root,
                    &manager,
                    &approved.workspace,
                    &privacy_v5,
                )
                .expect("real binding/material migration and receipt five commit");
            let projection = crate::commands::v031_checkpoint_receipts::ensure_v031_projection_backup_verified_gate(
                root,
                &manager,
                &approved.workspace,
                &binding_materials,
            )
            .expect("real Projection checkpoint and receipt six commit");
            let privacy_v6 =
                crate::commands::v031_privacy_migration::ensure_v031_privacy_v6_verified(
                    root,
                    &manager,
                    &approved.workspace,
                    &projection,
                )
                .expect("real Privacy-v6 projection and receipt seven commit");

            Self {
                _directory: directory,
                approved,
                manager,
                privacy_v6,
                user_path,
                privacy_path,
            }
        }

        fn root(&self) -> &Path {
            self._directory.path()
        }

        fn state(&self) -> (i64, i64, i64) {
            let user = Connection::open(&self.user_path).expect("Step-7 User state opens");
            let schema = exact_user_schema_version(&user).expect("Step-7 User schema is exact");
            let audit_rows = user
                .query_row(
                    "SELECT COUNT(*) FROM operation_audit
                     WHERE origin='desktop' AND operation=?1 AND idempotency_key_hash=?2",
                    (
                        database::V031_TO_V040_USER_AUDIT_OPERATION,
                        self.privacy_v6.receipt_context().lineage_id.as_str(),
                    ),
                    |row| row.get::<_, i64>(0),
                )
                .expect("Step-7 User audit cardinality reads");
            let privacy = Connection::open(&self.privacy_path).expect("Step-7 Privacy state opens");
            let lineage_rows = privacy
                .query_row(
                    "SELECT COUNT(*) FROM application_upgrade_lineage WHERE lineage_id=?1",
                    [self.privacy_v6.receipt_context().lineage_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("Step-7 Privacy lineage cardinality reads");
            (schema, audit_rows, lineage_rows)
        }

        fn receipt_eight_paths(&self) -> (PathBuf, PathBuf) {
            let directory = crate::v031_upgrade_r2::canonical_lineage_directory(
                self.root(),
                self.privacy_v6.receipt_context().lineage_id.as_str(),
            )
            .expect("Step-7 lineage directory resolves");
            let stage = V031UpgradeReceiptStage::UserV11Verified;
            (
                directory.join(stage.incoming_basename()),
                directory.join(stage.final_basename()),
            )
        }
    }

    #[cfg(windows)]
    fn cross_process_receipt_signer(
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        create: bool,
    ) -> privacy::ReceiptSigner {
        let mut key = if create {
            credentials
                .load_or_create_privacy_receipt_signer_key()
                .expect("cross-process Privacy signer credential creates")
        } else {
            credentials
                .load_privacy_receipt_signer_key_read_only()
                .expect("cross-process Privacy signer credential reopens read-only")
        };
        let signer = privacy::ReceiptSigner::new(key)
            .expect("cross-process Privacy receipt signer constructs");
        key.zeroize();
        signer
    }

    #[cfg(windows)]
    fn prepare_cross_process_receipt_eight(
        root: &Path,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
    ) -> (String, String) {
        let user_path = database::user_database_path(root);
        let privacy_path = root.join(PRIVACY_DATABASE_RELATIVE);
        create_exact_v031_user_database(&user_path);
        create_exact_privacy_v1_database(&privacy_path);
        let credential_probe = credentials.credential_probe();
        crate::v031_upgrade_r2::verify_exact_target_absence(root, &credential_probe)
            .expect("cross-process fixture starts with exact target absence");
        let rollback = crate::commands::original_migration_backup::
            establish_original_migration_backup_with_credential_probe_for_test(
                root,
                &user_path,
                &privacy_path,
                &credential_probe,
            )
            .expect("cross-process fixture commits real V2 and receipts zero/one");
        let target = crate::commands::v031_target_components::
            prepare_v031_target_components_with_ephemeral_workspace_for_test(
                root,
                &rollback,
                &credentials.workspace,
            )
            .expect("cross-process fixture creates four persistent target credentials");
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            root.to_path_buf(),
            target.workspace_instance_id().clone(),
            Arc::new(credentials.workspace.clone()),
        )
        .expect("cross-process parent migration manager opens");
        manager.set_test_runtime(
            cross_process_receipt_signer(credentials, true),
            receipt_timestamp_for_test(),
        );
        let case_backups = crate::commands::v031_checkpoint_receipts::
            ensure_v031_case_migration_backups_verified_gate(
                root,
                &manager,
                &credentials.workspace,
                &target,
            )
            .expect("cross-process fixture commits receipt three");
        let privacy_v5 = crate::commands::v031_privacy_migration::ensure_v031_privacy_v5_verified(
            root,
            &manager,
            &credentials.workspace,
            &case_backups,
        )
        .expect("cross-process fixture commits receipt four");
        let binding =
            crate::commands::v031_privacy_migration::ensure_v031_binding_materials_verified(
                root,
                &manager,
                &credentials.workspace,
                &privacy_v5,
            )
            .expect("cross-process fixture commits receipt five");
        let projection =
            crate::commands::v031_checkpoint_receipts::ensure_v031_projection_backup_verified_gate(
                root,
                &manager,
                &credentials.workspace,
                &binding,
            )
            .expect("cross-process fixture commits receipt six");
        let privacy_v6 = crate::commands::v031_privacy_migration::ensure_v031_privacy_v6_verified(
            root,
            &manager,
            &credentials.workspace,
            &projection,
        )
        .expect("cross-process fixture commits receipt seven");
        let pre_receipt_eight_process_start = crate::commands::v031_upgrade_complete::
            observe_v031_upgrade_at_process_start_read_only(root)
            .expect("parent captures its one frozen pre-Receipt8 process observation");
        assert_eq!(
            pre_receipt_eight_process_start.active_final_receipt_count(),
            Some(8)
        );
        assert!(pre_receipt_eight_process_start
            .receipt_eight_observed_at_process_start()
            .is_none());
        let receipt_eight = ensure_v031_user_v11_verified(
            root,
            &manager,
            &credentials.workspace,
            privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("cross-process fixture commits Receipt 8");
        assert!(
            pre_receipt_eight_process_start
                .receipt_eight_observed_at_process_start()
                .is_none(),
            "writing Receipt8 cannot upgrade the parent's frozen observation into Gate8"
        );
        let lineage_directory = crate::v031_upgrade_r2::canonical_lineage_directory(
            root,
            &receipt_eight.receipt_context().lineage_id,
        )
        .expect("cross-process Receipt8 lineage directory resolves");
        let before_stale_authorization = terminal_read_only_tree_snapshot(root);
        assert_eq!(
            crate::v031_startup::run_step_eight_with_existing_managers_for_test(
                root,
                &pre_receipt_eight_process_start,
                &manager,
                &credentials.workspace,
            ),
            Err(crate::v031_startup::V031StartupTransitionError::Observation),
            "the real Gate8 entry rejects the parent's stale pre-Receipt8 observation"
        );
        for forbidden in [
            crate::v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_INCOMING,
            crate::v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_FINAL,
            crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_INCOMING,
            crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_FINAL,
            V031UpgradeReceiptStage::UpgradeComplete.incoming_basename(),
            V031UpgradeReceiptStage::UpgradeComplete.final_basename(),
        ] {
            assert!(!lineage_directory.join(forbidden).exists());
        }
        assert_eq!(
            terminal_read_only_tree_snapshot(root),
            before_stale_authorization,
            "stale parent authorization rejection is fully read-only"
        );
        (
            target.workspace_instance_id().as_str().to_owned(),
            receipt_eight.receipt_context().lineage_id.clone(),
        )
    }

    #[cfg(windows)]
    #[derive(Debug)]
    struct Step8MaintenanceWindowState {
        retention: Option<(String, Option<i64>, i64, i64, String)>,
        vault: Option<(String, Option<i64>, i64, i64, i64, String)>,
        vault_candidate_state: Option<String>,
        object_state: String,
        retention_rows: i64,
        nonce_rows: i64,
        active_object_exists: bool,
        quarantine_exists: bool,
        case_key_exists: bool,
        decrypts: bool,
    }

    #[cfg(windows)]
    fn inspect_step8_maintenance_window(
        root: &Path,
        manager: &PrivacyWorkflowManager,
        fixture: &crate::privacy_workflow::V031Step8ExpiredVaultObjectFixture,
        retention_cleanup_id: &str,
        vault_cleanup_id: &str,
    ) -> Step8MaintenanceWindowState {
        let privacy = Connection::open_with_flags(
            root.join(PRIVACY_DATABASE_RELATIVE),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("Step-8 Privacy state opens read-only");
        let retention = privacy
            .query_row(
                "SELECT state,completed_at_unix,candidate_count,removed_count,event_hash
                 FROM privacy_cleanup_journal WHERE cleanup_id=?1",
                [retention_cleanup_id],
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
            .expect("Step-8 retention row reads");
        drop(privacy);

        let vault_root = root.join("case-vault-v2");
        let vault = Connection::open_with_flags(
            vault_root.join("vault-state.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("Step-8 Vault state opens read-only");
        let cleanup = vault
            .query_row(
                "SELECT state,completed_at_unix,candidate_count,removed_count,
                        key_records_destroyed,event_hash
                 FROM vault_cleanup_journal WHERE cleanup_id=?1",
                [vault_cleanup_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional()
            .expect("Step-8 Vault cleanup row reads");
        let vault_candidate_state = vault
            .query_row(
                "SELECT state FROM vault_cleanup_candidates
                 WHERE cleanup_id=?1 AND object_id=?2 AND version=?3",
                (
                    vault_cleanup_id,
                    fixture.object_id().as_str(),
                    i64::try_from(fixture.object_version()).expect("fixture version fits SQLite"),
                ),
                |row| row.get(0),
            )
            .optional()
            .expect("Step-8 Vault candidate reads");
        let object_state = vault
            .query_row(
                "SELECT state FROM object_journal WHERE object_id=?1 AND version=?2",
                (
                    fixture.object_id().as_str(),
                    i64::try_from(fixture.object_version()).expect("fixture version fits SQLite"),
                ),
                |row| row.get(0),
            )
            .expect("Step-8 Vault object state reads");
        let retention_rows = vault
            .query_row(
                "SELECT COUNT(*) FROM vault_object_retention
                 WHERE object_id=?1 AND version=?2",
                (
                    fixture.object_id().as_str(),
                    i64::try_from(fixture.object_version()).expect("fixture version fits SQLite"),
                ),
                |row| row.get(0),
            )
            .expect("Step-8 Vault retention count reads");
        let nonce_rows = vault
            .query_row(
                "SELECT COUNT(*) FROM nonce_reservations
                 WHERE object_id=?1 AND version=?2",
                (
                    fixture.object_id().as_str(),
                    i64::try_from(fixture.object_version()).expect("fixture version fits SQLite"),
                ),
                |row| row.get(0),
            )
            .expect("Step-8 Vault nonce count reads");
        drop(vault);

        let version = format!("v{:020}", fixture.object_version());
        let active_object = vault_root
            .join("objects")
            .join(fixture.case_id().as_str())
            .join(fixture.object_id().as_str())
            .join(&version);
        let quarantine = vault_root.join(".quarantine").join(format!(
            "{vault_cleanup_id}-{}-{version}",
            fixture.object_id().as_str()
        ));
        let key = vault_root
            .join("keys")
            .join(format!("{}.key.json", fixture.case_id().as_str()));
        Step8MaintenanceWindowState {
            retention,
            vault: cleanup,
            vault_candidate_state,
            object_state,
            retention_rows,
            nonce_rows,
            active_object_exists: active_object.is_dir(),
            quarantine_exists: quarantine.is_dir(),
            case_key_exists: key.is_file(),
            decrypts: manager
                .read_v031_step8_vault_object_for_test(fixture)
                .is_ok(),
        }
    }

    #[cfg(windows)]
    fn assert_step8_history_files(root: &Path, lineage_id: &str, terminal_complete: bool) {
        let directory = crate::v031_upgrade_r2::canonical_lineage_directory(root, lineage_id)
            .expect("Step-8 lineage directory resolves");
        assert!(directory
            .join(crate::v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_FINAL)
            .is_file());
        assert!(!directory
            .join(crate::v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_INCOMING)
            .exists());
        assert_eq!(
            directory
                .join(crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_FINAL)
                .is_file(),
            terminal_complete
        );
        assert!(!directory
            .join(crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_INCOMING)
            .exists());
        assert_eq!(
            directory
                .join(V031UpgradeReceiptStage::UpgradeComplete.final_basename())
                .is_file(),
            terminal_complete
        );
        assert!(!directory
            .join(V031UpgradeReceiptStage::UpgradeComplete.incoming_basename())
            .exists());
    }

    #[cfg(windows)]
    fn exercise_step8_maintenance_failure_window(
        failure_point: crate::privacy_workflow::V031Step8MaintenanceFailurePoint,
    ) {
        use crate::privacy_workflow::V031Step8MaintenanceFailurePoint as Point;

        let fixture = ProductionStepSevenFixture::new();
        let root = fixture.root().to_path_buf();
        let workspace_instance_id = fixture
            .privacy_v6
            .target_gate()
            .workspace_instance_id()
            .clone();
        let approved_workspace = fixture.approved.workspace.clone();
        let restarted_signer = privacy::ReceiptSigner::new(
            fixture
                .approved
                .ephemeral_secret_key()
                .expect("Step-8 restart receipt key"),
        )
        .expect("Step-8 restart signer");
        let vault_fixture = fixture
            .manager
            .seed_v031_step8_expired_vault_object_for_test(
                CaseId::parse("case_51515151515151515151515151515151")
                    .expect("Step-8 fixture case"),
                b"REAL_ENCRYPTED_EXPIRED_STEP8_OBJECT".to_vec(),
            )
            .expect("real encrypted expired Vault object seeds");
        assert_eq!(
            fixture
                .manager
                .read_v031_step8_vault_object_for_test(&vault_fixture)
                .expect("seeded Vault object decrypts"),
            vault_fixture.plaintext()
        );

        let receipt_eight = ensure_v031_user_v11_verified(
            &root,
            &fixture.manager,
            &approved_workspace,
            fixture.privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("real Receipt-8 commits with the encrypted Vault object anchored");
        let lineage_id = receipt_eight.receipt_context().lineage_id.clone();
        let (retention_cleanup_id, vault_cleanup_id) =
            crate::commands::v031_upgrade_complete::v031_step8_cleanup_ids_for_test(&lineage_id);
        let process_start =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                &root,
            )
            .expect("Receipt-8 process-start observation authenticates");
        let observed = process_start
            .receipt_eight_observed_at_process_start()
            .expect("Receipt-8 capability exists")
            .clone();
        assert_eq!(
            crate::commands::v031_upgrade_complete::ensure_v031_upgrade_complete_with_maintenance_failure_for_test(
                &root,
                &fixture.manager,
                &approved_workspace,
                &observed,
                failure_point,
            ),
            Err(crate::commands::v031_upgrade_complete::V031UpgradeCompleteError::Maintenance)
        );
        assert_step8_history_files(&root, &lineage_id, false);

        let interrupted = inspect_step8_maintenance_window(
            &root,
            &fixture.manager,
            &vault_fixture,
            &retention_cleanup_id,
            &vault_cleanup_id,
        );
        match failure_point {
            Point::AfterRetentionPreparedBeforeInvalidation => {
                assert_eq!(
                    interrupted.retention,
                    Some(("prepared".to_owned(), None, 0, 0, String::new()))
                );
            }
            _ => {
                let retention = interrupted
                    .retention
                    .as_ref()
                    .expect("retention cleanup committed");
                assert_eq!(retention.0, "committed");
                assert!(retention.1.is_some());
                assert_eq!((retention.2, retention.3), (0, 0));
                assert_eq!(retention.4.len(), 64);
            }
        }
        match failure_point {
            Point::AfterRetentionPreparedBeforeInvalidation
            | Point::AfterRetentionCommittedBeforeVault => {
                assert!(interrupted.vault.is_none());
                assert!(interrupted.vault_candidate_state.is_none());
                assert_eq!(interrupted.object_state, "committed");
                assert_eq!(interrupted.retention_rows, 1);
                assert!(interrupted.nonce_rows > 0);
                assert!(interrupted.active_object_exists);
                assert!(!interrupted.quarantine_exists);
                assert!(interrupted.case_key_exists);
                assert!(interrupted.decrypts);
            }
            Point::AfterVaultPreparedBeforeCommit => {
                assert_eq!(
                    interrupted.vault,
                    Some(("prepared".to_owned(), None, 1, 0, 0, String::new()))
                );
                assert_eq!(
                    interrupted.vault_candidate_state.as_deref(),
                    Some("pending")
                );
                assert_eq!(interrupted.object_state, "committed");
                assert_eq!(interrupted.retention_rows, 1);
                assert!(interrupted.nonce_rows > 0);
                assert!(interrupted.active_object_exists);
                assert!(!interrupted.quarantine_exists);
                assert!(interrupted.case_key_exists);
                assert!(interrupted.decrypts);
            }
            Point::AfterVaultCommittedBeforeFinalize => {
                let vault = interrupted.vault.as_ref().expect("Vault committed row");
                assert_eq!(vault.0, "committed");
                assert!(vault.1.is_some());
                assert_eq!((vault.2, vault.3, vault.4), (1, 1, 1));
                assert!(vault.5.is_empty());
                assert_eq!(
                    interrupted.vault_candidate_state.as_deref(),
                    Some("quarantined")
                );
                assert_eq!(interrupted.object_state, "quarantined");
                assert_eq!((interrupted.retention_rows, interrupted.nonce_rows), (0, 0));
                assert!(!interrupted.active_object_exists);
                assert!(interrupted.quarantine_exists);
                assert!(interrupted.case_key_exists);
                assert!(!interrupted.decrypts);
            }
            Point::AfterVaultPhysicalPurgeBeforeJournalCommit => {
                let vault = interrupted.vault.as_ref().expect("Vault committed row");
                assert_eq!(vault.0, "committed");
                assert!(vault.1.is_some());
                assert_eq!((vault.2, vault.3, vault.4), (1, 1, 1));
                assert!(vault.5.is_empty());
                assert_eq!(
                    interrupted.vault_candidate_state.as_deref(),
                    Some("quarantined")
                );
                assert_eq!(interrupted.object_state, "quarantined");
                assert_eq!((interrupted.retention_rows, interrupted.nonce_rows), (0, 0));
                assert!(!interrupted.active_object_exists);
                assert!(!interrupted.quarantine_exists);
                assert!(!interrupted.case_key_exists);
                assert!(!interrupted.decrypts);
            }
        }

        let interrupted_tree = snapshot_regular_files(&root);
        drop(fixture.manager);
        let restart_observation =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                &root,
            )
            .expect("new process authenticates the interrupted Step-8 history");
        let restart_gate = restart_observation
            .receipt_eight_observed_at_process_start()
            .expect("new process reconstructs Receipt-8 authorization")
            .clone();
        let restarted = PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
            root.clone(),
            workspace_instance_id,
            Arc::new(approved_workspace.clone()),
        )
        .expect("new-process manager opens without running maintenance");
        restarted.set_test_runtime(restarted_signer, receipt_timestamp_for_test());
        assert_eq!(
            snapshot_regular_files(&root),
            interrupted_tree,
            "process-start observation and manager construction are read-only"
        );

        let terminal = crate::commands::v031_upgrade_complete::ensure_v031_upgrade_complete(
            &root,
            &restarted,
            &approved_workspace,
            &restart_gate,
        )
        .expect("ordinary ensure resumes the exact maintenance journal and commits Receipt-9");
        assert_eq!(terminal.lineage_id(), lineage_id);
        let completed = inspect_step8_maintenance_window(
            &root,
            &restarted,
            &vault_fixture,
            &retention_cleanup_id,
            &vault_cleanup_id,
        );
        let retention = completed.retention.expect("retention terminal row");
        assert_eq!(retention.0, "committed");
        assert!(retention.1.is_some());
        assert_eq!((retention.2, retention.3), (0, 0));
        assert_eq!(retention.4.len(), 64);
        let vault = completed.vault.expect("Vault terminal row");
        assert_eq!(vault.0, "purged");
        assert!(vault.1.is_some());
        assert_eq!((vault.2, vault.3, vault.4), (1, 1, 1));
        assert_eq!(vault.5.len(), 64);
        assert_eq!(completed.vault_candidate_state.as_deref(), Some("purged"));
        assert_eq!(completed.object_state, "quarantined");
        assert_eq!((completed.retention_rows, completed.nonce_rows), (0, 0));
        assert!(!completed.active_object_exists);
        assert!(!completed.quarantine_exists);
        assert!(!completed.case_key_exists);
        assert!(!completed.decrypts);
        assert_step8_history_files(&root, &lineage_id, true);

        let terminal_observation =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                &root,
            )
            .expect("terminal process-start observation authenticates");
        assert_eq!(terminal_observation.terminal_lineage_count(), 1);
        assert!(terminal_observation.has_terminal_lineage_only());
        let before_terminal_loads = snapshot_regular_files(&root);
        let loaded_once =
            crate::commands::v031_upgrade_complete::load_v031_upgrade_complete_gate_read_only(
                &root,
                &restarted,
                &approved_workspace,
                &lineage_id,
            )
            .expect("terminal gate loads once");
        let loaded_twice =
            crate::commands::v031_upgrade_complete::load_v031_upgrade_complete_gate_read_only(
                &root,
                &restarted,
                &approved_workspace,
                &lineage_id,
            )
            .expect("terminal gate loads twice");
        assert_eq!(loaded_once, terminal);
        assert_eq!(loaded_twice, terminal);
        assert_eq!(
            snapshot_regular_files(&root),
            before_terminal_loads,
            "repeated terminal loads are full-tree read-only"
        );
    }

    #[cfg(windows)]
    #[test]
    fn step8_retention_maintenance_windows_resume_to_one_receipt_nine() {
        use crate::privacy_workflow::V031Step8MaintenanceFailurePoint as Point;
        for point in [
            Point::AfterRetentionPreparedBeforeInvalidation,
            Point::AfterRetentionCommittedBeforeVault,
        ] {
            exercise_step8_maintenance_failure_window(point);
        }
    }

    #[cfg(windows)]
    #[test]
    fn step8_vault_maintenance_windows_resume_real_encrypted_object_and_key_count() {
        use crate::privacy_workflow::V031Step8MaintenanceFailurePoint as Point;
        for point in [
            Point::AfterVaultPreparedBeforeCommit,
            Point::AfterVaultCommittedBeforeFinalize,
            Point::AfterVaultPhysicalPurgeBeforeJournalCommit,
        ] {
            exercise_step8_maintenance_failure_window(point);
        }
    }

    #[cfg(windows)]
    #[test]
    fn receipt_nine_final_failure_enters_terminal_loader_without_maintenance_replay() {
        let fixture = ProductionStepSevenFixture::new();
        let root = fixture.root();
        let receipt_eight = ensure_v031_user_v11_verified(
            root,
            &fixture.manager,
            &fixture.approved.workspace,
            fixture.privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("real Receipt 8 commits before the restart boundary");
        let lineage_id = receipt_eight.receipt_context().lineage_id.clone();
        let process_start =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                root,
            )
            .expect("the production observer authenticates Receipt 8");
        let observed = process_start
            .receipt_eight_observed_at_process_start()
            .expect("the process-start observer returns the opaque Gate 8");

        assert_eq!(
            crate::commands::v031_upgrade_complete::ensure_v031_upgrade_complete_with_failure_after_receipt_nine_for_test(
                root,
                &fixture.manager,
                &fixture.approved.workspace,
                observed,
            ),
            Err(crate::commands::v031_upgrade_complete::V031UpgradeCompleteError::Receipt),
            "the exact seam fails after authenticated Receipt 9 and before the outer live verify"
        );
        assert_step8_history_files(root, &lineage_id, true);

        let terminal_start =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                root,
            )
            .expect("the next process authenticates the durable terminal lineage");
        assert_eq!(terminal_start.terminal_lineage_count(), 1);
        assert!(terminal_start.has_terminal_lineage_only());
        assert!(terminal_start
            .receipt_eight_observed_at_process_start()
            .is_none());

        let before_terminal_load = terminal_read_only_tree_snapshot(root);
        crate::commands::v031_upgrade_complete::arm_step8_maintenance_replay_probe_for_test();
        let loaded =
            crate::commands::v031_upgrade_complete::load_v031_upgrade_complete_gate_read_only(
                root,
                &fixture.manager,
                &fixture.approved.workspace,
                &lineage_id,
            );
        let maintenance_entries =
            crate::commands::v031_upgrade_complete::finish_step8_maintenance_replay_probe_for_test(
            );
        let loaded = loaded.expect("the production terminal loader resumes without maintenance");
        assert_eq!(loaded.lineage_id(), lineage_id);
        assert_eq!(maintenance_entries, 0);
        assert_eq!(
            terminal_read_only_tree_snapshot(root),
            before_terminal_load,
            "terminal loading after the Receipt-9 crash seam is fully read-only"
        );
    }

    #[cfg(windows)]
    #[test]
    fn v031_real_restart_child_process() {
        let Some(mode) = std::env::var_os(V031_RESTART_CHILD_MODE_ENV) else {
            return;
        };
        let mode = mode
            .into_string()
            .expect("restart child mode is canonical ASCII");
        let root = PathBuf::from(
            std::env::var_os(V031_RESTART_ROOT_ENV).expect("restart child receives the test root"),
        );
        let credential_prefix = std::env::var(V031_RESTART_CREDENTIAL_PREFIX_ENV)
            .expect("restart child receives only the non-secret credential prefix");
        let expected_workspace = std::env::var(V031_RESTART_WORKSPACE_ENV)
            .expect("restart child receives the expected public workspace identity");
        let expected_lineage = std::env::var(V031_RESTART_LINEAGE_ENV)
            .expect("restart child receives the expected public lineage identity");
        let credentials = crate::approved_mcp::V031CrossProcessCredentialHarness::reopen_child(
            root.clone(),
            &credential_prefix,
        )
        .expect("child reopens all five credentials through Windows Credential Manager");

        let before_terminal = (mode == "terminal").then(|| terminal_read_only_tree_snapshot(&root));
        let process_start = crate::commands::v031_upgrade_complete::
            observe_v031_upgrade_at_process_start_read_only(&root)
            .expect("restart child production observer authenticates the frozen receipt history");
        let exact_current = if mode == "terminal" {
            Some(
                match crate::v031_startup::
                    observe_exact_current_profile_with_approved_workspace_for_test(
                        &root,
                        &credentials.workspace,
                    )
                    .expect("terminal child observes the exact isolated current five-slot profile")
                {
                    crate::v031_startup::ExactCurrentProfileObservation::Exact(gate) => gate,
                    crate::v031_startup::ExactCurrentProfileObservation::NotCurrent => {
                        panic!("terminal child must remain exact current")
                    }
                },
            )
        } else {
            None
        };
        let workspace_instance_id = privacy::vnext::WorkspaceInstanceId::parse(&expected_workspace)
            .expect("restart child workspace identity parses");
        let manager = PrivacyWorkflowManager::
            new_for_application_startup_with_approved_publication_invalidator(
                root.clone(),
                workspace_instance_id,
                Arc::new(credentials.workspace.clone()),
            )
            .expect("restart child constructs the maintenance-deferred manager");
        manager.set_test_runtime(
            cross_process_receipt_signer(&credentials, false),
            receipt_timestamp_for_test(),
        );

        match mode.as_str() {
            "step8" => {
                assert_eq!(process_start.active_final_receipt_count(), Some(9));
                assert_eq!(
                    process_start.active_lineage_id(),
                    Some(expected_lineage.as_str())
                );
                let gate = crate::v031_startup::run_step_eight_with_existing_managers_for_test(
                    &root,
                    &process_start,
                    &manager,
                    &credentials.workspace,
                )
                .expect("Step8 child uses the production Gate8 helper and ensure path");
                assert_eq!(gate.lineage_id(), expected_lineage);
            }
            "terminal" => {
                assert_eq!(process_start.terminal_lineage_count(), 1);
                assert!(process_start.has_terminal_lineage_only());
                let exact_current = exact_current.expect("terminal current gate was captured");
                assert_eq!(
                    exact_current.workspace_instance_id().as_str(),
                    expected_workspace
                );
                crate::commands::v031_upgrade_complete::arm_step8_maintenance_replay_probe_for_test(
                );
                let loaded =
                    crate::v031_startup::load_completed_v031_with_existing_managers_for_test(
                        &root,
                        &process_start,
                        &exact_current,
                        &manager,
                        &credentials.workspace,
                    );
                let frozen_step8_entries = crate::commands::v031_upgrade_complete::
                    finish_step8_maintenance_replay_probe_for_test();
                let loaded = loaded.expect(
                    "terminal child runs production history selection and the final live loader",
                );
                assert_eq!(loaded.lineage_id(), expected_lineage);
                assert_eq!(
                    frozen_step8_entries, 0,
                    "ordinary terminal gate loading never replays frozen Step8"
                );
                assert_eq!(
                    terminal_read_only_tree_snapshot(&root),
                    before_terminal.expect("terminal snapshot was captured before observation")
                );
                // Stop at the terminal gate. Current-version startup maintenance
                // and ordinary initialization are intentionally outside this
                // frozen-Step8 replay assertion.
            }
            _ => panic!("unknown restart child mode"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn real_os_process_restart_crosses_gate8_then_loads_terminal_without_raw_key_env() {
        fn run_child(
            mode: &str,
            root: &Path,
            credential_prefix: &str,
            workspace: &str,
            lineage: &str,
        ) -> std::io::Result<std::process::Output> {
            // The child receives only non-secret names and public identities.
            // All five raw keys remain inside the unique Credential Manager
            // namespace and are loaded independently by each process.
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    V031_RESTART_CHILD_TEST,
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(V031_RESTART_CHILD_MODE_ENV, mode)
                .env(V031_RESTART_ROOT_ENV, root)
                .env(V031_RESTART_CREDENTIAL_PREFIX_ENV, credential_prefix)
                .env(V031_RESTART_WORKSPACE_ENV, workspace)
                .env(V031_RESTART_LINEAGE_ENV, lineage)
                .output()
        }

        fn assert_child_succeeded(mode: &str, output: std::io::Result<std::process::Output>) {
            let output = output.unwrap_or_else(|error| {
                panic!("restart child {mode} failed to start after cleanup: {error}")
            });
            assert!(
                output.status.success(),
                "restart child {mode} failed after cleanup with status {}: stdout={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let directory = tempfile::tempdir().expect("real restart parent root");
        let root = directory.path();
        let mut credentials =
            crate::approved_mcp::V031CrossProcessCredentialHarness::create_parent(
                root.to_path_buf(),
            )
            .expect("parent allocates a unique Credential Manager namespace");
        let credential_prefix = credentials.service_prefix().to_owned();
        let (workspace, lineage) = prepare_cross_process_receipt_eight(root, &credentials);

        let step_eight_output = run_child("step8", root, &credential_prefix, &workspace, &lineage);
        let terminal_output = run_child("terminal", root, &credential_prefix, &workspace, &lineage);

        let cleanup_result = credentials.cleanup();
        let absent_result = credentials.verify_all_credentials_absent_read_only_for_test();
        cleanup_result.expect("parent explicitly deletes and verifies its five exact credentials");
        absent_result
            .expect("all four Approved keys and the Privacy signer are absent after cleanup");

        assert_child_succeeded("step8", step_eight_output);
        assert_child_succeeded("terminal", terminal_output);
    }

    struct ReceiptChainFixture {
        _directory: tempfile::TempDir,
        context: OwnedV031ReceiptContext,
        lineage_directory: PathBuf,
        receipt_seven_sha256: String,
    }

    impl ReceiptChainFixture {
        fn through_receipt_seven() -> Self {
            let directory = tempfile::tempdir().expect("receipt fixture root");
            let context = OwnedV031ReceiptContext {
                lineage_id: "1".repeat(64),
                envelope_binding_id: format!("ws_{}", "2".repeat(32)),
                source_profile_proof_sha256: "3".repeat(64),
            };
            let lineage_directory = crate::v031_upgrade_r2::canonical_lineage_directory(
                directory.path(),
                &context.lineage_id,
            )
            .expect("canonical lineage directory");
            fs::create_dir_all(&lineage_directory).expect("lineage directory creates");

            persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::SourcePreflightVerified,
            );
            write_fixed_evidence(
                &lineage_directory,
                &[
                    crate::v031_upgrade_r2::V2_IDENTITY_FINAL,
                    crate::v031_upgrade_r2::V2_BUNDLE_FINAL,
                ],
            );
            persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::OriginalRollbackVerified,
            );
            persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::TargetComponentsPrepared,
            );
            write_fixed_evidence(
                &lineage_directory,
                &[
                    crate::v031_upgrade_r2::V031_BINDING_CHECKPOINT_IDENTITY_FINAL,
                    crate::v031_upgrade_r2::V031_BINDING_CHECKPOINT_BUNDLE_FINAL,
                    crate::v031_upgrade_r2::V031_MATERIALS_CHECKPOINT_IDENTITY_FINAL,
                    crate::v031_upgrade_r2::V031_MATERIALS_CHECKPOINT_BUNDLE_FINAL,
                ],
            );
            persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::CaseMigrationBackupsVerified,
            );
            persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::PrivacyV5Verified,
            );
            persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::BindingMaterialsVerified,
            );
            write_fixed_evidence(
                &lineage_directory,
                &[
                    crate::v031_upgrade_r2::V031_PROJECTION_CHECKPOINT_IDENTITY_FINAL,
                    crate::v031_upgrade_r2::V031_PROJECTION_CHECKPOINT_BUNDLE_FINAL,
                ],
            );
            persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::ProjectionBackupVerified,
            );
            let receipt_seven_sha256 = persist_receipt_for_test(
                directory.path(),
                &context,
                V031UpgradeReceiptStage::PrivacyV6Verified,
            );

            Self {
                _directory: directory,
                context,
                lineage_directory,
                receipt_seven_sha256,
            }
        }

        fn root(&self) -> &Path {
            self._directory.path()
        }

        fn write_incoming(&self, stage: V031UpgradeReceiptStage, previous_receipt_sha256: &str) {
            let counts = receipt_counts_for_test(stage);
            let evidence = receipt_evidence_for_test(&self.context, stage);
            let protected = seal_v031_upgrade_receipt_v1(&V031UpgradeReceiptCreateRequest {
                context: self.context.as_borrowed(),
                stage,
                previous_receipt_sha256: Some(previous_receipt_sha256),
                evidence_sha256: evidence,
                counts: &counts,
                created_at_unix: receipt_timestamp_for_test(),
            })
            .expect("incoming receipt seals");
            fs::write(
                self.lineage_directory.join(stage.incoming_basename()),
                protected.protected_bytes(),
            )
            .expect("incoming receipt writes");
        }
    }

    fn write_fixed_evidence(directory: &Path, basenames: &[&str]) {
        // This receipt-adjacency fixture only supplies the exact filesystem
        // shape required by the receipt namespace classifier. It never loads
        // an OriginalRollback/Checkpoint gate and therefore is not evidence
        // that these bytes authenticate. The production end-to-end resume test
        // builds and verifies the real V2/V3 artifacts before loading a proof.
        for basename in basenames {
            fs::write(directory.join(basename), b"receipt-namespace-shape-only")
                .expect("fixed evidence writes");
        }
    }

    fn receipt_timestamp_for_test() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock follows epoch")
            .as_secs()
    }

    fn receipt_evidence_for_test(
        context: &OwnedV031ReceiptContext,
        stage: V031UpgradeReceiptStage,
    ) -> &str {
        if stage == V031UpgradeReceiptStage::SourcePreflightVerified {
            &context.source_profile_proof_sha256
        } else {
            "4444444444444444444444444444444444444444444444444444444444444444"
        }
    }

    fn persist_receipt_for_test(
        root: &Path,
        context: &OwnedV031ReceiptContext,
        stage: V031UpgradeReceiptStage,
    ) -> String {
        let counts = receipt_counts_for_test(stage);
        persist_v031_receipt(
            root,
            context,
            stage,
            receipt_evidence_for_test(context, stage),
            &counts,
            || Ok(()),
        )
        .expect("receipt persists")
        .receipt
        .protected_file_sha256
    }

    fn receipt_counts_for_test(
        stage: V031UpgradeReceiptStage,
    ) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
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
                    EXPECTED_PRIVACY_TABLE_COUNT,
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

    fn create_exact_v031_user_database(path: &Path) {
        let connection = Connection::open(path).expect("user fixture opens");
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
            .expect("schema version inserts");
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_CANONICAL_SCHEMA_MARKER],
            )
            .expect("canonical marker inserts");
    }

    #[cfg(windows)]
    fn create_exact_privacy_v1_database(path: &Path) {
        fs::create_dir(path.parent().expect("Privacy database has parent"))
            .expect("Privacy fixture directory creates");
        let connection = Connection::open(path).expect("Privacy-v1 fixture opens");
        connection
            .execute_batch(privacy::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
            .expect("frozen Privacy-v1 schema executes");
        connection
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value,updated_at)
                 VALUES('schema_version','1','2026-07-19 15:41:29')",
                [],
            )
            .expect("Privacy-v1 schema version inserts");
    }

    fn snapshot_regular_files(root: &Path) -> BTreeMap<String, (u64, SystemTime, String)> {
        fn visit(
            root: &Path,
            directory: &Path,
            snapshot: &mut BTreeMap<String, (u64, SystemTime, String)>,
        ) {
            let mut entries = fs::read_dir(directory)
                .expect("fixture directory enumerates")
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture entries enumerate");
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("fixture metadata reads");
                assert!(!metadata.file_type().is_symlink(), "fixture has no links");
                if metadata.file_type().is_dir() {
                    visit(root, &path, snapshot);
                    continue;
                }
                assert!(
                    metadata.file_type().is_file(),
                    "fixture entries are plain files"
                );
                let relative = path
                    .strip_prefix(root)
                    .expect("fixture path remains below root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let bytes = fs::read(&path).expect("fixture file reads");
                assert!(
                    snapshot
                        .insert(
                            relative,
                            (
                                metadata.len(),
                                metadata.modified().expect("fixture mtime reads"),
                                sha256_hex(&bytes),
                            ),
                        )
                        .is_none(),
                    "fixture relative paths are unique"
                );
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    #[cfg(windows)]
    fn snapshot_full_tree(root: &Path) -> BTreeMap<String, (bool, u64, SystemTime, String)> {
        fn visit(
            root: &Path,
            path: &Path,
            snapshot: &mut BTreeMap<String, (bool, u64, SystemTime, String)>,
        ) {
            let metadata = fs::symlink_metadata(path).expect("fixture tree metadata reads");
            assert!(
                !metadata.file_type().is_symlink(),
                "fixture tree has no links"
            );
            let relative = if path == root {
                ".".to_owned()
            } else {
                path.strip_prefix(root)
                    .expect("fixture tree remains below root")
                    .to_string_lossy()
                    .replace('\\', "/")
            };
            let is_directory = metadata.file_type().is_dir();
            let digest = if is_directory {
                String::new()
            } else {
                assert!(
                    metadata.file_type().is_file(),
                    "fixture tree entries are plain files or directories"
                );
                sha256_hex(&fs::read(path).expect("fixture tree file reads"))
            };
            assert!(
                snapshot
                    .insert(
                        relative,
                        (
                            is_directory,
                            metadata.len(),
                            metadata.modified().expect("fixture tree mtime reads"),
                            digest,
                        ),
                    )
                    .is_none(),
                "fixture tree relative paths are unique"
            );
            if !is_directory {
                return;
            }
            let mut entries = fs::read_dir(path)
                .expect("fixture tree directory enumerates")
                .collect::<Result<Vec<_>, _>>()
                .expect("fixture tree entries enumerate");
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                visit(root, &entry.path(), snapshot);
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    #[cfg(windows)]
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TerminalReadOnlyTreeEntry {
        Directory {
            attributes: u32,
        },
        RegularFile {
            attributes: u32,
            links: u32,
            bytes: u64,
            modified: SystemTime,
            sha256: String,
        },
        SqliteShm {
            attributes: u32,
            links: u32,
        },
        ReparseOrOther {
            attributes: u32,
            is_directory: bool,
            is_file: bool,
            bytes: u64,
        },
    }

    #[cfg(windows)]
    fn terminal_read_only_tree_snapshot(
        root: &Path,
    ) -> BTreeMap<String, TerminalReadOnlyTreeEntry> {
        fn single_link_count(path: &Path) -> u32 {
            use std::fs::OpenOptions;
            use std::os::windows::{fs::OpenOptionsExt as _, io::AsRawHandle as _};
            use windows_sys::Win32::Storage::FileSystem::{
                GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            };

            let file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .expect("terminal snapshot opens a no-follow file handle");
            let mut information = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: `file` owns a valid handle and `information` remains
            // writable for the duration of this metadata-only Win32 call.
            assert_ne!(
                unsafe { GetFileInformationByHandle(file.as_raw_handle(), &raw mut information) },
                0,
                "terminal snapshot authenticates the opened file handle"
            );
            assert_eq!(
                information.nNumberOfLinks, 1,
                "terminal snapshot accepts only ordinary single-link files"
            );
            information.nNumberOfLinks
        }

        fn visit(
            root: &Path,
            path: &Path,
            snapshot: &mut BTreeMap<String, TerminalReadOnlyTreeEntry>,
        ) {
            use std::os::windows::fs::MetadataExt as _;
            use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

            let metadata =
                fs::symlink_metadata(path).expect("terminal tree metadata reads no-follow");
            let attributes = metadata.file_attributes();
            let is_reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            let relative = if path == root {
                ".".to_owned()
            } else {
                path.strip_prefix(root)
                    .expect("terminal tree remains below its root")
                    .to_string_lossy()
                    .replace('\\', "/")
            };
            let observed = if is_reparse
                || (!metadata.file_type().is_dir() && !metadata.file_type().is_file())
            {
                TerminalReadOnlyTreeEntry::ReparseOrOther {
                    attributes,
                    is_directory: metadata.file_type().is_dir(),
                    is_file: metadata.file_type().is_file(),
                    bytes: metadata.len(),
                }
            } else if metadata.file_type().is_dir() {
                TerminalReadOnlyTreeEntry::Directory { attributes }
            } else {
                let links = single_link_count(path);
                if relative.ends_with("-shm") {
                    // SQLite SHM contains locks/read-marks. Bind only its fixed
                    // local ordinary-file shape, never its bytes/hash/mtime.
                    TerminalReadOnlyTreeEntry::SqliteShm { attributes, links }
                } else {
                    TerminalReadOnlyTreeEntry::RegularFile {
                        attributes,
                        links,
                        bytes: metadata.len(),
                        modified: metadata
                            .modified()
                            .expect("terminal ordinary-file mtime reads"),
                        sha256: sha256_hex(
                            &fs::read(path).expect("terminal ordinary-file bytes read"),
                        ),
                    }
                }
            };
            assert!(
                snapshot.insert(relative, observed).is_none(),
                "terminal tree paths are unique"
            );
            if metadata.file_type().is_dir() && !is_reparse {
                let mut children = fs::read_dir(path)
                    .expect("terminal tree directory enumerates")
                    .collect::<Result<Vec<_>, _>>()
                    .expect("terminal tree entries enumerate");
                children.sort_by_key(|entry| entry.file_name());
                for child in children {
                    visit(root, &child.path(), snapshot);
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    #[cfg(windows)]
    fn snapshot_sqlite_family(
        root: &Path,
        database_path: &Path,
    ) -> BTreeMap<String, (u64, SystemTime, String)> {
        let relative = database_path
            .strip_prefix(root)
            .expect("SQLite family remains below fixture root")
            .to_string_lossy()
            .replace('\\', "/");
        let allowed = [
            relative.clone(),
            format!("{relative}-wal"),
            format!("{relative}-shm"),
            format!("{relative}-journal"),
        ];
        snapshot_regular_files(root)
            .into_iter()
            .filter(|(path, _)| allowed.contains(path))
            .collect()
    }

    #[cfg(windows)]
    #[test]
    fn step8_predecessor_real_dpapi_rejects_conflicts_read_only_and_resumes_crashes_exactly() {
        use crate::commands::v031_upgrade_complete::V031Step8PredecessorInstallFailurePoint;

        const LEGACY_PREDECESSOR_BASENAME: &str = "08-user_v11_verified.predecessor-evidence.dpapi";

        let fixture = ProductionStepSevenFixture::new();
        let root = fixture.root();
        let receipt_eight = ensure_v031_user_v11_verified(
            root,
            &fixture.manager,
            &fixture.approved.workspace,
            fixture.privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("real receipt eight commits for the predecessor installer fixture");
        let process_start =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                root,
            )
            .expect("process start authenticates the real receipt-eight prefix");
        let observed = process_start
            .receipt_eight_observed_at_process_start()
            .expect("process start returns the opaque receipt-eight capability")
            .clone();
        let lineage_directory = crate::v031_upgrade_r2::canonical_lineage_directory(
            root,
            receipt_eight.receipt_context().lineage_id.as_str(),
        )
        .expect("real predecessor lineage directory resolves");
        let incoming_path =
            lineage_directory.join(crate::v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_INCOMING);
        let final_path =
            lineage_directory.join(crate::v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_FINAL);
        let legacy_path = lineage_directory.join(LEGACY_PREDECESSOR_BASENAME);
        assert!(!incoming_path.exists());
        assert!(!final_path.exists());
        assert!(!legacy_path.exists());

        let expected_protected =
            crate::commands::v031_upgrade_complete::build_v031_step8_predecessor_sidecar_for_test(
                root,
                &observed,
                &receipt_eight,
            )
            .expect("CurrentUser DPAPI protects the real canonical predecessor payload");
        let different_canonical_protected = crate::commands::v031_upgrade_complete::build_different_v031_step8_predecessor_sidecar_for_test(
            root,
            &observed,
            &receipt_eight,
        )
        .expect("CurrentUser DPAPI protects a different internally valid canonical payload");

        let assert_rejected_without_writes = |state: &str| {
            let before = snapshot_full_tree(root);
            let result = crate::commands::v031_upgrade_complete::install_and_authenticate_v031_step8_predecessor_for_test(
                root,
                &observed,
                receipt_eight.clone(),
            );
            assert!(
                result.is_err(),
                "{state} must fail before returning any predecessor maintenance capability"
            );
            assert_eq!(
                snapshot_full_tree(root),
                before,
                "{state} rejection must not write any directory or file in the full fixture tree"
            );
        };

        fs::write(&legacy_path, &expected_protected)
            .expect("legacy predecessor basename fixture writes");
        assert_rejected_without_writes("legacy predecessor basename");
        fs::remove_file(&legacy_path).expect("legacy predecessor basename fixture removes");

        fs::write(&incoming_path, &expected_protected)
            .expect("both-state incoming predecessor writes");
        fs::write(&final_path, &expected_protected).expect("both-state final predecessor writes");
        assert_rejected_without_writes("simultaneous incoming and final predecessor files");
        fs::remove_file(&incoming_path).expect("both-state incoming fixture removes");
        fs::remove_file(&final_path).expect("both-state final fixture removes");

        let mut incoming_bitflip = expected_protected.clone();
        let incoming_flip_index = incoming_bitflip.len() / 2;
        incoming_bitflip[incoming_flip_index] ^= 0x01;
        fs::write(&incoming_path, incoming_bitflip)
            .expect("bit-flipped incoming predecessor writes");
        assert_rejected_without_writes("bit-flipped incoming predecessor ciphertext");
        fs::remove_file(&incoming_path).expect("bit-flipped incoming fixture removes");

        fs::write(&incoming_path, &different_canonical_protected)
            .expect("different canonical incoming predecessor writes");
        assert_rejected_without_writes("different canonical incoming predecessor payload");
        fs::remove_file(&incoming_path).expect("different canonical incoming fixture removes");

        let mut final_bitflip = expected_protected;
        let final_flip_index = final_bitflip.len() / 2;
        final_bitflip[final_flip_index] ^= 0x01;
        fs::write(&final_path, final_bitflip).expect("bit-flipped final predecessor writes");
        assert_rejected_without_writes("bit-flipped final predecessor ciphertext");
        fs::remove_file(&final_path).expect("bit-flipped final fixture removes");

        let incoming_crash = crate::commands::v031_upgrade_complete::install_and_authenticate_v031_step8_predecessor_with_failure_for_test(
            root,
            &observed,
            receipt_eight.clone(),
            V031Step8PredecessorInstallFailurePoint::AfterAuthenticatedIncomingReadbackBeforeRename,
        );
        assert!(
            incoming_crash.is_err(),
            "the production common inner must stop after authenticated incoming readback"
        );
        assert!(incoming_path.is_file());
        assert!(!final_path.exists());
        let authenticated_incoming =
            fs::read(&incoming_path).expect("authenticated incoming crash bytes read");
        let incoming_crash_snapshot = snapshot_full_tree(root);
        let incoming_restart =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                root,
            )
            .expect("restart accepts the exact predecessor incoming state");
        let incoming_restart_gate = incoming_restart
            .receipt_eight_observed_at_process_start()
            .expect("restart rebuilds receipt-eight capability for incoming resume")
            .clone();
        assert_eq!(
            snapshot_full_tree(root),
            incoming_crash_snapshot,
            "restart observation of predecessor incoming is read-only"
        );
        let resumed_incoming = crate::commands::v031_upgrade_complete::install_and_authenticate_v031_step8_predecessor_for_test(
            root,
            &incoming_restart_gate,
            receipt_eight.clone(),
        )
        .expect("the production coordinator resumes the identical authenticated incoming bytes");
        assert!(!incoming_path.exists());
        assert_eq!(
            fs::read(&final_path).expect("resumed predecessor final reads"),
            authenticated_incoming,
            "incoming resume performs only the no-replacement rename of exact bytes"
        );
        assert_eq!(
            resumed_incoming.protected_sha256(),
            sha256_hex(&authenticated_incoming)
        );

        fs::remove_file(&final_path).expect("incoming-resume final fixture resets");
        let final_crash = crate::commands::v031_upgrade_complete::install_and_authenticate_v031_step8_predecessor_with_failure_for_test(
            root,
            &observed,
            receipt_eight.clone(),
            V031Step8PredecessorInstallFailurePoint::AfterFinalRenameSyncAuthenticatedReadbackAndInventory,
        );
        assert!(
            final_crash.is_err(),
            "the production common inner must stop after durable final authentication and inventory"
        );
        assert!(!incoming_path.exists());
        assert!(final_path.is_file());
        let durable_final = fs::read(&final_path).expect("post-rename crash final reads");
        let final_crash_snapshot = snapshot_full_tree(root);
        let final_restart =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                root,
            )
            .expect("restart authenticates the durable predecessor final");
        let final_restart_gate = final_restart
            .receipt_eight_observed_at_process_start()
            .expect("restart rebuilds receipt-eight capability after final rename crash")
            .clone();
        assert_eq!(
            snapshot_full_tree(root),
            final_crash_snapshot,
            "restart observation after predecessor final rename is read-only"
        );
        let resumed_final = crate::commands::v031_upgrade_complete::install_and_authenticate_v031_step8_predecessor_for_test(
            root,
            &final_restart_gate,
            receipt_eight,
        )
        .expect("the production coordinator resumes the already durable final exactly");
        assert_eq!(
            snapshot_full_tree(root),
            final_crash_snapshot,
            "post-rename resume authenticates and returns without rewriting any file"
        );
        assert_eq!(
            fs::read(&final_path).expect("resumed durable predecessor final reads"),
            durable_final
        );
        assert_eq!(resumed_final.protected_sha256(), sha256_hex(&durable_final));
    }

    #[cfg(windows)]
    fn assert_same_durable_rollback(
        expected: &OriginalRollbackVerifiedGate,
        observed: &OriginalRollbackVerifiedGate,
    ) {
        assert_eq!(observed.receipt_context(), expected.receipt_context());
        assert_eq!(observed.lineage_id(), expected.lineage_id());
        assert_eq!(
            observed.envelope_binding_id(),
            expected.envelope_binding_id()
        );
        assert_eq!(
            observed.source_profile_proof_sha256(),
            expected.source_profile_proof_sha256()
        );
        assert_eq!(
            observed.original_identity_sha256(),
            expected.original_identity_sha256()
        );
        assert_eq!(
            observed.original_bundle_sha256(),
            expected.original_bundle_sha256()
        );
        assert_eq!(
            observed.original_rollback_receipt_sha256(),
            expected.original_rollback_receipt_sha256()
        );
        assert_eq!(
            observed.original_user_physical_file_set_sha256(),
            expected.original_user_physical_file_set_sha256()
        );
        assert_eq!(
            observed.original_privacy_physical_file_set_sha256(),
            expected.original_privacy_physical_file_set_sha256()
        );
        assert_eq!(
            observed.original_privacy_logical_manifest_sha256(),
            expected.original_privacy_logical_manifest_sha256()
        );
        assert_eq!(
            observed.original_privacy_business_manifest_sha256(),
            expected.original_privacy_business_manifest_sha256()
        );
        assert_eq!(
            observed.original_privacy_table_count(),
            expected.original_privacy_table_count()
        );
        assert_eq!(
            observed.original_privacy_total_rows(),
            expected.original_privacy_total_rows()
        );
        let expected_user = expected.original_user_source_proof();
        let observed_user = observed.original_user_source_proof();
        assert_eq!(observed_user.schema, expected_user.schema);
        assert_eq!(
            observed_user.schema_manifest_sha256,
            expected_user.schema_manifest_sha256
        );
        assert_eq!(
            observed_user.logical_database_manifest_sha256,
            expected_user.logical_database_manifest_sha256
        );
        assert_eq!(
            observed_user.business_manifest_sha256,
            expected_user.business_manifest_sha256
        );
        assert_eq!(
            observed_user.business_primary_key_manifest_sha256,
            expected_user.business_primary_key_manifest_sha256
        );
        assert_eq!(
            observed_user.business_row_manifest_sha256,
            expected_user.business_row_manifest_sha256
        );
        assert_eq!(observed_user.tables, expected_user.tables);
        assert_eq!(observed_user.total_rows, expected_user.total_rows);
        assert!(
            expected.authenticates_same_original_rollback(observed),
            "the only excluded rollback fields are active-source handle metadata and SQLite data_version, which are process-local by construction"
        );
        assert!(observed.authenticates_same_original_rollback(expected));
    }

    #[cfg(windows)]
    fn assert_same_durable_target(
        expected: &V031TargetComponentsPreparedGate,
        observed: &V031TargetComponentsPreparedGate,
    ) {
        assert_eq!(observed.receipt_context(), expected.receipt_context());
        assert_same_durable_rollback(expected.rollback_gate(), observed.rollback_gate());
        assert_eq!(observed.approved_gate(), expected.approved_gate());
        assert_eq!(observed.vault_gate(), expected.vault_gate());
        assert_eq!(
            observed.target_components_evidence_sha256(),
            expected.target_components_evidence_sha256()
        );
        assert_eq!(
            observed.target_components_receipt_sha256(),
            expected.target_components_receipt_sha256()
        );
    }

    #[cfg(windows)]
    fn assert_same_durable_checkpoint(
        expected: &V031MigrationCheckpointProof,
        observed: &V031MigrationCheckpointProof,
    ) {
        assert_eq!(observed.kind(), expected.kind());
        assert_eq!(observed.lineage_id(), expected.lineage_id());
        assert_eq!(
            observed.original_identity_sha256(),
            expected.original_identity_sha256()
        );
        assert_eq!(
            observed.workspace_instance_id(),
            expected.workspace_instance_id()
        );
        assert_eq!(
            observed.identity_protected_sha256(),
            expected.identity_protected_sha256()
        );
        assert_eq!(observed.bundle_sha256(), expected.bundle_sha256());
        assert_eq!(
            observed.user_database_sha256(),
            expected.user_database_sha256()
        );
        assert_eq!(
            observed.user_schema_manifest_sha256(),
            expected.user_schema_manifest_sha256()
        );
        assert_eq!(
            observed.user_logical_manifest_sha256(),
            expected.user_logical_manifest_sha256()
        );
        assert_eq!(
            observed.user_business_manifest_sha256(),
            expected.user_business_manifest_sha256()
        );
        assert_eq!(observed.user_total_rows(), expected.user_total_rows());
        assert_eq!(
            observed.privacy_database_sha256(),
            expected.privacy_database_sha256()
        );
        assert_eq!(
            observed.privacy_schema_version(),
            expected.privacy_schema_version()
        );
        assert_eq!(
            observed.privacy_logical_manifest_sha256(),
            expected.privacy_logical_manifest_sha256()
        );
        assert_eq!(
            observed.privacy_business_manifest_sha256(),
            expected.privacy_business_manifest_sha256()
        );
        assert_eq!(observed.privacy_total_rows(), expected.privacy_total_rows());
        assert_eq!(
            observed.vault_bundle_sha256(),
            expected.vault_bundle_sha256()
        );
        assert_eq!(
            observed.approved_workspace_bundle_sha256(),
            expected.approved_workspace_bundle_sha256()
        );
        assert_eq!(
            observed.work_products_bundle_sha256(),
            expected.work_products_bundle_sha256()
        );
        assert_eq!(observed.source_fingerprint(), expected.source_fingerprint());
        assert_eq!(
            observed.candidate_manifest_sha256(),
            expected.candidate_manifest_sha256()
        );
        assert_eq!(observed.candidate_count(), expected.candidate_count());
        // `created` reports whether this invocation installed the immutable
        // checkpoint; a restart loader must return false for the same bytes.
        assert!(!observed.created());
    }

    #[cfg(windows)]
    fn assert_same_durable_case_backups(
        expected: &V031CaseMigrationBackupsVerifiedGate,
        observed: &V031CaseMigrationBackupsVerifiedGate,
    ) {
        assert_eq!(observed.receipt_context(), expected.receipt_context());
        assert_same_durable_rollback(expected.rollback_gate(), observed.rollback_gate());
        assert_same_durable_target(expected.target_gate(), observed.target_gate());
        assert_eq!(observed.source_proof(), expected.source_proof());
        assert_same_durable_checkpoint(
            expected.binding_checkpoint(),
            observed.binding_checkpoint(),
        );
        assert_same_durable_checkpoint(
            expected.material_checkpoint(),
            observed.material_checkpoint(),
        );
        assert_eq!(
            observed.case_migration_backups_evidence_sha256(),
            expected.case_migration_backups_evidence_sha256()
        );
        assert_eq!(
            observed.case_migration_backups_receipt_sha256(),
            expected.case_migration_backups_receipt_sha256()
        );
    }

    #[cfg(windows)]
    fn assert_same_durable_privacy_v5(
        expected: &V031PrivacyV5VerifiedGate,
        observed: &V031PrivacyV5VerifiedGate,
    ) {
        assert_same_durable_case_backups(
            expected.case_migration_backups_gate(),
            observed.case_migration_backups_gate(),
        );
        assert_eq!(
            observed.privacy_v5_schema_object_count(),
            expected.privacy_v5_schema_object_count()
        );
        assert_eq!(
            observed.privacy_v5_evidence_sha256(),
            expected.privacy_v5_evidence_sha256()
        );
        assert_eq!(
            observed.privacy_v5_receipt_sha256(),
            expected.privacy_v5_receipt_sha256()
        );
    }

    #[cfg(windows)]
    fn assert_same_durable_binding_materials(
        expected: &V031BindingMaterialsVerifiedGate,
        observed: &V031BindingMaterialsVerifiedGate,
    ) {
        assert_same_durable_privacy_v5(expected.privacy_v5_gate(), observed.privacy_v5_gate());
        assert_eq!(observed.terminal_proof(), expected.terminal_proof());
        assert_eq!(
            observed.binding_materials_evidence_sha256(),
            expected.binding_materials_evidence_sha256()
        );
        assert_eq!(
            observed.binding_materials_receipt_sha256(),
            expected.binding_materials_receipt_sha256()
        );
    }

    #[cfg(windows)]
    fn assert_same_durable_projection(
        expected: &V031ProjectionBackupVerifiedGate,
        observed: &V031ProjectionBackupVerifiedGate,
    ) {
        assert_eq!(observed.receipt_context(), expected.receipt_context());
        assert_same_durable_rollback(expected.rollback_gate(), observed.rollback_gate());
        assert_same_durable_target(expected.target_gate(), observed.target_gate());
        assert_eq!(observed.step5_terminal(), expected.step5_terminal());
        assert_eq!(
            observed.projection_source_proof(),
            expected.projection_source_proof()
        );
        assert_same_durable_checkpoint(
            expected.projection_checkpoint(),
            observed.projection_checkpoint(),
        );
        assert_eq!(
            observed.binding_materials_receipt_sha256(),
            expected.binding_materials_receipt_sha256()
        );
        assert_eq!(
            observed.projection_backup_evidence_sha256(),
            expected.projection_backup_evidence_sha256()
        );
        assert_eq!(
            observed.projection_backup_receipt_sha256(),
            expected.projection_backup_receipt_sha256()
        );
    }

    #[cfg(windows)]
    fn assert_same_durable_privacy_v6(
        expected: &V031PrivacyV6VerifiedGate,
        observed: &V031PrivacyV6VerifiedGate,
    ) {
        assert_same_durable_projection(
            expected.projection_backup_gate(),
            observed.projection_backup_gate(),
        );
        assert_eq!(observed.terminal_proof(), expected.terminal_proof());
        assert_eq!(
            observed.privacy_v6_evidence_sha256(),
            expected.privacy_v6_evidence_sha256()
        );
        assert_eq!(
            observed.privacy_v6_receipt_sha256(),
            expected.privacy_v6_receipt_sha256()
        );
    }

    #[cfg(windows)]
    struct ExpectedRestartPrefix<'a> {
        rollback: &'a OriginalRollbackVerifiedGate,
        target: &'a V031TargetComponentsPreparedGate,
        case_backups: Option<&'a V031CaseMigrationBackupsVerifiedGate>,
        privacy_v5: Option<&'a V031PrivacyV5VerifiedGate>,
        binding_materials: Option<&'a V031BindingMaterialsVerifiedGate>,
        projection: Option<&'a V031ProjectionBackupVerifiedGate>,
        privacy_v6: Option<&'a V031PrivacyV6VerifiedGate>,
    }

    #[cfg(windows)]
    fn assert_process_start_restart_prefix_read_only(
        root: &Path,
        approved_workspace: &ApprovedMcpWorkspace,
        expected_final_count: usize,
        expected: ExpectedRestartPrefix<'_>,
        observed_restart_counts: &mut Vec<usize>,
    ) {
        assert!((3..=8).contains(&expected_final_count));
        let before = snapshot_regular_files(root);
        {
            let process_start = crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(root)
                .expect("the real receipt prefix authenticates at process start");
            assert_eq!(
                process_start.active_final_receipt_count(),
                Some(expected_final_count)
            );
            assert_eq!(process_start.active_next_incoming_ordinal(), None);
            assert_eq!(process_start.terminal_lineage_count(), 0);
            assert!(process_start
                .receipt_eight_observed_at_process_start()
                .is_none());
            let lineage_id = process_start
                .active_lineage_id()
                .expect("the process-start prefix identifies one active lineage");
            assert_eq!(lineage_id, expected.rollback.lineage_id());

            // Rebuild from disk and the authenticated process-start lineage;
            // no gate or manager from the process that committed the receipt
            // is used as an authorization input below.
            let rollback = load_original_migration_backup_gate(root, lineage_id)
                .expect("restart reconstructs the original rollback gate");
            assert_same_durable_rollback(expected.rollback, &rollback);
            let target = if expected_final_count == 3 {
                load_v031_target_components_prepared_gate_read_only(
                    root,
                    &rollback,
                    approved_workspace,
                )
                .expect("final-count 3 reconstructs live Gate2")
            } else {
                load_v031_historical_target_components_from_checkpoint_read_only(
                    root,
                    &rollback,
                    approved_workspace,
                )
                .expect("final-count 4..8 reconstructs historical Gate2")
            };
            assert_same_durable_target(expected.target, &target);

            let manager =
                PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                    root.to_path_buf(),
                    target.workspace_instance_id().clone(),
                    Arc::new(approved_workspace.clone()),
                )
                .expect("restart constructs a maintenance-deferred migration manager");
            let case_backups = (expected_final_count >= 4).then(|| {
                load_v031_case_migration_backups_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    &target,
                )
                .expect("restart reconstructs committed Gate3")
            });
            match (expected.case_backups, case_backups.as_ref()) {
                (Some(expected), Some(observed)) => {
                    assert_same_durable_case_backups(expected, observed)
                }
                (None, None) => {}
                _ => panic!("Gate3 presence must match the authenticated receipt prefix"),
            }
            let privacy_v5 = (expected_final_count >= 5).then(|| {
                load_v031_privacy_v5_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    case_backups.as_ref().expect("Gate3 precedes Gate4"),
                )
                .expect("restart reconstructs committed Gate4")
            });
            match (expected.privacy_v5, privacy_v5.as_ref()) {
                (Some(expected), Some(observed)) => {
                    assert_same_durable_privacy_v5(expected, observed)
                }
                (None, None) => {}
                _ => panic!("Gate4 presence must match the authenticated receipt prefix"),
            }
            let binding_materials = (expected_final_count >= 6).then(|| {
                load_v031_binding_materials_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    privacy_v5.as_ref().expect("Gate4 precedes Gate5"),
                )
                .expect("restart reconstructs committed Gate5")
            });
            match (expected.binding_materials, binding_materials.as_ref()) {
                (Some(expected), Some(observed)) => {
                    assert_same_durable_binding_materials(expected, observed)
                }
                (None, None) => {}
                _ => panic!("Gate5 presence must match the authenticated receipt prefix"),
            }
            let projection = (expected_final_count >= 7).then(|| {
                load_v031_projection_backup_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    &target,
                )
                .expect("restart reconstructs committed Gate6")
            });
            match (expected.projection, projection.as_ref()) {
                (Some(expected), Some(observed)) => {
                    assert_same_durable_projection(expected, observed)
                }
                (None, None) => {}
                _ => panic!("Gate6 presence must match the authenticated receipt prefix"),
            }
            let privacy_v6 = (expected_final_count >= 8).then(|| {
                load_v031_privacy_v6_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    projection.as_ref().expect("Gate6 precedes Gate7"),
                )
                .expect("restart reconstructs committed Gate7")
            });
            match (expected.privacy_v6, privacy_v6.as_ref()) {
                (Some(expected), Some(observed)) => {
                    assert_same_durable_privacy_v6(expected, observed)
                }
                (None, None) => {}
                _ => panic!("Gate7 presence must match the authenticated receipt prefix"),
            }

            match expected_final_count {
                3 => verify_v031_target_components_prepared_gate_read_only(
                    root,
                    &target,
                    approved_workspace,
                )
                .expect("reloaded Gate2 drives its read-only no-op verifier"),
                4 => verify_v031_case_migration_backups_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    case_backups.as_ref().expect("final-count 4 has Gate3"),
                )
                .expect("reloaded Gate3 drives its read-only no-op verifier"),
                5 => verify_v031_privacy_v5_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    privacy_v5.as_ref().expect("final-count 5 has Gate4"),
                )
                .expect("reloaded Gate4 drives its read-only no-op verifier"),
                6 => verify_v031_binding_materials_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    binding_materials.as_ref().expect("final-count 6 has Gate5"),
                )
                .expect("reloaded Gate5 drives its read-only no-op verifier"),
                7 => verify_v031_projection_backup_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    projection.as_ref().expect("final-count 7 has Gate6"),
                )
                .expect("reloaded Gate6 drives its read-only no-op verifier"),
                8 => verify_v031_privacy_v6_verified_gate_read_only(
                    root,
                    &manager,
                    approved_workspace,
                    privacy_v6.as_ref().expect("final-count 8 has Gate7"),
                )
                .expect("reloaded Gate7 drives its read-only no-op verifier"),
                _ => unreachable!("validated final-count range"),
            }
        }
        assert_eq!(
            snapshot_regular_files(root),
            before,
            "process-start observation and the complete fresh gate rebuild must be source/history read-only at final-count {expected_final_count}"
        );
        observed_restart_counts.push(expected_final_count);
    }

    #[cfg(windows)]
    fn assert_v6_historical_gate4_gate5_loaders_are_read_only_and_fail_closed(
        root: &Path,
        manager: &PrivacyWorkflowManager,
        approved_workspace: &ApprovedMcpWorkspace,
        case_backups: &V031CaseMigrationBackupsVerifiedGate,
        expected_privacy_v5: &V031PrivacyV5VerifiedGate,
        expected_binding_materials: &V031BindingMaterialsVerifiedGate,
    ) {
        let before_load = snapshot_regular_files(root);
        let historical_privacy_v5 = load_v031_privacy_v5_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            case_backups,
        )
        .expect("live Privacy-v6 reconstructs historical Gate4 from the Projection checkpoint");
        assert_same_durable_privacy_v5(expected_privacy_v5, &historical_privacy_v5);
        let historical_binding_materials = load_v031_binding_materials_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            &historical_privacy_v5,
        )
        .expect("live Privacy-v6 reconstructs historical Gate5 from the Projection checkpoint");
        assert_same_durable_binding_materials(
            expected_binding_materials,
            &historical_binding_materials,
        );
        assert_eq!(
            snapshot_regular_files(root),
            before_load,
            "historical Gate4/Gate5 reconstruction must not write anywhere in the fixture tree",
        );

        let lineage_directory = crate::v031_upgrade_r2::canonical_lineage_directory(
            root,
            case_backups.receipt_context().lineage_id.as_str(),
        )
        .expect("historical Gate4/Gate5 lineage directory resolves");
        let projection_bundle_path =
            lineage_directory.join(V031CheckpointKind::Projection.bundle_final_basename());
        let original_projection_bundle =
            fs::read(&projection_bundle_path).expect("Projection checkpoint bundle reads");
        let mut tampered_projection_bundle = original_projection_bundle.clone();
        let projection_tamper_index = tampered_projection_bundle.len() / 2;
        tampered_projection_bundle[projection_tamper_index] ^= 0x01;
        fs::write(&projection_bundle_path, &tampered_projection_bundle)
            .expect("Projection checkpoint bundle is actually tampered");
        let tampered_checkpoint_tree = snapshot_regular_files(root);
        let gate4_rejects_checkpoint = load_v031_privacy_v5_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            case_backups,
        )
        .is_err();
        let gate5_rejects_checkpoint = load_v031_binding_materials_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            expected_privacy_v5,
        )
        .is_err();
        let after_checkpoint_rejections = snapshot_regular_files(root);
        fs::write(&projection_bundle_path, &original_projection_bundle)
            .expect("Projection checkpoint bundle restores exactly");
        assert!(
            gate4_rejects_checkpoint && gate5_rejects_checkpoint,
            "historical Gate4/Gate5 must reject Projection checkpoint tamper",
        );
        assert_eq!(
            after_checkpoint_rejections, tampered_checkpoint_tree,
            "checkpoint-tamper rejection must remain read-only",
        );

        let receipt_five_path = lineage_directory
            .join(V031UpgradeReceiptStage::BindingMaterialsVerified.final_basename());
        let original_receipt_five =
            fs::read(&receipt_five_path).expect("receipt five protected bytes read");
        let mut tampered_receipt_five = original_receipt_five.clone();
        let receipt_tamper_index = tampered_receipt_five.len() / 2;
        tampered_receipt_five[receipt_tamper_index] ^= 0x01;
        fs::write(&receipt_five_path, &tampered_receipt_five)
            .expect("receipt five is actually tampered");
        let tampered_receipt_tree = snapshot_regular_files(root);
        let gate4_rejects_receipt = load_v031_privacy_v5_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            case_backups,
        )
        .is_err();
        let gate5_rejects_receipt = load_v031_binding_materials_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            expected_privacy_v5,
        )
        .is_err();
        let after_receipt_rejections = snapshot_regular_files(root);
        fs::write(&receipt_five_path, &original_receipt_five)
            .expect("receipt five restores exactly");
        assert!(
            gate4_rejects_receipt && gate5_rejects_receipt,
            "historical Gate4/Gate5 must reject protected receipt tamper",
        );
        assert_eq!(
            after_receipt_rejections, tampered_receipt_tree,
            "receipt-tamper rejection must remain read-only",
        );

        let restored_privacy_v5 = load_v031_privacy_v5_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            case_backups,
        )
        .expect("restored Projection checkpoint and receipt reconstruct Gate4");
        let restored_binding_materials = load_v031_binding_materials_verified_gate_read_only(
            root,
            manager,
            approved_workspace,
            &restored_privacy_v5,
        )
        .expect("restored Projection checkpoint and receipt reconstruct Gate5");
        assert_same_durable_privacy_v5(expected_privacy_v5, &restored_privacy_v5);
        assert_same_durable_binding_materials(
            expected_binding_materials,
            &restored_binding_materials,
        );
    }

    fn ledger_counts(user: &Connection, privacy: &Connection) -> (i64, i64) {
        let audits = user
            .query_row(
                "SELECT COUNT(*) FROM operation_audit
                 WHERE origin='desktop' AND operation='v031_to_v040_upgrade'",
                [],
                |row| row.get(0),
            )
            .expect("audit count reads");
        let lineages = privacy
            .query_row(
                "SELECT COUNT(*) FROM application_upgrade_lineage",
                [],
                |row| row.get(0),
            )
            .expect("lineage count reads");
        (audits, lineages)
    }

    #[test]
    fn exact_cross_database_ledgers_commit_once_and_resume_as_read_only_verification() {
        let fixture = LedgerFixture::new();
        let (mut user, privacy) = fixture.open();
        let first =
            ensure_user_and_privacy_ledgers(&mut user, &privacy, &fixture.prerequisites(), None)
                .expect("fresh ledgers commit");
        assert_eq!(
            exact_user_schema_version(&user).unwrap(),
            USER_SCHEMA_VERSION
        );
        assert_eq!(ledger_counts(&user, &privacy), (1, 1));
        assert_eq!(
            first.privacy_post_audit.logical_manifest.total_row_count,
            first.privacy_pre_audit.logical_manifest.total_row_count + 1
        );
        assert_eq!(
            first.privacy_post_audit.business_manifest,
            first.privacy_pre_audit.business_manifest
        );
        assert_eq!(
            first.lineage.created_at_unix,
            canonical_audit_timestamp_unix(&user, &first.user.audit).unwrap()
        );
        assert!(!first
            .user
            .audit
            .details_json
            .contains("finalComponentManifest"));

        let second =
            ensure_user_and_privacy_ledgers(&mut user, &privacy, &fixture.prerequisites(), None)
                .expect("completed ledgers verify as no-op");
        assert!(same_ledger_result(&first, &second));
        assert_eq!(ledger_counts(&user, &privacy), (1, 1));
    }

    #[test]
    fn cross_database_ledger_failure_points_resume_without_duplicate_rows() {
        for (failure, expected_schema, expected_audits, expected_lineage) in [
            (
                LedgerFailurePoint::BeforeUserTransaction,
                V031_USER_SCHEMA_VERSION,
                0,
                0,
            ),
            (
                LedgerFailurePoint::AfterUserTransactionCommit,
                USER_SCHEMA_VERSION,
                1,
                0,
            ),
            (
                LedgerFailurePoint::BeforePrivacyLineageAppend,
                USER_SCHEMA_VERSION,
                1,
                0,
            ),
            (
                LedgerFailurePoint::AfterPrivacyLineageAppend,
                USER_SCHEMA_VERSION,
                1,
                1,
            ),
        ] {
            let fixture = LedgerFixture::new();
            let source_before =
                with_validated_user_database_migration_source_read_only(&fixture.user_path, |_| ())
                    .expect("the exact User-v10 source validates before Step 7")
                    .0;
            // The migration-source validator owns an exact no-follow physical
            // snapshot on Windows. Capture it before opening the later
            // transaction connection; a writable SQLite handle is not part of
            // the source-proof boundary and may deny that second physical
            // handle while it remains live.
            let (mut user, privacy) = fixture.open();
            let durable_before = snapshot_regular_files(fixture._directory.path());
            assert!(
                ensure_user_and_privacy_ledgers(
                    &mut user,
                    &privacy,
                    &fixture.prerequisites(),
                    Some(failure),
                )
                .is_err(),
                "injected crash boundary returns"
            );
            assert_eq!(
                exact_user_schema_version(&user).unwrap(),
                expected_schema,
                "the injected boundary leaves the exact expected User schema"
            );
            assert_eq!(
                ledger_counts(&user, &privacy),
                (expected_audits, expected_lineage),
                "the injected boundary leaves the exact expected audit/lineage cardinality"
            );
            if failure == LedgerFailurePoint::BeforeUserTransaction {
                assert_eq!(
                    snapshot_regular_files(fixture._directory.path()),
                    durable_before,
                    "all prerequisite validation before the User transaction is read-only"
                );
                drop(user);
                let source_after = with_validated_user_database_migration_source_read_only(
                    &fixture.user_path,
                    |_| (),
                )
                .expect("the exact User-v10 source remains valid before the transaction")
                .0;
                assert_eq!(source_after, source_before);
                user = open_existing_user_database(&fixture.user_path)
                    .expect("User-v10 transaction connection reopens after source proof");
            }

            let resumed = ensure_user_and_privacy_ledgers(
                &mut user,
                &privacy,
                &fixture.prerequisites(),
                None,
            )
            .expect("crash state resumes");
            assert_eq!(ledger_counts(&user, &privacy), (1, 1));
            verify_user_and_privacy_ledgers(&user, &privacy, &fixture.prerequisites())
                .expect("resumed ledgers verify");
            assert_eq!(resumed.lineage.previous_receipt_sha256, "8".repeat(64));
            let completed = snapshot_regular_files(fixture._directory.path());
            let repeated = ensure_user_and_privacy_ledgers(
                &mut user,
                &privacy,
                &fixture.prerequisites(),
                None,
            )
            .expect("completed cross-database ledgers verify as a no-op");
            assert!(same_ledger_result(&resumed, &repeated));
            assert_eq!(ledger_counts(&user, &privacy), (1, 1));
            assert_eq!(
                snapshot_regular_files(fixture._directory.path()),
                completed,
                "a second resume does not duplicate or rewrite either ledger"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn user_commit_and_privacy_lineage_crash_windows_resume_without_duplicate_rows() {
        for (failure, expected_error, expected_state) in [
            (
                LedgerFailurePoint::BeforeUserTransaction,
                V031UserUpgradeError::UserDatabase,
                (V031_USER_SCHEMA_VERSION, 0, 0),
            ),
            (
                LedgerFailurePoint::AfterUserTransactionCommit,
                V031UserUpgradeError::UserDatabase,
                (USER_SCHEMA_VERSION, 1, 0),
            ),
            (
                LedgerFailurePoint::BeforePrivacyLineageAppend,
                V031UserUpgradeError::PrivacyDatabase,
                (USER_SCHEMA_VERSION, 1, 0),
            ),
            (
                LedgerFailurePoint::AfterPrivacyLineageAppend,
                V031UserUpgradeError::PrivacyDatabase,
                (USER_SCHEMA_VERSION, 1, 1),
            ),
        ] {
            let fixture = ProductionStepSevenFixture::new();
            let root = fixture.root();
            let source_before =
                with_validated_user_database_migration_source_read_only(&fixture.user_path, |_| ())
                    .expect("Gate 7 leaves an exact User-v10 source before Step 7")
                    .0;
            assert_eq!(source_before.schema, ValidatedUserSourceSchema::V031V10);
            assert!(fixture
                .privacy_v6
                .rollback_gate()
                .authenticates_user_physical_file_set(&source_before));
            assert_eq!(
                source_before.logical_database_manifest_sha256,
                fixture
                    .privacy_v6
                    .rollback_gate()
                    .original_user_source_proof()
                    .logical_database_manifest_sha256
            );
            assert_eq!(fixture.state(), (V031_USER_SCHEMA_VERSION, 0, 0));
            let (receipt_incoming, receipt_final) = fixture.receipt_eight_paths();
            assert!(!receipt_incoming.exists());
            assert!(!receipt_final.exists());

            let error = ensure_v031_user_v11_verified_with_failure_for_test(
                root,
                &fixture.manager,
                &fixture.approved.workspace,
                fixture.privacy_v6.receipt_context().lineage_id.as_str(),
                failure,
            )
            .err();
            assert_eq!(error, Some(expected_error));
            assert_eq!(fixture.state(), expected_state);
            assert!(!receipt_incoming.exists());
            assert!(!receipt_final.exists());
            if failure == LedgerFailurePoint::BeforeUserTransaction {
                assert_eq!(
                    with_validated_user_database_migration_source_read_only(
                        &fixture.user_path,
                        |_| (),
                    )
                    .expect("the before-transaction source remains exact User-v10")
                    .0,
                    source_before
                );
            }

            let user_before_resume = snapshot_sqlite_family(root, &fixture.user_path);
            let privacy_before_resume = snapshot_sqlite_family(root, &fixture.privacy_path);
            let resumed = ensure_v031_user_v11_verified(
                root,
                &fixture.manager,
                &fixture.approved.workspace,
                fixture.privacy_v6.receipt_context().lineage_id.as_str(),
            )
            .expect("ordinary Step-7 ensure resumes through receipt eight");
            assert_eq!(fixture.state(), (USER_SCHEMA_VERSION, 1, 1));
            assert!(!receipt_incoming.exists());
            assert!(receipt_final.is_file());
            let user_after_resume = snapshot_sqlite_family(root, &fixture.user_path);
            let privacy_after_resume = snapshot_sqlite_family(root, &fixture.privacy_path);
            match failure {
                LedgerFailurePoint::BeforeUserTransaction => {
                    assert_ne!(user_after_resume, user_before_resume);
                    assert_ne!(privacy_after_resume, privacy_before_resume);
                }
                LedgerFailurePoint::AfterUserTransactionCommit
                | LedgerFailurePoint::BeforePrivacyLineageAppend => {
                    assert_eq!(
                        user_after_resume, user_before_resume,
                        "resume verifies the committed User transaction without rewriting it"
                    );
                    assert_ne!(privacy_after_resume, privacy_before_resume);
                }
                LedgerFailurePoint::AfterPrivacyLineageAppend => {
                    assert_eq!(
                        user_after_resume, user_before_resume,
                        "receipt-only resume does not rewrite User"
                    );
                    assert_eq!(
                        privacy_after_resume, privacy_before_resume,
                        "receipt-only resume does not rewrite Privacy"
                    );
                }
            }

            let completed = snapshot_regular_files(root);
            let repeated = ensure_v031_user_v11_verified(
                root,
                &fixture.manager,
                &fixture.approved.workspace,
                fixture.privacy_v6.receipt_context().lineage_id.as_str(),
            )
            .expect("completed Step 7 verifies as a production no-op");
            assert_eq!(repeated, resumed);
            assert_eq!(fixture.state(), (USER_SCHEMA_VERSION, 1, 1));
            assert_eq!(
                snapshot_regular_files(root),
                completed,
                "second ordinary ensure does not duplicate ledgers or rewrite receipt eight"
            );
        }
    }

    #[test]
    fn privacy_lineage_with_active_user_v10_is_an_impossible_state() {
        let fixture = LedgerFixture::new();
        let (mut user, privacy) = fixture.open();
        let privacy_manifest =
            compute_privacy_v6_manifests_read_only(&privacy).expect("Privacy manifest");
        append_application_upgrade_lineage(
            &privacy,
            &ApplicationUpgradeLineageRecord {
                lineage_id: fixture.rollback.lineage_id().to_owned(),
                migration_id: V031_TO_V040_USER_MIGRATION_ID.to_owned(),
                source_profile_proof_sha256: fixture
                    .rollback
                    .source_profile_proof_sha256()
                    .to_owned(),
                source_user_logical_manifest_sha256: fixture
                    .rollback
                    .original_user_source_proof()
                    .logical_database_manifest_sha256
                    .clone(),
                source_privacy_logical_manifest_sha256: fixture
                    .rollback
                    .original_privacy_logical_manifest_sha256()
                    .to_owned(),
                original_rollback_identity_sha256: fixture
                    .rollback
                    .original_identity_sha256()
                    .to_owned(),
                target_user_pre_audit_logical_manifest_sha256: "3".repeat(64),
                target_user_pre_audit_business_manifest_sha256: "4".repeat(64),
                target_privacy_pre_audit_logical_manifest_sha256: privacy_manifest
                    .logical_manifest
                    .sha256,
                target_privacy_pre_audit_business_manifest_sha256: privacy_manifest
                    .business_manifest
                    .sha256,
                previous_receipt_sha256: "8".repeat(64),
                result_code: APPLICATION_UPGRADE_RESULT_OK.to_owned(),
                created_at_unix: 1_785_433_600,
            },
        )
        .expect("impossible lineage seeds");

        assert!(matches!(
            ensure_user_and_privacy_ledgers(&mut user, &privacy, &fixture.prerequisites(), None,),
            Err(V031UserUpgradeError::LedgerConflict)
        ));
        assert_eq!(
            exact_user_schema_version(&user).unwrap(),
            V031_USER_SCHEMA_VERSION
        );
        assert_eq!(ledger_counts(&user, &privacy), (0, 1));
    }

    #[test]
    fn audit_timestamp_requires_exact_sqlite_utc_and_never_falls_back_to_a_clock() {
        let fixture = LedgerFixture::new();
        let (mut user, privacy) = fixture.open();
        let committed =
            ensure_user_and_privacy_ledgers(&mut user, &privacy, &fixture.prerequisites(), None)
                .expect("ledgers commit");
        user.execute(
            "UPDATE operation_audit
             SET created_at='2026-08-01T00:00:00Z',finished_at='2026-08-01T00:00:00Z'
             WHERE audit_id=?1",
            [&committed.user.audit.audit_id],
        )
        .expect("timestamp tamper writes");
        assert!(matches!(
            verify_user_and_privacy_ledgers(&user, &privacy, &fixture.prerequisites(),),
            Err(V031UserUpgradeError::AuditTimestamp)
        ));
    }

    #[test]
    fn final_manifest_has_five_fixed_ordered_live_slots_and_is_not_a_database_field() {
        let fixture = LedgerFixture::new();
        let (mut user, privacy) = fixture.open();
        let committed =
            ensure_user_and_privacy_ledgers(&mut user, &privacy, &fixture.prerequisites(), None)
                .expect("ledgers commit");
        drop(user);
        let (post_user, ()) =
            with_validated_user_database_migration_source_read_only(&fixture.user_path, |_| ())
                .expect("post user manifest");
        let non_database = FinalNonDatabaseComponents {
            workspace_instance_id: format!("ws_{}", "a".repeat(32)),
            vault_component_manifest_sha256: "1".repeat(64),
            vault_schema_sha256: "2".repeat(64),
            vault_database_sha256: "3".repeat(64),
            vault_layout_sha256: "4".repeat(64),
            approved_workspace_bundle_sha256: "5".repeat(64),
            approved_workspace_manifest_sha256: "6".repeat(64),
            approved_workspace_schema_sha256: "7".repeat(64),
            work_products_bundle_sha256: "8".repeat(64),
            work_products_manifest_sha256: "9".repeat(64),
            work_products_schema_sha256: "a".repeat(64),
        };
        let first = build_final_component_manifest(
            fixture.rollback.lineage_id(),
            &post_user,
            &committed.privacy_post_audit,
            &non_database,
        )
        .expect("final manifest builds");
        let second = build_final_component_manifest(
            fixture.rollback.lineage_id(),
            &post_user,
            &committed.privacy_post_audit,
            &non_database,
        )
        .expect("same final manifest rebuilds");
        assert_eq!(first, second);
        assert_eq!(first.user_table_count(), EXPECTED_TARGET_USER_TABLE_COUNT);
        assert_eq!(first.privacy_table_count(), EXPECTED_PRIVACY_TABLE_COUNT);

        let mut changed = non_database;
        changed.work_products_bundle_sha256 = "b".repeat(64);
        let changed = build_final_component_manifest(
            fixture.rollback.lineage_id(),
            &post_user,
            &committed.privacy_post_audit,
            &changed,
        )
        .expect("changed manifest builds");
        assert_ne!(first.sha256(), changed.sha256());
        assert!(!committed
            .user
            .audit
            .details_json
            .contains("finalComponentManifest"));
        let lineage_columns: i64 = privacy
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('application_upgrade_lineage')
                 WHERE name LIKE '%final%manifest%'",
                [],
                |row| row.get(0),
            )
            .expect("lineage schema reads");
        assert_eq!(
            lineage_columns, 0,
            "final manifest is receipt-only evidence"
        );
    }

    #[cfg(windows)]
    #[test]
    fn privacy_v5_gate_reloads_from_real_receipt_prefix_after_process_restart() {
        let directory = tempfile::tempdir().expect("real Gate4 restart fixture root");
        let root = directory.path();
        let user_path = database::user_database_path(root);
        let privacy_path = root.join(PRIVACY_DATABASE_RELATIVE);
        create_exact_v031_user_database(&user_path);
        create_exact_privacy_v1_database(&privacy_path);

        let approved = crate::approved_mcp::ApplicationBackupTestHarness::new_for_v031_migration(
            root.to_path_buf(),
        );
        let credential_probe = approved.workspace.v031_credential_probe_for_test();
        crate::v031_upgrade_r2::verify_exact_target_absence(root, &credential_probe)
            .expect("fresh Gate4 fixture has exact target absence");
        let rollback = crate::commands::original_migration_backup::establish_original_migration_backup_with_credential_probe_for_test(
            root,
            &user_path,
            &privacy_path,
            &credential_probe,
        )
        .expect("real V2 and receipts zero/one commit");
        let target = crate::commands::v031_target_components::prepare_v031_target_components_with_ephemeral_workspace_for_test(
            root,
            &rollback,
            &approved.workspace,
        )
        .expect("real target components and receipt two commit");
        let mut observed_restart_counts = Vec::new();
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            3,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: None,
                privacy_v5: None,
                binding_materials: None,
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            root.to_path_buf(),
            target.workspace_instance_id().clone(),
            Arc::new(approved.workspace.clone()),
        )
        .expect("migration manager opens exact Privacy v1 and prepared Vault");
        let privacy_receipt_signer = privacy::ReceiptSigner::new(
            approved
                .ephemeral_secret_key()
                .expect("one-test CSPRNG receipt key"),
        )
        .expect("one-test receipt signer constructs");
        manager.set_test_runtime(privacy_receipt_signer.clone(), receipt_timestamp_for_test());
        let case_backups = crate::commands::v031_checkpoint_receipts::ensure_v031_case_migration_backups_verified_gate(
            root,
            &manager,
            &approved.workspace,
            &target,
        )
        .expect("real binding/material V3 checkpoints and receipt three commit");
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            4,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: None,
                binding_materials: None,
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        let lineage_directory =
            crate::v031_upgrade_r2::canonical_lineage_directory(root, rollback.lineage_id())
                .expect("real Gate4 lineage directory resolves");
        let history_before_privacy_v5 = snapshot_regular_files(&lineage_directory);
        let user_v10_before_privacy_v5 =
            with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                .expect("User-v10 validates immediately before Privacy v1-to-v5")
                .0;
        assert!(
            crate::commands::v031_privacy_migration::ensure_v031_privacy_v5_verified_with_failure_for_test(
                root,
                &manager,
                &approved.workspace,
                &case_backups,
                crate::commands::v031_privacy_migration::V031PrivacyV5FailurePoint::AfterPrivacyV5CommitBeforeReceipt4,
            )
            .is_err(),
            "the production Gate4 coordinator stops after the real v5 commit and before receipt four"
        );
        let exact_v5 = {
            let privacy = open_existing_privacy_database(&privacy_path, false)
                .expect("committed Privacy-v5 opens read-only");
            privacy::compute_privacy_v5_manifests_read_only(&privacy)
                .expect("the injected boundary leaves exact Privacy-v5")
        };
        assert_eq!(exact_v5.schema_version, 5);
        assert_eq!(
            exact_v5.schema_object_count,
            privacy::PRIVACY_V5_SCHEMA_OBJECT_COUNT
        );
        let receipt_four = V031UpgradeReceiptStage::PrivacyV5Verified;
        assert!(!lineage_directory
            .join(receipt_four.incoming_basename())
            .exists());
        assert!(!lineage_directory
            .join(receipt_four.final_basename())
            .exists());
        assert_eq!(
            snapshot_regular_files(&lineage_directory),
            history_before_privacy_v5,
            "the commit-before-receipt fault does not rewrite V2, V3 checkpoints, or receipts zero through three"
        );
        assert_eq!(
            with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                .expect("User-v10 remains exact after Privacy-v5 commits")
                .0,
            user_v10_before_privacy_v5,
            "Privacy v1-to-v5 never writes the User-v10 source"
        );

        let privacy_after_fault = snapshot_sqlite_family(root, &privacy_path);
        drop(manager);
        let restarted_manager =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                root.to_path_buf(),
                target.workspace_instance_id().clone(),
                Arc::new(approved.workspace.clone()),
            )
            .expect("a new process constructs the maintenance-deferred migration manager");
        restarted_manager
            .set_test_runtime(privacy_receipt_signer.clone(), receipt_timestamp_for_test());
        assert_eq!(
            snapshot_sqlite_family(root, &privacy_path),
            privacy_after_fault,
            "new-process startup observes committed Privacy-v5 without rewriting it"
        );
        let privacy_v5 = crate::commands::v031_privacy_migration::ensure_v031_privacy_v5_verified(
            root,
            &restarted_manager,
            &approved.workspace,
            &case_backups,
        )
        .expect("ordinary ensure resumes the committed v5 state and installs receipt four");
        assert_eq!(
            snapshot_sqlite_family(root, &privacy_path),
            privacy_after_fault,
            "receipt-four resume proves exact v5 without rewriting Privacy"
        );
        assert!(!lineage_directory
            .join(receipt_four.incoming_basename())
            .exists());
        assert!(lineage_directory
            .join(receipt_four.final_basename())
            .is_file());
        let completed_gate_four = snapshot_regular_files(root);
        let repeated_privacy_v5 =
            crate::commands::v031_privacy_migration::ensure_v031_privacy_v5_verified(
                root,
                &restarted_manager,
                &approved.workspace,
                &case_backups,
            )
            .expect("a completed Gate4 verifies as an ordinary no-op");
        assert_same_durable_privacy_v5(&privacy_v5, &repeated_privacy_v5);
        assert_eq!(
            snapshot_regular_files(root),
            completed_gate_four,
            "a second Gate4 ensure is a full-tree no-op"
        );

        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            5,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: Some(&privacy_v5),
                binding_materials: None,
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        let user_v10_before_binding =
            with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                .expect("User-v10 validates immediately before binding/material migration")
                .0;
        let receipt_five = V031UpgradeReceiptStage::BindingMaterialsVerified;
        let history_before_binding_commit = snapshot_regular_files(&lineage_directory);
        assert!(
            crate::commands::v031_privacy_migration::ensure_v031_binding_materials_verified_with_failure_for_test(
                root,
                &restarted_manager,
                &approved.workspace,
                &privacy_v5,
                crate::privacy_workflow::BackfillFailurePoint::AfterCommit,
            )
            .is_err(),
            "the production Step-5 coordinator stops immediately after the real binding/material commit"
        );
        assert!(!lineage_directory
            .join(receipt_five.incoming_basename())
            .exists());
        assert!(!lineage_directory
            .join(receipt_five.final_basename())
            .exists());
        assert_eq!(
            snapshot_regular_files(&lineage_directory),
            history_before_binding_commit,
            "the binding/material commit fault leaves V2, all checkpoints, and receipts zero through four unchanged"
        );
        let terminal_after_commit = restarted_manager
            .v031_binding_material_terminal_proof_after_checkpoints(
                case_backups.rollback_gate(),
                case_backups.target_gate(),
                case_backups.binding_checkpoint(),
                case_backups.material_checkpoint(),
            )
            .expect("the committed binding/material identity and cardinality prove read-only");
        assert_eq!(
            with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                .expect("binding/material commit leaves User-v10 exact")
                .0,
            user_v10_before_binding,
            "binding/material commit never writes User-v10"
        );
        let privacy_after_binding_commit = snapshot_sqlite_family(root, &privacy_path);
        let user_after_binding_commit = snapshot_sqlite_family(root, &user_path);
        drop(restarted_manager);

        let receipt_five_manager =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                root.to_path_buf(),
                target.workspace_instance_id().clone(),
                Arc::new(approved.workspace.clone()),
            )
            .expect("receipt-five restart constructs a maintenance-deferred manager");
        receipt_five_manager.set_test_runtime(privacy_receipt_signer, receipt_timestamp_for_test());
        assert_eq!(
            snapshot_sqlite_family(root, &privacy_path),
            privacy_after_binding_commit,
            "receipt-five process restart does not rewrite Privacy"
        );
        assert_eq!(
            snapshot_sqlite_family(root, &user_path),
            user_after_binding_commit,
            "receipt-five process restart does not rewrite User-v10"
        );
        let binding_materials =
            crate::commands::v031_privacy_migration::ensure_v031_binding_materials_verified(
                root,
                &receipt_five_manager,
                &approved.workspace,
                &privacy_v5,
            )
            .expect("ordinary ensure appends only receipt five after committed Step 5");
        assert_eq!(binding_materials.terminal_proof(), &terminal_after_commit);
        assert_eq!(
            snapshot_sqlite_family(root, &privacy_path),
            privacy_after_binding_commit,
            "receipt-five resume preserves the committed binding/material database byte-for-byte"
        );
        assert_eq!(
            snapshot_sqlite_family(root, &user_path),
            user_after_binding_commit,
            "receipt-five resume preserves User-v10 byte-for-byte"
        );
        assert!(!lineage_directory
            .join(receipt_five.incoming_basename())
            .exists());
        assert!(lineage_directory
            .join(receipt_five.final_basename())
            .is_file());
        let completed_gate_five = snapshot_regular_files(root);
        let repeated_binding_materials =
            crate::commands::v031_privacy_migration::ensure_v031_binding_materials_verified(
                root,
                &receipt_five_manager,
                &approved.workspace,
                &privacy_v5,
            )
            .expect("completed Gate5 verifies as an ordinary no-op");
        assert_same_durable_binding_materials(&binding_materials, &repeated_binding_materials);
        assert_eq!(
            snapshot_regular_files(root),
            completed_gate_five,
            "a second Gate5 ensure is a full-tree no-op"
        );
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            6,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: Some(&privacy_v5),
                binding_materials: Some(&binding_materials),
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        assert_eq!(observed_restart_counts, [3, 4, 5, 6]);
    }

    #[cfg(windows)]
    #[test]
    fn committed_user_v11_resume_rebuilds_real_gate_seven_and_rejects_database_tamper() {
        // This full-chain test replaces only the four fixed production
        // Credential Manager names with one CSPRNG-backed ephemeral in-memory
        // provider. V2/V3/DPAPI, all receipts/checkpoints/migrations, and every
        // production loader below remain real. A separate unique-prefix test
        // covers the platform Credential Manager roundtrip. Fixed production
        // names and clean-machine provisioning remain external R7 gates; this
        // fixture intentionally makes no claim about either environment gate.
        let directory = tempfile::tempdir().expect("real committed-resume fixture root");
        let root = directory.path();
        let user_path = database::user_database_path(root);
        let privacy_path = root.join(PRIVACY_DATABASE_RELATIVE);
        create_exact_v031_user_database(&user_path);
        create_exact_privacy_v1_database(&privacy_path);

        let approved = crate::approved_mcp::ApplicationBackupTestHarness::new_for_v031_migration(
            root.to_path_buf(),
        );
        let credential_probe = approved.workspace.v031_credential_probe_for_test();
        crate::v031_upgrade_r2::verify_exact_target_absence(root, &credential_probe)
            .expect("fresh real fixture has exact target absence before receipt zero");
        let rollback = crate::commands::original_migration_backup::establish_original_migration_backup_with_credential_probe_for_test(
            root,
            &user_path,
            &privacy_path,
            &credential_probe,
        )
        .expect("real V2 and receipts zero/one commit");
        let target = crate::commands::v031_target_components::prepare_v031_target_components_with_ephemeral_workspace_for_test(
            root,
            &rollback,
            &approved.workspace,
        )
        .expect("real target components and receipt two commit");
        let mut observed_restart_counts = Vec::new();
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            3,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: None,
                privacy_v5: None,
                binding_materials: None,
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );

        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            root.to_path_buf(),
            target.workspace_instance_id().clone(),
            Arc::new(approved.workspace.clone()),
        )
        .expect("migration manager opens exact Privacy v1 and prepared Vault");
        let receipt_signer = privacy::ReceiptSigner::new(
            approved
                .ephemeral_secret_key()
                .expect("one-test CSPRNG receipt key"),
        )
        .expect("one-test receipt signer constructs");
        manager.set_test_runtime(receipt_signer, receipt_timestamp_for_test());

        let case_backups = crate::commands::v031_checkpoint_receipts::ensure_v031_case_migration_backups_verified_gate(
            root,
            &manager,
            &approved.workspace,
            &target,
        )
        .expect("real binding/material V3 checkpoints and receipt three commit");
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            4,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: None,
                binding_materials: None,
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        let privacy_v5 = crate::commands::v031_privacy_migration::ensure_v031_privacy_v5_verified(
            root,
            &manager,
            &approved.workspace,
            &case_backups,
        )
        .expect("real Privacy v1-to-v5 and receipt four commit");
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            5,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: Some(&privacy_v5),
                binding_materials: None,
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        let binding_materials =
            crate::commands::v031_privacy_migration::ensure_v031_binding_materials_verified(
                root,
                &manager,
                &approved.workspace,
                &privacy_v5,
            )
            .expect("real binding/material migration and receipt five commit");
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            6,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: Some(&privacy_v5),
                binding_materials: Some(&binding_materials),
                projection: None,
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        let projection =
            crate::commands::v031_checkpoint_receipts::ensure_v031_projection_backup_verified_gate(
                root,
                &manager,
                &approved.workspace,
                &binding_materials,
            )
            .expect("real projection V3 checkpoint and receipt six commit");
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            7,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: Some(&privacy_v5),
                binding_materials: Some(&binding_materials),
                projection: Some(&projection),
                privacy_v6: None,
            },
            &mut observed_restart_counts,
        );
        let privacy_v6 = crate::commands::v031_privacy_migration::ensure_v031_privacy_v6_verified(
            root,
            &manager,
            &approved.workspace,
            &projection,
        )
        .expect("real Privacy v6 projection and receipt seven commit");
        assert_v6_historical_gate4_gate5_loaders_are_read_only_and_fail_closed(
            root,
            &manager,
            &approved.workspace,
            &case_backups,
            &privacy_v5,
            &binding_materials,
        );
        assert_process_start_restart_prefix_read_only(
            root,
            &approved.workspace,
            8,
            ExpectedRestartPrefix {
                rollback: &rollback,
                target: &target,
                case_backups: Some(&case_backups),
                privacy_v5: Some(&privacy_v5),
                binding_materials: Some(&binding_materials),
                projection: Some(&projection),
                privacy_v6: Some(&privacy_v6),
            },
            &mut observed_restart_counts,
        );
        assert_eq!(observed_restart_counts, [3, 4, 5, 6, 7, 8]);

        let step_seven_state = || {
            let user = Connection::open(&user_path).expect("Step-7 User state opens");
            let schema = exact_user_schema_version(&user).expect("Step-7 User schema is exact");
            let audit_rows: i64 = user
                .query_row(
                    "SELECT COUNT(*) FROM operation_audit
                     WHERE origin='desktop' AND operation=?1 AND idempotency_key_hash=?2",
                    (
                        database::V031_TO_V040_USER_AUDIT_OPERATION,
                        privacy_v6.receipt_context().lineage_id.as_str(),
                    ),
                    |row| row.get(0),
                )
                .expect("Step-7 User audit cardinality reads");
            let privacy = Connection::open(&privacy_path).expect("Step-7 Privacy state opens");
            let lineage_rows: i64 = privacy
                .query_row(
                    "SELECT COUNT(*) FROM application_upgrade_lineage WHERE lineage_id=?1",
                    [privacy_v6.receipt_context().lineage_id.as_str()],
                    |row| row.get(0),
                )
                .expect("Step-7 Privacy lineage cardinality reads");
            (schema, audit_rows, lineage_rows)
        };
        let assert_receipt_eight_absent = || {
            let lineage_directory = crate::v031_upgrade_r2::canonical_lineage_directory(
                root,
                privacy_v6.receipt_context().lineage_id.as_str(),
            )
            .expect("Step-7 lineage directory resolves");
            let stage = V031UpgradeReceiptStage::UserV11Verified;
            assert!(!lineage_directory.join(stage.incoming_basename()).exists());
            assert!(!lineage_directory.join(stage.final_basename()).exists());
        };
        assert_eq!(
            step_seven_state(),
            (V031_USER_SCHEMA_VERSION, 0, 0),
            "Gate 7 leaves the original User-v10 source untouched before Step 7"
        );
        let source_before_step_seven =
            with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                .expect("the exact User-v10 source validates immediately before Step 7")
                .0;

        assert!(
            ensure_v031_user_v11_verified_with_failure_for_test(
                root,
                &manager,
                &approved.workspace,
                privacy_v6.receipt_context().lineage_id.as_str(),
                LedgerFailurePoint::BeforeUserTransaction,
            )
            .is_err(),
            "the production coordinator stops before the User transaction"
        );
        assert_eq!(step_seven_state(), (V031_USER_SCHEMA_VERSION, 0, 0));
        assert_eq!(
            with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                .expect("the pre-transaction User-v10 source remains exact")
                .0,
            source_before_step_seven,
            "all Step-7 prerequisite work is read-only against User-v10"
        );
        assert_receipt_eight_absent();

        assert!(
            ensure_v031_user_v11_verified_with_failure_for_test(
                root,
                &manager,
                &approved.workspace,
                privacy_v6.receipt_context().lineage_id.as_str(),
                LedgerFailurePoint::AfterUserTransactionCommit,
            )
            .is_err(),
            "the production coordinator resumes and stops after the real User transaction"
        );
        assert_eq!(step_seven_state(), (USER_SCHEMA_VERSION, 1, 0));
        assert_receipt_eight_absent();

        let after_user_commit = snapshot_regular_files(root);
        assert!(
            ensure_v031_user_v11_verified_with_failure_for_test(
                root,
                &manager,
                &approved.workspace,
                privacy_v6.receipt_context().lineage_id.as_str(),
                LedgerFailurePoint::BeforePrivacyLineageAppend,
            )
            .is_err(),
            "the production coordinator verifies the committed User transaction and stops before Privacy lineage"
        );
        assert_eq!(step_seven_state(), (USER_SCHEMA_VERSION, 1, 0));
        assert_eq!(
            snapshot_regular_files(root),
            after_user_commit,
            "the before-lineage resume verifies the committed User audit without rewriting it"
        );
        assert_receipt_eight_absent();

        let before_absent_resume = snapshot_regular_files(root);
        let absent_lineage_resume = load_v031_committed_user_v11_resume_proof_read_only(
            root,
            privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("committed user with absent Privacy lineage authenticates");
        assert_eq!(absent_lineage_resume.privacy_lineage_sha256(), None);
        let absent_lineage_gate =
            load_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
                root,
                &manager,
                &approved.workspace,
                &projection,
                &absent_lineage_resume,
            )
            .expect("special Gate7 loader accepts the authenticated absent-lineage window");
        verify_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
            root,
            &manager,
            &approved.workspace,
            &absent_lineage_gate,
            &absent_lineage_resume,
        )
        .expect("special Gate7 verifier accepts the absent-lineage window");
        assert_eq!(absent_lineage_gate, privacy_v6);
        assert_eq!(
            snapshot_regular_files(root),
            before_absent_resume,
            "committed-user proof and special Gate7 reconstruction are read-only"
        );

        let privacy = Connection::open(&privacy_path).expect("Privacy tamper fixture opens");
        let original_metadata_timestamp = privacy
            .query_row(
                "SELECT updated_at FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("Privacy schema timestamp reads");
        let tampered_metadata_timestamp = if original_metadata_timestamp == "2099-01-01 00:00:00" {
            "2099-01-02 00:00:00"
        } else {
            "2099-01-01 00:00:00"
        };
        privacy
            .execute(
                "UPDATE privacy_schema_metadata SET updated_at=?1 WHERE key='schema_version'",
                [tampered_metadata_timestamp],
            )
            .expect("Privacy logical manifest is actually changed");
        drop(privacy);
        assert!(
            load_v031_committed_user_v11_resume_proof_read_only(
                root,
                privacy_v6.receipt_context().lineage_id.as_str(),
            )
            .is_err(),
            "a real post-commit Privacy manifest change fails closed"
        );
        let privacy = Connection::open(&privacy_path).expect("Privacy tamper fixture reopens");
        privacy
            .execute(
                "UPDATE privacy_schema_metadata SET updated_at=?1 WHERE key='schema_version'",
                [original_metadata_timestamp.as_str()],
            )
            .expect("Privacy logical manifest is restored exactly");
        drop(privacy);
        assert_eq!(
            load_v031_committed_user_v11_resume_proof_read_only(
                root,
                privacy_v6.receipt_context().lineage_id.as_str(),
            )
            .expect("restored absent-lineage state authenticates"),
            absent_lineage_resume
        );

        assert!(
            ensure_v031_user_v11_verified_with_failure_for_test(
                root,
                &manager,
                &approved.workspace,
                privacy_v6.receipt_context().lineage_id.as_str(),
                LedgerFailurePoint::AfterPrivacyLineageAppend,
            )
            .is_err(),
            "the production coordinator resumes and stops after the real Privacy lineage append"
        );
        assert_eq!(step_seven_state(), (USER_SCHEMA_VERSION, 1, 1));
        assert_receipt_eight_absent();
        let before_present_resume = snapshot_regular_files(root);
        let ledger_cardinality = || {
            let user = Connection::open(&user_path).expect("user ledger cardinality opens");
            let relevant_user_audits: i64 = user
                .query_row(
                    "SELECT COUNT(*) FROM operation_audit
                     WHERE origin='desktop' AND operation=?1 AND idempotency_key_hash=?2",
                    (
                        database::V031_TO_V040_USER_AUDIT_OPERATION,
                        privacy_v6.receipt_context().lineage_id.as_str(),
                    ),
                    |row| row.get(0),
                )
                .expect("user ledger cardinality reads");
            let privacy = Connection::open(&privacy_path).expect("Privacy cardinality opens");
            let count = |table: &str| {
                privacy
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .expect("Privacy fixture table cardinality reads")
            };
            (
                relevant_user_audits,
                count("application_upgrade_lineage"),
                [
                    count("project_privacy_case_bindings"),
                    count("project_privacy_case_binding_audit"),
                    count("privacy_materials"),
                    count("privacy_redactions"),
                    count("case_material_migration_ledger"),
                    count("case_material_migration_events"),
                ],
            )
        };
        let before_present_cardinality = ledger_cardinality();
        assert_eq!(before_present_cardinality.0, 1);
        assert_eq!(before_present_cardinality.1, 1);
        assert_eq!(
            before_present_cardinality.2,
            [0, 0, 0, 0, 1, 1],
            "the real fixture has one committed case-material migration ledger/event pair and no unrelated business rows"
        );
        let present_lineage_resume = load_v031_committed_user_v11_resume_proof_read_only(
            root,
            privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("committed user with present Privacy lineage authenticates");
        assert!(present_lineage_resume.privacy_lineage_sha256().is_some());
        let present_lineage_gate =
            load_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
                root,
                &manager,
                &approved.workspace,
                &projection,
                &present_lineage_resume,
            )
            .expect("special Gate7 loader accepts the authenticated present-lineage window");
        verify_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
            root,
            &manager,
            &approved.workspace,
            &present_lineage_gate,
            &present_lineage_resume,
        )
        .expect("special Gate7 verifier accepts the present-lineage window");
        let repeated_resume = load_v031_committed_user_v11_resume_proof_read_only(
            root,
            privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("present-lineage proof reloads as a no-op");
        let repeated_gate =
            load_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
                root,
                &manager,
                &approved.workspace,
                &projection,
                &repeated_resume,
            )
            .expect("present-lineage Gate7 reloads as a no-op");
        assert_eq!(present_lineage_resume, repeated_resume);
        assert_eq!(present_lineage_gate, repeated_gate);
        assert_eq!(present_lineage_gate, privacy_v6);
        assert_eq!(ledger_cardinality(), before_present_cardinality);
        assert_eq!(
            snapshot_regular_files(root),
            before_present_resume,
            "repeated committed-user and Gate7 loaders do not rewrite any fixture file"
        );

        let receipt_eight = ensure_v031_user_v11_verified(
            root,
            &manager,
            &approved.workspace,
            privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("real receipt eight commits");
        assert_eq!(step_seven_state(), (USER_SCHEMA_VERSION, 1, 1));
        assert_eq!(ledger_cardinality(), before_present_cardinality);
        let after_receipt_eight = snapshot_regular_files(root);
        let repeated_receipt_eight = ensure_v031_user_v11_verified(
            root,
            &manager,
            &approved.workspace,
            privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("a completed Step 7 verifies as a production no-op");
        assert_eq!(repeated_receipt_eight, receipt_eight);
        assert_eq!(step_seven_state(), (USER_SCHEMA_VERSION, 1, 1));
        assert_eq!(ledger_cardinality(), before_present_cardinality);
        assert_eq!(
            snapshot_regular_files(root),
            after_receipt_eight,
            "the second ordinary Step-7 ensure neither duplicates ledgers nor rewrites receipt eight"
        );
        let process_start = crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(root)
            .expect("receipt-eight process-start observation authenticates");
        let observed_receipt_eight = process_start
            .receipt_eight_observed_at_process_start()
            .expect("process-start observation returns the receipt-eight capability")
            .clone();
        let predecessor = crate::commands::v031_upgrade_complete::install_and_authenticate_v031_step8_predecessor_for_test(
            root,
            &observed_receipt_eight,
            receipt_eight.clone(),
        )
        .expect("real DPAPI Step-8 predecessor installs and authenticates");
        let before_historical_load = snapshot_regular_files(root);
        let historical =
            load_v031_historical_receipt_eight_verified_gate_read_only(root, &predecessor)
                .expect("historical receipt eight authenticates before ordinary writes");
        assert_eq!(
            historical.user_v11_receipt_sha256(),
            receipt_eight.user_v11_receipt_sha256()
        );
        assert_eq!(
            historical.final_component_manifest(),
            receipt_eight.final_component_manifest()
        );
        assert_eq!(
            snapshot_regular_files(root),
            before_historical_load,
            "historical receipt-eight reconstruction is read-only"
        );

        let lineage_directory = crate::v031_upgrade_r2::canonical_lineage_directory(
            root,
            receipt_eight.receipt_context().lineage_id.as_str(),
        )
        .expect("lineage directory resolves");
        let binding_bundle_path =
            lineage_directory.join(V031CheckpointKind::Binding.bundle_final_basename());
        let original_binding_bundle =
            fs::read(&binding_bundle_path).expect("binding checkpoint bundle reads");
        let mut tampered_binding_bundle = original_binding_bundle.clone();
        tampered_binding_bundle[0] ^= 0x01;
        fs::write(&binding_bundle_path, &tampered_binding_bundle)
            .expect("binding checkpoint bundle is actually tampered");
        let attacker_recalculated_records =
            capture_v031_historical_checkpoint_file_records_read_only(
                root,
                receipt_eight.receipt_context().lineage_id.as_str(),
            )
            .expect("attacker can recalculate raw checkpoint data, but not an authority");
        assert_ne!(
            attacker_recalculated_records.as_slice(),
            predecessor.checkpoint_files(),
            "the authenticated DPAPI sidecar keeps the original binding/material anchors"
        );
        assert!(
            load_v031_historical_receipt_eight_verified_gate_read_only(root, &predecessor,)
                .is_err()
        );
        assert!(crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(root).is_err());
        fs::write(&binding_bundle_path, &original_binding_bundle)
            .expect("binding checkpoint bundle restores exactly");
        load_v031_historical_receipt_eight_verified_gate_read_only(root, &predecessor)
            .expect("restored binding checkpoint authenticates against the fixed DPAPI sidecar");

        let user = Connection::open(&user_path).expect("ordinary user write opens");
        user.execute(
            "INSERT INTO operation_audit (
                 audit_id, origin, operation, project_id, request_hash,
                 idempotency_key_hash, status, details_json, created_at, finished_at
             ) VALUES (
                 'post-receipt-eight-business-write', 'desktop', 'ordinary_business_write',
                 NULL, ?1, NULL, 'succeeded', '{}',
                 '2099-01-01 00:00:00', '2099-01-01 00:00:00'
             )",
            [&"a".repeat(64)],
        )
        .expect("ordinary post-receipt-eight business row inserts");
        drop(user);
        assert!(load_v031_user_v11_verified_gate_read_only(
            root,
            &manager,
            &approved.workspace,
            receipt_eight.receipt_context().lineage_id.as_str(),
        )
        .is_err());
        let after_business_write = snapshot_regular_files(root);
        load_v031_historical_receipt_eight_verified_gate_read_only(root, &predecessor)
            .expect("historical receipt eight tolerates later ordinary business rows");
        assert_eq!(snapshot_regular_files(root), after_business_write);
        let user = Connection::open(&user_path).expect("ordinary user write cleanup opens");
        assert_eq!(
            user.execute(
                "DELETE FROM operation_audit WHERE audit_id='post-receipt-eight-business-write'",
                [],
            )
            .expect("ordinary post-receipt-eight row cleans up"),
            1
        );
        drop(user);

        load_v031_user_v11_verified_gate_read_only(
            root,
            &manager,
            &approved.workspace,
            receipt_eight.receipt_context().lineage_id.as_str(),
        )
        .expect("deleting the ordinary business row restores the exact live receipt-eight state");

        crate::commands::v031_upgrade_complete::fail_upgrade_evidence_after_authenticated_incoming_for_test();
        let evidence_injected =
            crate::commands::v031_upgrade_complete::ensure_v031_upgrade_complete(
                root,
                &manager,
                &approved.workspace,
                &observed_receipt_eight,
            );
        crate::commands::v031_upgrade_complete::clear_upgrade_evidence_install_failure_for_test();
        let evidence_error = match evidence_injected {
            Err(error) => error,
            Ok(_) => panic!(
                "the production Step-9 evidence installer must stop after authenticated incoming"
            ),
        };
        assert!(
            lineage_directory
                .join(crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_INCOMING)
                .is_file(),
            "Step-9 failed before its injected incoming window: {evidence_error:?}"
        );
        assert!(!lineage_directory
            .join(crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_FINAL)
            .exists());
        assert!(!lineage_directory
            .join(V031UpgradeReceiptStage::UpgradeComplete.incoming_basename())
            .exists());
        let evidence_crash_observation =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                root,
            )
            .expect("Step-9 evidence incoming crash state authenticates read-only");
        let evidence_resume_gate = evidence_crash_observation
            .receipt_eight_observed_at_process_start()
            .expect("restart rebuilds Gate8 for Step-9 evidence resume")
            .clone();
        assert!(!evidence_resume_gate.incoming_receipt_nine_observed());
        let exact_current = match crate::v031_startup::
            observe_exact_current_profile_with_approved_workspace_for_test(
                root,
                &approved.workspace,
            )
            .expect("restart reconstructs the exact isolated current five-slot profile")
        {
            crate::v031_startup::ExactCurrentProfileObservation::Exact(gate) => gate,
            crate::v031_startup::ExactCurrentProfileObservation::NotCurrent => {
                panic!("the migrated fixture must remain an exact current profile")
            }
        };
        assert_eq!(
            exact_current.workspace_instance_id(),
            target.workspace_instance_id(),
            "the isolated exact-current observer preserves the target workspace identity"
        );

        crate::v031_upgrade_r2::fail_next_receipt_after_authenticated_incoming_for_test();
        let injected = crate::v031_startup::run_step_eight_with_existing_managers_for_test(
            root,
            &evidence_crash_observation,
            &manager,
            &approved.workspace,
        );
        crate::v031_upgrade_r2::clear_receipt_install_failure_for_test();
        assert!(
            injected.is_err(),
            "the production Receipt-9 installer stops at the injected post-incoming crash window"
        );
        assert!(lineage_directory
            .join(crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_FINAL)
            .is_file());
        assert!(lineage_directory
            .join(V031UpgradeReceiptStage::UpgradeComplete.incoming_basename())
            .is_file());
        assert!(!lineage_directory
            .join(V031UpgradeReceiptStage::UpgradeComplete.final_basename())
            .exists());
        let receipt_nine_crash_observation =
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
                root,
            )
            .expect("receipt-nine incoming crash state authenticates read-only");
        let receipt_nine_resume_gate = receipt_nine_crash_observation
            .receipt_eight_observed_at_process_start()
            .expect("restart rebuilds the receipt-eight capability for Receipt-9 resume")
            .clone();
        assert!(receipt_nine_resume_gate.incoming_receipt_nine_observed());
        crate::v031_startup::run_step_eight_with_existing_managers_for_test(
            root,
            &receipt_nine_crash_observation,
            &manager,
            &approved.workspace,
        )
        .expect("the production Gate-8 helper resumes the exact Receipt-9 incoming bytes");
        assert!(!lineage_directory
            .join(V031UpgradeReceiptStage::UpgradeComplete.incoming_basename())
            .exists());
        assert!(lineage_directory
            .join(V031UpgradeReceiptStage::UpgradeComplete.final_basename())
            .is_file());
        assert_eq!(
            crate::commands::original_migration_backup::verify_terminal_history_for_receipt_zero_bootstrap_for_test(root)
                .expect("fresh-lineage bootstrap authenticates the complete terminal history"),
            1
        );

        let terminal_bridge = PrivacyReceiptAuthenticationBridge::discovering();
        let terminal_inventory = load_authenticated_v031_lineage(
            root,
            receipt_eight.receipt_context().lineage_id.as_str(),
            &terminal_bridge,
        )
        .expect("terminal receipt chain authenticates");
        let terminal_context = terminal_bridge
            .context()
            .expect("terminal receipt context authenticates");
        crate::commands::v031_upgrade_complete::authenticate_v031_terminal_history_offline(
            root,
            &terminal_inventory,
            &terminal_context,
        )
        .expect("terminal predecessor and receipt-nine evidence authenticate together");

        let receipt_nine_evidence_path =
            lineage_directory.join(crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_FINAL);
        let receipt_nine_evidence =
            fs::read(&receipt_nine_evidence_path).expect("receipt-nine evidence sidecar reads");
        let mut tampered_receipt_nine_evidence = receipt_nine_evidence.clone();
        let last = tampered_receipt_nine_evidence.len() - 1;
        tampered_receipt_nine_evidence[last] ^= 0x01;
        fs::write(&receipt_nine_evidence_path, &tampered_receipt_nine_evidence)
            .expect("receipt-nine evidence sidecar is actually tampered");
        let before_terminal_rejections = snapshot_regular_files(root);
        assert!(
            crate::commands::v031_upgrade_complete::authenticate_v031_terminal_history_offline(
                root,
                &terminal_inventory,
                &terminal_context,
            )
            .is_err(),
            "the offline terminal gate decrypts and rejects tampered receipt-nine evidence"
        );
        assert!(
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(root)
                .is_err(),
            "the earliest process-start observer rejects tampered receipt-nine evidence"
        );
        assert!(
            crate::commands::original_migration_backup::verify_terminal_history_for_receipt_zero_bootstrap_for_test(root)
                .is_err(),
            "fresh-lineage bootstrap rejects terminal tamper before it can prepare receipt zero"
        );
        assert_eq!(
            snapshot_regular_files(root),
            before_terminal_rejections,
            "all three terminal rejection paths are source- and history-read-only"
        );
        fs::write(&receipt_nine_evidence_path, &receipt_nine_evidence)
            .expect("receipt-nine evidence sidecar restores exactly");
        crate::commands::v031_upgrade_complete::authenticate_v031_terminal_history_offline(
            root,
            &terminal_inventory,
            &terminal_context,
        )
        .expect("restored receipt-nine evidence authenticates");
        assert_eq!(
            crate::commands::original_migration_backup::verify_terminal_history_for_receipt_zero_bootstrap_for_test(root)
                .expect("restored complete terminal history authorizes fresh-lineage bootstrap"),
            1
        );

        let foreign_lineage_id = "f".repeat(64);
        let foreign_lineage_sidecar = crate::commands::v031_upgrade_complete::build_foreign_lineage_upgrade_complete_sidecar_for_test(
            &receipt_nine_evidence_path,
            &foreign_lineage_id,
        )
        .expect("a canonical DPAPI sidecar for a foreign lineage is built");
        fs::write(&receipt_nine_evidence_path, &foreign_lineage_sidecar)
            .expect("foreign-lineage receipt-nine sidecar is copied into the terminal lineage");
        let before_cross_lineage_rejections = snapshot_regular_files(root);
        assert!(
            crate::commands::v031_upgrade_complete::authenticate_v031_terminal_history_offline(
                root,
                &terminal_inventory,
                &terminal_context,
            )
            .is_err(),
            "an internally valid Receipt-9 sidecar cannot cross lineage boundaries"
        );
        assert!(
            crate::commands::original_migration_backup::verify_terminal_history_for_receipt_zero_bootstrap_for_test(root)
                .is_err(),
            "foreign-lineage Receipt-9 evidence is rejected before receipt-zero bootstrap"
        );
        assert_eq!(
            snapshot_regular_files(root),
            before_cross_lineage_rejections,
            "cross-lineage rejection creates no new lineage or receipt-zero file"
        );
        fs::write(&receipt_nine_evidence_path, &receipt_nine_evidence)
            .expect("same-lineage receipt-nine evidence restores exactly");
        assert_eq!(
            crate::commands::original_migration_backup::verify_terminal_history_for_receipt_zero_bootstrap_for_test(root)
                .expect("same-lineage complete terminal history authenticates again"),
            1
        );

        let v2_bundle_path = lineage_directory.join(crate::v031_upgrade_r2::V2_BUNDLE_FINAL);
        let v2_bundle = fs::read(&v2_bundle_path).expect("terminal Original-V2 bundle reads");
        let mut tampered_v2_bundle = v2_bundle.clone();
        let last = tampered_v2_bundle.len() - 1;
        tampered_v2_bundle[last] ^= 0x01;
        fs::write(&v2_bundle_path, &tampered_v2_bundle)
            .expect("terminal Original-V2 bundle is actually tampered");
        let before_v2_rejections = snapshot_regular_files(root);
        assert!(
            crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(root)
                .is_err(),
            "process-start terminal classification decrypts and rejects a tampered V2 bundle"
        );
        assert!(
            crate::commands::original_migration_backup::verify_terminal_history_for_receipt_zero_bootstrap_for_test(root)
                .is_err(),
            "fresh-lineage bootstrap rejects a tampered historical V2 bundle before receipt zero"
        );
        assert_eq!(
            snapshot_regular_files(root),
            before_v2_rejections,
            "V2 terminal rejection is read-only and creates no receipt-zero lineage"
        );
        fs::write(&v2_bundle_path, &v2_bundle)
            .expect("terminal Original-V2 bundle restores exactly");
        crate::commands::v031_upgrade_complete::observe_v031_upgrade_at_process_start_read_only(
            root,
        )
        .expect("restored terminal V2 bundle authenticates at process start");
        assert_eq!(
            crate::commands::original_migration_backup::verify_terminal_history_for_receipt_zero_bootstrap_for_test(root)
                .expect("restored terminal V2 bundle authorizes fresh-lineage bootstrap"),
            1
        );

        let privacy = Connection::open(&privacy_path).expect("Privacy lineage tamper opens");
        let original_previous_receipt = privacy
            .query_row(
                "SELECT previous_receipt_sha256 FROM application_upgrade_lineage
                 WHERE lineage_id=?1",
                [privacy_v6.receipt_context().lineage_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .expect("installed Privacy lineage reads");
        let tampered_previous_receipt = if original_previous_receipt == "f".repeat(64) {
            "e".repeat(64)
        } else {
            "f".repeat(64)
        };
        privacy
            .execute_batch("DROP TRIGGER trg_application_upgrade_lineage_no_update;")
            .expect("immutable trigger is deliberately removed for tamper fixture");
        privacy
            .execute(
                "UPDATE application_upgrade_lineage SET previous_receipt_sha256=?1
                 WHERE lineage_id=?2",
                (
                    tampered_previous_receipt.as_str(),
                    privacy_v6.receipt_context().lineage_id.as_str(),
                ),
            )
            .expect("Privacy lineage row is actually changed");
        privacy
            .execute_batch(
                "CREATE TRIGGER trg_application_upgrade_lineage_no_update
                 BEFORE UPDATE ON application_upgrade_lineage
                 BEGIN
                     SELECT RAISE(ABORT, 'application upgrade lineage is append only');
                 END;",
            )
            .expect("canonical immutable trigger is restored");
        drop(privacy);
        assert!(matches!(
            load_v031_historical_receipt_eight_verified_gate_read_only(root, &predecessor),
            Err(V031UserUpgradeError::LedgerConflict)
        ));
        assert!(
            load_v031_committed_user_v11_resume_proof_read_only(
                root,
                privacy_v6.receipt_context().lineage_id.as_str(),
            )
            .is_err(),
            "the committed-user/no-receipt loader also fails closed after terminal lineage tamper; the historical loader above owns the exact terminal LedgerConflict classification"
        );
    }

    #[cfg(windows)]
    #[test]
    fn receipt_eight_incoming_final_and_next_stage_restart_states_fail_closed() {
        let fixture = ReceiptChainFixture::through_receipt_seven();
        let evidence =
            receipt_evidence_for_test(&fixture.context, V031UpgradeReceiptStage::UserV11Verified);
        let counts = receipt_counts_for_test(V031UpgradeReceiptStage::UserV11Verified);

        let absent = validate_receipt_eight_namespace(
            fixture.root(),
            &fixture.context,
            &fixture.receipt_seven_sha256,
            None,
            None,
        )
        .expect("receipt-eight-absent prefix authenticates");
        assert_eq!(absent.final_receipt_sha256, None);
        assert_eq!(absent.next_incoming_ordinal, None);
        assert!(matches!(
            validate_receipt_eight_namespace(
                fixture.root(),
                &fixture.context,
                &"f".repeat(64),
                Some(evidence),
                Some(&counts),
            ),
            Err(V031UserUpgradeError::ReceiptPrefix)
        ));

        fixture.write_incoming(V031UpgradeReceiptStage::UserV11Verified, &"e".repeat(64));
        assert!(matches!(
            validate_receipt_eight_namespace(
                fixture.root(),
                &fixture.context,
                &fixture.receipt_seven_sha256,
                Some(evidence),
                Some(&counts),
            ),
            Err(V031UserUpgradeError::ReceiptPrefix)
        ));

        fixture.write_incoming(
            V031UpgradeReceiptStage::UserV11Verified,
            &fixture.receipt_seven_sha256,
        );
        let incoming = validate_receipt_eight_namespace(
            fixture.root(),
            &fixture.context,
            &fixture.receipt_seven_sha256,
            Some(evidence),
            Some(&counts),
        )
        .expect("valid receipt-eight incoming authenticates");
        assert_eq!(incoming.final_receipt_sha256, None);
        assert_eq!(
            incoming.next_incoming_ordinal,
            Some(V031UpgradeReceiptStage::UserV11Verified.ordinal())
        );

        let installed = persist_v031_receipt(
            fixture.root(),
            &fixture.context,
            V031UpgradeReceiptStage::UserV11Verified,
            evidence,
            &counts,
            || Ok(()),
        )
        .expect("receipt-eight incoming resumes and installs");
        assert!(installed.newly_installed);
        let receipt_eight_sha256 = installed.receipt.protected_file_sha256;
        let final_eight = validate_receipt_eight_namespace(
            fixture.root(),
            &fixture.context,
            &fixture.receipt_seven_sha256,
            Some(evidence),
            Some(&counts),
        )
        .expect("receipt-eight final authenticates");
        assert_eq!(
            final_eight.final_receipt_sha256.as_deref(),
            Some(receipt_eight_sha256.as_str())
        );
        assert_eq!(final_eight.next_incoming_ordinal, None);

        let idempotent = persist_v031_receipt(
            fixture.root(),
            &fixture.context,
            V031UpgradeReceiptStage::UserV11Verified,
            evidence,
            &counts,
            || Ok(()),
        )
        .expect("receipt-eight final reload is a no-op");
        assert!(!idempotent.newly_installed);
        assert_eq!(
            idempotent.receipt.protected_file_sha256,
            receipt_eight_sha256
        );

        write_fixed_evidence(
            &fixture.lineage_directory,
            &[
                crate::v031_upgrade_r2::STEP8_PREDECESSOR_EVIDENCE_FINAL,
                crate::v031_upgrade_r2::UPGRADE_COMPLETE_EVIDENCE_FINAL,
            ],
        );
        fixture.write_incoming(
            V031UpgradeReceiptStage::UpgradeComplete,
            &receipt_eight_sha256,
        );
        let incoming_nine = validate_receipt_eight_namespace(
            fixture.root(),
            &fixture.context,
            &fixture.receipt_seven_sha256,
            Some(evidence),
            Some(&counts),
        )
        .expect("receipt-nine incoming preserves receipt-eight evidence");
        assert_eq!(
            incoming_nine.final_receipt_sha256.as_deref(),
            Some(receipt_eight_sha256.as_str())
        );
        assert_eq!(
            incoming_nine.next_incoming_ordinal,
            Some(V031UpgradeReceiptStage::UpgradeComplete.ordinal())
        );

        persist_v031_receipt(
            fixture.root(),
            &fixture.context,
            V031UpgradeReceiptStage::UpgradeComplete,
            receipt_evidence_for_test(&fixture.context, V031UpgradeReceiptStage::UpgradeComplete),
            &receipt_counts_for_test(V031UpgradeReceiptStage::UpgradeComplete),
            || Ok(()),
        )
        .expect("receipt-nine incoming resumes and installs");
        let terminal = validate_receipt_eight_namespace(
            fixture.root(),
            &fixture.context,
            &fixture.receipt_seven_sha256,
            Some(evidence),
            Some(&counts),
        )
        .expect("terminal ten-receipt chain preserves receipt-eight evidence");
        assert_eq!(
            terminal.final_receipt_sha256.as_deref(),
            Some(receipt_eight_sha256.as_str())
        );
        assert_eq!(terminal.next_incoming_ordinal, None);
    }

    #[test]
    fn receipt_eight_started_without_privacy_lineage_is_rejected_before_resume() {
        assert!(validate_committed_resume_lineage_presence(8, None, false).is_ok());
        assert!(validate_committed_resume_lineage_presence(8, None, true).is_ok());
        assert!(matches!(
            validate_committed_resume_lineage_presence(
                8,
                Some(V031UpgradeReceiptStage::UserV11Verified.ordinal()),
                false,
            ),
            Err(V031UserUpgradeError::LedgerConflict)
        ));
        assert!(matches!(
            validate_committed_resume_lineage_presence(9, None, false),
            Err(V031UserUpgradeError::LedgerConflict)
        ));
        assert!(matches!(
            validate_committed_resume_lineage_presence(
                9,
                Some(V031UpgradeReceiptStage::UpgradeComplete.ordinal()),
                false,
            ),
            Err(V031UserUpgradeError::LedgerConflict)
        ));
        assert!(validate_committed_resume_lineage_presence(10, None, true).is_ok());
    }
}
