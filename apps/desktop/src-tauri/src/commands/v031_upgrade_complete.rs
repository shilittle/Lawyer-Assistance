//! Restart-bound Step 8 and the terminal ordinal-9 upgrade receipt.
//!
//! The receipt-8 observation is intentionally an opaque process-start
//! capability.  Code which installs receipt 8 cannot manufacture or refresh
//! it; the desktop startup router must retain the single read-only observation
//! made before it permits any R2 mutation.

use crate::{
    approved_mcp::ApprovedMcpWorkspace,
    commands::{
        self,
        original_migration_backup::{
            verify_one_v031_terminal_history_lineage_read_only, OriginalRollbackVerifiedGate,
        },
        v031_user_upgrade::{
            capture_v031_fresh_final_component_manifest_with_rollback_read_only,
            capture_v031_historical_checkpoint_file_records_read_only,
            load_v031_historical_receipt_eight_verified_gate_read_only,
            load_v031_user_v11_verified_gate_read_only,
            verify_v031_historical_user_and_privacy_ledgers_read_only,
            V031FinalComponentManifestProof, V031FinalComponentManifestRecordV1,
            V031HistoricalCheckpointFileRecordV1, V031UserV11ReceiptEvidenceRecordV1,
            V031UserV11VerifiedGate,
        },
    },
    privacy_workflow::{
        NoopV031Step8MaintenanceFailureInjector, PrivacyWorkflowManager,
        V031Step8MaintenanceFailureInjector, V031Step8PrivacyMaintenanceReport,
    },
    v031_upgrade_r2::{
        self, AuthenticatedLineageInventory, DirectorySync, PlatformDirectorySync,
        STEP8_PREDECESSOR_EVIDENCE_FINAL, STEP8_PREDECESSOR_EVIDENCE_INCOMING,
        UPGRADE_COMPLETE_EVIDENCE_FINAL, UPGRADE_COMPLETE_EVIDENCE_INCOMING,
    },
    v031_upgrade_receipts::{
        load_authenticated_v031_lineage, persist_v031_receipt, OwnedV031ReceiptContext,
        PrivacyReceiptAuthenticationBridge, V031ReceiptPersistenceError,
    },
};

#[cfg(test)]
use crate::privacy_workflow::V031Step8MaintenanceFailurePoint;
use database::{
    with_validated_user_database_migration_source_read_only, ValidatedUserSourceSchema,
};
use privacy::{
    protect_local, unprotect_local,
    upgrade_receipt_v1::{
        V031UpgradeReceiptCountKey, V031UpgradeReceiptStage, V031_UPGRADE_RECEIPT_MIGRATION_ID,
    },
    vnext::{canonical_json_v1, strict_json_v1_from_slice},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, path::Path, sync::Mutex};
use zeroize::Zeroizing;

const REQUIRED_RESTARTS: u64 = 1;
const REQUIRED_NOOP_MIGRATIONS: u64 = 4;
const REQUIRED_FINAL_COMPONENT_SLOTS: u64 = 5;
const REQUIRED_FINAL_MANIFEST_ENTRIES: u64 = 5;
const REQUIRED_MAINTENANCE_ACTIONS: u64 = 5;
const REQUIRED_PRIVACY_MANIFEST_TABLES: u64 = privacy::PRIVACY_V6_APPLICATION_TABLES.len() as u64;
static V031_UPGRADE_COMPLETE_OPERATION: Mutex<()> = Mutex::new(());
#[cfg(test)]
std::thread_local! {
    static FAIL_UPGRADE_EVIDENCE_AFTER_AUTHENTICATED_INCOMING: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static STEP8_MAINTENANCE_ENTRY_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static PANIC_ON_STEP8_MAINTENANCE_ENTRY: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}
const STEP8_PREDECESSOR_EVIDENCE_SCHEMA: &str =
    "lawyer-assistance-v031-step8-predecessor-evidence-v1";
const MAX_STEP8_PREDECESSOR_PROTECTED_BYTES: usize = 256 * 1024;
const MAX_UPGRADE_COMPLETE_EVIDENCE_PROTECTED_BYTES: usize = 512 * 1024;
const UPGRADE_COMPLETE_EVIDENCE_BINDING_SCHEMA: &str =
    "lawyer-assistance-v031-upgrade-complete-evidence-binding-v1";
const STEP8_CLEANUP_ID_DOMAIN: &str = "lawyer-assistance-v031-step8-cleanup-id-v1";

const NOOP_MIGRATIONS: [&str; 4] = [
    "privacy_schema_v6",
    "binding_materials",
    "approved_projection",
    "user_schema_v11",
];

const MAINTENANCE_ACTIONS: [&str; 5] = [
    "privacy_recovery_retention_cleanup",
    "user_database_current_schema_validation",
    "assistant_run_recovery",
    "assistant_artifact_export_recovery",
    "document_export_recovery",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031Step8PredecessorInstallFailurePoint {
    AfterAuthenticatedIncomingReadbackBeforeRename,
    AfterFinalRenameSyncAuthenticatedReadbackAndInventory,
}

#[cfg(test)]
pub(crate) fn fail_upgrade_evidence_after_authenticated_incoming_for_test() {
    FAIL_UPGRADE_EVIDENCE_AFTER_AUTHENTICATED_INCOMING.with(|armed| armed.set(true));
}

#[cfg(test)]
pub(crate) fn clear_upgrade_evidence_install_failure_for_test() {
    FAIL_UPGRADE_EVIDENCE_AFTER_AUTHENTICATED_INCOMING.with(|armed| armed.set(false));
}

#[cfg(test)]
pub(crate) fn arm_step8_maintenance_replay_probe_for_test() {
    STEP8_MAINTENANCE_ENTRY_COUNT.with(|count| count.set(0));
    PANIC_ON_STEP8_MAINTENANCE_ENTRY.with(|armed| armed.set(true));
}

#[cfg(test)]
pub(crate) fn finish_step8_maintenance_replay_probe_for_test() -> usize {
    PANIC_ON_STEP8_MAINTENANCE_ENTRY.with(|armed| armed.set(false));
    STEP8_MAINTENANCE_ENTRY_COUNT.with(std::cell::Cell::get)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031UpgradeCompleteError {
    Namespace,
    MultipleActiveLineages,
    InvalidTerminalLineage,
    InvalidReceiptEightLineage,
    ObservationMismatch,
    ReceiptEight,
    Maintenance,
    NoopProof,
    EvidenceEncoding,
    Receipt,
}

impl V031UpgradeCompleteError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Namespace => "v031_upgrade_complete_namespace_invalid",
            Self::MultipleActiveLineages => "v031_upgrade_complete_multiple_active_lineages",
            Self::InvalidTerminalLineage => "v031_upgrade_complete_terminal_lineage_invalid",
            Self::InvalidReceiptEightLineage => {
                "v031_upgrade_complete_receipt_eight_lineage_invalid"
            }
            Self::ObservationMismatch => "v031_upgrade_complete_process_observation_mismatch",
            Self::ReceiptEight => "v031_upgrade_complete_receipt_eight_invalid",
            Self::Maintenance => "v031_upgrade_complete_maintenance_failed",
            Self::NoopProof => "v031_upgrade_complete_noop_proof_failed",
            Self::EvidenceEncoding => "v031_upgrade_complete_evidence_encoding_failed",
            Self::Receipt => "v031_upgrade_complete_receipt_failed",
        }
    }
}

impl fmt::Display for V031UpgradeCompleteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031UpgradeCompleteError {}

/// Frozen read-only classification made once by the production startup router.
/// It contains no filesystem paths and cannot be upgraded in place after an R2
/// writer runs.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031ProcessStartUpgradeObservation {
    terminal_lineage_count: usize,
    active_lineage_id: Option<String>,
    active_final_receipt_count: Option<usize>,
    active_next_incoming_ordinal: Option<u8>,
    receipt_eight: Option<V031Receipt8ObservedAtProcessStartGate>,
}

impl fmt::Debug for V031ProcessStartUpgradeObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ProcessStartUpgradeObservation")
            .field("terminal_lineage_count", &self.terminal_lineage_count)
            .field("active_lineage_id", &self.active_lineage_id)
            .field(
                "active_final_receipt_count",
                &self.active_final_receipt_count,
            )
            .field(
                "active_next_incoming_ordinal",
                &self.active_next_incoming_ordinal,
            )
            .field("receipt_eight_observed", &self.receipt_eight.is_some())
            .finish()
    }
}

impl V031ProcessStartUpgradeObservation {
    pub(crate) const fn terminal_lineage_count(&self) -> usize {
        self.terminal_lineage_count
    }

    pub(crate) fn active_lineage_id(&self) -> Option<&str> {
        self.active_lineage_id.as_deref()
    }

    pub(crate) const fn active_final_receipt_count(&self) -> Option<usize> {
        self.active_final_receipt_count
    }

    pub(crate) const fn active_next_incoming_ordinal(&self) -> Option<u8> {
        self.active_next_incoming_ordinal
    }

    pub(crate) fn receipt_eight_observed_at_process_start(
        &self,
    ) -> Option<&V031Receipt8ObservedAtProcessStartGate> {
        self.receipt_eight.as_ref()
    }

    pub(crate) fn has_terminal_lineage_only(&self) -> bool {
        self.terminal_lineage_count > 0 && self.active_lineage_id.is_none()
    }
}

/// The only authorization accepted by Step 8.  Its constructor is private and
/// is reached solely while classifying an exact final receipt-8 prefix during
/// the read-only process-start pass.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031Receipt8ObservedAtProcessStartGate {
    receipt_context: OwnedV031ReceiptContext,
    receipt_seven_sha256: String,
    receipt_eight_sha256: String,
    receipt_eight_evidence_sha256: String,
    receipt_eight_counts: BTreeMap<String, u64>,
    incoming_receipt_nine_observed: bool,
}

impl fmt::Debug for V031Receipt8ObservedAtProcessStartGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031Receipt8ObservedAtProcessStartGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field("receipt_eight_sha256", &self.receipt_eight_sha256)
            .field(
                "receipt_eight_count_keys",
                &self.receipt_eight_counts.keys().collect::<Vec<_>>(),
            )
            .field(
                "receipt_eight_evidence_sha256",
                &self.receipt_eight_evidence_sha256,
            )
            .field(
                "incoming_receipt_nine_observed",
                &self.incoming_receipt_nine_observed,
            )
            .finish_non_exhaustive()
    }
}

impl V031Receipt8ObservedAtProcessStartGate {
    pub(crate) fn lineage_id(&self) -> &str {
        &self.receipt_context.lineage_id
    }

    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn receipt_eight_sha256(&self) -> &str {
        &self.receipt_eight_sha256
    }

    pub(crate) fn receipt_eight_evidence_sha256(&self) -> &str {
        &self.receipt_eight_evidence_sha256
    }

    #[cfg(test)]
    pub(crate) const fn incoming_receipt_nine_observed(&self) -> bool {
        self.incoming_receipt_nine_observed
    }

    pub(crate) fn matches_verified_receipt_eight(
        &self,
        verified: &V031UserV11VerifiedGate,
    ) -> bool {
        self.receipt_context == *verified.receipt_context()
            && self.receipt_eight_sha256 == verified.user_v11_receipt_sha256()
            && self.receipt_eight_evidence_sha256 == verified.evidence_sha256()
    }
}

/// Terminal authorization for ordinary startup.  The gate is returned only
/// after ordinal 9, all four no-op proofs, and the live five-component
/// manifest have been re-authenticated.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031UpgradeCompleteGate {
    receipt_context: OwnedV031ReceiptContext,
    receipt_nine_sha256: String,
    evidence_sha256: String,
    final_component_manifest_sha256: String,
}

impl fmt::Debug for V031UpgradeCompleteGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031UpgradeCompleteGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field("receipt_nine_sha256", &self.receipt_nine_sha256)
            .field("evidence_sha256", &self.evidence_sha256)
            .field(
                "final_component_manifest_sha256",
                &self.final_component_manifest_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl V031UpgradeCompleteGate {
    /// Retained for the frozen R3 authenticated downgrade-recovery contract.
    #[allow(dead_code)]
    pub(crate) fn lineage_id(&self) -> &str {
        &self.receipt_context.lineage_id
    }

    /// Retained for the frozen R3 authenticated downgrade-recovery contract.
    #[allow(dead_code)]
    pub(crate) fn receipt_nine_sha256(&self) -> &str {
        &self.receipt_nine_sha256
    }

    /// Retained for the frozen R3 authenticated downgrade-recovery contract.
    #[allow(dead_code)]
    pub(crate) fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    /// Retained for the frozen R3 authenticated downgrade-recovery contract.
    #[allow(dead_code)]
    pub(crate) fn final_component_manifest_sha256(&self) -> &str {
        &self.final_component_manifest_sha256
    }
}

/// Authenticates and classifies every lineage without opening a current manager
/// or writing any migration artifact.  Terminal history is allowed; there may
/// be at most one nonterminal lineage.
pub(crate) fn observe_v031_upgrade_at_process_start_read_only(
    app_local_data_dir: &Path,
) -> Result<V031ProcessStartUpgradeObservation, V031UpgradeCompleteError> {
    if !app_local_data_dir.is_absolute() {
        return Err(V031UpgradeCompleteError::Namespace);
    }
    match std::fs::symlink_metadata(app_local_data_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(V031ProcessStartUpgradeObservation {
                terminal_lineage_count: 0,
                active_lineage_id: None,
                active_final_receipt_count: None,
                active_next_incoming_ordinal: None,
                receipt_eight: None,
            });
        }
        Err(_) => return Err(V031UpgradeCompleteError::Namespace),
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(V031UpgradeCompleteError::Namespace);
        }
        Ok(_) => {}
    }
    let namespace = v031_upgrade_r2::inspect_receipt_zero_namespace(app_local_data_dir, |_| {
        PrivacyReceiptAuthenticationBridge::discovering()
    })
    .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    let lineage_ids = namespace.lineage_ids().to_vec();
    let empty_lineage_id = namespace.empty_lineage_id().map(str::to_owned);
    let mut terminal_lineage_count = 0usize;
    let mut active = None;
    let mut receipt_eight = None;

    for lineage_id in lineage_ids {
        if empty_lineage_id.as_deref() == Some(lineage_id.as_str()) {
            continue;
        }
        let bridge = PrivacyReceiptAuthenticationBridge::discovering();
        let inventory = v031_upgrade_r2::enumerate_and_authenticate_lineage(
            app_local_data_dir,
            &lineage_id,
            &bridge,
        )
        .map_err(|_| V031UpgradeCompleteError::Namespace)?;
        let context = bridge
            .context()
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
        let final_count = inventory.final_receipts.len();

        if final_count == privacy::upgrade_receipt_v1::V031_UPGRADE_RECEIPT_STAGE_COUNT {
            if !is_exact_terminal_lineage(&inventory) {
                return Err(V031UpgradeCompleteError::InvalidTerminalLineage);
            }
            verify_one_v031_terminal_history_lineage_read_only(app_local_data_dir, &inventory)
                .map_err(|_| V031UpgradeCompleteError::InvalidTerminalLineage)?;
            terminal_lineage_count = terminal_lineage_count
                .checked_add(1)
                .ok_or(V031UpgradeCompleteError::Namespace)?;
            continue;
        }
        if inventory.step8_predecessor.final_present {
            authenticate_v031_step8_predecessor_evidence_offline(
                app_local_data_dir,
                &inventory,
                &context,
            )?;
        }
        if active.is_some() {
            return Err(V031UpgradeCompleteError::MultipleActiveLineages);
        }
        let incoming = inventory
            .next_incoming_receipt
            .as_ref()
            .map(|receipt| receipt.ordinal);
        active = Some((lineage_id.clone(), final_count, incoming));

        if final_count == usize::from(V031UpgradeReceiptStage::UpgradeComplete.ordinal()) {
            if !is_exact_receipt_eight_lineage(&inventory) {
                return Err(V031UpgradeCompleteError::InvalidReceiptEightLineage);
            }
            let receipt = inventory
                .final_receipts
                .get(usize::from(
                    V031UpgradeReceiptStage::UserV11Verified.ordinal(),
                ))
                .ok_or(V031UpgradeCompleteError::InvalidReceiptEightLineage)?;
            receipt_eight = Some(V031Receipt8ObservedAtProcessStartGate {
                receipt_context: context,
                receipt_seven_sha256: receipt
                    .metadata
                    .previous_receipt_sha256
                    .clone()
                    .ok_or(V031UpgradeCompleteError::InvalidReceiptEightLineage)?,
                receipt_eight_sha256: receipt.protected_file_sha256.clone(),
                receipt_eight_evidence_sha256: receipt.metadata.evidence_sha256.clone(),
                receipt_eight_counts: receipt.metadata.counts.clone(),
                incoming_receipt_nine_observed: incoming.is_some(),
            });
        }
    }

    if let Some(empty_lineage_id) = empty_lineage_id {
        if active.is_some() {
            return Err(V031UpgradeCompleteError::MultipleActiveLineages);
        }
        active = Some((empty_lineage_id, 0, None));
    }

    let (active_lineage_id, active_final_receipt_count, active_next_incoming_ordinal) = active
        .map_or((None, None, None), |(lineage, count, incoming)| {
            (Some(lineage), Some(count), incoming)
        });
    Ok(V031ProcessStartUpgradeObservation {
        terminal_lineage_count,
        active_lineage_id,
        active_final_receipt_count,
        active_next_incoming_ordinal,
        receipt_eight,
    })
}

fn is_exact_terminal_lineage(inventory: &AuthenticatedLineageInventory) -> bool {
    inventory.final_receipts.len() == privacy::upgrade_receipt_v1::V031_UPGRADE_RECEIPT_STAGE_COUNT
        && inventory.next_incoming_receipt.is_none()
        && has_exact_final_migration_evidence(inventory)
        && inventory.step8_predecessor.is_exact_final()
        && inventory.upgrade_complete_evidence.is_exact_final()
        && inventory.final_receipts.last().is_some_and(|receipt| {
            receipt.ordinal == V031UpgradeReceiptStage::UpgradeComplete.ordinal()
                && receipt.stage == V031UpgradeReceiptStage::UpgradeComplete.as_str()
        })
}

fn is_exact_receipt_eight_lineage(inventory: &AuthenticatedLineageInventory) -> bool {
    inventory.final_receipts.len()
        == usize::from(V031UpgradeReceiptStage::UpgradeComplete.ordinal())
        && has_exact_final_migration_evidence(inventory)
        && (inventory.step8_predecessor.is_absent()
            || inventory.step8_predecessor.incoming_present
            || inventory.step8_predecessor.is_exact_final())
        && inventory.final_receipts.last().is_some_and(|receipt| {
            receipt.ordinal == V031UpgradeReceiptStage::UserV11Verified.ordinal()
                && receipt.stage == V031UpgradeReceiptStage::UserV11Verified.as_str()
        })
        && inventory
            .next_incoming_receipt
            .as_ref()
            .is_none_or(|receipt| {
                receipt.ordinal == V031UpgradeReceiptStage::UpgradeComplete.ordinal()
                    && receipt.stage == V031UpgradeReceiptStage::UpgradeComplete.as_str()
            })
}

fn has_exact_final_migration_evidence(inventory: &AuthenticatedLineageInventory) -> bool {
    inventory.v2.identity_final
        && inventory.v2.bundle_final
        && !inventory.v2.identity_incoming
        && !inventory.v2.bundle_incoming
        && !inventory.v2.user_snapshot_incoming
        && !inventory.v2.privacy_snapshot_incoming
        && inventory.checkpoints.binding.is_exact_final()
        && inventory.checkpoints.materials.is_exact_final()
        && inventory.checkpoints.projection.is_exact_final()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
struct UpgradeCompleteEvidenceV1 {
    schema_version: String,
    migration_id: String,
    lineage_id: String,
    source_profile_proof_sha256: String,
    previous_receipt_sha256: String,
    user_v11_evidence_sha256: String,
    step8_predecessor_evidence_sha256: String,
    predecessor_final_component_manifest_sha256: String,
    predecessor_final_component_manifest: V031FinalComponentManifestRecordV1,
    post_maintenance_final_component_manifest_sha256: String,
    post_maintenance_final_component_manifest: V031FinalComponentManifestRecordV1,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
    maintenance_cutoff_unix: u64,
    retention_cleanup_id: String,
    vault_cleanup_id: String,
    restart_receipt_observed_at_process_start: bool,
    noop_migrations: [Step8NoopMigrationProof; 4],
    maintenance_actions: [Step8MaintenanceActionProof; 5],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8NoopMigrationProof {
    migration: String,
    result_code: String,
    live_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8MaintenanceActionProof {
    action: String,
    result_code: String,
    semantic_sha256: String,
    semantic: Step8MaintenanceSemanticV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Step8LiveProofs {
    noop_migrations: [Step8NoopMigrationProof; 4],
    maintenance_actions: [Step8MaintenanceActionProof; 5],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "result", rename_all = "snake_case")]
// Variant names and inline payloads are part of the frozen Receipt-9 evidence
// model; indirection must not be introduced merely to change enum size.
#[allow(clippy::large_enum_variant)]
enum Step8MaintenanceSemanticV1 {
    PrivacyRecoveryRetentionCleanup(Step8PrivacyMaintenanceResultV1),
    UserDatabaseCurrentSchemaValidation(Step8UserValidationResultV1),
    AssistantRunRecovery(Step8PendingRunResultV1),
    AssistantArtifactExportRecovery(Step8PendingMarkerResultV1),
    DocumentExportRecovery(Step8PendingMarkerResultV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8PrivacyMaintenanceResultV1 {
    cutoff_unix: u64,
    retention_cleanup: Step8RetentionCleanupResultV1,
    vault_cleanup: Step8VaultCleanupResultV1,
    pending_project_deletions_after: u64,
    pending_retention_cleanups_after: u64,
    pending_vault_prepared_after: u64,
    pending_vault_committed_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8RetentionCleanupResultV1 {
    cleanup_id: String,
    state: String,
    candidates: u64,
    removed: u64,
    keys_destroyed: u64,
    started_at_unix: u64,
    completed_at_unix: u64,
    event_hash: String,
    erasure_disclosure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8VaultCleanupResultV1 {
    cleanup_id: String,
    state: String,
    candidate_count: u64,
    logically_removed_count: u64,
    key_records_destroyed: u64,
    quarantine_paths_pending: u64,
    started_at_unix: u64,
    completed_at_unix: u64,
    event_hash: String,
    erasure_disclosure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8UserValidationResultV1 {
    schema_version: u64,
    schema_manifest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8PendingRunResultV1 {
    pending_runs_after: u64,
    pending_tool_calls_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8PendingMarkerResultV1 {
    pending_markers_after: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Step8MaintenanceOutcomes {
    privacy: Step8PrivacyMaintenanceResultV1,
    user: Step8UserValidationResultV1,
    assistant_runs: Step8PendingRunResultV1,
    assistant_artifacts: Step8PendingMarkerResultV1,
    document_exports: Step8PendingMarkerResultV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step8PredecessorEvidenceV1 {
    schema_version: String,
    migration_id: String,
    lineage_id: String,
    source_profile_proof_sha256: String,
    receipt_seven_sha256: String,
    receipt_eight_sha256: String,
    receipt_eight_evidence_schema_version: String,
    receipt_eight_evidence_sha256: String,
    receipt_eight_counts: BTreeMap<String, u64>,
    user_audit_sha256: String,
    privacy_lineage_sha256: String,
    receipt_eight_evidence: V031UserV11ReceiptEvidenceRecordV1,
    checkpoint_files: Vec<V031HistoricalCheckpointFileRecordV1>,
    predecessor_manifest_sha256: String,
    predecessor_manifest: V031FinalComponentManifestRecordV1,
}

#[derive(Clone, PartialEq, Eq)]
struct V031Step8PredecessorGate {
    rollback_gate: OriginalRollbackVerifiedGate,
    receipt_context: OwnedV031ReceiptContext,
    sidecar: Step8PredecessorEvidenceV1,
    sidecar_protected_sha256: String,
}

#[derive(Clone, PartialEq, Eq)]
struct V031UpgradeCompleteEvidenceSidecarGate {
    evidence: UpgradeCompleteEvidenceV1,
    payload_sha256: String,
    protected_sha256: String,
}

impl fmt::Debug for V031UpgradeCompleteEvidenceSidecarGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031UpgradeCompleteEvidenceSidecarGate")
            .field("lineage_id", &self.evidence.lineage_id)
            .field("payload_sha256", &self.payload_sha256)
            .field("protected_sha256", &self.protected_sha256)
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpgradeCompleteEvidenceBindingV1<'a> {
    schema_version: &'static str,
    payload_canonical_sha256: &'a str,
    protected_file_sha256: &'a str,
}

impl fmt::Debug for V031Step8PredecessorGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031Step8PredecessorGate")
            .field("lineage_id", &self.sidecar.lineage_id)
            .field("receipt_eight_sha256", &self.sidecar.receipt_eight_sha256)
            .field(
                "predecessor_manifest_sha256",
                &self.sidecar.predecessor_manifest_sha256,
            )
            .field("sidecar_protected_sha256", &self.sidecar_protected_sha256)
            .finish_non_exhaustive()
    }
}

/// Offline-authenticated sidecar capability.  It is valid even after an
/// explicit rollback restored active user-v10/Privacy-v1 because every field
/// is bound only to the DPAPI receipt chain and immutable R2 evidence.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedV031Step8PredecessorEvidence {
    receipt_context: OwnedV031ReceiptContext,
    evidence: Step8PredecessorEvidenceV1,
    protected_sha256: String,
}

/// Full terminal-history authentication retained specifically for fresh
/// receipt-zero bootstrap.  In addition to the opaque Step-8 predecessor gate,
/// it binds the exact protected Receipt-9 sidecar bytes so the bootstrap can
/// pin and rehash every frozen checkpoint/sidecar immediately before writing a
/// new lineage.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuthenticatedV031TerminalHistoryEvidence {
    predecessor: AuthenticatedV031Step8PredecessorEvidence,
    upgrade_complete_protected_sha256: String,
}

impl AuthenticatedV031TerminalHistoryEvidence {
    pub(crate) fn predecessor(&self) -> &AuthenticatedV031Step8PredecessorEvidence {
        &self.predecessor
    }

    pub(crate) fn upgrade_complete_protected_sha256(&self) -> &str {
        &self.upgrade_complete_protected_sha256
    }
}

impl fmt::Debug for AuthenticatedV031Step8PredecessorEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedV031Step8PredecessorEvidence")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field("receipt_eight_sha256", &self.evidence.receipt_eight_sha256)
            .field(
                "predecessor_manifest_sha256",
                &self.evidence.predecessor_manifest_sha256,
            )
            .field("protected_sha256", &self.protected_sha256)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedV031Step8PredecessorEvidence {
    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn receipt_seven_sha256(&self) -> &str {
        &self.evidence.receipt_seven_sha256
    }

    pub(crate) fn receipt_eight_sha256(&self) -> &str {
        &self.evidence.receipt_eight_sha256
    }

    pub(crate) fn receipt_eight_evidence_sha256(&self) -> &str {
        &self.evidence.receipt_eight_evidence_sha256
    }

    pub(crate) fn receipt_eight_evidence_schema_version(&self) -> &str {
        &self.evidence.receipt_eight_evidence_schema_version
    }

    pub(crate) fn receipt_eight_counts(&self) -> &BTreeMap<String, u64> {
        &self.evidence.receipt_eight_counts
    }

    pub(crate) fn user_audit_sha256(&self) -> &str {
        &self.evidence.user_audit_sha256
    }

    pub(crate) fn privacy_lineage_sha256(&self) -> &str {
        &self.evidence.privacy_lineage_sha256
    }

    pub(crate) fn predecessor_manifest_sha256(&self) -> &str {
        &self.evidence.predecessor_manifest_sha256
    }

    pub(crate) fn predecessor_manifest(&self) -> &V031FinalComponentManifestRecordV1 {
        &self.evidence.predecessor_manifest
    }

    pub(crate) fn receipt_eight_evidence(&self) -> &V031UserV11ReceiptEvidenceRecordV1 {
        &self.evidence.receipt_eight_evidence
    }

    pub(crate) fn checkpoint_files(&self) -> &[V031HistoricalCheckpointFileRecordV1] {
        &self.evidence.checkpoint_files
    }

    pub(crate) fn protected_sha256(&self) -> &str {
        &self.protected_sha256
    }
}

pub(crate) fn upgrade_complete_counts() -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (V031UpgradeReceiptCountKey::Restarts, REQUIRED_RESTARTS),
        (
            V031UpgradeReceiptCountKey::NoopMigrations,
            REQUIRED_NOOP_MIGRATIONS,
        ),
        (
            V031UpgradeReceiptCountKey::FinalComponentSlots,
            REQUIRED_FINAL_COMPONENT_SLOTS,
        ),
        (
            V031UpgradeReceiptCountKey::FinalManifestEntries,
            REQUIRED_FINAL_MANIFEST_ENTRIES,
        ),
        (
            V031UpgradeReceiptCountKey::MaintenanceActions,
            REQUIRED_MAINTENANCE_ACTIONS,
        ),
    ])
}

fn ensure_step8_predecessor_evidence(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    receipt_eight: V031UserV11VerifiedGate,
) -> Result<V031Step8PredecessorGate, V031UpgradeCompleteError> {
    ensure_step8_predecessor_evidence_common_inner(
        app_local_data_dir,
        observed,
        receipt_eight,
        |_| Ok(()),
    )
}

fn ensure_step8_predecessor_evidence_common_inner(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    receipt_eight: V031UserV11VerifiedGate,
    mut inject_failure: impl FnMut(
        V031Step8PredecessorInstallFailurePoint,
    ) -> Result<(), V031UpgradeCompleteError>,
) -> Result<V031Step8PredecessorGate, V031UpgradeCompleteError> {
    if !observed.matches_verified_receipt_eight(&receipt_eight) {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    let expected = build_step8_predecessor_evidence(app_local_data_dir, observed, &receipt_eight)?;
    let directory =
        v031_upgrade_r2::canonical_lineage_directory(app_local_data_dir, observed.lineage_id())
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    let incoming_path = directory.join(STEP8_PREDECESSOR_EVIDENCE_INCOMING);
    let final_path = directory.join(STEP8_PREDECESSOR_EVIDENCE_FINAL);
    let bridge = PrivacyReceiptAuthenticationBridge::new(observed.receipt_context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, observed.lineage_id(), &bridge)
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    if inventory.final_receipts.len() != 9
        || inventory
            .next_incoming_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.ordinal != 9)
    {
        return Err(V031UpgradeCompleteError::InvalidReceiptEightLineage);
    }

    let mut installed_final_this_run = false;
    let protected_bytes = if inventory.step8_predecessor.final_present {
        if inventory.step8_predecessor.incoming_present {
            return Err(V031UpgradeCompleteError::Namespace);
        }
        let (observed_sidecar, protected) = open_step8_predecessor_evidence(&final_path)?;
        if observed_sidecar != expected {
            return Err(V031UpgradeCompleteError::ObservationMismatch);
        }
        protected
    } else {
        let protected = if inventory.step8_predecessor.incoming_present {
            let (observed_sidecar, protected) = open_step8_predecessor_evidence(&incoming_path)?;
            if observed_sidecar != expected {
                return Err(V031UpgradeCompleteError::ObservationMismatch);
            }
            protected
        } else {
            let plaintext = Zeroizing::new(
                canonical_json_v1(&expected)
                    .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?,
            );
            let protected = Zeroizing::new(
                protect_local(plaintext.as_slice())
                    .map_err(|_| V031UpgradeCompleteError::Receipt)?,
            );
            v031_upgrade_r2::write_create_new_sync(
                &incoming_path,
                protected.as_slice(),
                MAX_STEP8_PREDECESSOR_PROTECTED_BYTES,
            )
            .map_err(|_| V031UpgradeCompleteError::Receipt)?;
            let (observed_sidecar, readback) = open_step8_predecessor_evidence(&incoming_path)?;
            if observed_sidecar != expected || readback.as_slice() != protected.as_slice() {
                return Err(V031UpgradeCompleteError::Receipt);
            }
            readback
        };
        inject_failure(
            V031Step8PredecessorInstallFailurePoint::AfterAuthenticatedIncomingReadbackBeforeRename,
        )?;
        v031_upgrade_r2::rename_new_no_replace_write_through(&incoming_path, &final_path)
            .map_err(|_| V031UpgradeCompleteError::Receipt)?;
        PlatformDirectorySync
            .sync_directory(&directory)
            .map_err(|_| V031UpgradeCompleteError::Receipt)?;
        let (observed_sidecar, final_readback) = open_step8_predecessor_evidence(&final_path)?;
        if observed_sidecar != expected || final_readback.as_slice() != protected.as_slice() {
            return Err(V031UpgradeCompleteError::Receipt);
        }
        installed_final_this_run = true;
        final_readback
    };
    let post_bridge = PrivacyReceiptAuthenticationBridge::new(observed.receipt_context.clone());
    let post =
        load_authenticated_v031_lineage(app_local_data_dir, observed.lineage_id(), &post_bridge)
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    if !post.step8_predecessor.is_exact_final() {
        return Err(V031UpgradeCompleteError::Namespace);
    }
    if installed_final_this_run {
        inject_failure(
            V031Step8PredecessorInstallFailurePoint::AfterFinalRenameSyncAuthenticatedReadbackAndInventory,
        )?;
    }
    Ok(V031Step8PredecessorGate {
        rollback_gate: receipt_eight.original_rollback_gate().clone(),
        receipt_context: receipt_eight.receipt_context().clone(),
        sidecar: expected,
        sidecar_protected_sha256: sha256_hex(protected_bytes.as_slice()),
    })
}

fn build_step8_predecessor_evidence(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    receipt_eight: &V031UserV11VerifiedGate,
) -> Result<Step8PredecessorEvidenceV1, V031UpgradeCompleteError> {
    if !observed.matches_verified_receipt_eight(receipt_eight)
        || observed.receipt_seven_sha256 != receipt_eight.privacy_v6_receipt_sha256()
    {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    let manifest = receipt_eight.final_component_manifest();
    let checkpoint_files = capture_v031_historical_checkpoint_file_records_read_only(
        app_local_data_dir,
        observed.lineage_id(),
    )
    .map_err(|_| V031UpgradeCompleteError::Receipt)?;
    let evidence = Step8PredecessorEvidenceV1 {
        schema_version: STEP8_PREDECESSOR_EVIDENCE_SCHEMA.to_owned(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID.to_owned(),
        lineage_id: observed.lineage_id().to_owned(),
        source_profile_proof_sha256: observed.receipt_context.source_profile_proof_sha256.clone(),
        receipt_seven_sha256: observed.receipt_seven_sha256.clone(),
        receipt_eight_sha256: observed.receipt_eight_sha256.clone(),
        receipt_eight_evidence_schema_version: V031UpgradeReceiptStage::UserV11Verified
            .evidence_schema_version()
            .to_owned(),
        receipt_eight_evidence_sha256: observed.receipt_eight_evidence_sha256.clone(),
        receipt_eight_counts: observed.receipt_eight_counts.clone(),
        user_audit_sha256: receipt_eight.user_audit_sha256().to_owned(),
        privacy_lineage_sha256: receipt_eight.privacy_lineage_sha256().to_owned(),
        receipt_eight_evidence: receipt_eight.evidence_record().clone(),
        checkpoint_files,
        predecessor_manifest_sha256: manifest.sha256().to_owned(),
        predecessor_manifest: manifest.canonical_record().clone(),
    };
    validate_step8_predecessor_evidence(&evidence)?;
    Ok(evidence)
}

fn open_step8_predecessor_evidence(
    path: &Path,
) -> Result<(Step8PredecessorEvidenceV1, Zeroizing<Vec<u8>>), V031UpgradeCompleteError> {
    let protected = Zeroizing::new(
        v031_upgrade_r2::read_bounded_file(path, MAX_STEP8_PREDECESSOR_PROTECTED_BYTES)
            .map_err(|_| V031UpgradeCompleteError::Receipt)?,
    );
    let plaintext = Zeroizing::new(
        unprotect_local(protected.as_slice()).map_err(|_| V031UpgradeCompleteError::Receipt)?,
    );
    let evidence: Step8PredecessorEvidenceV1 = strict_json_v1_from_slice(plaintext.as_slice())
        .map_err(|_| V031UpgradeCompleteError::Receipt)?;
    validate_step8_predecessor_evidence(&evidence)?;
    let canonical =
        canonical_json_v1(&evidence).map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
    if canonical.as_slice() != plaintext.as_slice() {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    Ok((evidence, protected))
}

pub(crate) fn authenticate_v031_step8_predecessor_evidence_offline(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    receipt_context: &OwnedV031ReceiptContext,
) -> Result<AuthenticatedV031Step8PredecessorEvidence, V031UpgradeCompleteError> {
    if !inventory.authenticates(app_local_data_dir, &receipt_context.lineage_id)
        || !inventory.step8_predecessor.is_exact_final()
        || inventory.final_receipts.len() < 9
        || inventory.final_receipts.len() > 10
        || !has_exact_final_migration_evidence(inventory)
    {
        return Err(V031UpgradeCompleteError::InvalidReceiptEightLineage);
    }
    if inventory.final_receipts.len() == 10 && !is_exact_terminal_lineage(inventory) {
        return Err(V031UpgradeCompleteError::InvalidTerminalLineage);
    }
    let receipt_seven = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::PrivacyV6Verified.ordinal(),
        ))
        .ok_or(V031UpgradeCompleteError::InvalidReceiptEightLineage)?;
    let receipt_eight = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::UserV11Verified.ordinal(),
        ))
        .ok_or(V031UpgradeCompleteError::InvalidReceiptEightLineage)?;
    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &receipt_context.lineage_id,
    )
    .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    let (evidence, protected) =
        open_step8_predecessor_evidence(&directory.join(STEP8_PREDECESSOR_EVIDENCE_FINAL))?;
    let observed_checkpoint_files = capture_v031_historical_checkpoint_file_records_read_only(
        app_local_data_dir,
        &receipt_context.lineage_id,
    )
    .map_err(|_| V031UpgradeCompleteError::Receipt)?;
    if observed_checkpoint_files != evidence.checkpoint_files {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    if evidence.lineage_id != receipt_context.lineage_id
        || evidence.source_profile_proof_sha256 != receipt_context.source_profile_proof_sha256
        || evidence.receipt_seven_sha256 != receipt_seven.protected_file_sha256
        || evidence.receipt_eight_sha256 != receipt_eight.protected_file_sha256
        || evidence.receipt_eight_evidence_schema_version
            != receipt_eight.metadata.evidence_schema_version
        || evidence.receipt_eight_evidence_sha256 != receipt_eight.metadata.evidence_sha256
        || evidence.receipt_eight_counts != receipt_eight.metadata.counts
        || evidence
            .receipt_eight_evidence
            .canonical_sha256()
            .map_err(|_| V031UpgradeCompleteError::Receipt)?
            != receipt_eight.metadata.evidence_sha256
        || receipt_eight.metadata.previous_receipt_sha256.as_deref()
            != Some(receipt_seven.protected_file_sha256.as_str())
        || receipt_eight.metadata.lineage_id != receipt_context.lineage_id
        || receipt_eight.metadata.envelope_binding_id != receipt_context.envelope_binding_id
        || receipt_eight.metadata.source_profile_proof_sha256
            != receipt_context.source_profile_proof_sha256
    {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    Ok(AuthenticatedV031Step8PredecessorEvidence {
        receipt_context: receipt_context.clone(),
        evidence,
        protected_sha256: sha256_hex(protected.as_slice()),
    })
}

#[cfg(test)]
fn protect_step8_predecessor_evidence_for_test(
    evidence: &Step8PredecessorEvidenceV1,
) -> Result<Vec<u8>, V031UpgradeCompleteError> {
    validate_step8_predecessor_evidence(evidence)?;
    let canonical = Zeroizing::new(
        canonical_json_v1(evidence).map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?,
    );
    protect_local(canonical.as_slice()).map_err(|_| V031UpgradeCompleteError::Receipt)
}

#[cfg(test)]
pub(crate) fn build_v031_step8_predecessor_sidecar_for_test(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    receipt_eight: &V031UserV11VerifiedGate,
) -> Result<Vec<u8>, V031UpgradeCompleteError> {
    let evidence = build_step8_predecessor_evidence(app_local_data_dir, observed, receipt_eight)?;
    protect_step8_predecessor_evidence_for_test(&evidence)
}

#[cfg(test)]
pub(crate) fn build_different_v031_step8_predecessor_sidecar_for_test(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    receipt_eight: &V031UserV11VerifiedGate,
) -> Result<Vec<u8>, V031UpgradeCompleteError> {
    let mut evidence =
        build_step8_predecessor_evidence(app_local_data_dir, observed, receipt_eight)?;
    let replacement = if evidence.receipt_eight_sha256 == "f".repeat(64) {
        "e".repeat(64)
    } else {
        "f".repeat(64)
    };
    evidence.receipt_eight_sha256 = replacement;
    protect_step8_predecessor_evidence_for_test(&evidence)
}

/// Installs the real DPAPI predecessor sidecar and returns only the same opaque
/// evidence gate that production restart loading can obtain. This narrow test
/// seam lets the full-chain fixture prove that freshly recaptured raw
/// checkpoint hashes cannot replace the authenticated sidecar authorization.
#[cfg(test)]
pub(crate) fn install_and_authenticate_v031_step8_predecessor_for_test(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    receipt_eight: V031UserV11VerifiedGate,
) -> Result<AuthenticatedV031Step8PredecessorEvidence, V031UpgradeCompleteError> {
    ensure_step8_predecessor_evidence(app_local_data_dir, observed, receipt_eight)?;
    let bridge = PrivacyReceiptAuthenticationBridge::new(observed.receipt_context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, observed.lineage_id(), &bridge)
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    authenticate_v031_step8_predecessor_evidence_offline(
        app_local_data_dir,
        &inventory,
        observed.receipt_context(),
    )
}

#[cfg(test)]
pub(crate) fn install_and_authenticate_v031_step8_predecessor_with_failure_for_test(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    receipt_eight: V031UserV11VerifiedGate,
    failure_point: V031Step8PredecessorInstallFailurePoint,
) -> Result<AuthenticatedV031Step8PredecessorEvidence, V031UpgradeCompleteError> {
    ensure_step8_predecessor_evidence_common_inner(
        app_local_data_dir,
        observed,
        receipt_eight,
        |point| {
            if point == failure_point {
                Err(V031UpgradeCompleteError::Receipt)
            } else {
                Ok(())
            }
        },
    )?;
    let bridge = PrivacyReceiptAuthenticationBridge::new(observed.receipt_context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, observed.lineage_id(), &bridge)
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    authenticate_v031_step8_predecessor_evidence_offline(
        app_local_data_dir,
        &inventory,
        observed.receipt_context(),
    )
}

/// Builds a fully canonical and internally valid Receipt-9 evidence sidecar
/// for a different lineage.  Tests use it to prove that copying a valid
/// DPAPI-protected sidecar across lineages is rejected by the terminal gate,
/// rather than being mistaken for ordinary ciphertext corruption.
#[cfg(test)]
pub(crate) fn build_foreign_lineage_upgrade_complete_sidecar_for_test(
    installed_sidecar_path: &Path,
    foreign_lineage_id: &str,
) -> Result<Vec<u8>, V031UpgradeCompleteError> {
    if !is_hash(foreign_lineage_id) {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    let (mut evidence, _) = open_upgrade_complete_evidence(installed_sidecar_path)?;
    if evidence.lineage_id == foreign_lineage_id {
        return Err(V031UpgradeCompleteError::Receipt);
    }

    let manifest_for_lineage = |record: &V031FinalComponentManifestRecordV1| {
        let mut value =
            serde_json::to_value(record).map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
        value
            .as_object_mut()
            .ok_or(V031UpgradeCompleteError::EvidenceEncoding)?
            .insert(
                "lineageId".to_owned(),
                serde_json::Value::String(foreign_lineage_id.to_owned()),
            );
        serde_json::from_value::<V031FinalComponentManifestRecordV1>(value)
            .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)
    };
    evidence.lineage_id = foreign_lineage_id.to_owned();
    evidence.predecessor_final_component_manifest =
        manifest_for_lineage(&evidence.predecessor_final_component_manifest)?;
    evidence.predecessor_final_component_manifest_sha256 = evidence
        .predecessor_final_component_manifest
        .canonical_sha256()
        .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
    evidence.post_maintenance_final_component_manifest =
        manifest_for_lineage(&evidence.post_maintenance_final_component_manifest)?;
    evidence.post_maintenance_final_component_manifest_sha256 = evidence
        .post_maintenance_final_component_manifest
        .canonical_sha256()
        .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
    evidence.retention_cleanup_id =
        deterministic_step8_cleanup_id(foreign_lineage_id, "privacy_retention_cleanup");
    evidence.vault_cleanup_id =
        deterministic_step8_cleanup_id(foreign_lineage_id, "vault_expired_cleanup");
    let privacy = match &mut evidence.maintenance_actions[0].semantic {
        Step8MaintenanceSemanticV1::PrivacyRecoveryRetentionCleanup(value) => value,
        _ => return Err(V031UpgradeCompleteError::EvidenceEncoding),
    };
    privacy.retention_cleanup.cleanup_id = evidence.retention_cleanup_id.clone();
    privacy.vault_cleanup.cleanup_id = evidence.vault_cleanup_id.clone();
    evidence.maintenance_actions[0].semantic_sha256 =
        semantic_sha256(&evidence.maintenance_actions[0].semantic)?;
    validate_upgrade_complete_evidence(&evidence)?;
    let canonical = Zeroizing::new(
        canonical_json_v1(&evidence).map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?,
    );
    protect_local(canonical.as_slice()).map_err(|_| V031UpgradeCompleteError::Receipt)
}

fn validate_step8_predecessor_evidence(
    evidence: &Step8PredecessorEvidenceV1,
) -> Result<(), V031UpgradeCompleteError> {
    if evidence.schema_version != STEP8_PREDECESSOR_EVIDENCE_SCHEMA
        || evidence.migration_id != V031_UPGRADE_RECEIPT_MIGRATION_ID
        || evidence.receipt_eight_evidence_schema_version
            != V031UpgradeReceiptStage::UserV11Verified.evidence_schema_version()
        || evidence.receipt_eight_counts.len()
            != V031UpgradeReceiptStage::UserV11Verified.count_keys().len()
        || evidence.checkpoint_files.len() != 6
    {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    for hash in [
        evidence.lineage_id.as_str(),
        evidence.source_profile_proof_sha256.as_str(),
        evidence.receipt_seven_sha256.as_str(),
        evidence.receipt_eight_sha256.as_str(),
        evidence.receipt_eight_evidence_sha256.as_str(),
        evidence.user_audit_sha256.as_str(),
        evidence.privacy_lineage_sha256.as_str(),
        evidence.predecessor_manifest_sha256.as_str(),
    ] {
        if !is_hash(hash) {
            return Err(V031UpgradeCompleteError::Receipt);
        }
    }
    if evidence.predecessor_manifest.lineage_id() != evidence.lineage_id
        || evidence.receipt_eight_evidence.lineage_id() != evidence.lineage_id
        || evidence
            .receipt_eight_evidence
            .source_profile_proof_sha256()
            != evidence.source_profile_proof_sha256
        || evidence.receipt_eight_evidence.previous_receipt_sha256()
            != evidence.receipt_seven_sha256
        || evidence.receipt_eight_evidence.user_audit_sha256() != evidence.user_audit_sha256
        || evidence.receipt_eight_evidence.privacy_lineage_sha256()
            != evidence.privacy_lineage_sha256
        || evidence
            .receipt_eight_evidence
            .canonical_sha256()
            .map_err(|_| V031UpgradeCompleteError::Receipt)?
            != evidence.receipt_eight_evidence_sha256
        || evidence
            .receipt_eight_evidence
            .final_component_manifest_sha256()
            != evidence.predecessor_manifest_sha256
        || evidence
            .predecessor_manifest
            .canonical_sha256()
            .map_err(|_| V031UpgradeCompleteError::Receipt)?
            != evidence.predecessor_manifest_sha256
    {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    let exact =
        |key: &str, value: u64| evidence.receipt_eight_counts.get(key).copied() == Some(value);
    let ((user_tables, user_rows), (privacy_tables, privacy_rows)) = evidence
        .predecessor_manifest
        .database_manifest_counts()
        .ok_or(V031UpgradeCompleteError::Receipt)?;
    if !exact("user_audit_rows", 1)
        || !exact("privacy_lineage_rows", 1)
        || !exact("user_manifest_tables", user_tables)
        || !exact("user_manifest_rows", user_rows)
        || !exact("privacy_manifest_tables", privacy_tables)
        || !exact("privacy_manifest_rows", privacy_rows)
        || !exact("final_component_slots", 5)
        || user_tables != 29
        || privacy_tables != REQUIRED_PRIVACY_MANIFEST_TABLES
        || user_rows == 0
        || privacy_rows == 0
    {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    Ok(())
}

fn deterministic_step8_cleanup_id(lineage_id: &str, action: &str) -> String {
    let digest =
        sha256_hex(format!("{STEP8_CLEANUP_ID_DOMAIN}\0{lineage_id}\0{action}").as_bytes());
    format!("cln_{}", &digest[..32])
}

#[cfg(test)]
pub(crate) fn v031_step8_cleanup_ids_for_test(lineage_id: &str) -> (String, String) {
    (
        deterministic_step8_cleanup_id(lineage_id, "privacy_retention_cleanup"),
        deterministic_step8_cleanup_id(lineage_id, "vault_expired_cleanup"),
    )
}

fn semantic_sha256(
    semantic: &Step8MaintenanceSemanticV1,
) -> Result<String, V031UpgradeCompleteError> {
    canonical_json_v1(semantic)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)
}

fn build_upgrade_complete_evidence(
    observed: &V031Receipt8ObservedAtProcessStartGate,
    predecessor: &V031Step8PredecessorGate,
    post_manifest: &V031FinalComponentManifestProof,
    live_proofs: &Step8LiveProofs,
) -> Result<UpgradeCompleteEvidenceV1, V031UpgradeCompleteError> {
    if predecessor.receipt_context != *observed.receipt_context()
        || predecessor.sidecar.receipt_eight_sha256 != observed.receipt_eight_sha256
        || predecessor.sidecar.receipt_eight_evidence_sha256
            != observed.receipt_eight_evidence_sha256
    {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    let cutoff_unix = u64::try_from(
        predecessor
            .sidecar
            .receipt_eight_evidence
            .ledger_created_at_unix(),
    )
    .ok()
    .filter(|value| *value > 0)
    .ok_or(V031UpgradeCompleteError::ReceiptEight)?;
    let evidence = UpgradeCompleteEvidenceV1 {
        schema_version: V031UpgradeReceiptStage::UpgradeComplete
            .evidence_schema_version()
            .to_owned(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID.to_owned(),
        lineage_id: observed.lineage_id().to_owned(),
        source_profile_proof_sha256: observed.receipt_context.source_profile_proof_sha256.clone(),
        previous_receipt_sha256: observed.receipt_eight_sha256.clone(),
        user_v11_evidence_sha256: observed.receipt_eight_evidence_sha256.clone(),
        step8_predecessor_evidence_sha256: predecessor.sidecar_protected_sha256.clone(),
        predecessor_final_component_manifest_sha256: predecessor
            .sidecar
            .predecessor_manifest_sha256
            .clone(),
        predecessor_final_component_manifest: predecessor.sidecar.predecessor_manifest.clone(),
        post_maintenance_final_component_manifest_sha256: post_manifest.sha256().to_owned(),
        post_maintenance_final_component_manifest: post_manifest.canonical_record().clone(),
        user_audit_sha256: predecessor.sidecar.user_audit_sha256.clone(),
        privacy_lineage_sha256: predecessor.sidecar.privacy_lineage_sha256.clone(),
        maintenance_cutoff_unix: cutoff_unix,
        retention_cleanup_id: deterministic_step8_cleanup_id(
            observed.lineage_id(),
            "privacy_retention_cleanup",
        ),
        vault_cleanup_id: deterministic_step8_cleanup_id(
            observed.lineage_id(),
            "vault_expired_cleanup",
        ),
        restart_receipt_observed_at_process_start: true,
        noop_migrations: live_proofs.noop_migrations.clone(),
        maintenance_actions: live_proofs.maintenance_actions.clone(),
    };
    validate_upgrade_complete_evidence(&evidence)?;
    Ok(evidence)
}

fn validate_upgrade_complete_evidence(
    evidence: &UpgradeCompleteEvidenceV1,
) -> Result<(), V031UpgradeCompleteError> {
    if evidence.schema_version != V031UpgradeReceiptStage::UpgradeComplete.evidence_schema_version()
        || evidence.migration_id != V031_UPGRADE_RECEIPT_MIGRATION_ID
        || !evidence.restart_receipt_observed_at_process_start
        || evidence.maintenance_cutoff_unix == 0
        || evidence.retention_cleanup_id
            != deterministic_step8_cleanup_id(&evidence.lineage_id, "privacy_retention_cleanup")
        || evidence.vault_cleanup_id
            != deterministic_step8_cleanup_id(&evidence.lineage_id, "vault_expired_cleanup")
    {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    for hash in [
        evidence.lineage_id.as_str(),
        evidence.source_profile_proof_sha256.as_str(),
        evidence.previous_receipt_sha256.as_str(),
        evidence.user_v11_evidence_sha256.as_str(),
        evidence.step8_predecessor_evidence_sha256.as_str(),
        evidence
            .predecessor_final_component_manifest_sha256
            .as_str(),
        evidence
            .post_maintenance_final_component_manifest_sha256
            .as_str(),
        evidence.user_audit_sha256.as_str(),
        evidence.privacy_lineage_sha256.as_str(),
    ] {
        if !is_hash(hash) {
            return Err(V031UpgradeCompleteError::Receipt);
        }
    }
    if evidence.predecessor_final_component_manifest.lineage_id() != evidence.lineage_id
        || evidence
            .post_maintenance_final_component_manifest
            .lineage_id()
            != evidence.lineage_id
        || evidence
            .predecessor_final_component_manifest
            .canonical_sha256()
            .map_err(|_| V031UpgradeCompleteError::Receipt)?
            != evidence.predecessor_final_component_manifest_sha256
        || evidence
            .post_maintenance_final_component_manifest
            .canonical_sha256()
            .map_err(|_| V031UpgradeCompleteError::Receipt)?
            != evidence.post_maintenance_final_component_manifest_sha256
    {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    for (proof, expected) in evidence.noop_migrations.iter().zip(NOOP_MIGRATIONS) {
        if proof.migration != expected
            || proof.result_code != "no_op"
            || !is_hash(&proof.live_manifest_sha256)
        {
            return Err(V031UpgradeCompleteError::Receipt);
        }
    }
    for (proof, expected) in evidence.maintenance_actions.iter().zip(MAINTENANCE_ACTIONS) {
        if proof.action != expected
            || proof.result_code != "verified"
            || !is_hash(&proof.semantic_sha256)
            || proof.semantic_sha256 != semantic_sha256(&proof.semantic)?
        {
            return Err(V031UpgradeCompleteError::Receipt);
        }
    }
    let privacy = match &evidence.maintenance_actions[0].semantic {
        Step8MaintenanceSemanticV1::PrivacyRecoveryRetentionCleanup(value) => value,
        _ => return Err(V031UpgradeCompleteError::Receipt),
    };
    if privacy.cutoff_unix != evidence.maintenance_cutoff_unix
        || privacy.pending_project_deletions_after != 0
        || privacy.pending_retention_cleanups_after != 0
        || privacy.pending_vault_prepared_after != 0
        || privacy.pending_vault_committed_after != 0
        || privacy.retention_cleanup.cleanup_id != evidence.retention_cleanup_id
        || privacy.retention_cleanup.state != "committed"
        || privacy.retention_cleanup.started_at_unix != evidence.maintenance_cutoff_unix
        || privacy.retention_cleanup.completed_at_unix != evidence.maintenance_cutoff_unix
        || privacy.retention_cleanup.removed > privacy.retention_cleanup.candidates
        || !is_hash(&privacy.retention_cleanup.event_hash)
        || privacy.retention_cleanup.erasure_disclosure != privacy::LOGICAL_ERASURE_DISCLOSURE
        || privacy.vault_cleanup.cleanup_id != evidence.vault_cleanup_id
        || privacy.vault_cleanup.state != "purged"
        || privacy.vault_cleanup.started_at_unix != evidence.maintenance_cutoff_unix
        || privacy.vault_cleanup.completed_at_unix != evidence.maintenance_cutoff_unix
        || privacy.vault_cleanup.logically_removed_count != privacy.vault_cleanup.candidate_count
        || privacy.vault_cleanup.quarantine_paths_pending != 0
        || !is_hash(&privacy.vault_cleanup.event_hash)
        || privacy.vault_cleanup.erasure_disclosure != privacy::VAULT_LOGICAL_ERASURE_DISCLOSURE
    {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    match &evidence.maintenance_actions[1].semantic {
        Step8MaintenanceSemanticV1::UserDatabaseCurrentSchemaValidation(value)
            if value.schema_version == 11 && is_hash(&value.schema_manifest_sha256) => {}
        _ => return Err(V031UpgradeCompleteError::Receipt),
    }
    match &evidence.maintenance_actions[2].semantic {
        Step8MaintenanceSemanticV1::AssistantRunRecovery(value)
            if value.pending_runs_after == 0 && value.pending_tool_calls_after == 0 => {}
        _ => return Err(V031UpgradeCompleteError::Receipt),
    }
    match &evidence.maintenance_actions[3].semantic {
        Step8MaintenanceSemanticV1::AssistantArtifactExportRecovery(value)
            if value.pending_markers_after == 0 => {}
        _ => return Err(V031UpgradeCompleteError::Receipt),
    }
    match &evidence.maintenance_actions[4].semantic {
        Step8MaintenanceSemanticV1::DocumentExportRecovery(value)
            if value.pending_markers_after == 0 => {}
        _ => return Err(V031UpgradeCompleteError::Receipt),
    }
    Ok(())
}

fn open_upgrade_complete_evidence(
    path: &Path,
) -> Result<(UpgradeCompleteEvidenceV1, Zeroizing<Vec<u8>>), V031UpgradeCompleteError> {
    let protected = Zeroizing::new(
        v031_upgrade_r2::read_bounded_file(path, MAX_UPGRADE_COMPLETE_EVIDENCE_PROTECTED_BYTES)
            .map_err(|_| V031UpgradeCompleteError::Receipt)?,
    );
    let plaintext = Zeroizing::new(
        unprotect_local(protected.as_slice()).map_err(|_| V031UpgradeCompleteError::Receipt)?,
    );
    let evidence: UpgradeCompleteEvidenceV1 = strict_json_v1_from_slice(plaintext.as_slice())
        .map_err(|_| V031UpgradeCompleteError::Receipt)?;
    validate_upgrade_complete_evidence(&evidence)?;
    let canonical =
        canonical_json_v1(&evidence).map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
    if canonical.as_slice() != plaintext.as_slice() {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    Ok((evidence, protected))
}

fn ensure_upgrade_complete_evidence_sidecar(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    expected: UpgradeCompleteEvidenceV1,
) -> Result<V031UpgradeCompleteEvidenceSidecarGate, V031UpgradeCompleteError> {
    validate_upgrade_complete_evidence(&expected)?;
    let directory =
        v031_upgrade_r2::canonical_lineage_directory(app_local_data_dir, observed.lineage_id())
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    let incoming_path = directory.join(UPGRADE_COMPLETE_EVIDENCE_INCOMING);
    let final_path = directory.join(UPGRADE_COMPLETE_EVIDENCE_FINAL);
    let bridge = PrivacyReceiptAuthenticationBridge::new(observed.receipt_context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, observed.lineage_id(), &bridge)
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    if inventory.final_receipts.len() != 9
        || !inventory.step8_predecessor.is_exact_final()
        || inventory.upgrade_complete_evidence.final_present
            && inventory.upgrade_complete_evidence.incoming_present
    {
        return Err(V031UpgradeCompleteError::InvalidReceiptEightLineage);
    }
    let protected = if inventory.upgrade_complete_evidence.final_present {
        let (observed_evidence, protected) = open_upgrade_complete_evidence(&final_path)?;
        if observed_evidence != expected {
            return Err(V031UpgradeCompleteError::ObservationMismatch);
        }
        protected
    } else {
        let protected = if inventory.upgrade_complete_evidence.incoming_present {
            let (observed_evidence, protected) = open_upgrade_complete_evidence(&incoming_path)?;
            if observed_evidence != expected {
                return Err(V031UpgradeCompleteError::ObservationMismatch);
            }
            protected
        } else {
            let plaintext = Zeroizing::new(
                canonical_json_v1(&expected)
                    .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?,
            );
            let protected = Zeroizing::new(
                protect_local(plaintext.as_slice())
                    .map_err(|_| V031UpgradeCompleteError::Receipt)?,
            );
            v031_upgrade_r2::write_create_new_sync(
                &incoming_path,
                protected.as_slice(),
                MAX_UPGRADE_COMPLETE_EVIDENCE_PROTECTED_BYTES,
            )
            .map_err(|_| V031UpgradeCompleteError::Receipt)?;
            let (observed_evidence, readback) = open_upgrade_complete_evidence(&incoming_path)?;
            if observed_evidence != expected || readback.as_slice() != protected.as_slice() {
                return Err(V031UpgradeCompleteError::Receipt);
            }
            readback
        };
        #[cfg(test)]
        if FAIL_UPGRADE_EVIDENCE_AFTER_AUTHENTICATED_INCOMING.with(|armed| armed.replace(false)) {
            // Model process loss after the evidence ciphertext is durable and
            // authenticated but before its no-replacement final rename.
            return Err(V031UpgradeCompleteError::Receipt);
        }
        v031_upgrade_r2::rename_new_no_replace_write_through(&incoming_path, &final_path)
            .map_err(|_| V031UpgradeCompleteError::Receipt)?;
        PlatformDirectorySync
            .sync_directory(&directory)
            .map_err(|_| V031UpgradeCompleteError::Receipt)?;
        let (observed_evidence, readback) = open_upgrade_complete_evidence(&final_path)?;
        if observed_evidence != expected || readback.as_slice() != protected.as_slice() {
            return Err(V031UpgradeCompleteError::Receipt);
        }
        readback
    };
    let payload =
        canonical_json_v1(&expected).map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
    Ok(V031UpgradeCompleteEvidenceSidecarGate {
        evidence: expected,
        payload_sha256: sha256_hex(&payload),
        protected_sha256: sha256_hex(protected.as_slice()),
    })
}

fn upgrade_complete_evidence_binding_sha256(
    sidecar: &V031UpgradeCompleteEvidenceSidecarGate,
) -> Result<String, V031UpgradeCompleteError> {
    canonical_json_v1(&UpgradeCompleteEvidenceBindingV1 {
        schema_version: UPGRADE_COMPLETE_EVIDENCE_BINDING_SCHEMA,
        payload_canonical_sha256: &sidecar.payload_sha256,
        protected_file_sha256: &sidecar.protected_sha256,
    })
    .map(|bytes| sha256_hex(&bytes))
    .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)
}

fn upgrade_complete_wire_counts() -> Result<BTreeMap<String, u64>, V031UpgradeCompleteError> {
    upgrade_complete_counts()
        .into_iter()
        .map(|(key, value)| {
            serde_json::to_value(key)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .map(|key| (key, value))
                .ok_or(V031UpgradeCompleteError::EvidenceEncoding)
        })
        .collect()
}

fn authenticate_upgrade_complete_evidence_offline(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    receipt_context: &OwnedV031ReceiptContext,
    predecessor: &AuthenticatedV031Step8PredecessorEvidence,
) -> Result<V031UpgradeCompleteEvidenceSidecarGate, V031UpgradeCompleteError> {
    if !inventory.authenticates(app_local_data_dir, &receipt_context.lineage_id)
        || !is_exact_terminal_lineage(inventory)
        || predecessor.receipt_context() != receipt_context
    {
        return Err(V031UpgradeCompleteError::InvalidTerminalLineage);
    }
    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &receipt_context.lineage_id,
    )
    .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    let (evidence, protected) =
        open_upgrade_complete_evidence(&directory.join(UPGRADE_COMPLETE_EVIDENCE_FINAL))?;
    let payload =
        canonical_json_v1(&evidence).map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
    let sidecar = V031UpgradeCompleteEvidenceSidecarGate {
        evidence,
        payload_sha256: sha256_hex(&payload),
        protected_sha256: sha256_hex(protected.as_slice()),
    };
    let receipt_nine = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::UpgradeComplete.ordinal(),
        ))
        .ok_or(V031UpgradeCompleteError::InvalidTerminalLineage)?;
    let expected_cutoff = u64::try_from(
        predecessor
            .receipt_eight_evidence()
            .ledger_created_at_unix(),
    )
    .ok()
    .filter(|value| *value > 0)
    .ok_or(V031UpgradeCompleteError::ReceiptEight)?;
    if sidecar.evidence.lineage_id != receipt_context.lineage_id
        || sidecar.evidence.source_profile_proof_sha256
            != receipt_context.source_profile_proof_sha256
        || sidecar.evidence.previous_receipt_sha256 != predecessor.receipt_eight_sha256()
        || sidecar.evidence.user_v11_evidence_sha256 != predecessor.receipt_eight_evidence_sha256()
        || sidecar.evidence.step8_predecessor_evidence_sha256 != predecessor.protected_sha256()
        || sidecar.evidence.predecessor_final_component_manifest_sha256
            != predecessor.predecessor_manifest_sha256()
        || &sidecar.evidence.predecessor_final_component_manifest
            != predecessor.predecessor_manifest()
        || sidecar.evidence.user_audit_sha256 != predecessor.user_audit_sha256()
        || sidecar.evidence.privacy_lineage_sha256 != predecessor.privacy_lineage_sha256()
        || sidecar.evidence.maintenance_cutoff_unix != expected_cutoff
        || receipt_nine.metadata.previous_receipt_sha256.as_deref()
            != Some(predecessor.receipt_eight_sha256())
        || receipt_nine.metadata.lineage_id != receipt_context.lineage_id
        || receipt_nine.metadata.envelope_binding_id != receipt_context.envelope_binding_id
        || receipt_nine.metadata.source_profile_proof_sha256
            != receipt_context.source_profile_proof_sha256
        || receipt_nine.metadata.evidence_schema_version
            != V031UpgradeReceiptStage::UpgradeComplete.evidence_schema_version()
        || receipt_nine.metadata.counts != upgrade_complete_wire_counts()?
        || receipt_nine.metadata.evidence_sha256
            != upgrade_complete_evidence_binding_sha256(&sidecar)?
    {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    Ok(sidecar)
}

/// Authenticates the complete immutable evidence chain for one terminal
/// historical lineage.  Callers receive only the already-authenticated Step-8
/// predecessor capability they need; the Receipt-9 sidecar is deliberately
/// kept private so merely observing or recapturing its raw bytes cannot become
/// an authorization path.
pub(crate) fn authenticate_v031_terminal_history_offline(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    receipt_context: &OwnedV031ReceiptContext,
) -> Result<AuthenticatedV031Step8PredecessorEvidence, V031UpgradeCompleteError> {
    authenticate_v031_terminal_history_for_bootstrap_offline(
        app_local_data_dir,
        inventory,
        receipt_context,
    )
    .map(|authenticated| authenticated.predecessor)
}

pub(crate) fn authenticate_v031_terminal_history_for_bootstrap_offline(
    app_local_data_dir: &Path,
    inventory: &AuthenticatedLineageInventory,
    receipt_context: &OwnedV031ReceiptContext,
) -> Result<AuthenticatedV031TerminalHistoryEvidence, V031UpgradeCompleteError> {
    if !is_exact_terminal_lineage(inventory) {
        return Err(V031UpgradeCompleteError::InvalidTerminalLineage);
    }
    let predecessor = authenticate_v031_step8_predecessor_evidence_offline(
        app_local_data_dir,
        inventory,
        receipt_context,
    )?;
    let upgrade_complete = authenticate_upgrade_complete_evidence_offline(
        app_local_data_dir,
        inventory,
        receipt_context,
        &predecessor,
    )?;
    Ok(AuthenticatedV031TerminalHistoryEvidence {
        predecessor,
        upgrade_complete_protected_sha256: upgrade_complete.protected_sha256,
    })
}

/// Runs the five frozen Step-8 maintenance actions and installs or resumes the
/// terminal receipt.  A gate observed before receipt 8 existed cannot be
/// supplied here, which makes the required restart a type-level boundary in
/// the production router.
pub(crate) fn ensure_v031_upgrade_complete(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    observed: &V031Receipt8ObservedAtProcessStartGate,
) -> Result<V031UpgradeCompleteGate, V031UpgradeCompleteError> {
    ensure_v031_upgrade_complete_inner(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        observed,
        &NoopV031Step8MaintenanceFailureInjector,
        &|| Ok(()),
    )
}

#[cfg(test)]
struct SelectedV031Step8MaintenanceFailureInjector {
    point: V031Step8MaintenanceFailurePoint,
}

#[cfg(test)]
impl V031Step8MaintenanceFailureInjector for SelectedV031Step8MaintenanceFailureInjector {
    fn should_fail(&self, point: V031Step8MaintenanceFailurePoint) -> bool {
        self.point == point
    }
}

#[cfg(test)]
pub(crate) fn ensure_v031_upgrade_complete_with_maintenance_failure_for_test(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    point: V031Step8MaintenanceFailurePoint,
) -> Result<V031UpgradeCompleteGate, V031UpgradeCompleteError> {
    ensure_v031_upgrade_complete_inner(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        observed,
        &SelectedV031Step8MaintenanceFailureInjector { point },
        &|| Ok(()),
    )
}

/// Runs the production Step-8 common inner and fails only after Receipt 9 is a
/// durable authenticated final file (including the persistence callback's
/// final live-state authentication), but before the coordinator's outer live
/// verification. This models process loss at that exact boundary without
/// forging a Gate 8 or duplicating the production receipt writer.
#[cfg(test)]
pub(crate) fn ensure_v031_upgrade_complete_with_failure_after_receipt_nine_for_test(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    observed: &V031Receipt8ObservedAtProcessStartGate,
) -> Result<V031UpgradeCompleteGate, V031UpgradeCompleteError> {
    ensure_v031_upgrade_complete_inner(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        observed,
        &NoopV031Step8MaintenanceFailureInjector,
        &|| Err(V031UpgradeCompleteError::Receipt),
    )
}

fn ensure_v031_upgrade_complete_inner(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    failure_injector: &dyn V031Step8MaintenanceFailureInjector,
    after_authenticated_receipt_nine: &dyn Fn() -> Result<(), V031UpgradeCompleteError>,
) -> Result<V031UpgradeCompleteGate, V031UpgradeCompleteError> {
    let _operation = V031_UPGRADE_COMPLETE_OPERATION
        .lock()
        .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    let predecessor = load_or_install_step8_predecessor_for_maintenance(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        observed,
    )?;

    let outcomes = run_frozen_step8_maintenance_for_predecessor(
        app_local_data_dir,
        privacy_manager,
        &predecessor,
        failure_injector,
    )?;
    let post_maintenance_manifest =
        capture_v031_fresh_final_component_manifest_with_rollback_read_only(
            app_local_data_dir,
            approved_workspace,
            &predecessor.rollback_gate,
            predecessor.sidecar.lineage_id.as_str(),
            predecessor
                .sidecar
                .predecessor_manifest
                .workspace_instance_id(),
        )
        .map_err(|_| V031UpgradeCompleteError::ReceiptEight)?;
    let live_proofs = prove_step8_live_results(
        app_local_data_dir,
        privacy_manager,
        &post_maintenance_manifest,
        &outcomes,
    )?;
    verify_receipt_eight_prefix_authenticated(app_local_data_dir, observed)?;

    let complete_evidence = build_upgrade_complete_evidence(
        observed,
        &predecessor,
        &post_maintenance_manifest,
        &live_proofs,
    )?;
    let complete_evidence =
        ensure_upgrade_complete_evidence_sidecar(app_local_data_dir, observed, complete_evidence)?;
    let evidence_sha256 = upgrade_complete_evidence_binding_sha256(&complete_evidence)?;
    let counts = upgrade_complete_counts();
    let verify_live_state = || {
        verify_upgrade_complete_live_state(
            app_local_data_dir,
            privacy_manager,
            approved_workspace,
            observed,
            &predecessor,
            &post_maintenance_manifest,
            &live_proofs,
            &complete_evidence,
            &evidence_sha256,
        )
        .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
    };
    let persisted = persist_v031_receipt(
        app_local_data_dir,
        &predecessor.receipt_context,
        V031UpgradeReceiptStage::UpgradeComplete,
        &evidence_sha256,
        &counts,
        verify_live_state,
    )
    .map_err(|_| V031UpgradeCompleteError::Receipt)?;

    run_after_newly_installed_receipt_nine(
        persisted.newly_installed,
        after_authenticated_receipt_nine,
    )?;
    verify_upgrade_complete_live_state(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        observed,
        &predecessor,
        &post_maintenance_manifest,
        &live_proofs,
        &complete_evidence,
        &evidence_sha256,
    )?;
    Ok(V031UpgradeCompleteGate {
        receipt_context: predecessor.receipt_context.clone(),
        receipt_nine_sha256: persisted.receipt.protected_file_sha256,
        evidence_sha256,
        final_component_manifest_sha256: post_maintenance_manifest.sha256().to_owned(),
    })
}

fn run_after_newly_installed_receipt_nine(
    newly_installed: bool,
    after_authenticated_receipt_nine: &dyn Fn() -> Result<(), V031UpgradeCompleteError>,
) -> Result<(), V031UpgradeCompleteError> {
    if newly_installed {
        after_authenticated_receipt_nine()?;
    }
    Ok(())
}

/// Before maintenance starts, the exact live Receipt-8 gate is used once to
/// install the immutable predecessor sidecar.  After any maintenance crash,
/// the live manifests are expected to differ, so restart authenticates that
/// final sidecar and reconstructs the historical Receipt-8 capability instead
/// of demanding the pre-maintenance bytes again.
fn load_or_install_step8_predecessor_for_maintenance(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    observed: &V031Receipt8ObservedAtProcessStartGate,
) -> Result<V031Step8PredecessorGate, V031UpgradeCompleteError> {
    let bridge = PrivacyReceiptAuthenticationBridge::new(observed.receipt_context().clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, observed.lineage_id(), &bridge)
            .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    if inventory.step8_predecessor.is_exact_final() {
        let authenticated = authenticate_v031_step8_predecessor_evidence_offline(
            app_local_data_dir,
            &inventory,
            observed.receipt_context(),
        )?;
        if authenticated.receipt_eight_sha256() != observed.receipt_eight_sha256()
            || authenticated.receipt_eight_evidence_sha256()
                != observed.receipt_eight_evidence_sha256()
        {
            return Err(V031UpgradeCompleteError::ObservationMismatch);
        }
        let historical = load_v031_historical_receipt_eight_verified_gate_read_only(
            app_local_data_dir,
            &authenticated,
        )
        .map_err(|_| V031UpgradeCompleteError::ReceiptEight)?;
        let rollback_gate = historical.original_rollback_gate().clone();
        return Ok(V031Step8PredecessorGate {
            rollback_gate,
            receipt_context: authenticated.receipt_context.clone(),
            sidecar: authenticated.evidence,
            sidecar_protected_sha256: authenticated.protected_sha256,
        });
    }

    let before = load_v031_user_v11_verified_gate_read_only(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        observed.lineage_id(),
    )
    .map_err(|_| V031UpgradeCompleteError::ReceiptEight)?;
    if !observed.matches_verified_receipt_eight(&before) {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    ensure_step8_predecessor_evidence(app_local_data_dir, observed, before)
}

/// Reconstructs the terminal capability without re-running maintenance.  This
/// is the ordinary-startup path after a completed upgrade.
pub(crate) fn load_v031_upgrade_complete_gate_read_only(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    lineage_id: &str,
) -> Result<V031UpgradeCompleteGate, V031UpgradeCompleteError> {
    let _operation = V031_UPGRADE_COMPLETE_OPERATION
        .lock()
        .map_err(|_| V031UpgradeCompleteError::Namespace)?;
    load_v031_upgrade_complete_gate_read_only_unlocked(
        app_local_data_dir,
        privacy_manager,
        approved_workspace,
        lineage_id,
        None,
    )
}

fn load_v031_upgrade_complete_gate_read_only_unlocked(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    lineage_id: &str,
    expected_receipt_sha256: Option<&str>,
) -> Result<V031UpgradeCompleteGate, V031UpgradeCompleteError> {
    let bridge = PrivacyReceiptAuthenticationBridge::discovering();
    let inventory = load_authenticated_v031_lineage(app_local_data_dir, lineage_id, &bridge)
        .map_err(|_| V031UpgradeCompleteError::Receipt)?;
    if !is_exact_terminal_lineage(&inventory) {
        return Err(V031UpgradeCompleteError::InvalidTerminalLineage);
    }
    let receipt_context = bridge
        .context()
        .map_err(|_| V031UpgradeCompleteError::Receipt)?;
    let predecessor = authenticate_v031_step8_predecessor_evidence_offline(
        app_local_data_dir,
        &inventory,
        &receipt_context,
    )?;
    let receipt_eight = load_v031_historical_receipt_eight_verified_gate_read_only(
        app_local_data_dir,
        &predecessor,
    )
    .map_err(|_| V031UpgradeCompleteError::ReceiptEight)?;
    let complete_evidence = authenticate_upgrade_complete_evidence_offline(
        app_local_data_dir,
        &inventory,
        &receipt_context,
        &predecessor,
    )?;
    let post_manifest = capture_v031_fresh_final_component_manifest_with_rollback_read_only(
        app_local_data_dir,
        approved_workspace,
        receipt_eight.original_rollback_gate(),
        lineage_id,
        receipt_eight
            .final_component_manifest()
            .workspace_instance_id(),
    )
    .map_err(|_| V031UpgradeCompleteError::ReceiptEight)?;
    if privacy_manager.privacy_store_schema_upgrade_required()
        || privacy_manager
            .case_material_migration_required()
            .map_err(|_| V031UpgradeCompleteError::NoopProof)?
        || privacy_manager
            .approved_projection_migration_required()
            .map_err(|_| V031UpgradeCompleteError::NoopProof)?
    {
        return Err(V031UpgradeCompleteError::NoopProof);
    }
    let receipt_nine = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::UpgradeComplete.ordinal(),
        ))
        .ok_or(V031UpgradeCompleteError::Receipt)?;
    let expected_wire_counts = upgrade_complete_wire_counts()?;
    if receipt_nine.ordinal != V031UpgradeReceiptStage::UpgradeComplete.ordinal()
        || receipt_nine.stage != V031UpgradeReceiptStage::UpgradeComplete.as_str()
        || receipt_nine.metadata.evidence_schema_version
            != V031UpgradeReceiptStage::UpgradeComplete.evidence_schema_version()
        || receipt_nine.metadata.counts != expected_wire_counts
        || receipt_nine.metadata.lineage_id != receipt_eight.receipt_context().lineage_id
        || receipt_nine.metadata.envelope_binding_id
            != receipt_eight.receipt_context().envelope_binding_id
        || receipt_nine.metadata.source_profile_proof_sha256
            != receipt_eight.receipt_context().source_profile_proof_sha256
        || expected_receipt_sha256
            .is_some_and(|expected| expected != receipt_nine.protected_file_sha256)
        || receipt_nine.metadata.evidence_sha256
            != upgrade_complete_evidence_binding_sha256(&complete_evidence)?
    {
        return Err(V031UpgradeCompleteError::Receipt);
    }
    Ok(V031UpgradeCompleteGate {
        receipt_context: receipt_eight.receipt_context().clone(),
        receipt_nine_sha256: receipt_nine.protected_file_sha256.clone(),
        evidence_sha256: receipt_nine.metadata.evidence_sha256.clone(),
        final_component_manifest_sha256: post_manifest.sha256().to_owned(),
    })
}

fn run_frozen_step8_maintenance_for_predecessor(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    predecessor: &V031Step8PredecessorGate,
    failure_injector: &dyn V031Step8MaintenanceFailureInjector,
) -> Result<Step8MaintenanceOutcomes, V031UpgradeCompleteError> {
    #[cfg(test)]
    {
        STEP8_MAINTENANCE_ENTRY_COUNT.with(|count| count.set(count.get() + 1));
        PANIC_ON_STEP8_MAINTENANCE_ENTRY.with(|armed| {
            assert!(
                !armed.get(),
                "terminal loader replayed frozen Step-8 maintenance"
            );
        });
    }
    let cutoff_unix = u64::try_from(
        predecessor
            .sidecar
            .receipt_eight_evidence
            .ledger_created_at_unix(),
    )
    .ok()
    .filter(|value| *value > 0)
    .ok_or(V031UpgradeCompleteError::Maintenance)?;
    let retention_cleanup_id = deterministic_step8_cleanup_id(
        &predecessor.sidecar.lineage_id,
        "privacy_retention_cleanup",
    );
    let vault_cleanup_id =
        deterministic_step8_cleanup_id(&predecessor.sidecar.lineage_id, "vault_expired_cleanup");
    let privacy = privacy_manager
        .complete_v031_step8_privacy_maintenance_with_failure_injector(
            cutoff_unix,
            &retention_cleanup_id,
            &vault_cleanup_id,
            failure_injector,
        )
        .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    let expected_user_path = database::user_database_path(app_local_data_dir);
    let (validated_user, ()) =
        with_validated_user_database_migration_source_read_only(&expected_user_path, |_| ())
            .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    if validated_user.schema != ValidatedUserSourceSchema::CurrentV11 {
        return Err(V031UpgradeCompleteError::Maintenance);
    }
    commands::assistant_run::recover_interrupted_assistant_runs(&expected_user_path)
        .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    commands::assistant::recover_pending_assistant_artifact_exports(app_local_data_dir)
        .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    commands::document::recover_pending_document_exports(app_local_data_dir, &expected_user_path)
        .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    let (pending_runs_after, pending_tool_calls_after) =
        commands::assistant_run::pending_assistant_run_recovery_counts_read_only(
            &expected_user_path,
        )
        .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    let pending_artifact_markers_after =
        commands::assistant::pending_assistant_artifact_export_marker_count_read_only(
            app_local_data_dir,
        )
        .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    let pending_document_markers_after =
        commands::document::pending_document_export_marker_count_read_only(app_local_data_dir)
            .map_err(|_| V031UpgradeCompleteError::Maintenance)?;
    if pending_runs_after != 0
        || pending_tool_calls_after != 0
        || pending_artifact_markers_after != 0
        || pending_document_markers_after != 0
    {
        return Err(V031UpgradeCompleteError::Maintenance);
    }
    Ok(Step8MaintenanceOutcomes {
        privacy: privacy_maintenance_result(privacy),
        user: Step8UserValidationResultV1 {
            schema_version: 11,
            schema_manifest_sha256: validated_user.schema_manifest_sha256,
        },
        assistant_runs: Step8PendingRunResultV1 {
            pending_runs_after,
            pending_tool_calls_after,
        },
        assistant_artifacts: Step8PendingMarkerResultV1 {
            pending_markers_after: pending_artifact_markers_after,
        },
        document_exports: Step8PendingMarkerResultV1 {
            pending_markers_after: pending_document_markers_after,
        },
    })
}

fn privacy_maintenance_result(
    report: V031Step8PrivacyMaintenanceReport,
) -> Step8PrivacyMaintenanceResultV1 {
    Step8PrivacyMaintenanceResultV1 {
        cutoff_unix: report.cutoff_unix,
        retention_cleanup: Step8RetentionCleanupResultV1 {
            cleanup_id: report.retention_cleanup.cleanup_id,
            state: report.retention_cleanup.state,
            candidates: report.retention_cleanup.candidates,
            removed: report.retention_cleanup.removed,
            keys_destroyed: report.retention_cleanup.keys_destroyed,
            started_at_unix: report.retention_cleanup.started_at_unix,
            completed_at_unix: report.retention_cleanup.completed_at_unix,
            event_hash: report.retention_cleanup.event_hash,
            erasure_disclosure: report.retention_cleanup.erasure_disclosure.to_owned(),
        },
        vault_cleanup: Step8VaultCleanupResultV1 {
            cleanup_id: report.vault_cleanup.cleanup_id,
            state: report.vault_cleanup.state,
            candidate_count: report.vault_cleanup.candidate_count,
            logically_removed_count: report.vault_cleanup.logically_removed_count,
            key_records_destroyed: report.vault_cleanup.key_records_destroyed,
            quarantine_paths_pending: report.vault_cleanup.quarantine_paths_pending,
            started_at_unix: report.vault_cleanup.started_at_unix,
            completed_at_unix: report.vault_cleanup.completed_at_unix,
            event_hash: report.vault_cleanup.event_hash,
            erasure_disclosure: report.vault_cleanup.erasure_disclosure.to_owned(),
        },
        pending_project_deletions_after: report.pending_project_deletions_after,
        pending_retention_cleanups_after: report.pending_retention_cleanups_after,
        pending_vault_prepared_after: report.pending_vault_prepared_after,
        pending_vault_committed_after: report.pending_vault_committed_after,
    }
}

fn prove_step8_live_results(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    post_manifest: &V031FinalComponentManifestProof,
    outcomes: &Step8MaintenanceOutcomes,
) -> Result<Step8LiveProofs, V031UpgradeCompleteError> {
    if privacy_manager.privacy_store_schema_upgrade_required()
        || privacy_manager
            .case_material_migration_required()
            .map_err(|_| V031UpgradeCompleteError::NoopProof)?
        || privacy_manager
            .approved_projection_migration_required()
            .map_err(|_| V031UpgradeCompleteError::NoopProof)?
    {
        return Err(V031UpgradeCompleteError::NoopProof);
    }
    let user_path = database::user_database_path(app_local_data_dir);
    let (user, ()) = with_validated_user_database_migration_source_read_only(&user_path, |_| ())
        .map_err(|_| V031UpgradeCompleteError::NoopProof)?;
    if user.schema != ValidatedUserSourceSchema::CurrentV11 {
        return Err(V031UpgradeCompleteError::NoopProof);
    }
    let noop_migrations = [
        Step8NoopMigrationProof {
            migration: NOOP_MIGRATIONS[0].to_owned(),
            result_code: "no_op".to_owned(),
            live_manifest_sha256: post_manifest.privacy_logical_manifest_sha256().to_owned(),
        },
        Step8NoopMigrationProof {
            migration: NOOP_MIGRATIONS[1].to_owned(),
            result_code: "no_op".to_owned(),
            live_manifest_sha256: post_manifest.privacy_business_manifest_sha256().to_owned(),
        },
        Step8NoopMigrationProof {
            migration: NOOP_MIGRATIONS[2].to_owned(),
            result_code: "no_op".to_owned(),
            live_manifest_sha256: post_manifest.approved_workspace_bundle_sha256().to_owned(),
        },
        Step8NoopMigrationProof {
            migration: NOOP_MIGRATIONS[3].to_owned(),
            result_code: "no_op".to_owned(),
            live_manifest_sha256: post_manifest.user_logical_manifest_sha256().to_owned(),
        },
    ];
    let semantics = [
        Step8MaintenanceSemanticV1::PrivacyRecoveryRetentionCleanup(outcomes.privacy.clone()),
        Step8MaintenanceSemanticV1::UserDatabaseCurrentSchemaValidation(outcomes.user.clone()),
        Step8MaintenanceSemanticV1::AssistantRunRecovery(outcomes.assistant_runs.clone()),
        Step8MaintenanceSemanticV1::AssistantArtifactExportRecovery(
            outcomes.assistant_artifacts.clone(),
        ),
        Step8MaintenanceSemanticV1::DocumentExportRecovery(outcomes.document_exports.clone()),
    ];
    let maintenance_actions = semantics
        .into_iter()
        .zip(MAINTENANCE_ACTIONS)
        .map(|(semantic, action)| {
            Ok(Step8MaintenanceActionProof {
                action: action.to_owned(),
                result_code: "verified".to_owned(),
                semantic_sha256: semantic_sha256(&semantic)?,
                semantic,
            })
        })
        .collect::<Result<Vec<_>, V031UpgradeCompleteError>>()?
        .try_into()
        .map_err(|_| V031UpgradeCompleteError::EvidenceEncoding)?;
    Ok(Step8LiveProofs {
        noop_migrations,
        maintenance_actions,
    })
}

fn verify_receipt_eight_prefix_authenticated(
    app_local_data_dir: &Path,
    observed: &V031Receipt8ObservedAtProcessStartGate,
) -> Result<(), V031UpgradeCompleteError> {
    let bridge = PrivacyReceiptAuthenticationBridge::new(observed.receipt_context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, observed.lineage_id(), &bridge)
            .map_err(|_| V031UpgradeCompleteError::Receipt)?;
    if inventory.final_receipts.len() < 9 || inventory.final_receipts.len() > 10 {
        return Err(V031UpgradeCompleteError::InvalidReceiptEightLineage);
    }
    let receipt = inventory
        .final_receipts
        .get(usize::from(
            V031UpgradeReceiptStage::UserV11Verified.ordinal(),
        ))
        .ok_or(V031UpgradeCompleteError::InvalidReceiptEightLineage)?;
    if receipt.protected_file_sha256 != observed.receipt_eight_sha256
        || receipt.metadata.evidence_sha256 != observed.receipt_eight_evidence_sha256
        || receipt.metadata.lineage_id != observed.receipt_context.lineage_id
        || receipt.metadata.envelope_binding_id != observed.receipt_context.envelope_binding_id
        || receipt.metadata.source_profile_proof_sha256
            != observed.receipt_context.source_profile_proof_sha256
        || !has_exact_final_migration_evidence(&inventory)
    {
        return Err(V031UpgradeCompleteError::InvalidReceiptEightLineage);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_upgrade_complete_live_state(
    app_local_data_dir: &Path,
    privacy_manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    observed: &V031Receipt8ObservedAtProcessStartGate,
    expected_predecessor: &V031Step8PredecessorGate,
    expected_post_manifest: &V031FinalComponentManifestProof,
    expected_live_proofs: &Step8LiveProofs,
    expected_complete_evidence: &V031UpgradeCompleteEvidenceSidecarGate,
    expected_evidence_sha256: &str,
) -> Result<(), V031UpgradeCompleteError> {
    verify_receipt_eight_prefix_authenticated(app_local_data_dir, observed)?;
    if expected_predecessor.receipt_context != *observed.receipt_context()
        || expected_predecessor.sidecar.receipt_eight_sha256 != observed.receipt_eight_sha256
    {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    verify_v031_historical_user_and_privacy_ledgers_read_only(
        app_local_data_dir,
        &expected_predecessor.rollback_gate,
        &expected_predecessor.sidecar.receipt_seven_sha256,
        &expected_predecessor.sidecar.user_audit_sha256,
        &expected_predecessor.sidecar.privacy_lineage_sha256,
    )
    .map_err(|_| V031UpgradeCompleteError::ReceiptEight)?;
    let current_post_manifest =
        capture_v031_fresh_final_component_manifest_with_rollback_read_only(
            app_local_data_dir,
            approved_workspace,
            &expected_predecessor.rollback_gate,
            &expected_predecessor.sidecar.lineage_id,
            expected_predecessor
                .sidecar
                .predecessor_manifest
                .workspace_instance_id(),
        )
        .map_err(|_| V031UpgradeCompleteError::ReceiptEight)?;
    let live_proofs = prove_step8_live_results(
        app_local_data_dir,
        privacy_manager,
        &current_post_manifest,
        &Step8MaintenanceOutcomes {
            privacy: match &expected_live_proofs.maintenance_actions[0].semantic {
                Step8MaintenanceSemanticV1::PrivacyRecoveryRetentionCleanup(value) => value.clone(),
                _ => return Err(V031UpgradeCompleteError::ObservationMismatch),
            },
            user: match &expected_live_proofs.maintenance_actions[1].semantic {
                Step8MaintenanceSemanticV1::UserDatabaseCurrentSchemaValidation(value) => {
                    value.clone()
                }
                _ => return Err(V031UpgradeCompleteError::ObservationMismatch),
            },
            assistant_runs: match &expected_live_proofs.maintenance_actions[2].semantic {
                Step8MaintenanceSemanticV1::AssistantRunRecovery(value) => value.clone(),
                _ => return Err(V031UpgradeCompleteError::ObservationMismatch),
            },
            assistant_artifacts: match &expected_live_proofs.maintenance_actions[3].semantic {
                Step8MaintenanceSemanticV1::AssistantArtifactExportRecovery(value) => value.clone(),
                _ => return Err(V031UpgradeCompleteError::ObservationMismatch),
            },
            document_exports: match &expected_live_proofs.maintenance_actions[4].semantic {
                Step8MaintenanceSemanticV1::DocumentExportRecovery(value) => value.clone(),
                _ => return Err(V031UpgradeCompleteError::ObservationMismatch),
            },
        },
    )?;
    let current_evidence = build_upgrade_complete_evidence(
        observed,
        expected_predecessor,
        &current_post_manifest,
        &live_proofs,
    )?;
    if &current_post_manifest != expected_post_manifest
        || &live_proofs != expected_live_proofs
        || current_evidence != expected_complete_evidence.evidence
        || upgrade_complete_evidence_binding_sha256(expected_complete_evidence)?
            != expected_evidence_sha256
    {
        return Err(V031UpgradeCompleteError::ObservationMismatch);
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn synthetic_final_manifest(lineage_id: &str) -> (V031FinalComponentManifestRecordV1, String) {
        let hash = "a".repeat(64);
        let workspace = format!("ws_{}", "b".repeat(32));
        let record: V031FinalComponentManifestRecordV1 =
            serde_json::from_value(serde_json::json!({
                "schemaVersion": "lawyer-assistance-v031-final-five-component-manifest-v1",
                "migrationId": database::V031_TO_V040_USER_MIGRATION_ID,
                "lineageId": lineage_id,
                "workspaceInstanceId": workspace,
                "slots": [
                    {
                        "slotName": "user_database",
                        "evidence": {
                            "schemaVersion": 11,
                            "schemaManifestSha256": hash,
                            "logicalManifestSha256": hash,
                            "businessManifestSha256": hash,
                            "businessPrimaryKeyManifestSha256": hash,
                            "businessRowManifestSha256": hash,
                            "tableCount": 29,
                            "totalRows": 1
                        }
                    },
                    {
                        "slotName": "privacy_database",
                        "evidence": {
                            "schemaVersion": privacy::PRIVACY_STORE_SCHEMA_VERSION,
                            "schemaObjectCount": 1,
                            "logicalManifestSha256": hash,
                            "businessManifestSha256": hash,
                            "businessPrimaryKeyManifestSha256": hash,
                            "businessRowManifestSha256": hash,
                            "tableCount": privacy::PRIVACY_V6_APPLICATION_TABLES.len(),
                            "totalRows": 1
                        }
                    },
                    {
                        "slotName": "vault",
                        "evidence": {
                            "workspaceInstanceId": workspace,
                            "componentManifestSha256": hash,
                            "schemaSha256": hash,
                            "databaseSha256": hash,
                            "layoutSha256": hash
                        }
                    },
                    {
                        "slotName": "approved_workspace",
                        "evidence": {
                            "workspaceInstanceId": workspace,
                            "bundleSha256": hash,
                            "manifestSha256": hash,
                            "schemaSha256": hash
                        }
                    },
                    {
                        "slotName": "work_products",
                        "evidence": {
                            "workspaceInstanceId": workspace,
                            "bundleSha256": hash,
                            "manifestSha256": hash,
                            "schemaSha256": hash
                        }
                    }
                ]
            }))
            .expect("synthetic five-slot manifest decodes");
        let manifest_sha256 = record
            .canonical_sha256()
            .expect("synthetic five-slot manifest validates");
        (record, manifest_sha256)
    }

    fn synthetic_upgrade_complete_evidence() -> UpgradeCompleteEvidenceV1 {
        let lineage_id = "1".repeat(64);
        let hash = "2".repeat(64);
        let cutoff_unix = 700;
        let retention_cleanup_id =
            deterministic_step8_cleanup_id(&lineage_id, "privacy_retention_cleanup");
        let vault_cleanup_id = deterministic_step8_cleanup_id(&lineage_id, "vault_expired_cleanup");
        let (manifest, manifest_sha256) = synthetic_final_manifest(&lineage_id);
        let semantics = [
            Step8MaintenanceSemanticV1::PrivacyRecoveryRetentionCleanup(
                Step8PrivacyMaintenanceResultV1 {
                    cutoff_unix,
                    retention_cleanup: Step8RetentionCleanupResultV1 {
                        cleanup_id: retention_cleanup_id.clone(),
                        state: "committed".to_owned(),
                        candidates: 0,
                        removed: 0,
                        keys_destroyed: 0,
                        started_at_unix: cutoff_unix,
                        completed_at_unix: cutoff_unix,
                        event_hash: hash.clone(),
                        erasure_disclosure: privacy::LOGICAL_ERASURE_DISCLOSURE.to_owned(),
                    },
                    vault_cleanup: Step8VaultCleanupResultV1 {
                        cleanup_id: vault_cleanup_id.clone(),
                        state: "purged".to_owned(),
                        candidate_count: 0,
                        logically_removed_count: 0,
                        key_records_destroyed: 0,
                        quarantine_paths_pending: 0,
                        started_at_unix: cutoff_unix,
                        completed_at_unix: cutoff_unix,
                        event_hash: hash.clone(),
                        erasure_disclosure: privacy::VAULT_LOGICAL_ERASURE_DISCLOSURE.to_owned(),
                    },
                    pending_project_deletions_after: 0,
                    pending_retention_cleanups_after: 0,
                    pending_vault_prepared_after: 0,
                    pending_vault_committed_after: 0,
                },
            ),
            Step8MaintenanceSemanticV1::UserDatabaseCurrentSchemaValidation(
                Step8UserValidationResultV1 {
                    schema_version: 11,
                    schema_manifest_sha256: hash.clone(),
                },
            ),
            Step8MaintenanceSemanticV1::AssistantRunRecovery(Step8PendingRunResultV1 {
                pending_runs_after: 0,
                pending_tool_calls_after: 0,
            }),
            Step8MaintenanceSemanticV1::AssistantArtifactExportRecovery(
                Step8PendingMarkerResultV1 {
                    pending_markers_after: 0,
                },
            ),
            Step8MaintenanceSemanticV1::DocumentExportRecovery(Step8PendingMarkerResultV1 {
                pending_markers_after: 0,
            }),
        ];
        let maintenance_actions = std::array::from_fn(|index| Step8MaintenanceActionProof {
            action: MAINTENANCE_ACTIONS[index].to_owned(),
            result_code: "verified".to_owned(),
            semantic_sha256: semantic_sha256(&semantics[index])
                .expect("synthetic maintenance semantic hashes"),
            semantic: semantics[index].clone(),
        });
        UpgradeCompleteEvidenceV1 {
            schema_version: V031UpgradeReceiptStage::UpgradeComplete
                .evidence_schema_version()
                .to_owned(),
            migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID.to_owned(),
            lineage_id,
            source_profile_proof_sha256: hash.clone(),
            previous_receipt_sha256: hash.clone(),
            user_v11_evidence_sha256: hash.clone(),
            step8_predecessor_evidence_sha256: hash.clone(),
            predecessor_final_component_manifest_sha256: manifest_sha256.clone(),
            predecessor_final_component_manifest: manifest.clone(),
            post_maintenance_final_component_manifest_sha256: manifest_sha256,
            post_maintenance_final_component_manifest: manifest,
            user_audit_sha256: hash.clone(),
            privacy_lineage_sha256: hash.clone(),
            maintenance_cutoff_unix: cutoff_unix,
            retention_cleanup_id,
            vault_cleanup_id,
            restart_receipt_observed_at_process_start: true,
            noop_migrations: std::array::from_fn(|index| Step8NoopMigrationProof {
                migration: NOOP_MIGRATIONS[index].to_owned(),
                result_code: "no_op".to_owned(),
                live_manifest_sha256: hash.clone(),
            }),
            maintenance_actions,
        }
    }

    fn synthetic_step8_predecessor_evidence() -> Step8PredecessorEvidenceV1 {
        let lineage_id = "1".repeat(64);
        let source_profile = "2".repeat(64);
        let receipt_seven = "3".repeat(64);
        let receipt_eight = "4".repeat(64);
        let user_audit = "5".repeat(64);
        let privacy_lineage = "6".repeat(64);
        let hash = "7".repeat(64);
        let (predecessor_manifest, predecessor_manifest_sha256) =
            synthetic_final_manifest(&lineage_id);
        let receipt_eight_evidence: V031UserV11ReceiptEvidenceRecordV1 =
            serde_json::from_value(serde_json::json!({
                "schemaVersion": V031UpgradeReceiptStage::UserV11Verified
                    .evidence_schema_version(),
                "migrationId": database::V031_TO_V040_USER_MIGRATION_ID,
                "lineageId": lineage_id,
                "sourceProfileProofSha256": source_profile,
                "originalRollbackIdentitySha256": hash,
                "previousReceiptSha256": receipt_seven,
                "privacyV6EvidenceSha256": hash,
                "projectionCheckpointIdentitySha256": hash,
                "projectionCheckpointBundleSha256": hash,
                "sourceUserPhysicalFileSetSha256": hash,
                "sourcePrivacyPhysicalFileSetSha256": hash,
                "sourceUserLogicalManifestSha256": hash,
                "sourceUserBusinessManifestSha256": hash,
                "sourcePrivacyLogicalManifestSha256": hash,
                "sourcePrivacyBusinessManifestSha256": hash,
                "targetUserPreAuditLogicalManifestSha256": hash,
                "targetUserPreAuditBusinessManifestSha256": hash,
                "targetPrivacyPreAuditLogicalManifestSha256": hash,
                "targetPrivacyPreAuditBusinessManifestSha256": hash,
                "userAuditSha256": user_audit,
                "privacyLineageSha256": privacy_lineage,
                "ledgerCreatedAtUnix": 1,
                "finalComponentManifestSha256": predecessor_manifest_sha256,
            }))
            .expect("synthetic receipt-eight evidence decodes");
        let receipt_eight_evidence_sha256 = receipt_eight_evidence
            .canonical_sha256()
            .expect("synthetic receipt-eight evidence validates");
        let checkpoint_files: Vec<V031HistoricalCheckpointFileRecordV1> =
            serde_json::from_value(serde_json::Value::Array(
                (0..6)
                    .map(|index| {
                        serde_json::json!({
                            "basename": format!("checkpoint-{index}"),
                            "fileBytes": 1,
                            "sha256": hash,
                        })
                    })
                    .collect(),
            ))
            .expect("synthetic checkpoint records decode");
        Step8PredecessorEvidenceV1 {
            schema_version: STEP8_PREDECESSOR_EVIDENCE_SCHEMA.to_owned(),
            migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID.to_owned(),
            lineage_id,
            source_profile_proof_sha256: source_profile,
            receipt_seven_sha256: receipt_seven,
            receipt_eight_sha256: receipt_eight,
            receipt_eight_evidence_schema_version: V031UpgradeReceiptStage::UserV11Verified
                .evidence_schema_version()
                .to_owned(),
            receipt_eight_evidence_sha256,
            receipt_eight_counts: BTreeMap::from([
                ("user_audit_rows".to_owned(), 1),
                ("privacy_lineage_rows".to_owned(), 1),
                ("user_manifest_tables".to_owned(), 29),
                ("user_manifest_rows".to_owned(), 1),
                (
                    "privacy_manifest_tables".to_owned(),
                    REQUIRED_PRIVACY_MANIFEST_TABLES,
                ),
                ("privacy_manifest_rows".to_owned(), 1),
                ("final_component_slots".to_owned(), 5),
            ]),
            user_audit_sha256: user_audit,
            privacy_lineage_sha256: privacy_lineage,
            receipt_eight_evidence,
            checkpoint_files,
            predecessor_manifest_sha256,
            predecessor_manifest,
        }
    }

    #[test]
    fn step8_predecessor_accepts_only_canonical_full_v6_privacy_table_count() {
        let evidence = synthetic_step8_predecessor_evidence();
        validate_step8_predecessor_evidence(&evidence)
            .expect("canonical full-v6 predecessor evidence");

        let mut stale_count = evidence;
        stale_count.receipt_eight_counts.insert(
            "privacy_manifest_tables".to_owned(),
            REQUIRED_PRIVACY_MANIFEST_TABLES - 1,
        );
        assert_eq!(
            validate_step8_predecessor_evidence(&stale_count),
            Err(V031UpgradeCompleteError::Receipt)
        );
    }

    #[test]
    fn receipt_nine_counts_are_the_frozen_exact_contract() {
        let counts = upgrade_complete_counts();
        assert_eq!(counts.len(), 5);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::Restarts], 1);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::NoopMigrations], 4);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::FinalComponentSlots], 5);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::FinalManifestEntries], 5);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::MaintenanceActions], 5);
        assert_eq!(
            V031UpgradeReceiptStage::UpgradeComplete.evidence_schema_version(),
            "lawyer-assistance-v031-upgrade-evidence-upgrade-complete-v1"
        );
    }

    #[test]
    fn receipt_nine_new_final_failure_seam_has_the_exact_common_inner_order() {
        let source = include_str!("v031_upgrade_complete.rs");
        let common_inner = source
            .split("fn ensure_v031_upgrade_complete_inner")
            .nth(1)
            .and_then(|value| {
                value
                    .split("fn load_or_install_step8_predecessor_for_maintenance")
                    .next()
            })
            .expect("Step8 production common inner source");
        let persisted = common_inner
            .find("let persisted = persist_v031_receipt")
            .expect("Receipt9 production persistence call");
        let newly_installed = common_inner
            .find("run_after_newly_installed_receipt_nine(")
            .expect("new-final-only failure branch");
        let injected = common_inner
            .find("after_authenticated_receipt_nine,")
            .expect("post-authenticated-final failure seam");
        let outer_verify = injected
            + common_inner[injected..]
                .find("verify_upgrade_complete_live_state(")
                .expect("outer live verification after the failure seam");
        assert!(persisted < newly_installed);
        assert!(newly_installed < injected);
        assert!(injected < outer_verify);
    }

    #[test]
    fn receipt_nine_failure_seam_runs_only_for_a_newly_installed_final() {
        use std::cell::Cell;

        let calls = Cell::new(0_u8);
        let seam = || {
            calls.set(calls.get() + 1);
            Err(V031UpgradeCompleteError::Receipt)
        };
        run_after_newly_installed_receipt_nine(false, &seam)
            .expect("an existing authenticated final bypasses the new-install seam");
        assert_eq!(calls.get(), 0);
        assert_eq!(
            run_after_newly_installed_receipt_nine(true, &seam),
            Err(V031UpgradeCompleteError::Receipt)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn process_start_observation_debug_contains_no_filesystem_path() {
        let observation = V031ProcessStartUpgradeObservation {
            terminal_lineage_count: 2,
            active_lineage_id: Some("a".repeat(64)),
            active_final_receipt_count: Some(9),
            active_next_incoming_ordinal: Some(9),
            receipt_eight: None,
        };
        let debug = format!("{observation:?}");
        assert!(!debug.contains('\\'));
        assert!(!debug.contains("migration-backups"));
        assert!(debug.contains("receipt_eight_observed: false"));
    }

    #[test]
    fn process_start_observation_treats_missing_app_root_as_empty_without_creating_it() {
        let parent = tempfile::tempdir().expect("missing-root parent");
        let missing = parent.path().join("not-created");
        assert!(!missing.exists());
        let observation = observe_v031_upgrade_at_process_start_read_only(&missing)
            .expect("a missing absolute app root is a fresh empty observation");
        assert_eq!(observation.terminal_lineage_count(), 0);
        assert_eq!(observation.active_lineage_id(), None);
        assert_eq!(observation.active_final_receipt_count(), None);
        assert_eq!(observation.active_next_incoming_ordinal(), None);
        assert!(observation
            .receipt_eight_observed_at_process_start()
            .is_none());
        assert!(
            !missing.exists(),
            "read-only observation never creates the root"
        );
    }

    #[test]
    fn upgrade_complete_semantic_evidence_and_ciphertext_binding_are_exact() {
        let evidence = synthetic_upgrade_complete_evidence();
        validate_upgrade_complete_evidence(&evidence).expect("synthetic evidence validates");
        let payload = canonical_json_v1(&evidence).expect("canonical payload");
        let decoded: UpgradeCompleteEvidenceV1 =
            strict_json_v1_from_slice(&payload).expect("strict canonical roundtrip");
        assert_eq!(decoded, evidence);

        let mut semantic_tamper = evidence.clone();
        if let Step8MaintenanceSemanticV1::AssistantRunRecovery(result) =
            &mut semantic_tamper.maintenance_actions[2].semantic
        {
            result.pending_runs_after = 1;
        }
        assert!(validate_upgrade_complete_evidence(&semantic_tamper).is_err());

        let payload_sha256 = sha256_hex(&payload);
        let first = V031UpgradeCompleteEvidenceSidecarGate {
            evidence: evidence.clone(),
            payload_sha256: payload_sha256.clone(),
            protected_sha256: "3".repeat(64),
        };
        let second = V031UpgradeCompleteEvidenceSidecarGate {
            evidence,
            payload_sha256,
            protected_sha256: "4".repeat(64),
        };
        assert_ne!(
            upgrade_complete_evidence_binding_sha256(&first).expect("first ciphertext binding"),
            upgrade_complete_evidence_binding_sha256(&second).expect("second ciphertext binding"),
            "receipt 9 binds the protected file bytes as well as canonical plaintext"
        );
    }

    #[cfg(windows)]
    #[test]
    fn upgrade_complete_dpapi_sidecar_rejects_missing_tamper_unknown_and_noncanonical() {
        let directory = tempfile::tempdir().expect("receipt-nine sidecar directory");
        let path = directory.path().join("evidence.dpapi");
        let evidence = synthetic_upgrade_complete_evidence();
        assert!(open_upgrade_complete_evidence(&path).is_err());

        let canonical = canonical_json_v1(&evidence).expect("canonical evidence");
        let protected = protect_local(&canonical).expect("DPAPI protects canonical evidence");
        fs::write(&path, &protected).expect("write protected canonical evidence");
        let (opened, opened_protected) =
            open_upgrade_complete_evidence(&path).expect("canonical DPAPI sidecar opens");
        assert_eq!(opened, evidence);
        assert_eq!(opened_protected.as_slice(), protected.as_slice());

        let mut tampered = protected.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        fs::write(&path, tampered).expect("write tampered protected evidence");
        assert!(open_upgrade_complete_evidence(&path).is_err());

        let mut unknown = serde_json::to_value(&evidence).expect("evidence JSON value");
        unknown
            .as_object_mut()
            .expect("evidence JSON object")
            .insert("unknownField".to_owned(), serde_json::json!(true));
        let unknown = serde_json::to_vec(&unknown).expect("unknown-field evidence bytes");
        fs::write(
            &path,
            protect_local(&unknown).expect("DPAPI protects unknown-field fixture"),
        )
        .expect("write unknown-field fixture");
        assert!(open_upgrade_complete_evidence(&path).is_err());

        let noncanonical = serde_json::to_vec_pretty(&evidence).expect("pretty evidence bytes");
        fs::write(
            &path,
            protect_local(&noncanonical).expect("DPAPI protects noncanonical fixture"),
        )
        .expect("write noncanonical fixture");
        assert!(open_upgrade_complete_evidence(&path).is_err());
    }
}
