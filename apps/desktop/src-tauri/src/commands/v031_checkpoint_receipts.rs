//! Receipt ordinals 3 and 6 for the frozen v0.3.1 upgrade.
//!
//! A receipt is never treated as proof by itself.  Each loader authenticates
//! the complete receipt prefix, reopens the fixed DPAPI checkpoint identities,
//! verifies all five V3 components, and reconstructs the migration source
//! proof from current read-only state or the authenticated pre-write images.

#[cfg(test)]
use super::v031_target_components::verify_v031_historical_target_components_receipt_gate_with_approved_workspace_for_test;
use super::{
    original_migration_backup::OriginalRollbackVerifiedGate,
    v031_migration_checkpoint::{
        ensure_v031_migration_checkpoint, load_v031_migration_checkpoint_read_only,
        load_v031_partial_v5_checkpoint_set_from_authenticated_rollback_read_only,
        load_v031_projection_checkpoint_recovery_proof_read_only, V031MigrationCheckpointProof,
    },
    v031_privacy_migration::{
        validate_v031_privacy_v5_and_binding_materials_receipts_from_recovery,
        verify_v031_binding_materials_verified_gate_read_only, V031BindingMaterialsVerifiedGate,
    },
    v031_target_components::{
        verify_v031_historical_target_components_receipt_gate_read_only,
        V031TargetComponentsPreparedGate,
    },
};
use crate::{
    approved_mcp::ApprovedMcpWorkspace,
    privacy_workflow::{
        reconstruct_v031_step4_source_proof_from_authenticated_checkpoints_read_only,
        PrivacyWorkflowManager, V031ApprovedProjectionSourceProof,
        V031BindingMaterialTerminalProof, V031CaseMigrationCheckpointSourceProof,
    },
    v031_upgrade_r2::{
        AuthenticatedLineageInventory, AuthenticatedReceiptFile, V031CheckpointKind,
    },
    v031_upgrade_receipts::{
        load_authenticated_v031_lineage, persist_v031_receipt, OwnedV031ReceiptContext,
        PrivacyReceiptAuthenticationBridge, V031ReceiptPersistenceError,
    },
};
use privacy::{
    sha256_hex,
    upgrade_receipt_v1::{
        V031UpgradeReceiptCountKey, V031UpgradeReceiptStage, V031_UPGRADE_RECEIPT_MIGRATION_ID,
        V031_UPGRADE_RECEIPT_RESULT_CODE, V031_UPGRADE_RECEIPT_SCHEMA_VERSION,
    },
    vnext::{canonical_json_v1, WorkspaceInstanceId},
};
use serde::Serialize;
use std::{collections::BTreeMap, fmt, path::Path, sync::Mutex};

const CASE_BACKUPS_STAGE: V031UpgradeReceiptStage =
    V031UpgradeReceiptStage::CaseMigrationBackupsVerified;
const PROJECTION_BACKUP_STAGE: V031UpgradeReceiptStage =
    V031UpgradeReceiptStage::ProjectionBackupVerified;

static V031_CHECKPOINT_RECEIPT_OPERATION: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn with_v031_checkpoint_receipt_operation_for_test<T>(
    operation: impl FnOnce() -> T,
) -> T {
    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .expect("checkpoint receipt operation lock is available to production-order tests");
    operation()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031CheckpointReceiptError {
    InvalidInput,
    TargetGate,
    SourceProof,
    Checkpoint,
    ReceiptPrefix,
    Evidence,
    ReceiptPersistence,
}

impl V031CheckpointReceiptError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "v031_checkpoint_receipt_invalid_input",
            Self::TargetGate => "v031_checkpoint_receipt_target_gate_invalid",
            Self::SourceProof => "v031_checkpoint_receipt_source_proof_invalid",
            Self::Checkpoint => "v031_checkpoint_receipt_checkpoint_invalid",
            Self::ReceiptPrefix => "v031_checkpoint_receipt_prefix_invalid",
            Self::Evidence => "v031_checkpoint_receipt_evidence_invalid",
            Self::ReceiptPersistence => "v031_checkpoint_receipt_persistence_failed",
        }
    }
}

impl fmt::Display for V031CheckpointReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031CheckpointReceiptError {}

/// Opaque committed receipt-3 capability.  It owns both authenticated source
/// checkpoints and the source proof reconstructed from those immutable images.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031CaseMigrationBackupsVerifiedGate {
    receipt_context: OwnedV031ReceiptContext,
    rollback_gate: OriginalRollbackVerifiedGate,
    target_gate: V031TargetComponentsPreparedGate,
    source_proof: V031CaseMigrationCheckpointSourceProof,
    binding_checkpoint: V031MigrationCheckpointProof,
    material_checkpoint: V031MigrationCheckpointProof,
    case_migration_backups_evidence_sha256: String,
    case_migration_backups_receipt_sha256: String,
}

/// Opaque workspace identity authenticated from exact receipts 0..3 plus both
/// complete Step-4 checkpoints.  Raw checkpoint identities or a schema-5
/// database cannot construct this proof.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031PartialV5WorkspaceProof {
    workspace_instance_id: WorkspaceInstanceId,
    _authenticated: (),
}

impl V031PartialV5WorkspaceProof {
    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        &self.workspace_instance_id
    }
}

impl fmt::Debug for V031CaseMigrationBackupsVerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031CaseMigrationBackupsVerifiedGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field(
                "source_evidence_sha256",
                &self.source_proof.evidence_sha256(),
            )
            .field(
                "binding_checkpoint_identity_sha256",
                &self.binding_checkpoint.identity_protected_sha256(),
            )
            .field(
                "material_checkpoint_identity_sha256",
                &self.material_checkpoint.identity_protected_sha256(),
            )
            .field(
                "case_migration_backups_evidence_sha256",
                &self.case_migration_backups_evidence_sha256,
            )
            .field(
                "case_migration_backups_receipt_sha256",
                &self.case_migration_backups_receipt_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl V031CaseMigrationBackupsVerifiedGate {
    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn rollback_gate(&self) -> &OriginalRollbackVerifiedGate {
        &self.rollback_gate
    }

    pub(crate) fn target_gate(&self) -> &V031TargetComponentsPreparedGate {
        &self.target_gate
    }

    pub(crate) fn source_proof(&self) -> &V031CaseMigrationCheckpointSourceProof {
        &self.source_proof
    }

    pub(crate) fn binding_checkpoint(&self) -> &V031MigrationCheckpointProof {
        &self.binding_checkpoint
    }

    pub(crate) fn material_checkpoint(&self) -> &V031MigrationCheckpointProof {
        &self.material_checkpoint
    }

    #[cfg(test)]
    pub(crate) fn case_migration_backups_evidence_sha256(&self) -> &str {
        &self.case_migration_backups_evidence_sha256
    }

    pub(crate) fn case_migration_backups_receipt_sha256(&self) -> &str {
        &self.case_migration_backups_receipt_sha256
    }
}

/// Opaque committed receipt-6 capability.  It deliberately stores immutable
/// receipt-5 anchors instead of embedding Gate5, avoiding a recursive type
/// while still allowing receipt-7 callbacks to perform a fresh disk reload.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031ProjectionBackupVerifiedGate {
    receipt_context: OwnedV031ReceiptContext,
    rollback_gate: OriginalRollbackVerifiedGate,
    target_gate: V031TargetComponentsPreparedGate,
    step5_terminal: V031BindingMaterialTerminalProof,
    projection_source_proof: V031ApprovedProjectionSourceProof,
    projection_checkpoint: V031MigrationCheckpointProof,
    binding_materials_receipt_sha256: String,
    projection_backup_evidence_sha256: String,
    projection_backup_receipt_sha256: String,
}

impl fmt::Debug for V031ProjectionBackupVerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ProjectionBackupVerifiedGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field(
                "step5_terminal_manifest_sha256",
                &self.step5_terminal.terminal_manifest_sha256(),
            )
            .field(
                "projection_source_evidence_sha256",
                &self.projection_source_proof.evidence_sha256(),
            )
            .field(
                "projection_candidate_count",
                &self.projection_source_proof.candidate_count(),
            )
            .field(
                "projection_checkpoint_identity_sha256",
                &self.projection_checkpoint.identity_protected_sha256(),
            )
            .field(
                "binding_materials_receipt_sha256",
                &self.binding_materials_receipt_sha256,
            )
            .field(
                "projection_backup_evidence_sha256",
                &self.projection_backup_evidence_sha256,
            )
            .field(
                "projection_backup_receipt_sha256",
                &self.projection_backup_receipt_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl V031ProjectionBackupVerifiedGate {
    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn rollback_gate(&self) -> &OriginalRollbackVerifiedGate {
        &self.rollback_gate
    }

    pub(crate) fn target_gate(&self) -> &V031TargetComponentsPreparedGate {
        &self.target_gate
    }

    pub(crate) fn step5_terminal(&self) -> &V031BindingMaterialTerminalProof {
        &self.step5_terminal
    }

    pub(crate) fn projection_source_proof(&self) -> &V031ApprovedProjectionSourceProof {
        &self.projection_source_proof
    }

    pub(crate) fn projection_checkpoint(&self) -> &V031MigrationCheckpointProof {
        &self.projection_checkpoint
    }

    pub(crate) fn binding_materials_receipt_sha256(&self) -> &str {
        &self.binding_materials_receipt_sha256
    }

    #[cfg(test)]
    pub(crate) fn projection_backup_evidence_sha256(&self) -> &str {
        &self.projection_backup_evidence_sha256
    }

    pub(crate) fn projection_backup_receipt_sha256(&self) -> &str {
        &self.projection_backup_receipt_sha256
    }
}

struct CaseBackupsLiveProof {
    source: V031CaseMigrationCheckpointSourceProof,
    binding: V031MigrationCheckpointProof,
    materials: V031MigrationCheckpointProof,
    evidence_sha256: String,
}

struct ProjectionBackupLiveProof {
    step5_terminal: V031BindingMaterialTerminalProof,
    source: V031ApprovedProjectionSourceProof,
    checkpoint: V031MigrationCheckpointProof,
    binding_materials_receipt_sha256: String,
    evidence_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointReceiptEvidence<'a> {
    kind: &'static str,
    identity_protected_sha256: &'a str,
    bundle_sha256: &'a str,
    user_database_sha256: &'a str,
    user_schema_manifest_sha256: &'a str,
    user_logical_manifest_sha256: &'a str,
    user_business_manifest_sha256: &'a str,
    user_total_rows: u64,
    privacy_database_sha256: &'a str,
    privacy_schema_version: i64,
    privacy_logical_manifest_sha256: &'a str,
    privacy_business_manifest_sha256: &'a str,
    privacy_total_rows: u64,
    vault_bundle_sha256: &'a str,
    approved_workspace_bundle_sha256: &'a str,
    work_products_bundle_sha256: &'a str,
    source_fingerprint: &'a str,
    candidate_manifest_sha256: &'a str,
    candidate_count: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CaseBackupsReceiptEvidence<'a> {
    evidence_schema_version: &'static str,
    migration_id: &'static str,
    lineage_id: &'a str,
    envelope_binding_id: &'a str,
    source_profile_proof_sha256: &'a str,
    original_identity_sha256: &'a str,
    original_rollback_receipt_sha256: &'a str,
    original_user_physical_file_set_sha256: &'a str,
    original_privacy_physical_file_set_sha256: &'a str,
    target_components_evidence_sha256: &'a str,
    target_components_receipt_sha256: &'a str,
    source_evidence_sha256: &'a str,
    source_fingerprint: &'a str,
    binding_checkpoint: CheckpointReceiptEvidence<'a>,
    material_checkpoint: CheckpointReceiptEvidence<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectionBackupReceiptEvidence<'a> {
    evidence_schema_version: &'static str,
    migration_id: &'static str,
    lineage_id: &'a str,
    envelope_binding_id: &'a str,
    source_profile_proof_sha256: &'a str,
    original_identity_sha256: &'a str,
    target_components_receipt_sha256: &'a str,
    binding_materials_receipt_sha256: &'a str,
    step5_source_evidence_sha256: &'a str,
    step5_terminal_manifest_sha256: &'a str,
    projection_source_evidence_sha256: &'a str,
    projection_source_fingerprint: &'a str,
    projection_candidate_manifest_sha256: &'a str,
    projection_candidate_count: u64,
    projection_checkpoint: CheckpointReceiptEvidence<'a>,
}

/// Creates/resumes both pre-v5 checkpoints and commits receipt ordinal 3.
/// Existing receipt 3 is handled only through the read-only restart loader, so
/// a post-v5 process never attempts to reinterpret the live store as v1.
pub(crate) fn ensure_v031_case_migration_backups_verified_gate(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<V031CaseMigrationBackupsVerifiedGate, V031CheckpointReceiptError> {
    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .map_err(|_| V031CheckpointReceiptError::InvalidInput)?;
    validate_root_and_target(app_local_data_dir, target_gate)?;
    let context = target_gate.receipt_context().clone();
    let initial = authenticated_lineage(app_local_data_dir, &context)?;
    if initial
        .final_receipts
        .get(usize::from(CASE_BACKUPS_STAGE.ordinal()))
        .is_some()
    {
        return load_case_backups_gate_locked(
            app_local_data_dir,
            manager,
            approved_workspace,
            target_gate,
        );
    }

    let source = manager
        .v031_case_migration_checkpoint_source_proof(target_gate.rollback_gate(), target_gate)
        .map_err(|_| V031CheckpointReceiptError::SourceProof)?;
    let user_database_path = database::user_database_path(app_local_data_dir);
    let privacy_database_path = app_local_data_dir
        .join("privacy")
        .join("privacy-workflow.sqlite");
    let binding_candidate = source.binding_checkpoint_candidate_evidence();
    ensure_v031_migration_checkpoint(
        app_local_data_dir,
        &user_database_path,
        &privacy_database_path,
        V031CheckpointKind::Binding,
        &binding_candidate,
        target_gate.rollback_gate(),
        target_gate.approved_gate(),
        target_gate.vault_gate(),
        &initial,
        approved_workspace,
    )
    .map_err(|_| V031CheckpointReceiptError::Checkpoint)?;

    let after_binding = authenticated_lineage(app_local_data_dir, &context)?;
    let material_candidate = source.material_checkpoint_candidate_evidence();
    ensure_v031_migration_checkpoint(
        app_local_data_dir,
        &user_database_path,
        &privacy_database_path,
        V031CheckpointKind::Materials,
        &material_candidate,
        target_gate.rollback_gate(),
        target_gate.approved_gate(),
        target_gate.vault_gate(),
        &after_binding,
        approved_workspace,
    )
    .map_err(|_| V031CheckpointReceiptError::Checkpoint)?;

    let live = load_case_backups_live_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        target_gate,
    )?;
    if live.source != source {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    let counts = case_backups_counts();
    let expected_source = live.source.clone();
    let expected_binding = live.binding.clone();
    let expected_materials = live.materials.clone();
    let expected_evidence = live.evidence_sha256.clone();
    persist_v031_receipt(
        app_local_data_dir,
        &context,
        CASE_BACKUPS_STAGE,
        &expected_evidence,
        &counts,
        || {
            let observed = load_case_backups_live_locked(
                app_local_data_dir,
                manager,
                approved_workspace,
                target_gate,
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)?;
            if observed.source != expected_source
                || observed.binding != expected_binding
                || observed.materials != expected_materials
                || observed.evidence_sha256 != expected_evidence
            {
                return Err(V031ReceiptPersistenceError::EvidenceConflict);
            }
            Ok(())
        },
    )
    .map_err(|_| V031CheckpointReceiptError::ReceiptPersistence)?;

    load_case_backups_gate_locked(app_local_data_dir, manager, approved_workspace, target_gate)
}

/// Loads committed receipt 3 after any later Privacy schema transition.  The
/// original candidate proof is reconstructed solely from the two final
/// authenticated checkpoints.
pub(crate) fn load_v031_case_migration_backups_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<V031CaseMigrationBackupsVerifiedGate, V031CheckpointReceiptError> {
    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .map_err(|_| V031CheckpointReceiptError::InvalidInput)?;
    load_case_backups_gate_locked(app_local_data_dir, manager, approved_workspace, target_gate)
}

/// Manager-free startup verification of receipt 3. Both final checkpoint
/// identities/bundles, their persisted historical Gate2 fields, and the exact
/// receipt evidence are rebuilt through the same chain used by the stage
/// loaders, without opening evolved live business state.
pub(crate) fn verify_v031_case_migration_backups_historical_profile_read_only(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<(), V031CheckpointReceiptError> {
    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .map_err(|_| V031CheckpointReceiptError::InvalidInput)?;
    load_case_backups_gate_historical_locked(app_local_data_dir, approved_workspace, target_gate)?;
    Ok(())
}

/// Authenticates the only Receipt-3 profile from which a schema-5 partial
/// transition may resume.  Unlike the ordinary historical loader, this path is
/// entered while Original-V2 itself is being freshly reloaded, so it consumes
/// that opaque rollback gate and its already-authenticated lineage directly
/// instead of recursing through the target-component loader.
pub(crate) fn authenticate_v031_partial_v5_workspace_profile_read_only(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
    rollback_gate: &OriginalRollbackVerifiedGate,
    lineage: &AuthenticatedLineageInventory,
) -> Result<V031PartialV5WorkspaceProof, V031CheckpointReceiptError> {
    // Read-only by construction. Do not acquire the checkpoint-receipt mutex:
    // target/checkpoint verifiers may re-authenticate Original-V2 while already
    // holding that mutex, and the opaque rollback+inventory pair is the actual
    // authorization for this no-write path.
    let checkpoints = load_v031_partial_v5_checkpoint_set_from_authenticated_rollback_read_only(
        app_local_data_dir,
        rollback_gate,
        lineage,
        approved_workspace,
    )
    .map_err(|_| V031CheckpointReceiptError::Checkpoint)?;
    let target = checkpoints.target();
    let source = reconstruct_v031_step4_source_proof_from_authenticated_checkpoints_read_only(
        rollback_gate,
        target,
        checkpoints.binding(),
        checkpoints.materials(),
    )
    .map_err(|_| V031CheckpointReceiptError::SourceProof)?;
    if source.binding_checkpoint_candidate_evidence() != checkpoints.binding_candidate().clone()
        || source.material_checkpoint_candidate_evidence()
            != checkpoints.material_candidate().clone()
    {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    let evidence_sha256 = case_backups_evidence_sha256(
        target,
        &source,
        checkpoints.binding(),
        checkpoints.materials(),
    )?;
    let receipt = required_final_receipt(lineage, CASE_BACKUPS_STAGE)?;
    validate_receipt_metadata(
        receipt,
        target.receipt_context(),
        CASE_BACKUPS_STAGE,
        &evidence_sha256,
        &case_backups_expected_counts(),
        None,
    )?;
    Ok(V031PartialV5WorkspaceProof {
        workspace_instance_id: target.workspace_instance_id().clone(),
        _authenticated: (),
    })
}

/// Fresh read-only verification used by receipt-4/5 callbacks.  It compares a
/// newly authenticated disk capability with the caller's opaque predecessor.
pub(crate) fn verify_v031_case_migration_backups_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031CaseMigrationBackupsVerifiedGate,
) -> Result<(), V031CheckpointReceiptError> {
    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .map_err(|_| V031CheckpointReceiptError::InvalidInput)?;
    let observed = load_case_backups_gate_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        &expected.target_gate,
    )?;
    if &observed != expected {
        return Err(V031CheckpointReceiptError::Evidence);
    }
    Ok(())
}

fn load_case_backups_gate_locked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<V031CaseMigrationBackupsVerifiedGate, V031CheckpointReceiptError> {
    let observed = load_case_backups_gate_historical_locked(
        app_local_data_dir,
        approved_workspace,
        target_gate,
    )?;
    let source = manager
        .v031_case_migration_checkpoint_source_proof_from_verified_checkpoints(
            target_gate.rollback_gate(),
            target_gate,
            observed.binding_checkpoint(),
            observed.material_checkpoint(),
        )
        .map_err(|_| V031CheckpointReceiptError::SourceProof)?;
    if source != observed.source_proof {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    Ok(observed)
}

fn load_case_backups_gate_historical_locked(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<V031CaseMigrationBackupsVerifiedGate, V031CheckpointReceiptError> {
    validate_root_and_target(app_local_data_dir, target_gate)?;
    let context = target_gate.receipt_context().clone();
    let live =
        load_case_backups_historical_locked(app_local_data_dir, approved_workspace, target_gate)?;
    let lineage = authenticated_lineage(app_local_data_dir, &context)?;
    let receipt = required_final_receipt(&lineage, CASE_BACKUPS_STAGE)?;
    validate_receipt_metadata(
        receipt,
        &context,
        CASE_BACKUPS_STAGE,
        &live.evidence_sha256,
        &case_backups_expected_counts(),
        None,
    )?;
    Ok(V031CaseMigrationBackupsVerifiedGate {
        receipt_context: context,
        rollback_gate: target_gate.rollback_gate().clone(),
        target_gate: target_gate.clone(),
        source_proof: live.source,
        binding_checkpoint: live.binding,
        material_checkpoint: live.materials,
        case_migration_backups_evidence_sha256: live.evidence_sha256,
        case_migration_backups_receipt_sha256: receipt.protected_file_sha256.clone(),
    })
}

fn load_case_backups_live_locked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<CaseBackupsLiveProof, V031CheckpointReceiptError> {
    let historical =
        load_case_backups_historical_locked(app_local_data_dir, approved_workspace, target_gate)?;
    let source = manager
        .v031_case_migration_checkpoint_source_proof_from_verified_checkpoints(
            target_gate.rollback_gate(),
            target_gate,
            &historical.binding,
            &historical.materials,
        )
        .map_err(|_| V031CheckpointReceiptError::SourceProof)?;
    if source != historical.source {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    Ok(historical)
}

fn load_case_backups_historical_locked(
    app_local_data_dir: &Path,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<CaseBackupsLiveProof, V031CheckpointReceiptError> {
    validate_root_and_target(app_local_data_dir, target_gate)?;
    #[cfg(not(test))]
    verify_v031_historical_target_components_receipt_gate_read_only(
        app_local_data_dir,
        target_gate,
    )
    .map_err(|_| V031CheckpointReceiptError::TargetGate)?;
    #[cfg(test)]
    verify_v031_historical_target_components_receipt_gate_with_approved_workspace_for_test(
        app_local_data_dir,
        target_gate,
        approved_workspace,
    )
    .map_err(|_| V031CheckpointReceiptError::TargetGate)?;
    let lineage = authenticated_lineage(app_local_data_dir, target_gate.receipt_context())?;
    let (binding_candidate, binding) = load_v031_migration_checkpoint_read_only(
        app_local_data_dir,
        V031CheckpointKind::Binding,
        target_gate.rollback_gate(),
        target_gate.approved_gate(),
        target_gate.vault_gate(),
        &lineage,
        approved_workspace,
    )
    .map_err(|_| V031CheckpointReceiptError::Checkpoint)?;
    let (material_candidate, materials) = load_v031_migration_checkpoint_read_only(
        app_local_data_dir,
        V031CheckpointKind::Materials,
        target_gate.rollback_gate(),
        target_gate.approved_gate(),
        target_gate.vault_gate(),
        &lineage,
        approved_workspace,
    )
    .map_err(|_| V031CheckpointReceiptError::Checkpoint)?;
    let source = reconstruct_v031_step4_source_proof_from_authenticated_checkpoints_read_only(
        target_gate.rollback_gate(),
        target_gate,
        &binding,
        &materials,
    )
    .map_err(|_| V031CheckpointReceiptError::SourceProof)?;
    if source.binding_checkpoint_candidate_evidence() != binding_candidate
        || source.material_checkpoint_candidate_evidence() != material_candidate
    {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    let evidence_sha256 = case_backups_evidence_sha256(target_gate, &source, &binding, &materials)?;
    Ok(CaseBackupsLiveProof {
        source,
        binding,
        materials,
        evidence_sha256,
    })
}

fn validate_root_and_target(
    app_local_data_dir: &Path,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<(), V031CheckpointReceiptError> {
    if !app_local_data_dir.is_absolute()
        || target_gate.receipt_context() != &target_gate.rollback_gate().receipt_context()
        || target_gate.receipt_context().lineage_id != target_gate.rollback_gate().lineage_id()
    {
        return Err(V031CheckpointReceiptError::InvalidInput);
    }
    Ok(())
}

fn authenticated_lineage(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
) -> Result<AuthenticatedLineageInventory, V031CheckpointReceiptError> {
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    load_authenticated_v031_lineage(app_local_data_dir, &context.lineage_id, &bridge)
        .map_err(|_| V031CheckpointReceiptError::ReceiptPrefix)
}

fn required_final_receipt(
    lineage: &AuthenticatedLineageInventory,
    stage: V031UpgradeReceiptStage,
) -> Result<&AuthenticatedReceiptFile, V031CheckpointReceiptError> {
    lineage
        .final_receipts
        .get(usize::from(stage.ordinal()))
        .filter(|receipt| !receipt.incoming)
        .ok_or(V031CheckpointReceiptError::ReceiptPrefix)
}

fn validate_receipt_metadata(
    receipt: &AuthenticatedReceiptFile,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    evidence_sha256: &str,
    counts: &BTreeMap<String, u64>,
    expected_protected_sha256: Option<&str>,
) -> Result<(), V031CheckpointReceiptError> {
    let metadata = &receipt.metadata;
    if receipt.ordinal != stage.ordinal()
        || receipt.stage != stage.as_str()
        || receipt.incoming
        || metadata.schema_version != V031_UPGRADE_RECEIPT_SCHEMA_VERSION
        || metadata.migration_id != V031_UPGRADE_RECEIPT_MIGRATION_ID
        || metadata.lineage_id != context.lineage_id
        || metadata.envelope_binding_id != context.envelope_binding_id
        || metadata.ordinal != stage.ordinal()
        || metadata.stage != stage.as_str()
        || metadata.source_profile_proof_sha256 != context.source_profile_proof_sha256
        || metadata.evidence_schema_version != stage.evidence_schema_version()
        || metadata.evidence_sha256 != evidence_sha256
        || &metadata.counts != counts
        || metadata.result_code != V031_UPGRADE_RECEIPT_RESULT_CODE
        || expected_protected_sha256
            .is_some_and(|expected| receipt.protected_file_sha256 != expected)
    {
        return Err(V031CheckpointReceiptError::Evidence);
    }
    Ok(())
}

fn case_backups_counts() -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (V031UpgradeReceiptCountKey::BindingCheckpoints, 1),
        (V031UpgradeReceiptCountKey::MaterialCheckpoints, 1),
        (V031UpgradeReceiptCountKey::CheckpointComponents, 10),
    ])
}

fn case_backups_expected_counts() -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("binding_checkpoints".to_owned(), 1),
        ("material_checkpoints".to_owned(), 1),
        ("checkpoint_components".to_owned(), 10),
    ])
}

fn projection_backup_counts(candidate_count: u64) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (V031UpgradeReceiptCountKey::ProjectionCheckpoints, 1),
        (V031UpgradeReceiptCountKey::CheckpointComponents, 5),
        (
            V031UpgradeReceiptCountKey::ApprovedGenerations,
            candidate_count,
        ),
        (V031UpgradeReceiptCountKey::SourceRevalidations, 2),
    ])
}

fn projection_backup_expected_counts(candidate_count: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("projection_checkpoints".to_owned(), 1),
        ("checkpoint_components".to_owned(), 5),
        ("approved_generations".to_owned(), candidate_count),
        ("source_revalidations".to_owned(), 2),
    ])
}

fn checkpoint_receipt_evidence(
    proof: &V031MigrationCheckpointProof,
) -> CheckpointReceiptEvidence<'_> {
    CheckpointReceiptEvidence {
        kind: proof.kind().label(),
        identity_protected_sha256: proof.identity_protected_sha256(),
        bundle_sha256: proof.bundle_sha256(),
        user_database_sha256: proof.user_database_sha256(),
        user_schema_manifest_sha256: proof.user_schema_manifest_sha256(),
        user_logical_manifest_sha256: proof.user_logical_manifest_sha256(),
        user_business_manifest_sha256: proof.user_business_manifest_sha256(),
        user_total_rows: proof.user_total_rows(),
        privacy_database_sha256: proof.privacy_database_sha256(),
        privacy_schema_version: proof.privacy_schema_version(),
        privacy_logical_manifest_sha256: proof.privacy_logical_manifest_sha256(),
        privacy_business_manifest_sha256: proof.privacy_business_manifest_sha256(),
        privacy_total_rows: proof.privacy_total_rows(),
        vault_bundle_sha256: proof.vault_bundle_sha256(),
        approved_workspace_bundle_sha256: proof.approved_workspace_bundle_sha256(),
        work_products_bundle_sha256: proof.work_products_bundle_sha256(),
        source_fingerprint: proof.source_fingerprint(),
        candidate_manifest_sha256: proof.candidate_manifest_sha256(),
        candidate_count: proof.candidate_count(),
    }
}

fn case_backups_evidence_sha256(
    target_gate: &V031TargetComponentsPreparedGate,
    source: &V031CaseMigrationCheckpointSourceProof,
    binding: &V031MigrationCheckpointProof,
    materials: &V031MigrationCheckpointProof,
) -> Result<String, V031CheckpointReceiptError> {
    let rollback = target_gate.rollback_gate();
    let evidence = CaseBackupsReceiptEvidence {
        evidence_schema_version: CASE_BACKUPS_STAGE.evidence_schema_version(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID,
        lineage_id: rollback.lineage_id(),
        envelope_binding_id: rollback.envelope_binding_id(),
        source_profile_proof_sha256: rollback.source_profile_proof_sha256(),
        original_identity_sha256: rollback.original_identity_sha256(),
        original_rollback_receipt_sha256: rollback.original_rollback_receipt_sha256(),
        original_user_physical_file_set_sha256: rollback.original_user_physical_file_set_sha256(),
        original_privacy_physical_file_set_sha256: rollback
            .original_privacy_physical_file_set_sha256(),
        target_components_evidence_sha256: target_gate.target_components_evidence_sha256(),
        target_components_receipt_sha256: target_gate.target_components_receipt_sha256(),
        source_evidence_sha256: source.evidence_sha256(),
        source_fingerprint: source.source_fingerprint(),
        binding_checkpoint: checkpoint_receipt_evidence(binding),
        material_checkpoint: checkpoint_receipt_evidence(materials),
    };
    canonical_json_v1(&evidence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| V031CheckpointReceiptError::Evidence)
}

/// Creates/resumes the Projection checkpoint and commits receipt ordinal 6.
/// Gate5 is freshly verified before this module takes its own lock, avoiding a
/// cross-module lock cycle while preserving the predecessor authorization.
pub(crate) fn ensure_v031_projection_backup_verified_gate(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    binding_materials_gate: &V031BindingMaterialsVerifiedGate,
) -> Result<V031ProjectionBackupVerifiedGate, V031CheckpointReceiptError> {
    if !app_local_data_dir.is_absolute() {
        return Err(V031CheckpointReceiptError::InvalidInput);
    }
    let initial_bridge =
        PrivacyReceiptAuthenticationBridge::new(binding_materials_gate.receipt_context().clone());
    let initial_inventory = load_authenticated_v031_lineage(
        app_local_data_dir,
        &binding_materials_gate.receipt_context().lineage_id,
        &initial_bridge,
    )
    .map_err(|_| V031CheckpointReceiptError::ReceiptPrefix)?;
    if initial_inventory
        .final_receipts
        .get(usize::from(PROJECTION_BACKUP_STAGE.ordinal()))
        .is_some()
    {
        return load_v031_projection_backup_verified_gate_read_only(
            app_local_data_dir,
            manager,
            approved_workspace,
            binding_materials_gate.target_gate(),
        );
    }
    verify_v031_binding_materials_verified_gate_read_only(
        app_local_data_dir,
        manager,
        approved_workspace,
        binding_materials_gate,
    )
    .map_err(|_| V031CheckpointReceiptError::ReceiptPrefix)?;

    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .map_err(|_| V031CheckpointReceiptError::InvalidInput)?;
    let target_gate = binding_materials_gate.target_gate();
    validate_root_and_target(app_local_data_dir, target_gate)?;
    if binding_materials_gate.receipt_context() != target_gate.receipt_context()
        || binding_materials_gate.rollback_gate() != target_gate.rollback_gate()
        || binding_materials_gate
            .case_migration_backups_gate()
            .target_gate()
            != target_gate
    {
        return Err(V031CheckpointReceiptError::ReceiptPrefix);
    }
    let context = target_gate.receipt_context().clone();
    let initial = authenticated_lineage(app_local_data_dir, &context)?;
    if let Some(receipt) = initial
        .final_receipts
        .get(usize::from(PROJECTION_BACKUP_STAGE.ordinal()))
    {
        return load_projection_backup_gate_locked(
            app_local_data_dir,
            manager,
            approved_workspace,
            target_gate,
            Some(binding_materials_gate.binding_materials_receipt_sha256()),
            Some(receipt.protected_file_sha256.as_str()),
        );
    }
    let receipt_five =
        required_final_receipt(&initial, V031UpgradeReceiptStage::BindingMaterialsVerified)?;
    if receipt_five.protected_file_sha256
        != binding_materials_gate.binding_materials_receipt_sha256()
    {
        return Err(V031CheckpointReceiptError::ReceiptPrefix);
    }
    let source = manager
        .v031_approved_projection_source_proof(
            binding_materials_gate.rollback_gate(),
            binding_materials_gate.terminal_proof(),
        )
        .map_err(|_| V031CheckpointReceiptError::SourceProof)?;
    let user_database_path = database::user_database_path(app_local_data_dir);
    let privacy_database_path = app_local_data_dir
        .join("privacy")
        .join("privacy-workflow.sqlite");
    ensure_v031_migration_checkpoint(
        app_local_data_dir,
        &user_database_path,
        &privacy_database_path,
        V031CheckpointKind::Projection,
        &source.checkpoint_candidate_evidence(),
        target_gate.rollback_gate(),
        target_gate.approved_gate(),
        target_gate.vault_gate(),
        &initial,
        approved_workspace,
    )
    .map_err(|_| V031CheckpointReceiptError::Checkpoint)?;

    let live = load_projection_backup_live_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        target_gate,
        Some(binding_materials_gate.binding_materials_receipt_sha256()),
    )?;
    if live.source != source {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    if &live.step5_terminal != binding_materials_gate.terminal_proof() {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    let counts = projection_backup_counts(live.source.candidate_count());
    let expected_terminal = live.step5_terminal.clone();
    let expected_source = live.source.clone();
    let expected_checkpoint = live.checkpoint.clone();
    let expected_evidence = live.evidence_sha256.clone();
    let receipt_five_sha256 = binding_materials_gate
        .binding_materials_receipt_sha256()
        .to_owned();
    persist_v031_receipt(
        app_local_data_dir,
        &context,
        PROJECTION_BACKUP_STAGE,
        &expected_evidence,
        &counts,
        || {
            let observed = load_projection_backup_live_locked(
                app_local_data_dir,
                manager,
                approved_workspace,
                target_gate,
                Some(&receipt_five_sha256),
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)?;
            if observed.step5_terminal != expected_terminal
                || observed.source != expected_source
                || observed.checkpoint != expected_checkpoint
                || observed.evidence_sha256 != expected_evidence
            {
                return Err(V031ReceiptPersistenceError::EvidenceConflict);
            }
            Ok(())
        },
    )
    .map_err(|_| V031CheckpointReceiptError::ReceiptPersistence)?;

    load_projection_backup_gate_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        target_gate,
        Some(&receipt_five_sha256),
        None,
    )
}

/// Standalone restart loader.  It needs only the committed target gate; the
/// receipt-5 anchor, Step5 terminal, and Projection source are recovered from
/// the authenticated chain and Projection checkpoint images.
pub(crate) fn load_v031_projection_backup_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
) -> Result<V031ProjectionBackupVerifiedGate, V031CheckpointReceiptError> {
    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .map_err(|_| V031CheckpointReceiptError::InvalidInput)?;
    load_projection_backup_gate_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        target_gate,
        None,
        None,
    )
}

/// Reopens receipt0..6 and every checkpoint from disk, then compares the fresh
/// flattened capability with the expected Gate6.  Receipt7 callbacks can use
/// this after Privacy-v6 or User-v11 without recreating Gate5 from live state.
pub(crate) fn verify_v031_projection_backup_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031ProjectionBackupVerifiedGate,
) -> Result<(), V031CheckpointReceiptError> {
    let _operation = V031_CHECKPOINT_RECEIPT_OPERATION
        .lock()
        .map_err(|_| V031CheckpointReceiptError::InvalidInput)?;
    let observed = load_projection_backup_gate_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        &expected.target_gate,
        Some(&expected.binding_materials_receipt_sha256),
        Some(&expected.projection_backup_receipt_sha256),
    )?;
    if &observed != expected {
        return Err(V031CheckpointReceiptError::Evidence);
    }
    Ok(())
}

fn load_projection_backup_gate_locked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
    expected_receipt_five_sha256: Option<&str>,
    expected_receipt_six_sha256: Option<&str>,
) -> Result<V031ProjectionBackupVerifiedGate, V031CheckpointReceiptError> {
    let live = load_projection_backup_live_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        target_gate,
        expected_receipt_five_sha256,
    )?;
    let context = target_gate.receipt_context().clone();
    let lineage = authenticated_lineage(app_local_data_dir, &context)?;
    let receipt = required_final_receipt(&lineage, PROJECTION_BACKUP_STAGE)?;
    validate_receipt_metadata(
        receipt,
        &context,
        PROJECTION_BACKUP_STAGE,
        &live.evidence_sha256,
        &projection_backup_expected_counts(live.source.candidate_count()),
        expected_receipt_six_sha256,
    )?;
    Ok(V031ProjectionBackupVerifiedGate {
        receipt_context: context,
        rollback_gate: target_gate.rollback_gate().clone(),
        target_gate: target_gate.clone(),
        step5_terminal: live.step5_terminal,
        projection_source_proof: live.source,
        projection_checkpoint: live.checkpoint,
        binding_materials_receipt_sha256: live.binding_materials_receipt_sha256,
        projection_backup_evidence_sha256: live.evidence_sha256,
        projection_backup_receipt_sha256: receipt.protected_file_sha256.clone(),
    })
}

fn load_projection_backup_live_locked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    target_gate: &V031TargetComponentsPreparedGate,
    expected_receipt_five_sha256: Option<&str>,
) -> Result<ProjectionBackupLiveProof, V031CheckpointReceiptError> {
    validate_root_and_target(app_local_data_dir, target_gate)?;
    verify_v031_historical_target_components_receipt_gate_read_only(
        app_local_data_dir,
        target_gate,
    )
    .map_err(|_| V031CheckpointReceiptError::TargetGate)?;
    let context = target_gate.receipt_context();
    let lineage = authenticated_lineage(app_local_data_dir, context)?;
    let receipt_five =
        required_final_receipt(&lineage, V031UpgradeReceiptStage::BindingMaterialsVerified)?;
    if expected_receipt_five_sha256
        .is_some_and(|expected| receipt_five.protected_file_sha256 != expected)
    {
        return Err(V031CheckpointReceiptError::ReceiptPrefix);
    }
    let case_gate = load_case_backups_gate_locked(
        app_local_data_dir,
        manager,
        approved_workspace,
        target_gate,
    )?;
    let recovery = load_v031_projection_checkpoint_recovery_proof_read_only(
        app_local_data_dir,
        target_gate,
        case_gate.binding_checkpoint(),
        case_gate.material_checkpoint(),
        &lineage,
        approved_workspace,
        manager,
    )
    .map_err(|_| V031CheckpointReceiptError::Checkpoint)?;
    let _historical_privacy_gates =
        validate_v031_privacy_v5_and_binding_materials_receipts_from_recovery(
            &lineage,
            &case_gate,
            recovery.step5_terminal(),
        )
        .map_err(|_| V031CheckpointReceiptError::ReceiptPrefix)?;
    if recovery.candidate() != &recovery.projection_source().checkpoint_candidate_evidence() {
        return Err(V031CheckpointReceiptError::SourceProof);
    }
    let evidence_sha256 = projection_backup_evidence_sha256(
        target_gate,
        recovery.step5_terminal(),
        recovery.projection_source(),
        recovery.checkpoint(),
        &receipt_five.protected_file_sha256,
    )?;
    Ok(ProjectionBackupLiveProof {
        step5_terminal: recovery.step5_terminal().clone(),
        source: recovery.projection_source().clone(),
        checkpoint: recovery.checkpoint().clone(),
        binding_materials_receipt_sha256: receipt_five.protected_file_sha256.clone(),
        evidence_sha256,
    })
}

fn projection_backup_evidence_sha256(
    target_gate: &V031TargetComponentsPreparedGate,
    step5_terminal: &V031BindingMaterialTerminalProof,
    source: &V031ApprovedProjectionSourceProof,
    checkpoint: &V031MigrationCheckpointProof,
    binding_materials_receipt_sha256: &str,
) -> Result<String, V031CheckpointReceiptError> {
    let rollback = target_gate.rollback_gate();
    let evidence = ProjectionBackupReceiptEvidence {
        evidence_schema_version: PROJECTION_BACKUP_STAGE.evidence_schema_version(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID,
        lineage_id: rollback.lineage_id(),
        envelope_binding_id: rollback.envelope_binding_id(),
        source_profile_proof_sha256: rollback.source_profile_proof_sha256(),
        original_identity_sha256: rollback.original_identity_sha256(),
        target_components_receipt_sha256: target_gate.target_components_receipt_sha256(),
        binding_materials_receipt_sha256,
        step5_source_evidence_sha256: step5_terminal.source_evidence_sha256(),
        step5_terminal_manifest_sha256: step5_terminal.terminal_manifest_sha256(),
        projection_source_evidence_sha256: source.evidence_sha256(),
        projection_source_fingerprint: source.source_fingerprint(),
        projection_candidate_manifest_sha256: source.candidate_manifest_sha256(),
        projection_candidate_count: source.candidate_count(),
        projection_checkpoint: checkpoint_receipt_evidence(checkpoint),
    };
    canonical_json_v1(&evidence)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| V031CheckpointReceiptError::Evidence)
}
