//! Frozen v0.3.1 Privacy migration receipt orchestration.
//!
//! This startup-only boundary owns receipt ordinals 4, 5, and 7.  It never
//! manufactures a checkpoint capability: every writer consumes the opaque
//! committed predecessor gate from `v031_checkpoint_receipts`, reloads that
//! gate from disk, and then revalidates the live checkpoint immediately before
//! entering the corresponding Privacy writer.

use super::v031_checkpoint_receipts::{
    load_v031_projection_backup_verified_gate_read_only,
    verify_v031_case_migration_backups_verified_gate_read_only,
    verify_v031_projection_backup_verified_gate_read_only, V031CaseMigrationBackupsVerifiedGate,
    V031ProjectionBackupVerifiedGate,
};
use super::v031_user_upgrade::V031CommittedUserV11ResumeProof;
#[cfg(test)]
use crate::privacy_workflow::BackfillFailurePoint;
use crate::{
    approved_mcp::ApprovedMcpWorkspace,
    privacy_workflow::{
        PrivacyWorkflowManager, V031BindingMaterialTerminalProof, V031PrivacyV6TerminalProof,
    },
    v031_upgrade_r2::{AuthenticatedLineageInventory, AuthenticatedReceiptFile},
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
    validate_fixed_local_directory,
    vnext::canonical_json_v1,
    PrivacyV5ManifestProof, PrivacyV6ManifestProof,
};
use serde::Serialize;
use std::{collections::BTreeMap, fmt, path::Path, sync::Mutex};

const PRIVACY_V5_STAGE: V031UpgradeReceiptStage = V031UpgradeReceiptStage::PrivacyV5Verified;
const BINDING_MATERIALS_STAGE: V031UpgradeReceiptStage =
    V031UpgradeReceiptStage::BindingMaterialsVerified;
const PRIVACY_V6_STAGE: V031UpgradeReceiptStage = V031UpgradeReceiptStage::PrivacyV6Verified;
const PRIVACY_DATABASE_RELATIVE: &str = "privacy/privacy-workflow.sqlite";
const ONE_MIGRATION_BATCH: u64 = 1;
static V031_PRIVACY_MIGRATION_OPERATION: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031PrivacyMigrationError {
    InvalidInput,
    PredecessorGate,
    ReceiptPrefix,
    LiveState,
    EvidenceEncoding,
    ReceiptPersistence,
}

impl V031PrivacyMigrationError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "v031_privacy_migration_invalid_input",
            Self::PredecessorGate => "v031_privacy_migration_predecessor_gate_invalid",
            Self::ReceiptPrefix => "v031_privacy_migration_receipt_prefix_invalid",
            Self::LiveState => "v031_privacy_migration_live_state_invalid",
            Self::EvidenceEncoding => "v031_privacy_migration_evidence_encoding_failed",
            Self::ReceiptPersistence => "v031_privacy_migration_receipt_persistence_failed",
        }
    }
}

impl fmt::Display for V031PrivacyMigrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031PrivacyMigrationError {}

pub(crate) type V031PrivacyMigrationReceiptError = V031PrivacyMigrationError;

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031PrivacyV5FailurePoint {
    AfterSchemaCommitBeforeLifecycleInitialize,
    AfterLifecycleCommitBeforeBindingInitialize,
    AfterPrivacyV5CommitBeforeReceipt4,
}

/// Opaque committed receipt-4 capability.  The pre-v5 source proof remains
/// reachable only through the authenticated receipt-3 predecessor.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031PrivacyV5VerifiedGate {
    predecessor: V031CaseMigrationBackupsVerifiedGate,
    privacy_v5_schema_object_count: u64,
    evidence_sha256: String,
    receipt_sha256: String,
}

impl fmt::Debug for V031PrivacyV5VerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031PrivacyV5VerifiedGate")
            .field("lineage_id", &self.receipt_context().lineage_id)
            .field("privacy_v5_schema_version", &5_i64)
            .field(
                "privacy_v5_schema_object_count",
                &self.privacy_v5_schema_object_count,
            )
            .field("privacy_v5_evidence_sha256", &self.evidence_sha256)
            .field("privacy_v5_receipt_sha256", &self.receipt_sha256)
            .finish_non_exhaustive()
    }
}

impl V031PrivacyV5VerifiedGate {
    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        self.predecessor.receipt_context()
    }

    pub(crate) fn case_migration_backups_gate(&self) -> &V031CaseMigrationBackupsVerifiedGate {
        &self.predecessor
    }

    pub(crate) fn rollback_gate(
        &self,
    ) -> &super::original_migration_backup::OriginalRollbackVerifiedGate {
        self.predecessor.rollback_gate()
    }

    pub(crate) fn target_gate(
        &self,
    ) -> &super::v031_target_components::V031TargetComponentsPreparedGate {
        self.predecessor.target_gate()
    }

    pub(crate) const fn privacy_v5_schema_object_count(&self) -> u64 {
        self.privacy_v5_schema_object_count
    }

    pub(crate) fn privacy_v5_evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub(crate) fn privacy_v5_receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
}

/// Opaque committed receipt-5 capability.  Counts are reconstructed from the
/// terminal ledger proof; no writer invocation counter is retained.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031BindingMaterialsVerifiedGate {
    privacy_v5_gate: V031PrivacyV5VerifiedGate,
    terminal: V031BindingMaterialTerminalProof,
    evidence_sha256: String,
    receipt_sha256: String,
}

impl fmt::Debug for V031BindingMaterialsVerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031BindingMaterialsVerifiedGate")
            .field("lineage_id", &self.receipt_context().lineage_id)
            .field("binding_ledger_rows", &self.terminal.binding_ledger_rows())
            .field(
                "material_ledger_rows",
                &self.terminal.material_ledger_rows(),
            )
            .field("terminal_rows", &self.terminal.terminal_rows())
            .field("blocked_rows", &self.terminal.blocked_rows())
            .field("binding_materials_evidence_sha256", &self.evidence_sha256)
            .field("binding_materials_receipt_sha256", &self.receipt_sha256)
            .finish_non_exhaustive()
    }
}

impl V031BindingMaterialsVerifiedGate {
    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        self.privacy_v5_gate.receipt_context()
    }

    pub(crate) fn rollback_gate(
        &self,
    ) -> &super::original_migration_backup::OriginalRollbackVerifiedGate {
        self.privacy_v5_gate.rollback_gate()
    }

    pub(crate) fn target_gate(
        &self,
    ) -> &super::v031_target_components::V031TargetComponentsPreparedGate {
        self.privacy_v5_gate.target_gate()
    }

    pub(crate) fn case_migration_backups_gate(&self) -> &V031CaseMigrationBackupsVerifiedGate {
        self.privacy_v5_gate.case_migration_backups_gate()
    }

    pub(crate) fn privacy_v5_gate(&self) -> &V031PrivacyV5VerifiedGate {
        &self.privacy_v5_gate
    }

    pub(crate) fn terminal_proof(&self) -> &V031BindingMaterialTerminalProof {
        &self.terminal
    }

    pub(crate) fn binding_materials_evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub(crate) fn binding_materials_receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
}

/// Opaque committed receipt-7 capability consumed by the final User-v11
/// stage.  It retains the freshly authenticated projection checkpoint proof
/// so the final five-component manifest can be rebuilt without trusting a
/// previous process object.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031PrivacyV6VerifiedGate {
    predecessor: V031ProjectionBackupVerifiedGate,
    terminal: V031PrivacyV6TerminalProof,
    evidence_sha256: String,
    receipt_sha256: String,
}

impl fmt::Debug for V031PrivacyV6VerifiedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031PrivacyV6VerifiedGate")
            .field("lineage_id", &self.receipt_context().lineage_id)
            .field("projection_rows", &self.terminal.projection_rows())
            .field("blocked_projection_rows", &self.terminal.blocked_rows())
            .field("privacy_v6_evidence_sha256", &self.evidence_sha256)
            .field("privacy_v6_receipt_sha256", &self.receipt_sha256)
            .finish_non_exhaustive()
    }
}

impl V031PrivacyV6VerifiedGate {
    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        self.predecessor.receipt_context()
    }

    pub(crate) fn rollback_gate(
        &self,
    ) -> &super::original_migration_backup::OriginalRollbackVerifiedGate {
        self.predecessor.rollback_gate()
    }

    pub(crate) fn target_gate(
        &self,
    ) -> &super::v031_target_components::V031TargetComponentsPreparedGate {
        self.predecessor.target_gate()
    }

    pub(crate) fn projection_backup_gate(&self) -> &V031ProjectionBackupVerifiedGate {
        &self.predecessor
    }

    pub(crate) fn projection_checkpoint(
        &self,
    ) -> &super::v031_migration_checkpoint::V031MigrationCheckpointProof {
        self.predecessor.projection_checkpoint()
    }

    #[cfg(test)]
    pub(crate) fn terminal_proof(&self) -> &V031PrivacyV6TerminalProof {
        &self.terminal
    }

    pub(crate) fn privacy_v6_evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub(crate) fn privacy_v6_receipt_sha256(&self) -> &str {
        &self.receipt_sha256
    }
}

/// Pure, lock-free recovery validator used by the receipt-6 checkpoint
/// loader. `lineage` is already an authenticated opaque inventory; this
/// function performs no live database reads. Receipt 4 remains an authenticated
/// historical pre-Step-5 anchor; receipt 5 is recomputed against the
/// offline-rebuilt post-Step-5 terminal proof and the exact protected receipt-4
/// hash.
pub(crate) fn validate_v031_privacy_v5_and_binding_materials_receipts_from_recovery(
    lineage: &AuthenticatedLineageInventory,
    gate3: &V031CaseMigrationBackupsVerifiedGate,
    terminal: &V031BindingMaterialTerminalProof,
) -> Result<
    (V031PrivacyV5VerifiedGate, V031BindingMaterialsVerifiedGate),
    V031PrivacyMigrationReceiptError,
> {
    if lineage.lineage_id != gate3.receipt_context().lineage_id
        || lineage.final_receipts.len() < 6
        || lineage.final_receipts.get(3).is_none_or(|receipt| {
            receipt.protected_file_sha256 != gate3.case_migration_backups_receipt_sha256()
        })
    {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    let receipt4 = lineage
        .final_receipts
        .get(4)
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    validate_receipt_metadata(
        receipt4,
        gate3.receipt_context(),
        PRIVACY_V5_STAGE,
        gate3.case_migration_backups_receipt_sha256(),
        &receipt4.metadata.evidence_sha256,
        &privacy_v5_wire_counts(terminal.privacy_v5().schema_object_count),
        Some(&receipt4.protected_file_sha256),
    )?;
    if receipt4.incoming {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }

    let receipt5 = lineage
        .final_receipts
        .get(5)
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    let binding_evidence = binding_materials_evidence_sha256_from_parts(
        gate3.receipt_context(),
        &receipt4.protected_file_sha256,
        terminal,
    )?;
    validate_receipt_metadata(
        receipt5,
        gate3.receipt_context(),
        BINDING_MATERIALS_STAGE,
        &receipt4.protected_file_sha256,
        &binding_evidence,
        &binding_materials_wire_counts(terminal),
        Some(&receipt5.protected_file_sha256),
    )?;
    if receipt5.incoming {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    let privacy_v5_gate = committed_privacy_v5_gate(
        gate3.clone(),
        terminal.privacy_v5().schema_object_count,
        receipt4.metadata.evidence_sha256.clone(),
        receipt4.protected_file_sha256.clone(),
    )?;
    let binding_materials_gate = committed_binding_materials_gate(
        privacy_v5_gate.clone(),
        terminal.clone(),
        binding_evidence,
        receipt5.protected_file_sha256.clone(),
    )?;
    Ok((privacy_v5_gate, binding_materials_gate))
}

/// Executes or resumes only the Privacy v1->v5 transition, then commits
/// receipt ordinal 4.  A committed receipt is always handled as a read-only
/// loader path.
pub(crate) fn ensure_v031_privacy_v5_verified(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
) -> Result<V031PrivacyV5VerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    ensure_v031_privacy_v5_verified_inner(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        None,
    )
}

/// Runs the production receipt-4 coordinator and stops only after the real
/// Privacy v1->v5 writer has committed, before either receipt-4 pathname can be
/// created. The wrapper owns the operation lock and calls the common inner
/// directly, so the failure seam can never recursively acquire the mutex.
#[cfg(test)]
pub(crate) fn ensure_v031_privacy_v5_verified_with_failure_for_test(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
    failure_point: V031PrivacyV5FailurePoint,
) -> Result<V031PrivacyV5VerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    ensure_v031_privacy_v5_verified_inner(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        Some(failure_point),
    )
}

fn ensure_v031_privacy_v5_verified_inner(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
    #[cfg(test)] failure_point: Option<V031PrivacyV5FailurePoint>,
    #[cfg(not(test))] _failure_point: Option<()>,
) -> Result<V031PrivacyV5VerifiedGate, V031PrivacyMigrationError> {
    validate_app_root(app_local_data_dir)?;
    verify_case_migration_predecessor(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
    )?;
    let stage_state = receipt_stage_state(
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V5_STAGE,
        predecessor.case_migration_backups_receipt_sha256(),
    )?;
    if stage_state == ReceiptStageState::Final {
        return load_privacy_v5_gate_unlocked(
            app_local_data_dir,
            manager,
            approved_workspace,
            predecessor,
            ReceiptWindow::StrictCurrent,
        );
    }

    let (privacy_v5, _writer_committed) = if stage_state == ReceiptStageState::Incoming {
        // An authenticated incoming receipt can exist only after the schema
        // transition and its first live-state callback completed. Resume by
        // proving that state read-only; never re-enter the initializer.
        (
            manager
                .v031_initial_privacy_v5_proof_before_receipt4_read_only(
                    predecessor.rollback_gate(),
                    predecessor.target_gate(),
                    predecessor.binding_checkpoint(),
                    predecessor.material_checkpoint(),
                )
                .map_err(|_| V031PrivacyMigrationError::LiveState)?,
            false,
        )
    } else {
        // Receipt four may still be absent after the schema transaction
        // committed. Prove exact v5 first so that crash recovery installs only
        // the receipt and never re-enters any writable initializer. Falling
        // through to the writer is authorized only by the exact original-v1
        // physical and semantic proof; all other states fail before a write.
        match manager.v031_initial_privacy_v5_proof_before_receipt4_read_only(
            predecessor.rollback_gate(),
            predecessor.target_gate(),
            predecessor.binding_checkpoint(),
            predecessor.material_checkpoint(),
        ) {
            Ok(proof) => (proof, false),
            Err(_) => {
                if validate_exact_privacy_v1_writer_source(app_local_data_dir, predecessor).is_ok()
                {
                    #[cfg(test)]
                    let upgraded = match failure_point {
                        Some(
                            V031PrivacyV5FailurePoint::AfterSchemaCommitBeforeLifecycleInitialize,
                        ) => manager
                            .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_schema_for_test(
                                predecessor.rollback_gate(),
                                predecessor.target_gate(),
                                predecessor.source_proof(),
                                predecessor.binding_checkpoint(),
                                predecessor.material_checkpoint(),
                            ),
                        Some(
                            V031PrivacyV5FailurePoint::AfterLifecycleCommitBeforeBindingInitialize,
                        ) => manager
                            .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_lifecycle_for_test(
                                predecessor.rollback_gate(),
                                predecessor.target_gate(),
                                predecessor.source_proof(),
                                predecessor.binding_checkpoint(),
                                predecessor.material_checkpoint(),
                            ),
                        None
                        | Some(V031PrivacyV5FailurePoint::AfterPrivacyV5CommitBeforeReceipt4) => {
                            manager
                                .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                                    predecessor.rollback_gate(),
                                    predecessor.target_gate(),
                                    predecessor.source_proof(),
                                    predecessor.binding_checkpoint(),
                                    predecessor.material_checkpoint(),
                                )
                        }
                    };
                    #[cfg(not(test))]
                    let upgraded = manager
                        .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                            predecessor.rollback_gate(),
                            predecessor.target_gate(),
                            predecessor.source_proof(),
                            predecessor.binding_checkpoint(),
                            predecessor.material_checkpoint(),
                        );
                    (
                        upgraded.map_err(|_| V031PrivacyMigrationError::LiveState)?,
                        true,
                    )
                } else {
                    // A raw schema-version-5 fallback is forbidden. This path
                    // constructs and consumes the manager-private capability
                    // only if the complete receipt-3/checkpoint/target gate and
                    // one exact partial-v5 prefix agree before the first write.
                    (
                        manager
                            .resume_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                                predecessor.rollback_gate(),
                                predecessor.target_gate(),
                                predecessor.source_proof(),
                                predecessor.binding_checkpoint(),
                                predecessor.material_checkpoint(),
                            )
                            .map_err(|_| V031PrivacyMigrationError::LiveState)?,
                        true,
                    )
                }
            }
        }
    };
    #[cfg(test)]
    if _writer_committed
        && failure_point == Some(V031PrivacyV5FailurePoint::AfterPrivacyV5CommitBeforeReceipt4)
    {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    let evidence_sha256 = privacy_v5_evidence_sha256(predecessor, &privacy_v5)?;
    let counts = privacy_v5_counts(privacy_v5.schema_object_count);
    let context = predecessor.receipt_context();
    let persisted = persist_v031_receipt(
        app_local_data_dir,
        context,
        PRIVACY_V5_STAGE,
        &evidence_sha256,
        &counts,
        || {
            verify_privacy_v5_live_state(
                app_local_data_dir,
                manager,
                approved_workspace,
                predecessor,
                &privacy_v5,
                &evidence_sha256,
                &counts,
                None,
                ReceiptWindow::StrictCurrent,
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
        },
    )
    .map_err(|_| V031PrivacyMigrationError::ReceiptPersistence)?;
    verify_privacy_v5_live_state(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        &privacy_v5,
        &evidence_sha256,
        &counts,
        Some(&persisted.receipt.protected_file_sha256),
        ReceiptWindow::StrictCurrent,
    )?;
    committed_privacy_v5_gate(
        predecessor.clone(),
        privacy_v5.schema_object_count,
        evidence_sha256,
        persisted.receipt.protected_file_sha256,
    )
}

/// Restart loader for receipt ordinal 4.  Its only capability input is the
/// freshly reconstructed committed receipt-3 gate.
pub(crate) fn load_v031_privacy_v5_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
) -> Result<V031PrivacyV5VerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    load_privacy_v5_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        ReceiptWindow::CommittedWithSuccessors { max_final: 8 },
    )
}

#[cfg(test)]
pub(crate) fn verify_v031_privacy_v5_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031PrivacyV5VerifiedGate,
) -> Result<(), V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    let observed = load_privacy_v5_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        expected.case_migration_backups_gate(),
        ReceiptWindow::CommittedWithSuccessors { max_final: 8 },
    )?;
    if &observed != expected {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    Ok(())
}

/// Executes or resumes the strict binding/material writer and commits receipt
/// ordinal 5 from a committed-state-only terminal proof.
pub(crate) fn ensure_v031_binding_materials_verified(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031PrivacyV5VerifiedGate,
) -> Result<V031BindingMaterialsVerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    ensure_v031_binding_materials_verified_inner(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        None,
    )
}

/// Runs the production receipt-5 coordinator through one real binding/material
/// durable boundary while acquiring the shared operation mutex exactly once.
#[cfg(test)]
pub(crate) fn ensure_v031_binding_materials_verified_with_failure_for_test(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031PrivacyV5VerifiedGate,
    failure_point: BackfillFailurePoint,
) -> Result<V031BindingMaterialsVerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    ensure_v031_binding_materials_verified_inner(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        Some(failure_point),
    )
}

fn ensure_v031_binding_materials_verified_inner(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031PrivacyV5VerifiedGate,
    #[cfg(test)] failure_point: Option<BackfillFailurePoint>,
    #[cfg(not(test))] _failure_point: Option<()>,
) -> Result<V031BindingMaterialsVerifiedGate, V031PrivacyMigrationError> {
    validate_app_root(app_local_data_dir)?;
    let fresh_v5 = load_privacy_v5_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor.case_migration_backups_gate(),
        ReceiptWindow::CommittedWithSuccessors { max_final: 7 },
    )?;
    if &fresh_v5 != predecessor {
        return Err(V031PrivacyMigrationError::PredecessorGate);
    }
    let stage_state = receipt_stage_state(
        app_local_data_dir,
        predecessor.receipt_context(),
        BINDING_MATERIALS_STAGE,
        predecessor.privacy_v5_receipt_sha256(),
    )?;
    if stage_state == ReceiptStageState::Final {
        return load_binding_materials_gate_unlocked(
            app_local_data_dir,
            manager,
            approved_workspace,
            predecessor,
            ReceiptWindow::StrictCurrent,
        );
    }

    let checkpoint_gate = predecessor.case_migration_backups_gate();
    if stage_state == ReceiptStageState::Absent {
        // The predecessor reload above re-opened both exact-final checkpoint
        // files immediately before this sole writable Step-5 call.
        #[cfg(test)]
        let migration = match failure_point {
            Some(failure_point) => manager
                .run_v031_case_material_migration_after_checkpoints_with_failure(
                    checkpoint_gate.rollback_gate(),
                    checkpoint_gate.target_gate(),
                    checkpoint_gate.binding_checkpoint(),
                    checkpoint_gate.material_checkpoint(),
                    failure_point,
                ),
            None => manager.run_v031_case_material_migration_after_checkpoints(
                checkpoint_gate.rollback_gate(),
                checkpoint_gate.target_gate(),
                checkpoint_gate.binding_checkpoint(),
                checkpoint_gate.material_checkpoint(),
            ),
        };
        #[cfg(not(test))]
        let migration = manager.run_v031_case_material_migration_after_checkpoints(
            checkpoint_gate.rollback_gate(),
            checkpoint_gate.target_gate(),
            checkpoint_gate.binding_checkpoint(),
            checkpoint_gate.material_checkpoint(),
        );
        migration.map_err(|_| V031PrivacyMigrationError::LiveState)?;
    }
    let terminal = manager
        .v031_binding_material_terminal_proof_after_checkpoints(
            checkpoint_gate.rollback_gate(),
            checkpoint_gate.target_gate(),
            checkpoint_gate.binding_checkpoint(),
            checkpoint_gate.material_checkpoint(),
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    let evidence_sha256 = binding_materials_evidence_sha256(predecessor, &terminal)?;
    let counts = binding_materials_counts_from_terminal(&terminal);
    let persisted = persist_v031_receipt(
        app_local_data_dir,
        predecessor.receipt_context(),
        BINDING_MATERIALS_STAGE,
        &evidence_sha256,
        &counts,
        || {
            verify_binding_materials_live_state(
                app_local_data_dir,
                manager,
                approved_workspace,
                predecessor,
                &terminal,
                &evidence_sha256,
                &counts,
                None,
                ReceiptWindow::StrictCurrent,
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
        },
    )
    .map_err(|_| V031PrivacyMigrationError::ReceiptPersistence)?;
    verify_binding_materials_live_state(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        &terminal,
        &evidence_sha256,
        &counts,
        Some(&persisted.receipt.protected_file_sha256),
        ReceiptWindow::StrictCurrent,
    )?;
    committed_binding_materials_gate(
        predecessor.clone(),
        terminal,
        evidence_sha256,
        persisted.receipt.protected_file_sha256,
    )
}

/// Restart loader for receipt ordinal 5.  All counts are rebuilt from the live
/// ledger; in particular binding rows are never inferred from terminal rows.
pub(crate) fn load_v031_binding_materials_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031PrivacyV5VerifiedGate,
) -> Result<V031BindingMaterialsVerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    load_binding_materials_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        ReceiptWindow::CommittedWithSuccessors { max_final: 8 },
    )
}

pub(crate) fn verify_v031_binding_materials_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031BindingMaterialsVerifiedGate,
) -> Result<(), V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    let observed = load_binding_materials_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        expected.privacy_v5_gate(),
        ReceiptWindow::CommittedWithSuccessors { max_final: 8 },
    )?;
    if &observed != expected {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    Ok(())
}

/// Executes or resumes only the authenticated approved projection writer and
/// commits receipt ordinal 7.
pub(crate) fn ensure_v031_privacy_v6_verified(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031ProjectionBackupVerifiedGate,
) -> Result<V031PrivacyV6VerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    verify_projection_predecessor(app_local_data_dir, manager, approved_workspace, predecessor)?;
    let stage_state = receipt_stage_state(
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V6_STAGE,
        predecessor.projection_backup_receipt_sha256(),
    )?;
    if stage_state == ReceiptStageState::Final {
        return load_privacy_v6_gate_unlocked(
            app_local_data_dir,
            manager,
            approved_workspace,
            predecessor,
            ReceiptWindow::StrictCurrent,
        );
    }

    let terminal = if stage_state == ReceiptStageState::Incoming {
        manager
            .v031_privacy_v6_terminal_proof(
                predecessor.rollback_gate(),
                predecessor.step5_terminal(),
                predecessor.projection_source_proof(),
                predecessor.projection_checkpoint(),
            )
            .map_err(|_| V031PrivacyMigrationError::LiveState)?
    } else {
        // The predecessor verifier re-opened the exact-final Projection
        // checkpoint immediately before this sole writable Step-6 call.
        manager
            .run_v031_approved_projection_migration_after_checkpoint(
                predecessor.rollback_gate(),
                predecessor.step5_terminal(),
                predecessor.projection_source_proof(),
                predecessor.projection_checkpoint(),
            )
            .map_err(|_| V031PrivacyMigrationError::LiveState)?
    };
    let evidence_sha256 = privacy_v6_evidence_sha256(predecessor, &terminal)?;
    let counts = privacy_v6_counts_from_terminal(&terminal);
    let persisted = persist_v031_receipt(
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V6_STAGE,
        &evidence_sha256,
        &counts,
        || {
            verify_privacy_v6_live_state(
                app_local_data_dir,
                manager,
                approved_workspace,
                predecessor,
                &terminal,
                &evidence_sha256,
                &counts,
                None,
                ReceiptWindow::StrictCurrent,
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
        },
    )
    .map_err(|_| V031PrivacyMigrationError::ReceiptPersistence)?;
    verify_privacy_v6_live_state(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        &terminal,
        &evidence_sha256,
        &counts,
        Some(&persisted.receipt.protected_file_sha256),
        ReceiptWindow::StrictCurrent,
    )?;
    committed_privacy_v6_gate(
        predecessor.clone(),
        terminal,
        evidence_sha256,
        persisted.receipt.protected_file_sha256,
    )
}

/// Restart loader for receipt ordinal 7.  It takes only the freshly rebuilt
/// committed receipt-6 predecessor and current Privacy-v6 state.
pub(crate) fn load_v031_privacy_v6_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031ProjectionBackupVerifiedGate,
) -> Result<V031PrivacyV6VerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    load_privacy_v6_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        ReceiptWindow::CommittedWithSuccessors { max_final: 8 },
    )
}

pub(crate) fn verify_v031_privacy_v6_verified_gate_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031PrivacyV6VerifiedGate,
) -> Result<(), V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    let observed = load_privacy_v6_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        expected.projection_backup_gate(),
        ReceiptWindow::CommittedWithSuccessors { max_final: 8 },
    )?;
    if &observed != expected {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    Ok(())
}

/// Cross-schema restart loader for the state where the User-v11 transaction
/// committed before receipt ordinal 8. The opaque resume proof is the only
/// authorization that permits replacing the unavailable active User-v10
/// physical check with the authenticated Projection-checkpoint v10 image and
/// exact committed v11 audit.
pub(crate) fn load_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031ProjectionBackupVerifiedGate,
    resume: &V031CommittedUserV11ResumeProof,
) -> Result<V031PrivacyV6VerifiedGate, V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    load_privacy_v6_gate_for_committed_user_v11_resume_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
        resume,
    )
}

pub(crate) fn verify_v031_privacy_v6_verified_gate_for_committed_user_v11_resume_read_only(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031PrivacyV6VerifiedGate,
    resume: &V031CommittedUserV11ResumeProof,
) -> Result<(), V031PrivacyMigrationError> {
    let _operation = operation_guard()?;
    validate_app_root(app_local_data_dir)?;
    let observed = load_privacy_v6_gate_for_committed_user_v11_resume_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        expected.projection_backup_gate(),
        resume,
    )?;
    if &observed != expected {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    Ok(())
}

fn load_privacy_v5_gate_unlocked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
    window: ReceiptWindow,
) -> Result<V031PrivacyV5VerifiedGate, V031PrivacyMigrationError> {
    verify_case_migration_predecessor(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
    )?;
    let inventory = authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?;
    if inventory_has_committed_privacy_v6_successor(&inventory, predecessor.receipt_context())? {
        let (privacy_v5, _) =
            load_privacy_v5_and_binding_materials_from_projection_recovery_unlocked(
                app_local_data_dir,
                manager,
                approved_workspace,
                predecessor,
                &inventory,
            )?;
        let receipt_sha256 = validate_stage_receipt_inventory(
            &inventory,
            app_local_data_dir,
            predecessor.receipt_context(),
            PRIVACY_V5_STAGE,
            predecessor.case_migration_backups_receipt_sha256(),
            privacy_v5.privacy_v5_evidence_sha256(),
            &privacy_v5_wire_counts(privacy_v5.privacy_v5_schema_object_count()),
            Some(privacy_v5.privacy_v5_receipt_sha256()),
            window,
        )?
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
        if receipt_sha256 != privacy_v5.privacy_v5_receipt_sha256() {
            return Err(V031PrivacyMigrationError::ReceiptPrefix);
        }
        return Ok(privacy_v5);
    }
    let receipt = inventory
        .final_receipts
        .get(usize::from(PRIVACY_V5_STAGE.ordinal()))
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    let privacy_v5 = manager
        .v031_privacy_v5_manifest_proof_after_checkpoints_read_only(
            predecessor.rollback_gate(),
            predecessor.target_gate(),
            predecessor.binding_checkpoint(),
            predecessor.material_checkpoint(),
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    let live_evidence_sha256 = privacy_v5_evidence_sha256(predecessor, &privacy_v5)?;
    // Receipt 4 authenticates the exact schema-5 state immediately before the
    // Step-5 transaction. Once that transaction commits, its ledger/material
    // rows legitimately change the full v5 manifest. In that state the exact
    // terminal proof, reconstructed from both Step-4 checkpoints, replaces an
    // impossible comparison against the historical pre-Step-5 live image.
    let (evidence_sha256, schema_object_count) =
        if receipt.metadata.evidence_sha256 == live_evidence_sha256 {
            (live_evidence_sha256, privacy_v5.schema_object_count)
        } else {
            let terminal = manager
                .v031_binding_material_terminal_proof_after_checkpoints(
                    predecessor.rollback_gate(),
                    predecessor.target_gate(),
                    predecessor.binding_checkpoint(),
                    predecessor.material_checkpoint(),
                )
                .map_err(|_| V031PrivacyMigrationError::LiveState)?;
            (
                receipt.metadata.evidence_sha256.clone(),
                terminal.privacy_v5().schema_object_count,
            )
        };
    let receipt_sha256 = validate_stage_receipt_inventory(
        &inventory,
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V5_STAGE,
        predecessor.case_migration_backups_receipt_sha256(),
        &evidence_sha256,
        &privacy_v5_wire_counts(schema_object_count),
        None,
        window,
    )?
    .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    committed_privacy_v5_gate(
        predecessor.clone(),
        schema_object_count,
        evidence_sha256,
        receipt_sha256,
    )
}

fn load_binding_materials_gate_unlocked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031PrivacyV5VerifiedGate,
    window: ReceiptWindow,
) -> Result<V031BindingMaterialsVerifiedGate, V031PrivacyMigrationError> {
    let inventory = authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?;
    if inventory_has_committed_privacy_v6_successor(&inventory, predecessor.receipt_context())? {
        let (historical_v5, binding_materials) =
            load_privacy_v5_and_binding_materials_from_projection_recovery_unlocked(
                app_local_data_dir,
                manager,
                approved_workspace,
                predecessor.case_migration_backups_gate(),
                &inventory,
            )?;
        if &historical_v5 != predecessor {
            return Err(V031PrivacyMigrationError::PredecessorGate);
        }
        let receipt_sha256 = validate_stage_receipt_inventory(
            &inventory,
            app_local_data_dir,
            predecessor.receipt_context(),
            BINDING_MATERIALS_STAGE,
            predecessor.privacy_v5_receipt_sha256(),
            binding_materials.binding_materials_evidence_sha256(),
            &binding_materials_wire_counts(binding_materials.terminal_proof()),
            Some(binding_materials.binding_materials_receipt_sha256()),
            window,
        )?
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
        if receipt_sha256 != binding_materials.binding_materials_receipt_sha256() {
            return Err(V031PrivacyMigrationError::ReceiptPrefix);
        }
        return Ok(binding_materials);
    }
    let fresh_v5 = load_privacy_v5_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor.case_migration_backups_gate(),
        ReceiptWindow::CommittedWithSuccessors { max_final: 7 },
    )?;
    if &fresh_v5 != predecessor {
        return Err(V031PrivacyMigrationError::PredecessorGate);
    }
    let checkpoint_gate = predecessor.case_migration_backups_gate();
    let terminal = manager
        .v031_binding_material_terminal_proof_after_checkpoints(
            checkpoint_gate.rollback_gate(),
            checkpoint_gate.target_gate(),
            checkpoint_gate.binding_checkpoint(),
            checkpoint_gate.material_checkpoint(),
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    let evidence_sha256 = binding_materials_evidence_sha256(predecessor, &terminal)?;
    let receipt_sha256 = validate_stage_receipt_inventory(
        &authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?,
        app_local_data_dir,
        predecessor.receipt_context(),
        BINDING_MATERIALS_STAGE,
        predecessor.privacy_v5_receipt_sha256(),
        &evidence_sha256,
        &binding_materials_wire_counts(&terminal),
        None,
        window,
    )?
    .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    committed_binding_materials_gate(
        predecessor.clone(),
        terminal,
        evidence_sha256,
        receipt_sha256,
    )
}

fn inventory_has_committed_privacy_v6_successor(
    inventory: &AuthenticatedLineageInventory,
    context: &OwnedV031ReceiptContext,
) -> Result<bool, V031PrivacyMigrationError> {
    if inventory.final_receipts.len() < usize::from(PRIVACY_V6_STAGE.ordinal()) + 1 {
        return Ok(false);
    }
    let predecessor = inventory
        .final_receipts
        .get(usize::from(PRIVACY_V6_STAGE.ordinal()) - 1)
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    let privacy_v6 = inventory
        .final_receipts
        .get(usize::from(PRIVACY_V6_STAGE.ordinal()))
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    validate_receipt_common(
        privacy_v6,
        context,
        PRIVACY_V6_STAGE,
        &predecessor.protected_file_sha256,
    )?;
    if privacy_v6.incoming {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    Ok(true)
}

fn load_privacy_v5_and_binding_materials_from_projection_recovery_unlocked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    gate3: &V031CaseMigrationBackupsVerifiedGate,
    inventory: &AuthenticatedLineageInventory,
) -> Result<(V031PrivacyV5VerifiedGate, V031BindingMaterialsVerifiedGate), V031PrivacyMigrationError>
{
    let projection = load_v031_projection_backup_verified_gate_read_only(
        app_local_data_dir,
        manager,
        approved_workspace,
        gate3.target_gate(),
    )
    .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    let gates = validate_v031_privacy_v5_and_binding_materials_receipts_from_recovery(
        inventory,
        gate3,
        projection.step5_terminal(),
    )?;
    if projection.receipt_context() != gate3.receipt_context()
        || projection.target_gate() != gate3.target_gate()
        || projection.binding_materials_receipt_sha256()
            != gates.1.binding_materials_receipt_sha256()
    {
        return Err(V031PrivacyMigrationError::PredecessorGate);
    }
    Ok(gates)
}

fn load_privacy_v6_gate_unlocked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031ProjectionBackupVerifiedGate,
    window: ReceiptWindow,
) -> Result<V031PrivacyV6VerifiedGate, V031PrivacyMigrationError> {
    verify_projection_predecessor(app_local_data_dir, manager, approved_workspace, predecessor)?;
    let terminal = manager
        .v031_privacy_v6_terminal_proof(
            predecessor.rollback_gate(),
            predecessor.step5_terminal(),
            predecessor.projection_source_proof(),
            predecessor.projection_checkpoint(),
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    let evidence_sha256 = privacy_v6_evidence_sha256(predecessor, &terminal)?;
    let receipt_sha256 = validate_stage_receipt_inventory(
        &authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?,
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V6_STAGE,
        predecessor.projection_backup_receipt_sha256(),
        &evidence_sha256,
        &privacy_v6_wire_counts(&terminal),
        None,
        window,
    )?
    .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    committed_privacy_v6_gate(
        predecessor.clone(),
        terminal,
        evidence_sha256,
        receipt_sha256,
    )
}

fn load_privacy_v6_gate_for_committed_user_v11_resume_unlocked(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031ProjectionBackupVerifiedGate,
    resume: &V031CommittedUserV11ResumeProof,
) -> Result<V031PrivacyV6VerifiedGate, V031PrivacyMigrationError> {
    verify_projection_predecessor(app_local_data_dir, manager, approved_workspace, predecessor)?;
    if !predecessor
        .rollback_gate()
        .authenticates_same_original_rollback(resume.rollback_gate())
        || predecessor.receipt_context() != resume.receipt_context()
        || !is_lower_sha256(resume.privacy_v6_receipt_sha256())
        || !is_lower_sha256(resume.privacy_v6_evidence_sha256())
    {
        return Err(V031PrivacyMigrationError::PredecessorGate);
    }
    let terminal = manager
        .v031_privacy_v6_terminal_proof_for_committed_user_v11_resume(
            predecessor.rollback_gate(),
            predecessor.step5_terminal(),
            predecessor.projection_source_proof(),
            predecessor.projection_checkpoint(),
            resume,
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    let evidence_sha256 = privacy_v6_evidence_sha256(predecessor, &terminal)?;
    if evidence_sha256 != resume.privacy_v6_evidence_sha256() {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    let receipt_sha256 = validate_stage_receipt_inventory(
        &authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?,
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V6_STAGE,
        predecessor.projection_backup_receipt_sha256(),
        &evidence_sha256,
        &privacy_v6_wire_counts(&terminal),
        Some(resume.privacy_v6_receipt_sha256()),
        // Covers receipt-8 final/incoming and receipt-9 final/incoming while
        // still rejecting any ordinal beyond the frozen ten-file chain.
        ReceiptWindow::CommittedWithSuccessors { max_final: 10 },
    )?
    .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    if receipt_sha256 != resume.privacy_v6_receipt_sha256() {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    committed_privacy_v6_gate(
        predecessor.clone(),
        terminal,
        evidence_sha256,
        receipt_sha256,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_privacy_v5_live_state(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
    expected_privacy_v5: &PrivacyV5ManifestProof,
    expected_evidence_sha256: &str,
    expected_counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
    expected_receipt_sha256: Option<&str>,
    window: ReceiptWindow,
) -> Result<(), V031PrivacyMigrationError> {
    verify_case_migration_predecessor(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor,
    )?;
    let observed = manager
        .v031_initial_privacy_v5_proof_before_receipt4_read_only(
            predecessor.rollback_gate(),
            predecessor.target_gate(),
            predecessor.binding_checkpoint(),
            predecessor.material_checkpoint(),
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    if &observed != expected_privacy_v5
        || privacy_v5_evidence_sha256(predecessor, &observed)? != expected_evidence_sha256
        || &privacy_v5_counts(observed.schema_object_count) != expected_counts
    {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    validate_stage_receipt_inventory(
        &authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?,
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V5_STAGE,
        predecessor.case_migration_backups_receipt_sha256(),
        expected_evidence_sha256,
        &privacy_v5_wire_counts(observed.schema_object_count),
        expected_receipt_sha256,
        window,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_binding_materials_live_state(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031PrivacyV5VerifiedGate,
    expected_terminal: &V031BindingMaterialTerminalProof,
    expected_evidence_sha256: &str,
    expected_counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
    expected_receipt_sha256: Option<&str>,
    window: ReceiptWindow,
) -> Result<(), V031PrivacyMigrationError> {
    let fresh_v5 = load_privacy_v5_gate_unlocked(
        app_local_data_dir,
        manager,
        approved_workspace,
        predecessor.case_migration_backups_gate(),
        ReceiptWindow::CommittedWithSuccessors { max_final: 7 },
    )?;
    if &fresh_v5 != predecessor {
        return Err(V031PrivacyMigrationError::PredecessorGate);
    }
    let checkpoint_gate = predecessor.case_migration_backups_gate();
    let observed = manager
        .v031_binding_material_terminal_proof_after_checkpoints(
            checkpoint_gate.rollback_gate(),
            checkpoint_gate.target_gate(),
            checkpoint_gate.binding_checkpoint(),
            checkpoint_gate.material_checkpoint(),
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    if &observed != expected_terminal
        || binding_materials_evidence_sha256(predecessor, &observed)? != expected_evidence_sha256
        || &binding_materials_counts_from_terminal(&observed) != expected_counts
    {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    validate_stage_receipt_inventory(
        &authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?,
        app_local_data_dir,
        predecessor.receipt_context(),
        BINDING_MATERIALS_STAGE,
        predecessor.privacy_v5_receipt_sha256(),
        expected_evidence_sha256,
        &binding_materials_wire_counts(&observed),
        expected_receipt_sha256,
        window,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_privacy_v6_live_state(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    predecessor: &V031ProjectionBackupVerifiedGate,
    expected_terminal: &V031PrivacyV6TerminalProof,
    expected_evidence_sha256: &str,
    expected_counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
    expected_receipt_sha256: Option<&str>,
    window: ReceiptWindow,
) -> Result<(), V031PrivacyMigrationError> {
    verify_projection_predecessor(app_local_data_dir, manager, approved_workspace, predecessor)?;
    let observed = manager
        .v031_privacy_v6_terminal_proof(
            predecessor.rollback_gate(),
            predecessor.step5_terminal(),
            predecessor.projection_source_proof(),
            predecessor.projection_checkpoint(),
        )
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    if &observed != expected_terminal
        || privacy_v6_evidence_sha256(predecessor, &observed)? != expected_evidence_sha256
        || &privacy_v6_counts_from_terminal(&observed) != expected_counts
    {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    validate_stage_receipt_inventory(
        &authenticated_inventory(app_local_data_dir, predecessor.receipt_context())?,
        app_local_data_dir,
        predecessor.receipt_context(),
        PRIVACY_V6_STAGE,
        predecessor.projection_backup_receipt_sha256(),
        expected_evidence_sha256,
        &privacy_v6_wire_counts(&observed),
        expected_receipt_sha256,
        window,
    )?;
    Ok(())
}

fn verify_case_migration_predecessor(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031CaseMigrationBackupsVerifiedGate,
) -> Result<(), V031PrivacyMigrationError> {
    verify_v031_case_migration_backups_verified_gate_read_only(
        app_local_data_dir,
        manager,
        approved_workspace,
        expected,
    )
    .map_err(|_| V031PrivacyMigrationError::PredecessorGate)
}

fn verify_projection_predecessor(
    app_local_data_dir: &Path,
    manager: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
    expected: &V031ProjectionBackupVerifiedGate,
) -> Result<(), V031PrivacyMigrationError> {
    verify_v031_projection_backup_verified_gate_read_only(
        app_local_data_dir,
        manager,
        approved_workspace,
        expected,
    )
    .map_err(|_| V031PrivacyMigrationError::PredecessorGate)
}

fn authenticated_inventory(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
) -> Result<AuthenticatedLineageInventory, V031PrivacyMigrationError> {
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, &context.lineage_id, &bridge)
            .map_err(|_| V031PrivacyMigrationError::ReceiptPrefix)?;
    if !inventory.authenticates(app_local_data_dir, &context.lineage_id) {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    Ok(inventory)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiptStageState {
    Absent,
    Incoming,
    Final,
}

fn receipt_stage_state(
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    predecessor_sha256: &str,
) -> Result<ReceiptStageState, V031PrivacyMigrationError> {
    let inventory = authenticated_inventory(app_local_data_dir, context)?;
    let ordinal = usize::from(stage.ordinal());
    if inventory.final_receipts.len() < ordinal || inventory.final_receipts.len() > ordinal + 1 {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    let previous = inventory
        .final_receipts
        .get(ordinal.saturating_sub(1))
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    if previous.protected_file_sha256 != predecessor_sha256 {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    if let Some(final_receipt) = inventory.final_receipts.get(ordinal) {
        validate_receipt_common(final_receipt, context, stage, predecessor_sha256)?;
        if inventory.next_incoming_receipt.is_some() {
            return Err(V031PrivacyMigrationError::ReceiptPrefix);
        }
        return Ok(ReceiptStageState::Final);
    }
    match inventory.next_incoming_receipt.as_ref() {
        None => Ok(ReceiptStageState::Absent),
        Some(incoming) => {
            validate_receipt_common(incoming, context, stage, predecessor_sha256)?;
            Ok(ReceiptStageState::Incoming)
        }
    }
}

#[derive(Clone, Copy)]
enum ReceiptWindow {
    StrictCurrent,
    CommittedWithSuccessors { max_final: usize },
}

#[allow(clippy::too_many_arguments)]
fn validate_stage_receipt_inventory(
    inventory: &AuthenticatedLineageInventory,
    app_local_data_dir: &Path,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    predecessor_sha256: &str,
    evidence_sha256: &str,
    expected_wire_counts: &BTreeMap<String, u64>,
    expected_receipt_sha256: Option<&str>,
    window: ReceiptWindow,
) -> Result<Option<String>, V031PrivacyMigrationError> {
    if !inventory.authenticates(app_local_data_dir, &context.lineage_id) {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    let ordinal = usize::from(stage.ordinal());
    let previous = inventory
        .final_receipts
        .get(ordinal.saturating_sub(1))
        .ok_or(V031PrivacyMigrationError::ReceiptPrefix)?;
    if previous.protected_file_sha256 != predecessor_sha256 {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }

    match window {
        ReceiptWindow::StrictCurrent => {
            if inventory.final_receipts.len() < ordinal
                || inventory.final_receipts.len() > ordinal + 1
            {
                return Err(V031PrivacyMigrationError::ReceiptPrefix);
            }
        }
        ReceiptWindow::CommittedWithSuccessors { max_final } => {
            if inventory.final_receipts.len() < ordinal + 1
                || inventory.final_receipts.len() > max_final
            {
                return Err(V031PrivacyMigrationError::ReceiptPrefix);
            }
        }
    }

    let final_receipt = inventory.final_receipts.get(ordinal);
    if let Some(receipt) = final_receipt {
        validate_receipt_metadata(
            receipt,
            context,
            stage,
            predecessor_sha256,
            evidence_sha256,
            expected_wire_counts,
            expected_receipt_sha256,
        )?;
    } else if expected_receipt_sha256.is_some()
        || matches!(window, ReceiptWindow::CommittedWithSuccessors { .. })
    {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }

    if let Some(incoming) = inventory.next_incoming_receipt.as_ref() {
        match window {
            ReceiptWindow::StrictCurrent if final_receipt.is_none() => {
                validate_receipt_metadata(
                    incoming,
                    context,
                    stage,
                    predecessor_sha256,
                    evidence_sha256,
                    expected_wire_counts,
                    expected_receipt_sha256,
                )?;
            }
            ReceiptWindow::CommittedWithSuccessors { max_final }
                if inventory.final_receipts.len() < max_final
                    && incoming.ordinal as usize == inventory.final_receipts.len() => {}
            _ => return Err(V031PrivacyMigrationError::ReceiptPrefix),
        }
    }

    Ok(final_receipt.map(|receipt| receipt.protected_file_sha256.clone()))
}

fn validate_receipt_common(
    receipt: &AuthenticatedReceiptFile,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    predecessor_sha256: &str,
) -> Result<(), V031PrivacyMigrationError> {
    if receipt.ordinal != stage.ordinal()
        || receipt.stage != stage.as_str()
        || receipt.metadata.schema_version != V031_UPGRADE_RECEIPT_SCHEMA_VERSION
        || receipt.metadata.migration_id != V031_UPGRADE_RECEIPT_MIGRATION_ID
        || receipt.metadata.lineage_id != context.lineage_id
        || receipt.metadata.envelope_binding_id != context.envelope_binding_id
        || receipt.metadata.source_profile_proof_sha256 != context.source_profile_proof_sha256
        || receipt.metadata.ordinal != stage.ordinal()
        || receipt.metadata.stage != stage.as_str()
        || receipt.metadata.previous_receipt_sha256.as_deref() != Some(predecessor_sha256)
        || receipt.metadata.evidence_schema_version != stage.evidence_schema_version()
        || receipt.metadata.result_code != V031_UPGRADE_RECEIPT_RESULT_CODE
    {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_receipt_metadata(
    receipt: &AuthenticatedReceiptFile,
    context: &OwnedV031ReceiptContext,
    stage: V031UpgradeReceiptStage,
    predecessor_sha256: &str,
    evidence_sha256: &str,
    expected_wire_counts: &BTreeMap<String, u64>,
    expected_receipt_sha256: Option<&str>,
) -> Result<(), V031PrivacyMigrationError> {
    validate_receipt_common(receipt, context, stage, predecessor_sha256)?;
    if receipt.metadata.evidence_sha256 != evidence_sha256
        || &receipt.metadata.counts != expected_wire_counts
        || expected_receipt_sha256.is_some_and(|expected| expected != receipt.protected_file_sha256)
    {
        return Err(V031PrivacyMigrationError::ReceiptPrefix);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckpointEvidence<'a> {
    kind: &'static str,
    lineage_id: &'a str,
    original_identity_sha256: &'a str,
    workspace_instance_id: &'a str,
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

impl<'a> From<&'a super::v031_migration_checkpoint::V031MigrationCheckpointProof>
    for CheckpointEvidence<'a>
{
    fn from(proof: &'a super::v031_migration_checkpoint::V031MigrationCheckpointProof) -> Self {
        Self {
            kind: proof.kind().label(),
            lineage_id: proof.lineage_id(),
            original_identity_sha256: proof.original_identity_sha256(),
            workspace_instance_id: proof.workspace_instance_id(),
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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyV5Evidence<'a> {
    schema_version: i64,
    schema_manifest_sha256: &'a str,
    internal_schema_manifest_sha256: &'a str,
    schema_object_count: u64,
    table_count: u64,
    total_row_count: u64,
    logical_manifest_sha256: &'a str,
    logical_row_count: u64,
    business_manifest_sha256: &'a str,
    business_primary_key_sha256: &'a str,
    business_row_sha256: &'a str,
    business_row_count: u64,
}

impl<'a> From<&'a PrivacyV5ManifestProof> for PrivacyV5Evidence<'a> {
    fn from(proof: &'a PrivacyV5ManifestProof) -> Self {
        Self {
            schema_version: proof.schema_version,
            schema_manifest_sha256: &proof.schema_manifest_sha256,
            internal_schema_manifest_sha256: &proof.internal_schema_manifest_sha256,
            schema_object_count: proof.schema_object_count,
            table_count: proof.table_count,
            total_row_count: proof.total_row_count,
            logical_manifest_sha256: &proof.logical_manifest.sha256,
            logical_row_count: proof.logical_manifest.total_row_count,
            business_manifest_sha256: &proof.business_manifest.sha256,
            business_primary_key_sha256: &proof.business_manifest.primary_key_sha256,
            business_row_sha256: &proof.business_manifest.row_sha256,
            business_row_count: proof.business_manifest.total_row_count,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyV6Evidence<'a> {
    schema_version: i64,
    schema_object_count: usize,
    logical_manifest_sha256: &'a str,
    logical_row_count: u64,
    business_manifest_sha256: &'a str,
    business_primary_key_sha256: &'a str,
    business_row_sha256: &'a str,
    business_row_count: u64,
}

impl<'a> From<&'a PrivacyV6ManifestProof> for PrivacyV6Evidence<'a> {
    fn from(proof: &'a PrivacyV6ManifestProof) -> Self {
        Self {
            schema_version: proof.schema_version,
            schema_object_count: proof.schema_object_count,
            logical_manifest_sha256: &proof.logical_manifest.sha256,
            logical_row_count: proof.logical_manifest.total_row_count,
            business_manifest_sha256: &proof.business_manifest.sha256,
            business_primary_key_sha256: &proof.business_manifest.primary_key_sha256,
            business_row_sha256: &proof.business_manifest.row_sha256,
            business_row_count: proof.business_manifest.total_row_count,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyV5ReceiptEvidence<'a> {
    evidence_schema_version: &'static str,
    migration_id: &'static str,
    lineage_id: &'a str,
    original_identity_sha256: &'a str,
    target_components_evidence_sha256: &'a str,
    case_migration_backups_receipt_sha256: &'a str,
    source_evidence_sha256: &'a str,
    source_fingerprint: &'a str,
    binding_checkpoint: CheckpointEvidence<'a>,
    material_checkpoint: CheckpointEvidence<'a>,
    privacy_v5: PrivacyV5Evidence<'a>,
}

fn privacy_v5_evidence_sha256(
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
    proof: &PrivacyV5ManifestProof,
) -> Result<String, V031PrivacyMigrationError> {
    validate_hashes([
        predecessor.rollback_gate().original_identity_sha256(),
        predecessor
            .target_gate()
            .target_components_evidence_sha256(),
        predecessor.case_migration_backups_receipt_sha256(),
        predecessor.source_proof().evidence_sha256(),
        predecessor.source_proof().source_fingerprint(),
        proof.schema_manifest_sha256.as_str(),
        proof.internal_schema_manifest_sha256.as_str(),
        proof.logical_manifest.sha256.as_str(),
        proof.business_manifest.sha256.as_str(),
        proof.business_manifest.primary_key_sha256.as_str(),
        proof.business_manifest.row_sha256.as_str(),
    ])?;
    canonical_sha256(&PrivacyV5ReceiptEvidence {
        evidence_schema_version: PRIVACY_V5_STAGE.evidence_schema_version(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID,
        lineage_id: &predecessor.receipt_context().lineage_id,
        original_identity_sha256: predecessor.rollback_gate().original_identity_sha256(),
        target_components_evidence_sha256: predecessor
            .target_gate()
            .target_components_evidence_sha256(),
        case_migration_backups_receipt_sha256: predecessor.case_migration_backups_receipt_sha256(),
        source_evidence_sha256: predecessor.source_proof().evidence_sha256(),
        source_fingerprint: predecessor.source_proof().source_fingerprint(),
        binding_checkpoint: CheckpointEvidence::from(predecessor.binding_checkpoint()),
        material_checkpoint: CheckpointEvidence::from(predecessor.material_checkpoint()),
        privacy_v5: PrivacyV5Evidence::from(proof),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BindingMaterialsReceiptEvidence<'a> {
    evidence_schema_version: &'static str,
    migration_id: &'static str,
    lineage_id: &'a str,
    privacy_v5_receipt_sha256: &'a str,
    source_evidence_sha256: &'a str,
    privacy_v5: PrivacyV5Evidence<'a>,
    terminal_manifest_sha256: &'a str,
    binding_ledger_rows: u64,
    material_ledger_rows: u64,
    terminal_rows: u64,
    blocked_rows: u64,
    privacy_migration_batches: u64,
    bindings_verified: u64,
}

fn binding_materials_evidence_sha256(
    predecessor: &V031PrivacyV5VerifiedGate,
    terminal: &V031BindingMaterialTerminalProof,
) -> Result<String, V031PrivacyMigrationError> {
    binding_materials_evidence_sha256_from_parts(
        predecessor.receipt_context(),
        predecessor.privacy_v5_receipt_sha256(),
        terminal,
    )
}

fn binding_materials_evidence_sha256_from_parts(
    context: &OwnedV031ReceiptContext,
    privacy_v5_receipt_sha256: &str,
    terminal: &V031BindingMaterialTerminalProof,
) -> Result<String, V031PrivacyMigrationError> {
    validate_hashes([
        privacy_v5_receipt_sha256,
        terminal.source_evidence_sha256(),
        terminal.terminal_manifest_sha256(),
    ])?;
    canonical_sha256(&BindingMaterialsReceiptEvidence {
        evidence_schema_version: BINDING_MATERIALS_STAGE.evidence_schema_version(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID,
        lineage_id: &context.lineage_id,
        privacy_v5_receipt_sha256,
        source_evidence_sha256: terminal.source_evidence_sha256(),
        privacy_v5: PrivacyV5Evidence::from(terminal.privacy_v5()),
        terminal_manifest_sha256: terminal.terminal_manifest_sha256(),
        binding_ledger_rows: terminal.binding_ledger_rows(),
        material_ledger_rows: terminal.material_ledger_rows(),
        terminal_rows: terminal.terminal_rows(),
        blocked_rows: terminal.blocked_rows(),
        privacy_migration_batches: terminal.privacy_migration_batches(),
        bindings_verified: terminal.bindings_verified(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrivacyV6ReceiptEvidence<'a> {
    evidence_schema_version: &'static str,
    migration_id: &'static str,
    lineage_id: &'a str,
    projection_backup_receipt_sha256: &'a str,
    binding_materials_receipt_sha256: &'a str,
    source_evidence_sha256: &'a str,
    v5_source_fingerprint: &'a str,
    candidate_manifest_sha256: &'a str,
    candidate_count: u64,
    projection_checkpoint: CheckpointEvidence<'a>,
    privacy_v6: PrivacyV6Evidence<'a>,
    terminal_manifest_sha256: &'a str,
    approved_generation_count: u64,
    projection_rows: u64,
    blocked_projection_rows: u64,
    risk_head_rows: u64,
    revocation_rows: u64,
    binding_verified_rows: u64,
    security_trigger_count: u64,
}

fn privacy_v6_evidence_sha256(
    predecessor: &V031ProjectionBackupVerifiedGate,
    terminal: &V031PrivacyV6TerminalProof,
) -> Result<String, V031PrivacyMigrationError> {
    validate_hashes([
        predecessor.projection_backup_receipt_sha256(),
        predecessor.binding_materials_receipt_sha256(),
        terminal.source_evidence_sha256(),
        terminal.v5_source_fingerprint(),
        terminal.candidate_manifest_sha256(),
        terminal.terminal_manifest_sha256(),
        terminal.privacy_v6().logical_manifest.sha256.as_str(),
        terminal.privacy_v6().business_manifest.sha256.as_str(),
        terminal
            .privacy_v6()
            .business_manifest
            .primary_key_sha256
            .as_str(),
        terminal.privacy_v6().business_manifest.row_sha256.as_str(),
    ])?;
    canonical_sha256(&PrivacyV6ReceiptEvidence {
        evidence_schema_version: PRIVACY_V6_STAGE.evidence_schema_version(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID,
        lineage_id: &predecessor.receipt_context().lineage_id,
        projection_backup_receipt_sha256: predecessor.projection_backup_receipt_sha256(),
        binding_materials_receipt_sha256: predecessor.binding_materials_receipt_sha256(),
        source_evidence_sha256: terminal.source_evidence_sha256(),
        v5_source_fingerprint: terminal.v5_source_fingerprint(),
        candidate_manifest_sha256: terminal.candidate_manifest_sha256(),
        candidate_count: predecessor.projection_source_proof().candidate_count(),
        projection_checkpoint: CheckpointEvidence::from(predecessor.projection_checkpoint()),
        privacy_v6: PrivacyV6Evidence::from(terminal.privacy_v6()),
        terminal_manifest_sha256: terminal.terminal_manifest_sha256(),
        approved_generation_count: terminal.approved_generation_count(),
        projection_rows: terminal.projection_rows(),
        blocked_projection_rows: terminal.blocked_rows(),
        risk_head_rows: terminal.risk_head_rows(),
        revocation_rows: terminal.revocation_rows(),
        binding_verified_rows: terminal.binding_verified_rows(),
        security_trigger_count: terminal.security_trigger_count(),
    })
}

fn privacy_v5_counts(schema_objects: u64) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (
            V031UpgradeReceiptCountKey::PrivacySchemaObjects,
            schema_objects,
        ),
        (
            V031UpgradeReceiptCountKey::PrivacyMigrationBatches,
            ONE_MIGRATION_BATCH,
        ),
    ])
}

fn binding_materials_counts_from_terminal(
    terminal: &V031BindingMaterialTerminalProof,
) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    binding_materials_counts(
        terminal.binding_ledger_rows(),
        terminal.material_ledger_rows(),
        terminal.terminal_rows(),
        terminal.blocked_rows(),
        terminal.privacy_migration_batches(),
    )
}

fn binding_materials_counts(
    binding_ledger_rows: u64,
    material_ledger_rows: u64,
    terminal_rows: u64,
    blocked_rows: u64,
    privacy_migration_batches: u64,
) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (
            V031UpgradeReceiptCountKey::BindingLedgerRows,
            binding_ledger_rows,
        ),
        (
            V031UpgradeReceiptCountKey::MaterialLedgerRows,
            material_ledger_rows,
        ),
        (V031UpgradeReceiptCountKey::TerminalRows, terminal_rows),
        (V031UpgradeReceiptCountKey::BlockedRows, blocked_rows),
        (
            V031UpgradeReceiptCountKey::PrivacyMigrationBatches,
            privacy_migration_batches,
        ),
    ])
}

fn privacy_v6_counts_from_terminal(
    terminal: &V031PrivacyV6TerminalProof,
) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    privacy_v6_counts(
        terminal.schema_object_count(),
        terminal.projection_rows(),
        terminal.risk_head_rows(),
        terminal.revocation_rows(),
        terminal.security_trigger_count(),
        terminal.binding_verified_rows(),
    )
}

fn privacy_v6_counts(
    schema_objects: u64,
    projection_rows: u64,
    risk_heads: u64,
    revocation_rows: u64,
    security_triggers: u64,
    bindings_verified: u64,
) -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (
            V031UpgradeReceiptCountKey::PrivacySchemaObjects,
            schema_objects,
        ),
        (V031UpgradeReceiptCountKey::ProjectionRows, projection_rows),
        (V031UpgradeReceiptCountKey::RiskHeads, risk_heads),
        (V031UpgradeReceiptCountKey::RevocationRows, revocation_rows),
        (
            V031UpgradeReceiptCountKey::SecurityTriggers,
            security_triggers,
        ),
        (
            V031UpgradeReceiptCountKey::BindingsVerified,
            bindings_verified,
        ),
    ])
}

fn privacy_v5_wire_counts(schema_objects: u64) -> BTreeMap<String, u64> {
    BTreeMap::from([
        ("privacy_migration_batches".to_owned(), ONE_MIGRATION_BATCH),
        ("privacy_schema_objects".to_owned(), schema_objects),
    ])
}

fn binding_materials_wire_counts(
    terminal: &V031BindingMaterialTerminalProof,
) -> BTreeMap<String, u64> {
    BTreeMap::from([
        (
            "binding_ledger_rows".to_owned(),
            terminal.binding_ledger_rows(),
        ),
        ("blocked_rows".to_owned(), terminal.blocked_rows()),
        (
            "material_ledger_rows".to_owned(),
            terminal.material_ledger_rows(),
        ),
        (
            "privacy_migration_batches".to_owned(),
            terminal.privacy_migration_batches(),
        ),
        ("terminal_rows".to_owned(), terminal.terminal_rows()),
    ])
}

fn privacy_v6_wire_counts(terminal: &V031PrivacyV6TerminalProof) -> BTreeMap<String, u64> {
    BTreeMap::from([
        (
            "bindings_verified".to_owned(),
            terminal.binding_verified_rows(),
        ),
        (
            "privacy_schema_objects".to_owned(),
            terminal.schema_object_count(),
        ),
        ("projection_rows".to_owned(), terminal.projection_rows()),
        ("revocation_rows".to_owned(), terminal.revocation_rows()),
        ("risk_heads".to_owned(), terminal.risk_head_rows()),
        (
            "security_triggers".to_owned(),
            terminal.security_trigger_count(),
        ),
    ])
}

fn committed_privacy_v5_gate(
    predecessor: V031CaseMigrationBackupsVerifiedGate,
    privacy_v5_schema_object_count: u64,
    evidence_sha256: String,
    receipt_sha256: String,
) -> Result<V031PrivacyV5VerifiedGate, V031PrivacyMigrationError> {
    validate_hashes([evidence_sha256.as_str(), receipt_sha256.as_str()])?;
    Ok(V031PrivacyV5VerifiedGate {
        predecessor,
        privacy_v5_schema_object_count,
        evidence_sha256,
        receipt_sha256,
    })
}

fn committed_binding_materials_gate(
    privacy_v5_gate: V031PrivacyV5VerifiedGate,
    terminal: V031BindingMaterialTerminalProof,
    evidence_sha256: String,
    receipt_sha256: String,
) -> Result<V031BindingMaterialsVerifiedGate, V031PrivacyMigrationError> {
    validate_hashes([evidence_sha256.as_str(), receipt_sha256.as_str()])?;
    Ok(V031BindingMaterialsVerifiedGate {
        privacy_v5_gate,
        terminal,
        evidence_sha256,
        receipt_sha256,
    })
}

fn committed_privacy_v6_gate(
    predecessor: V031ProjectionBackupVerifiedGate,
    terminal: V031PrivacyV6TerminalProof,
    evidence_sha256: String,
    receipt_sha256: String,
) -> Result<V031PrivacyV6VerifiedGate, V031PrivacyMigrationError> {
    validate_hashes([evidence_sha256.as_str(), receipt_sha256.as_str()])?;
    Ok(V031PrivacyV6VerifiedGate {
        predecessor,
        terminal,
        evidence_sha256,
        receipt_sha256,
    })
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, V031PrivacyMigrationError> {
    canonical_json_v1(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| V031PrivacyMigrationError::EvidenceEncoding)
}

fn validate_hashes<'a>(
    hashes: impl IntoIterator<Item = &'a str>,
) -> Result<(), V031PrivacyMigrationError> {
    if hashes.into_iter().all(is_lower_sha256) {
        Ok(())
    } else {
        Err(V031PrivacyMigrationError::InvalidInput)
    }
}

fn validate_exact_privacy_v1_writer_source(
    app_local_data_dir: &Path,
    predecessor: &V031CaseMigrationBackupsVerifiedGate,
) -> Result<(), V031PrivacyMigrationError> {
    let source = privacy::validate_privacy_v1_migration_source_read_only(
        app_local_data_dir.join(PRIVACY_DATABASE_RELATIVE),
    )
    .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    let rollback = predecessor.rollback_gate();
    let table_count = u64::try_from(source.logical_manifest.tables.len())
        .map_err(|_| V031PrivacyMigrationError::LiveState)?;
    if !rollback.authenticates_privacy_physical_file_set(&source)
        || source.logical_manifest.sha256 != rollback.original_privacy_logical_manifest_sha256()
        || source.business_manifest.sha256 != rollback.original_privacy_business_manifest_sha256()
        || table_count != rollback.original_privacy_table_count()
        || source.logical_manifest.total_row_count != rollback.original_privacy_total_rows()
    {
        return Err(V031PrivacyMigrationError::LiveState);
    }
    Ok(())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn operation_guard() -> Result<std::sync::MutexGuard<'static, ()>, V031PrivacyMigrationError> {
    V031_PRIVACY_MIGRATION_OPERATION
        .lock()
        .map_err(|_| V031PrivacyMigrationError::InvalidInput)
}

fn validate_app_root(app_local_data_dir: &Path) -> Result<(), V031PrivacyMigrationError> {
    if !app_local_data_dir.is_absolute() {
        return Err(V031PrivacyMigrationError::InvalidInput);
    }
    validate_fixed_local_directory(app_local_data_dir)
        .map_err(|_| V031PrivacyMigrationError::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[derive(serde::Deserialize)]
    struct FrozenV031UserSchemaObject {
        object_type: String,
        sql: String,
    }

    fn hash(character: char) -> String {
        std::iter::repeat_n(character, 64).collect()
    }

    fn context() -> OwnedV031ReceiptContext {
        OwnedV031ReceiptContext {
            lineage_id: hash('1'),
            envelope_binding_id: "ws_22222222222222222222222222222222".to_owned(),
            source_profile_proof_sha256: hash('3'),
        }
    }

    #[cfg(windows)]
    fn sqlite_family_bytes(path: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
        ["", "-wal", "-shm", "-journal"]
            .into_iter()
            .map(|suffix| {
                let candidate = if suffix.is_empty() {
                    path.to_path_buf()
                } else {
                    std::path::PathBuf::from(format!("{}{}", path.display(), suffix))
                };
                (
                    suffix.to_owned(),
                    match std::fs::read(candidate) {
                        Ok(bytes) => Some(bytes),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => panic!("SQLite family member reads: {error}"),
                    },
                )
            })
            .collect()
    }

    fn authenticated_receipt(
        stage: V031UpgradeReceiptStage,
        predecessor_sha256: &str,
        evidence_sha256: &str,
        counts: BTreeMap<String, u64>,
        protected_sha256: &str,
    ) -> AuthenticatedReceiptFile {
        let context = context();
        AuthenticatedReceiptFile {
            ordinal: stage.ordinal(),
            stage: stage.as_str(),
            incoming: false,
            protected_file_sha256: protected_sha256.to_owned(),
            protected_byte_len: 512,
            metadata: crate::v031_upgrade_r2::AuthenticatedReceiptMetadata {
                schema_version: V031_UPGRADE_RECEIPT_SCHEMA_VERSION.to_owned(),
                migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID.to_owned(),
                lineage_id: context.lineage_id,
                envelope_binding_id: context.envelope_binding_id,
                ordinal: stage.ordinal(),
                stage: stage.as_str().to_owned(),
                previous_receipt_sha256: Some(predecessor_sha256.to_owned()),
                source_profile_proof_sha256: context.source_profile_proof_sha256,
                evidence_schema_version: stage.evidence_schema_version().to_owned(),
                evidence_sha256: evidence_sha256.to_owned(),
                counts,
                created_at_unix: 1_800_000_000,
                result_code: V031_UPGRADE_RECEIPT_RESULT_CODE.to_owned(),
            },
        }
    }

    #[test]
    fn receipt5_binding_count_is_independent_from_material_terminal_count() {
        let counts = binding_materials_counts(7, 3, 3, 1, 1);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::BindingLedgerRows], 7);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::MaterialLedgerRows], 3);
        assert_eq!(counts[&V031UpgradeReceiptCountKey::TerminalRows], 3);
        assert_ne!(
            counts[&V031UpgradeReceiptCountKey::BindingLedgerRows],
            counts[&V031UpgradeReceiptCountKey::TerminalRows]
        );
    }

    #[test]
    fn receipt7_allowlist_excludes_blocked_and_approved_generation_counts() {
        let counts = privacy_v6_counts(24, 2, 2, 1, 8, 2);
        assert_eq!(counts.len(), PRIVACY_V6_STAGE.count_keys().len());
        assert!(PRIVACY_V6_STAGE
            .count_keys()
            .iter()
            .all(|key| counts.contains_key(key)));
        assert!(!counts.contains_key(&V031UpgradeReceiptCountKey::BlockedRows));
        assert!(!counts.contains_key(&V031UpgradeReceiptCountKey::ApprovedGenerations));
    }

    #[test]
    fn receipt7_blocked_projection_rows_are_evidence_only() {
        let hashes = "123456789abcdef0".chars().map(hash).collect::<Vec<_>>();
        let checkpoint = CheckpointEvidence {
            kind: "approved_case_projection",
            lineage_id: &hashes[0],
            original_identity_sha256: &hashes[1],
            workspace_instance_id: "ws_33333333333333333333333333333333",
            identity_protected_sha256: &hashes[3],
            bundle_sha256: &hashes[4],
            user_database_sha256: &hashes[5],
            user_schema_manifest_sha256: &hashes[6],
            user_logical_manifest_sha256: &hashes[7],
            user_business_manifest_sha256: &hashes[8],
            user_total_rows: 11,
            privacy_database_sha256: &hashes[9],
            privacy_schema_version: 5,
            privacy_logical_manifest_sha256: &hashes[10],
            privacy_business_manifest_sha256: &hashes[11],
            privacy_total_rows: 12,
            vault_bundle_sha256: &hashes[12],
            approved_workspace_bundle_sha256: &hashes[13],
            work_products_bundle_sha256: &hashes[14],
            source_fingerprint: &hashes[15],
            candidate_manifest_sha256: &hashes[0],
            candidate_count: 7,
        };
        let evidence = PrivacyV6ReceiptEvidence {
            evidence_schema_version: PRIVACY_V6_STAGE.evidence_schema_version(),
            migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID,
            lineage_id: &hashes[1],
            projection_backup_receipt_sha256: &hashes[2],
            binding_materials_receipt_sha256: &hashes[3],
            source_evidence_sha256: &hashes[4],
            v5_source_fingerprint: &hashes[5],
            candidate_manifest_sha256: &hashes[6],
            candidate_count: 7,
            projection_checkpoint: checkpoint,
            privacy_v6: PrivacyV6Evidence {
                schema_version: 6,
                schema_object_count: 24,
                logical_manifest_sha256: &hashes[7],
                logical_row_count: 18,
                business_manifest_sha256: &hashes[8],
                business_primary_key_sha256: &hashes[9],
                business_row_sha256: &hashes[10],
                business_row_count: 13,
            },
            terminal_manifest_sha256: &hashes[11],
            approved_generation_count: 7,
            projection_rows: 2,
            blocked_projection_rows: 5,
            risk_head_rows: 2,
            revocation_rows: 1,
            binding_verified_rows: 2,
            security_trigger_count: 8,
        };
        let json = String::from_utf8(canonical_json_v1(&evidence).unwrap()).unwrap();
        assert!(json.contains("\"blockedProjectionRows\":5"));
        assert!(json.contains("\"approvedGenerationCount\":7"));
        let counts = privacy_v6_counts(24, 2, 2, 1, 8, 2);
        assert!(!counts.contains_key(&V031UpgradeReceiptCountKey::BlockedRows));
        assert!(!counts.contains_key(&V031UpgradeReceiptCountKey::ApprovedGenerations));
    }

    #[test]
    fn receipt_metadata_validator_binds_previous_schema_counts_and_protected_hash() {
        let predecessor = hash('1');
        let evidence = hash('2');
        let protected = hash('3');
        let counts = privacy_v5_wire_counts(19);
        let receipt = authenticated_receipt(
            PRIVACY_V5_STAGE,
            &predecessor,
            &evidence,
            counts.clone(),
            &protected,
        );
        validate_receipt_metadata(
            &receipt,
            &context(),
            PRIVACY_V5_STAGE,
            &predecessor,
            &evidence,
            &counts,
            Some(&protected),
        )
        .unwrap();

        let mut wrong_previous = receipt.clone();
        wrong_previous.metadata.previous_receipt_sha256 = Some(hash('4'));
        assert!(validate_receipt_metadata(
            &wrong_previous,
            &context(),
            PRIVACY_V5_STAGE,
            &predecessor,
            &evidence,
            &counts,
            Some(&protected),
        )
        .is_err());

        let mut wrong_schema = receipt.clone();
        wrong_schema.metadata.evidence_schema_version = "wrong-evidence-v1".to_owned();
        assert!(validate_receipt_metadata(
            &wrong_schema,
            &context(),
            PRIVACY_V5_STAGE,
            &predecessor,
            &evidence,
            &counts,
            Some(&protected),
        )
        .is_err());

        let wrong_counts = privacy_v5_wire_counts(20);
        assert!(validate_receipt_metadata(
            &receipt,
            &context(),
            PRIVACY_V5_STAGE,
            &predecessor,
            &evidence,
            &wrong_counts,
            Some(&protected),
        )
        .is_err());
        assert!(validate_receipt_metadata(
            &receipt,
            &context(),
            PRIVACY_V5_STAGE,
            &predecessor,
            &evidence,
            &counts,
            Some(&hash('5')),
        )
        .is_err());
    }

    #[test]
    fn receipt4_5_7_count_maps_use_only_the_frozen_allowlists() {
        let v5 = privacy_v5_counts(19);
        let binding = binding_materials_counts(7, 3, 3, 1, 1);
        let v6 = privacy_v6_counts(24, 2, 2, 1, 8, 2);
        for (stage, counts) in [
            (PRIVACY_V5_STAGE, v5),
            (BINDING_MATERIALS_STAGE, binding),
            (PRIVACY_V6_STAGE, v6),
        ] {
            assert_eq!(counts.len(), stage.count_keys().len());
            assert!(stage
                .count_keys()
                .iter()
                .all(|key| counts.contains_key(key)));
        }
    }

    #[cfg(windows)]
    #[test]
    fn full_v5_before_receipt4_with_valid_binding_is_rejected_read_only_by_startup_and_coordinator()
    {
        use std::sync::Arc;

        const TEST_NOW_UNIX: u64 = 1_800_000_000;
        let directory = tempfile::tempdir().expect("Receipt-4 full-v5 tamper root");
        let root = directory.path();
        let user_path = database::user_database_path(root);
        let privacy_path = root.join(PRIVACY_DATABASE_RELATIVE);
        create_exact_v031_user_database_for_partial_restart(&user_path);
        create_exact_privacy_v1_database_for_partial_restart(&privacy_path);

        let approved = crate::approved_mcp::ApplicationBackupTestHarness::new_for_v031_migration(
            root.to_path_buf(),
        );
        let credential_probe = approved.workspace.v031_credential_probe_for_test();
        crate::v031_upgrade_r2::verify_exact_target_absence(root, &credential_probe)
            .expect("fixture has exact target absence");
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
        let lineage_id = rollback.lineage_id().to_owned();
        let receipt_context = target.receipt_context().clone();
        let signer = privacy::ReceiptSigner::new(
            approved
                .ephemeral_secret_key()
                .expect("one-test CSPRNG receipt key"),
        )
        .expect("receipt signer constructs");
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            root.to_path_buf(),
            target.workspace_instance_id().clone(),
            Arc::new(approved.workspace.clone()),
        )
        .expect("migration manager opens exact Privacy-v1 and prepared Vault");
        manager.set_test_runtime(signer, TEST_NOW_UNIX);
        let case_backups = crate::commands::v031_checkpoint_receipts::ensure_v031_case_migration_backups_verified_gate(
            root,
            &manager,
            &approved.workspace,
            &target,
        )
        .expect("real checkpoints and Receipt 3 commit");
        ensure_v031_privacy_v5_verified_with_failure_for_test(
            root,
            &manager,
            &approved.workspace,
            &case_backups,
            V031PrivacyV5FailurePoint::AfterPrivacyV5CommitBeforeReceipt4,
        )
        .expect_err("full initial v5 commits before Receipt 4");

        let mut privacy_connection =
            rusqlite::Connection::open(&privacy_path).expect("full-v5 binding tamper writer opens");
        privacy::ProjectPrivacyCaseBindingStore::resolve_or_create(
            &mut privacy_connection,
            &privacy::ProjectId::parse("case-pre-receipt4-binding-tamper")
                .expect("tamper project id"),
            &privacy::BindingLifecycleContext::new(
                privacy::BindingCreationSource::LegacyMigration,
                "pre-receipt4-binding-tamper-audit",
                Some("project-privacy-case-binding-v1".to_owned()),
            )
            .expect("tamper binding context"),
        )
        .expect("constraint-valid audited binding tamper commits");
        privacy::compute_privacy_v5_manifests_read_only(&privacy_connection)
            .expect("the broad canonical v5 verifier still accepts this state");
        drop(privacy_connection);

        let before_rejections = sqlite_family_bytes(&privacy_path);
        crate::commands::original_migration_backup::load_original_migration_backup_gate_with_approved_workspace_for_test(
            root,
            &lineage_id,
            &approved.workspace,
        )
        .expect_err("startup Original-V2 reload rejects non-initial full v5");
        ensure_v031_privacy_v5_verified(root, &manager, &approved.workspace, &case_backups)
            .expect_err("ordinary Receipt-4 coordinator rejects non-initial full v5");
        assert_eq!(sqlite_family_bytes(&privacy_path), before_rejections);

        let inventory = load_authenticated_v031_lineage(
            root,
            &lineage_id,
            &PrivacyReceiptAuthenticationBridge::new(receipt_context),
        )
        .expect("Receipt 0..3 prefix remains authenticated");
        assert_eq!(inventory.final_receipts.len(), 4);
        assert!(inventory.next_incoming_receipt.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn receipt4_authenticated_incoming_restarts_through_startup_and_coordinator_without_privacy_rewrite(
    ) {
        use std::{fs, sync::Arc};

        const TEST_NOW_UNIX: u64 = 1_800_000_000;
        let directory = tempfile::tempdir().expect("Receipt-4 incoming restart root");
        let root = directory.path();
        let user_path = database::user_database_path(root);
        let privacy_path = root.join(PRIVACY_DATABASE_RELATIVE);
        create_exact_v031_user_database_for_partial_restart(&user_path);
        create_exact_privacy_v1_database_for_partial_restart(&privacy_path);

        let approved = crate::approved_mcp::ApplicationBackupTestHarness::new_for_v031_migration(
            root.to_path_buf(),
        );
        let credential_probe = approved.workspace.v031_credential_probe_for_test();
        crate::v031_upgrade_r2::verify_exact_target_absence(root, &credential_probe)
            .expect("fixture has exact target absence");
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
        let workspace_instance_id = target.workspace_instance_id().clone();
        let lineage_id = rollback.lineage_id().to_owned();
        let receipt_context = target.receipt_context().clone();
        let signer = privacy::ReceiptSigner::new(
            approved
                .ephemeral_secret_key()
                .expect("one-test CSPRNG receipt key"),
        )
        .expect("receipt signer constructs");
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            root.to_path_buf(),
            workspace_instance_id.clone(),
            Arc::new(approved.workspace.clone()),
        )
        .expect("migration manager opens exact Privacy-v1 and prepared Vault");
        manager.set_test_runtime(signer.clone(), TEST_NOW_UNIX);
        let case_backups = crate::commands::v031_checkpoint_receipts::ensure_v031_case_migration_backups_verified_gate(
            root,
            &manager,
            &approved.workspace,
            &target,
        )
        .expect("real V3 checkpoints and receipts zero through three commit");
        let prefix_before_v5 = load_authenticated_v031_lineage(
            root,
            &lineage_id,
            &PrivacyReceiptAuthenticationBridge::new(receipt_context.clone()),
        )
        .expect("receipt prefix authenticates before Privacy-v5");
        assert_eq!(prefix_before_v5.final_receipts.len(), 4);
        assert!(prefix_before_v5.next_incoming_receipt.is_none());
        let receipts_zero_through_three = prefix_before_v5.final_receipts;

        ensure_v031_privacy_v5_verified_with_failure_for_test(
            root,
            &manager,
            &approved.workspace,
            &case_backups,
            V031PrivacyV5FailurePoint::AfterPrivacyV5CommitBeforeReceipt4,
        )
        .expect_err("full initial Privacy-v5 commits before Receipt-4");
        manager
            .v031_initial_privacy_v5_proof_before_receipt4_read_only(
                case_backups.rollback_gate(),
                case_backups.target_gate(),
                case_backups.binding_checkpoint(),
                case_backups.material_checkpoint(),
            )
            .expect("strict initial full-v5 proof holds before Receipt-4");
        let privacy_before_receipt_install = sqlite_family_bytes(&privacy_path);

        crate::v031_upgrade_r2::fail_next_receipt_after_authenticated_incoming_for_test();
        let interrupted =
            ensure_v031_privacy_v5_verified(root, &manager, &approved.workspace, &case_backups);
        crate::v031_upgrade_r2::clear_receipt_install_failure_for_test();
        assert_eq!(
            interrupted.expect_err("Receipt-4 install stops after authenticated incoming"),
            V031PrivacyMigrationError::ReceiptPersistence
        );

        let lineage_directory =
            crate::v031_upgrade_r2::canonical_lineage_directory(root, &lineage_id)
                .expect("lineage directory resolves");
        let incoming_path = lineage_directory.join(PRIVACY_V5_STAGE.incoming_basename());
        let final_path = lineage_directory.join(PRIVACY_V5_STAGE.final_basename());
        assert!(incoming_path.is_file());
        assert!(!final_path.exists());
        let incoming_bytes =
            fs::read(&incoming_path).expect("authenticated Receipt-4 incoming reads");
        let staged_inventory = load_authenticated_v031_lineage(
            root,
            &lineage_id,
            &PrivacyReceiptAuthenticationBridge::new(receipt_context.clone()),
        )
        .expect("Receipt-4 incoming authenticates after the injected crash");
        assert_eq!(staged_inventory.final_receipts, receipts_zero_through_three);
        let staged = staged_inventory
            .next_incoming_receipt
            .expect("Receipt-4 is the unique authenticated incoming");
        assert!(staged.incoming);
        assert_eq!(staged.ordinal, PRIVACY_V5_STAGE.ordinal());
        assert_eq!(staged.stage, PRIVACY_V5_STAGE.as_str());
        assert_eq!(
            staged.metadata.previous_receipt_sha256.as_deref(),
            receipts_zero_through_three
                .last()
                .map(|receipt| receipt.protected_file_sha256.as_str())
        );
        assert_eq!(sha256_hex(&incoming_bytes), staged.protected_file_sha256);
        assert_eq!(
            sqlite_family_bytes(&privacy_path),
            privacy_before_receipt_install,
            "creating the authenticated Receipt-4 incoming never rewrites Privacy"
        );

        drop(case_backups);
        drop(manager);
        drop(target);
        drop(rollback);

        let process_start = crate::commands::v031_upgrade_complete::
            observe_v031_upgrade_at_process_start_read_only(root)
            .expect("process-start observer accepts Receipt-4 incoming");
        assert_eq!(process_start.active_lineage_id(), Some(lineage_id.as_str()));
        assert_eq!(process_start.active_final_receipt_count(), Some(4));
        assert_eq!(
            process_start.active_next_incoming_ordinal(),
            Some(PRIVACY_V5_STAGE.ordinal())
        );
        let restarted_rollback = crate::commands::original_migration_backup::load_original_migration_backup_gate_with_approved_workspace_for_test(
            root,
            &lineage_id,
            &approved.workspace,
        )
        .expect("startup Original-V2 reload accepts strict full-v5 plus Receipt-4 incoming");
        let restarted_target = crate::commands::v031_migration_checkpoint::
            load_v031_historical_target_components_from_checkpoint_read_only(
                root,
                &restarted_rollback,
                &approved.workspace,
            )
            .expect("historical Gate2 reloads from the authenticated checkpoint");
        crate::commands::v031_checkpoint_receipts::
            verify_v031_case_migration_backups_historical_profile_read_only(
                root,
                &approved.workspace,
                &restarted_target,
            )
            .expect("historical Gate3 profile verifies with Receipt-4 incoming");
        let restarted_manager = PrivacyWorkflowManager::
            new_for_application_startup_with_approved_publication_invalidator(
                root.to_path_buf(),
                workspace_instance_id,
                Arc::new(approved.workspace.clone()),
            )
            .expect("fresh startup manager observes full Privacy-v5 without maintenance");
        restarted_manager.set_test_runtime(signer, TEST_NOW_UNIX);
        let restarted_case_backups = crate::commands::v031_checkpoint_receipts::
            load_v031_case_migration_backups_verified_gate_read_only(
                root,
                &restarted_manager,
                &approved.workspace,
                &restarted_target,
            )
            .expect("Receipt-3 and both V3 checkpoints reload with Receipt-4 incoming");
        assert_eq!(
            sqlite_family_bytes(&privacy_path),
            privacy_before_receipt_install,
            "all production startup reconstruction remains read-only"
        );
        assert_eq!(
            fs::read(&incoming_path).expect("Receipt-4 incoming rereads after startup"),
            incoming_bytes
        );
        assert!(!final_path.exists());

        let completed = ensure_v031_privacy_v5_verified(
            root,
            &restarted_manager,
            &approved.workspace,
            &restarted_case_backups,
        )
        .expect("ordinary Receipt-4 coordinator resumes authenticated incoming");
        assert_eq!(
            completed.privacy_v5_schema_object_count(),
            privacy::PRIVACY_V5_SCHEMA_OBJECT_COUNT
        );
        assert_eq!(
            completed.privacy_v5_receipt_sha256(),
            staged.protected_file_sha256
        );
        assert_eq!(
            completed.privacy_v5_evidence_sha256(),
            staged.metadata.evidence_sha256
        );
        assert_eq!(
            sqlite_family_bytes(&privacy_path),
            privacy_before_receipt_install,
            "Receipt-4 incoming resume never rewrites Privacy"
        );
        assert!(!incoming_path.exists());
        assert_eq!(
            fs::read(&final_path).expect("Receipt-4 final reads"),
            incoming_bytes,
            "the exact authenticated incoming bytes become final"
        );
        let completed_inventory = load_authenticated_v031_lineage(
            root,
            &lineage_id,
            &PrivacyReceiptAuthenticationBridge::new(receipt_context),
        )
        .expect("Receipt-4 final authenticates after resume");
        assert_eq!(completed_inventory.final_receipts.len(), 5);
        assert_eq!(
            &completed_inventory.final_receipts[..4],
            receipts_zero_through_three.as_slice()
        );
        assert!(completed_inventory.next_incoming_receipt.is_none());
        let final_receipt = completed_inventory
            .final_receipts
            .last()
            .expect("Receipt-4 is final");
        assert!(!final_receipt.incoming);
        assert_eq!(final_receipt.ordinal, staged.ordinal);
        assert_eq!(final_receipt.stage, staged.stage);
        assert_eq!(
            final_receipt.protected_file_sha256,
            staged.protected_file_sha256
        );
        assert_eq!(final_receipt.protected_byte_len, staged.protected_byte_len);
        assert_eq!(final_receipt.metadata, staged.metadata);
    }

    #[cfg(windows)]
    #[test]
    fn partial_v5_schema_and_lifecycle_failpoints_restart_through_production_receipt4_coordinator()
    {
        for (failure_point, expected_partial_stage) in [
            (
                V031PrivacyV5FailurePoint::AfterSchemaCommitBeforeLifecycleInitialize,
                privacy::PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle,
            ),
            (
                V031PrivacyV5FailurePoint::AfterLifecycleCommitBeforeBindingInitialize,
                privacy::PrivacyV5PartialStage::LifecycleCommittedBeforeBinding,
            ),
        ] {
            run_partial_v5_receipt4_restart(failure_point, expected_partial_stage);
        }
    }

    #[cfg(windows)]
    fn run_partial_v5_receipt4_restart(
        failure_point: V031PrivacyV5FailurePoint,
        expected_partial_stage: privacy::PrivacyV5PartialStage,
    ) {
        use rusqlite::OpenFlags;
        use std::{fs, sync::Arc};

        const TEST_NOW_UNIX: u64 = 1_800_000_000;
        let directory = tempfile::tempdir().expect("receipt-4 partial restart root");
        let root = directory.path();
        let user_path = database::user_database_path(root);
        let privacy_path = root.join(PRIVACY_DATABASE_RELATIVE);
        create_exact_v031_user_database_for_partial_restart(&user_path);
        create_exact_privacy_v1_database_for_partial_restart(&privacy_path);

        let approved = crate::approved_mcp::ApplicationBackupTestHarness::new_for_v031_migration(
            root.to_path_buf(),
        );
        let credential_probe = approved.workspace.v031_credential_probe_for_test();
        crate::v031_upgrade_r2::verify_exact_target_absence(root, &credential_probe)
            .expect("partial-restart fixture has exact target absence");
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
        let workspace_instance_id = target.workspace_instance_id().clone();
        let lineage_id = rollback.lineage_id().to_owned();
        let receipt_context = target.receipt_context().clone();
        let signer = privacy::ReceiptSigner::new(
            approved
                .ephemeral_secret_key()
                .expect("one-test CSPRNG receipt key"),
        )
        .expect("receipt signer constructs");
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            root.to_path_buf(),
            workspace_instance_id.clone(),
            Arc::new(approved.workspace.clone()),
        )
        .expect("migration manager opens exact Privacy-v1 and prepared Vault");
        manager.set_test_runtime(signer.clone(), TEST_NOW_UNIX);
        let case_backups = crate::commands::v031_checkpoint_receipts::ensure_v031_case_migration_backups_verified_gate(
            root,
            &manager,
            &approved.workspace,
            &target,
        )
        .expect("real V3 checkpoints and receipts zero through three commit");

        let before_fault = load_authenticated_v031_lineage(
            root,
            &lineage_id,
            &PrivacyReceiptAuthenticationBridge::new(receipt_context.clone()),
        )
        .expect("receipt prefix authenticates before the fault");
        assert_eq!(before_fault.final_receipts.len(), 4);
        assert!(before_fault.next_incoming_receipt.is_none());
        ensure_v031_privacy_v5_verified_with_failure_for_test(
            root,
            &manager,
            &approved.workspace,
            &case_backups,
            failure_point,
        )
        .expect_err("the requested durable partial-v5 boundary interrupts receipt four");

        let partial_connection = rusqlite::Connection::open_with_flags(
            &privacy_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("partial Privacy-v5 opens read-only");
        let partial = privacy::classify_privacy_v5_partial_read_only(
            &partial_connection,
            &workspace_instance_id,
        )
        .expect("the crash residue is one exact recoverable partial-v5 prefix");
        assert_eq!(partial.stage(), expected_partial_stage);
        drop(partial_connection);
        let after_fault = load_authenticated_v031_lineage(
            root,
            &lineage_id,
            &PrivacyReceiptAuthenticationBridge::new(receipt_context.clone()),
        )
        .expect("receipts zero through three still authenticate after the fault");
        assert_eq!(after_fault.final_receipts, before_fault.final_receipts);
        assert!(after_fault.next_incoming_receipt.is_none());

        // Model a real process restart: discard every manager and receipts
        // zero-through-three gate, then rebuild the complete production gate
        // chain from the authenticated on-disk prefix before invoking the
        // ordinary receipt-4 coordinator.
        drop(case_backups);
        drop(manager);
        drop(target);
        drop(rollback);
        let restarted_rollback = crate::commands::original_migration_backup::load_original_migration_backup_gate_with_approved_workspace_for_test(
            root,
            &lineage_id,
            &approved.workspace,
        )
        .expect("startup reload accepts only the target-gated exact partial-v5 prefix");
        let restarted_target = crate::commands::v031_target_components::load_v031_target_components_prepared_gate_read_only(
            root,
            &restarted_rollback,
            &approved.workspace,
        )
        .expect("receipt-two target gate reloads read-only");
        let restarted_manager =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                root.to_path_buf(),
                workspace_instance_id,
                Arc::new(approved.workspace.clone()),
            )
            .expect("a fresh startup manager observes partial Privacy-v5 without maintenance");
        restarted_manager.set_test_runtime(signer, TEST_NOW_UNIX);
        let restarted_case_backups = crate::commands::v031_checkpoint_receipts::load_v031_case_migration_backups_verified_gate_read_only(
            root,
            &restarted_manager,
            &approved.workspace,
            &restarted_target,
        )
        .expect("receipt-three and both V3 checkpoints reload read-only");
        let completed = ensure_v031_privacy_v5_verified(
            root,
            &restarted_manager,
            &approved.workspace,
            &restarted_case_backups,
        )
        .expect("ordinary receipt-4 coordinator resumes the exact partial prefix");
        assert_eq!(
            completed.privacy_v5_schema_object_count(),
            privacy::PRIVACY_V5_SCHEMA_OBJECT_COUNT
        );
        let completed_connection = rusqlite::Connection::open_with_flags(
            &privacy_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("completed Privacy-v5 opens read-only");
        let completed_manifest =
            privacy::compute_privacy_v5_manifests_read_only(&completed_connection)
                .expect("receipt four is preceded by a full canonical Privacy-v5 proof");
        assert_eq!(
            completed_manifest.schema_object_count,
            privacy::PRIVACY_V5_SCHEMA_OBJECT_COUNT
        );
        assert!(privacy::classify_privacy_v5_partial_read_only(
            &completed_connection,
            restarted_target.workspace_instance_id(),
        )
        .is_err());
        drop(completed_connection);
        database::validate_user_database_migration_source_read_only(&user_path)
            .expect("the restarted coordinator leaves exact User-v10 unchanged");

        let completed_inventory = load_authenticated_v031_lineage(
            root,
            &lineage_id,
            &PrivacyReceiptAuthenticationBridge::new(receipt_context),
        )
        .expect("receipt four authenticates after full-v5 completion");
        assert_eq!(completed_inventory.final_receipts.len(), 5);
        assert!(completed_inventory.next_incoming_receipt.is_none());
        let receipt_four_path =
            crate::v031_upgrade_r2::canonical_lineage_directory(root, &lineage_id)
                .expect("lineage directory resolves")
                .join(PRIVACY_V5_STAGE.final_basename());
        let privacy_before_noop = fs::read(&privacy_path).expect("completed Privacy bytes read");
        let receipt_before_noop =
            fs::read(&receipt_four_path).expect("completed receipt-four bytes read");
        let repeated = ensure_v031_privacy_v5_verified(
            root,
            &restarted_manager,
            &approved.workspace,
            &restarted_case_backups,
        )
        .expect("a second ordinary receipt-4 ensure is a read-only no-op");
        assert_eq!(repeated, completed);
        assert_eq!(
            fs::read(&privacy_path).expect("Privacy bytes reread"),
            privacy_before_noop
        );
        assert_eq!(
            fs::read(receipt_four_path).expect("receipt-four bytes reread"),
            receipt_before_noop
        );
    }

    #[cfg(windows)]
    fn create_exact_v031_user_database_for_partial_restart(path: &Path) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("User-v10 fixture directory creates");
        }
        let connection = rusqlite::Connection::open(path).expect("User-v10 fixture opens");
        let objects =
            include_str!("../../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
                .lines()
                .map(|line| {
                    serde_json::from_str::<FrozenV031UserSchemaObject>(line)
                        .expect("frozen User-v10 schema object parses")
                })
                .collect::<Vec<_>>();
        for object_type in ["table", "index", "trigger", "view"] {
            for object in objects
                .iter()
                .filter(|object| object.object_type == object_type)
            {
                connection
                    .execute_batch(&object.sql)
                    .expect("frozen User-v10 schema DDL executes");
            }
        }
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_SCHEMA_VERSION.to_string()],
            )
            .expect("User-v10 schema version inserts");
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_CANONICAL_SCHEMA_MARKER],
            )
            .expect("User-v10 canonical marker inserts");
    }

    #[cfg(windows)]
    fn create_exact_privacy_v1_database_for_partial_restart(path: &Path) {
        std::fs::create_dir_all(path.parent().expect("Privacy-v1 fixture has parent"))
            .expect("Privacy-v1 fixture directory creates");
        let connection = rusqlite::Connection::open(path).expect("Privacy-v1 fixture opens");
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
}
