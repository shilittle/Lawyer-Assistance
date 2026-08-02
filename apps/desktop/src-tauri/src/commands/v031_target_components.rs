//! Frozen migration Step 3 and receipt ordinal 2 orchestration.
//!
//! This is a startup-only capability boundary, not a Tauri command. Callers
//! must already hold the process-wide startup and migration-operation guards.
//! The module independently re-authenticates receipt ordinals 0..1 and the
//! installed Original V2 rollback point before authorizing any target write.

#[cfg(test)]
use super::original_migration_backup::load_original_migration_backup_gate_with_approved_workspace_for_test;
use super::original_migration_backup::{
    load_original_migration_backup_gate, OriginalRollbackVerifiedGate,
};
#[cfg(test)]
use crate::{
    approved_mcp::V031ApprovedTargetWriterFailurePoint,
    privacy_workflow::{
        prepare_v031_vault_target_component_with_writer_failure_for_test,
        V031VaultTargetWriterFailurePoint,
    },
};
use crate::{
    approved_mcp::{
        load_v031_approved_mcp_target_components_read_only,
        prepare_v031_approved_mcp_target_components,
        verify_v031_approved_mcp_target_components_read_only, ApprovedMcpWorkspace,
        V031ApprovedMcpTargetComponentsGate,
    },
    privacy_workflow::{
        load_v031_vault_target_component_read_only, prepare_v031_vault_target_component,
        verify_v031_vault_target_component_read_only, V031VaultTargetComponentGate,
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
    },
    validate_fixed_local_directory,
    vnext::{canonical_json_v1, WorkspaceInstanceId},
};
use serde::Serialize;
use std::{collections::BTreeMap, fmt, path::Path, sync::Mutex};

const TARGET_COMPONENTS_STAGE: V031UpgradeReceiptStage =
    V031UpgradeReceiptStage::TargetComponentsPrepared;
const TARGET_CREDENTIAL_COUNT: u64 = 4;
const WORKSPACE_IDENTITY_COUNT: u64 = 1;
const EMPTY_TARGET_COMPONENT_COUNT: u64 = 3;
static V031_TARGET_COMPONENTS_OPERATION: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031TargetComponentsError {
    InvalidInput,
    RollbackAuthentication,
    ReceiptPrefix,
    ApprovedTarget,
    VaultTarget,
    NonemptyTarget,
    EvidenceEncoding,
    ReceiptPersistence,
}

impl V031TargetComponentsError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "v031_target_components_stage_invalid_input",
            Self::RollbackAuthentication => {
                "v031_target_components_stage_rollback_authentication_failed"
            }
            Self::ReceiptPrefix => "v031_target_components_stage_receipt_prefix_invalid",
            Self::ApprovedTarget => "v031_target_components_stage_approved_target_invalid",
            Self::VaultTarget => "v031_target_components_stage_vault_target_invalid",
            Self::NonemptyTarget => "v031_target_components_stage_target_nonempty",
            Self::EvidenceEncoding => "v031_target_components_stage_evidence_encoding_failed",
            Self::ReceiptPersistence => "v031_target_components_stage_receipt_persistence_failed",
        }
    }
}

impl fmt::Display for V031TargetComponentsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031TargetComponentsError {}

/// Opaque committed Step 3 capability consumed by the checkpoint stage.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031TargetComponentsPreparedGate {
    receipt_context: OwnedV031ReceiptContext,
    rollback_gate: OriginalRollbackVerifiedGate,
    approved_gate: V031ApprovedMcpTargetComponentsGate,
    vault_gate: V031VaultTargetComponentGate,
    target_components_evidence_sha256: String,
    target_components_receipt_sha256: String,
}

impl fmt::Debug for V031TargetComponentsPreparedGate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031TargetComponentsPreparedGate")
            .field("lineage_id", &self.receipt_context.lineage_id)
            .field(
                "workspace_instance_id",
                self.approved_gate.workspace_instance_id(),
            )
            .field(
                "target_components_evidence_sha256",
                &self.target_components_evidence_sha256,
            )
            .field(
                "target_components_receipt_sha256",
                &self.target_components_receipt_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl V031TargetComponentsPreparedGate {
    pub(crate) fn receipt_context(&self) -> &OwnedV031ReceiptContext {
        &self.receipt_context
    }

    pub(crate) fn rollback_gate(&self) -> &OriginalRollbackVerifiedGate {
        &self.rollback_gate
    }

    pub(crate) fn approved_gate(&self) -> &V031ApprovedMcpTargetComponentsGate {
        &self.approved_gate
    }

    pub(crate) fn vault_gate(&self) -> &V031VaultTargetComponentGate {
        &self.vault_gate
    }

    pub(crate) fn workspace_instance_id(&self) -> &WorkspaceInstanceId {
        self.approved_gate.workspace_instance_id()
    }

    pub(crate) fn target_components_evidence_sha256(&self) -> &str {
        &self.target_components_evidence_sha256
    }

    pub(crate) fn target_components_receipt_sha256(&self) -> &str {
        &self.target_components_receipt_sha256
    }

    #[cfg(test)]
    pub(crate) fn for_case_material_checkpoint_test(
        rollback_gate: OriginalRollbackVerifiedGate,
        workspace_instance_id: WorkspaceInstanceId,
    ) -> Self {
        let discriminator = rollback_gate.original_identity_sha256().as_bytes().to_vec();
        let rollback_gate_binding_sha256 = sha256_hex(
            [
                b"v031-case-material-test-rollback-binding\0".as_slice(),
                discriminator.as_slice(),
            ]
            .concat()
            .as_slice(),
        );
        let approved_gate =
            V031ApprovedMcpTargetComponentsGate::for_v031_target_components_orchestrator_test(
                workspace_instance_id.clone(),
                rollback_gate_binding_sha256.clone(),
                discriminator.as_slice(),
            );
        let vault_gate = V031VaultTargetComponentGate::for_v031_target_components_orchestrator_test(
            workspace_instance_id,
            rollback_gate_binding_sha256,
            approved_gate.evidence_sha256().to_owned(),
            discriminator.as_slice(),
        );
        let receipt_context = rollback_gate.receipt_context();
        Self {
            receipt_context,
            rollback_gate,
            approved_gate,
            vault_gate,
            target_components_evidence_sha256: sha256_hex(
                [
                    b"v031-case-material-test-target-evidence\0".as_slice(),
                    discriminator.as_slice(),
                ]
                .concat()
                .as_slice(),
            ),
            target_components_receipt_sha256: sha256_hex(
                [
                    b"v031-case-material-test-target-receipt\0".as_slice(),
                    discriminator.as_slice(),
                ]
                .concat()
                .as_slice(),
            ),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031RollbackGateBindingEvidence<'a> {
    lineage_id: &'a str,
    envelope_binding_id: &'a str,
    source_profile_proof_sha256: &'a str,
    original_identity_sha256: &'a str,
    original_bundle_sha256: &'a str,
    original_rollback_receipt_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct V031TargetComponentsPreparedEvidence<'a> {
    evidence_schema_version: &'static str,
    migration_id: &'static str,
    lineage_id: &'a str,
    envelope_binding_id: &'a str,
    source_profile_proof_sha256: &'a str,
    original_identity_sha256: &'a str,
    original_bundle_sha256: &'a str,
    original_rollback_receipt_sha256: &'a str,
    rollback_gate_binding_sha256: &'a str,
    workspace_instance_id: &'a str,
    approved_credential_manifest_sha256: &'a str,
    approved_workspace_schema_sha256: &'a str,
    approved_work_products_schema_sha256: &'a str,
    approved_workspace_manifest_sha256: &'a str,
    approved_work_products_manifest_sha256: &'a str,
    approved_target_components_evidence_sha256: &'a str,
    approved_credential_count: u64,
    approved_business_rows: u64,
    approved_work_product_business_rows: u64,
    vault_schema_sha256: &'a str,
    vault_database_sha256: &'a str,
    vault_layout_sha256: &'a str,
    vault_component_manifest_sha256: &'a str,
    vault_target_component_evidence_sha256: &'a str,
    vault_metadata_rows: u64,
    vault_business_rows: u64,
    vault_key_record_count: u64,
    vault_object_root_entry_count: u64,
    target_credentials: u64,
    workspace_identities: u64,
    empty_target_components: u64,
}

trait V031TargetComponentOperations {
    fn reload_rollback_gate(
        &self,
        app_local_data_dir: &Path,
        expected: &OriginalRollbackVerifiedGate,
    ) -> Result<OriginalRollbackVerifiedGate, V031TargetComponentsError>;

    fn prepare_approved(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError>;

    fn load_approved_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError>;

    fn verify_approved_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        expected: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<(), V031TargetComponentsError>;

    fn prepare_vault(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError>;

    fn load_vault_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError>;

    fn verify_vault_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
        expected: &V031VaultTargetComponentGate,
    ) -> Result<(), V031TargetComponentsError>;
}

/// Test-only coordinator failures surround the real component writers. The
/// writer-specific points are passed through separately and remain no-ops in
/// production; receipt wire contracts are never replaced.
trait V031TargetComponentsFailureInjector {
    fn before_approved_prepare(&self) -> Result<(), V031TargetComponentsError> {
        Ok(())
    }

    fn after_approved_prepare(&self) -> Result<(), V031TargetComponentsError> {
        Ok(())
    }

    fn before_vault_prepare(&self) -> Result<(), V031TargetComponentsError> {
        Ok(())
    }

    fn after_vault_prepare_before_receipt_two(&self) -> Result<(), V031TargetComponentsError> {
        Ok(())
    }
}

struct NoV031TargetComponentsFailure;

impl V031TargetComponentsFailureInjector for NoV031TargetComponentsFailure {}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031TargetComponentsFailurePoint {
    BeforeApprovedPrepare,
    AfterApprovedCredentialPrefix1,
    AfterApprovedCredentialPrefix2,
    AfterApprovedCredentialPrefix3,
    AfterApprovedCredentialPrefix4,
    AfterApprovedWorkspaceClosed,
    AfterWorkProductsClosedBeforeSync,
    AfterApprovedPrepare,
    BeforeVaultPrepare,
    AfterVaultInitializedBeforeSync,
    AfterVaultPrepareBeforeReceipt2,
}

#[cfg(test)]
impl V031TargetComponentsFailurePoint {
    fn approved_writer_failure(self) -> Option<V031ApprovedTargetWriterFailurePoint> {
        match self {
            Self::AfterApprovedCredentialPrefix1 => {
                Some(V031ApprovedTargetWriterFailurePoint::AfterCredentialPrefix1)
            }
            Self::AfterApprovedCredentialPrefix2 => {
                Some(V031ApprovedTargetWriterFailurePoint::AfterCredentialPrefix2)
            }
            Self::AfterApprovedCredentialPrefix3 => {
                Some(V031ApprovedTargetWriterFailurePoint::AfterCredentialPrefix3)
            }
            Self::AfterApprovedCredentialPrefix4 => {
                Some(V031ApprovedTargetWriterFailurePoint::AfterCredentialPrefix4)
            }
            Self::AfterApprovedWorkspaceClosed => {
                Some(V031ApprovedTargetWriterFailurePoint::AfterApprovedWorkspaceClosed)
            }
            Self::AfterWorkProductsClosedBeforeSync => {
                Some(V031ApprovedTargetWriterFailurePoint::AfterWorkProductsClosedBeforeSync)
            }
            Self::BeforeApprovedPrepare
            | Self::AfterApprovedPrepare
            | Self::BeforeVaultPrepare
            | Self::AfterVaultInitializedBeforeSync
            | Self::AfterVaultPrepareBeforeReceipt2 => None,
        }
    }

    fn vault_writer_failure(self) -> Option<V031VaultTargetWriterFailurePoint> {
        match self {
            Self::AfterVaultInitializedBeforeSync => {
                Some(V031VaultTargetWriterFailurePoint::AfterInitializedBeforeSync)
            }
            Self::BeforeApprovedPrepare
            | Self::AfterApprovedCredentialPrefix1
            | Self::AfterApprovedCredentialPrefix2
            | Self::AfterApprovedCredentialPrefix3
            | Self::AfterApprovedCredentialPrefix4
            | Self::AfterApprovedWorkspaceClosed
            | Self::AfterWorkProductsClosedBeforeSync
            | Self::AfterApprovedPrepare
            | Self::BeforeVaultPrepare
            | Self::AfterVaultPrepareBeforeReceipt2 => None,
        }
    }
}

#[cfg(test)]
impl V031TargetComponentsFailureInjector for V031TargetComponentsFailurePoint {
    fn before_approved_prepare(&self) -> Result<(), V031TargetComponentsError> {
        if *self == Self::BeforeApprovedPrepare {
            return Err(V031TargetComponentsError::ApprovedTarget);
        }
        Ok(())
    }

    fn after_approved_prepare(&self) -> Result<(), V031TargetComponentsError> {
        if *self == Self::AfterApprovedPrepare {
            return Err(V031TargetComponentsError::ApprovedTarget);
        }
        Ok(())
    }

    fn before_vault_prepare(&self) -> Result<(), V031TargetComponentsError> {
        if *self == Self::BeforeVaultPrepare {
            return Err(V031TargetComponentsError::VaultTarget);
        }
        Ok(())
    }

    fn after_vault_prepare_before_receipt_two(&self) -> Result<(), V031TargetComponentsError> {
        if *self == Self::AfterVaultPrepareBeforeReceipt2 {
            return Err(V031TargetComponentsError::VaultTarget);
        }
        Ok(())
    }
}

struct ProductionTargetComponentOperations;

impl V031TargetComponentOperations for ProductionTargetComponentOperations {
    fn reload_rollback_gate(
        &self,
        app_local_data_dir: &Path,
        expected: &OriginalRollbackVerifiedGate,
    ) -> Result<OriginalRollbackVerifiedGate, V031TargetComponentsError> {
        load_original_migration_backup_gate(app_local_data_dir, expected.lineage_id())
            .map_err(|_| V031TargetComponentsError::RollbackAuthentication)
    }

    fn prepare_approved(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError> {
        prepare_v031_approved_mcp_target_components(app_local_data_dir, rollback)
            .map_err(map_approved_error)
    }

    fn load_approved_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError> {
        load_v031_approved_mcp_target_components_read_only(app_local_data_dir, rollback)
            .map_err(map_approved_error)
    }

    fn verify_approved_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        expected: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<(), V031TargetComponentsError> {
        verify_v031_approved_mcp_target_components_read_only(app_local_data_dir, rollback, expected)
            .map_err(map_approved_error)
    }

    fn prepare_vault(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError> {
        prepare_v031_vault_target_component(app_local_data_dir, rollback, approved)
            .map_err(map_vault_error)
    }

    fn load_vault_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError> {
        load_v031_vault_target_component_read_only(app_local_data_dir, rollback, approved)
            .map_err(map_vault_error)
    }

    fn verify_vault_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
        expected: &V031VaultTargetComponentGate,
    ) -> Result<(), V031TargetComponentsError> {
        verify_v031_vault_target_component_read_only(
            app_local_data_dir,
            rollback,
            approved,
            expected,
        )
        .map_err(map_vault_error)
    }
}

#[cfg(test)]
struct EphemeralWorkspaceTargetComponentOperations<'a> {
    workspace: &'a ApprovedMcpWorkspace,
    writer_failure_point: Option<V031TargetComponentsFailurePoint>,
}

#[cfg(test)]
impl V031TargetComponentOperations for EphemeralWorkspaceTargetComponentOperations<'_> {
    fn reload_rollback_gate(
        &self,
        app_local_data_dir: &Path,
        expected: &OriginalRollbackVerifiedGate,
    ) -> Result<OriginalRollbackVerifiedGate, V031TargetComponentsError> {
        load_original_migration_backup_gate_with_approved_workspace_for_test(
            app_local_data_dir,
            expected.lineage_id(),
            self.workspace,
        )
        .map_err(|_| V031TargetComponentsError::RollbackAuthentication)
    }

    fn prepare_approved(
        &self,
        _app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError> {
        match self
            .writer_failure_point
            .and_then(V031TargetComponentsFailurePoint::approved_writer_failure)
        {
            Some(failure_point) => self
                .workspace
                .prepare_v031_target_components_with_writer_failure_for_test(
                    rollback,
                    failure_point,
                )
                .map_err(map_approved_error),
            None => self
                .workspace
                .prepare_v031_target_components_for_checkpoint_test(rollback)
                .map_err(map_approved_error),
        }
    }

    fn load_approved_read_only(
        &self,
        _app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
    ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError> {
        self.workspace
            .load_v031_target_components_for_checkpoint_test(rollback)
            .map_err(map_approved_error)
    }

    fn verify_approved_read_only(
        &self,
        _app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        expected: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<(), V031TargetComponentsError> {
        self.workspace
            .verify_v031_target_components_for_checkpoint_test(rollback, expected)
            .map_err(map_approved_error)
    }

    fn prepare_vault(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError> {
        match self
            .writer_failure_point
            .and_then(V031TargetComponentsFailurePoint::vault_writer_failure)
        {
            Some(failure_point) => {
                prepare_v031_vault_target_component_with_writer_failure_for_test(
                    app_local_data_dir,
                    rollback,
                    approved,
                    failure_point,
                )
                .map_err(map_vault_error)
            }
            None => prepare_v031_vault_target_component(app_local_data_dir, rollback, approved)
                .map_err(map_vault_error),
        }
    }

    fn load_vault_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
    ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError> {
        load_v031_vault_target_component_read_only(app_local_data_dir, rollback, approved)
            .map_err(map_vault_error)
    }

    fn verify_vault_read_only(
        &self,
        app_local_data_dir: &Path,
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
        expected: &V031VaultTargetComponentGate,
    ) -> Result<(), V031TargetComponentsError> {
        verify_v031_vault_target_component_read_only(
            app_local_data_dir,
            rollback,
            approved,
            expected,
        )
        .map_err(map_vault_error)
    }
}

/// Prepares or resumes the exact three empty Step 3 components and commits
/// ordinal 2. No target writer is reachable without the opaque rollback gate.
pub(crate) fn prepare_v031_target_components(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    prepare_v031_target_components_with_operations(
        app_local_data_dir,
        rollback_gate,
        &ProductionTargetComponentOperations,
    )
}

/// Runs the production Step-3 state machine with a CSPRNG-backed ephemeral
/// in-memory Approved workspace. This is the only test seam: V2 reload,
/// component initialization, Vault verification and the DPAPI receipt remain
/// production code, while fixed production Credential Manager names are never
/// touched.
#[cfg(test)]
pub(crate) fn prepare_v031_target_components_with_ephemeral_workspace_for_test(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    prepare_v031_target_components_with_operations(
        app_local_data_dir,
        rollback_gate,
        &EphemeralWorkspaceTargetComponentOperations {
            workspace: approved_workspace,
            writer_failure_point: None,
        },
    )
}

/// Runs the same Step-3 coordinator and real Approved/work-products/Vault
/// writers as the normal ephemeral-credential migration harness, but stops at
/// one explicit durable boundary before receipt ordinal 2 is installed.
#[cfg(test)]
pub(crate) fn prepare_v031_target_components_with_ephemeral_workspace_and_failure_for_test(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_workspace: &ApprovedMcpWorkspace,
    failure_point: V031TargetComponentsFailurePoint,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    prepare_v031_target_components_with_operations_and_failure_injector(
        app_local_data_dir,
        rollback_gate,
        &EphemeralWorkspaceTargetComponentOperations {
            workspace: approved_workspace,
            writer_failure_point: Some(failure_point),
        },
        &failure_point,
    )
}

/// Loads an already committed ordinal-2 gate without invoking any target
/// initializer or credential mutation path.
pub(crate) fn load_v031_target_components_prepared_gate_read_only(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    let _operation = V031_TARGET_COMPONENTS_OPERATION
        .lock()
        .map_err(|_| V031TargetComponentsError::InvalidInput)?;
    validate_app_root(app_local_data_dir)?;
    #[cfg(not(test))]
    let _ = approved_workspace;
    #[cfg(not(test))]
    let operations: &dyn V031TargetComponentOperations = &ProductionTargetComponentOperations;
    #[cfg(test)]
    let ephemeral_operations = EphemeralWorkspaceTargetComponentOperations {
        workspace: approved_workspace,
        writer_failure_point: None,
    };
    #[cfg(test)]
    let operations: &dyn V031TargetComponentOperations = &ephemeral_operations;
    authenticate_expected_rollback(operations, app_local_data_dir, rollback_gate)?;
    let inventory = authenticate_receipt_prefix(app_local_data_dir, rollback_gate)?;
    let receipt_two = inventory
        .final_receipts
        .get(usize::from(TARGET_COMPONENTS_STAGE.ordinal()))
        .ok_or(V031TargetComponentsError::ReceiptPrefix)?;
    let approved_gate = operations.load_approved_read_only(app_local_data_dir, rollback_gate)?;
    let vault_gate =
        operations.load_vault_read_only(app_local_data_dir, rollback_gate, &approved_gate)?;
    let evidence_sha256 =
        target_components_evidence_sha256(rollback_gate, &approved_gate, &vault_gate)?;
    let counts = target_components_counts();
    verify_target_components_live_state(
        operations,
        app_local_data_dir,
        rollback_gate,
        &approved_gate,
        &vault_gate,
        &evidence_sha256,
        &counts,
        Some(&receipt_two.protected_file_sha256),
    )?;
    committed_gate(
        rollback_gate,
        approved_gate,
        vault_gate,
        evidence_sha256,
        receipt_two.protected_file_sha256.clone(),
    )
}

/// Rebinds the historical empty Gate2 material recovered from an authenticated
/// checkpoint identity to the independently authenticated rollback and final
/// receipt 2. It deliberately performs no read of the legally evolved live
/// Approved, work-products, or Vault business state.
pub(crate) fn bind_v031_historical_target_components_to_receipt_read_only(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: V031ApprovedMcpTargetComponentsGate,
    vault_gate: V031VaultTargetComponentGate,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    let _operation = V031_TARGET_COMPONENTS_OPERATION
        .lock()
        .map_err(|_| V031TargetComponentsError::InvalidInput)?;
    validate_app_root(app_local_data_dir)?;
    let observed =
        load_original_migration_backup_gate(app_local_data_dir, rollback_gate.lineage_id())
            .map_err(|_| V031TargetComponentsError::RollbackAuthentication)?;
    if !rollback_gate.authenticates_same_original_rollback(&observed) {
        return Err(V031TargetComponentsError::RollbackAuthentication);
    }
    let inventory = authenticate_receipt_prefix(app_local_data_dir, rollback_gate)?;
    bind_v031_historical_target_components_from_authenticated_rollback_read_only(
        app_local_data_dir,
        rollback_gate,
        &inventory,
        approved_gate,
        vault_gate,
    )
}

#[cfg(test)]
pub(crate) fn bind_v031_historical_target_components_with_approved_workspace_for_test(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: V031ApprovedMcpTargetComponentsGate,
    vault_gate: V031VaultTargetComponentGate,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    let _operation = V031_TARGET_COMPONENTS_OPERATION
        .lock()
        .map_err(|_| V031TargetComponentsError::InvalidInput)?;
    validate_app_root(app_local_data_dir)?;
    let observed = load_original_migration_backup_gate_with_approved_workspace_for_test(
        app_local_data_dir,
        rollback_gate.lineage_id(),
        approved_workspace,
    )
    .map_err(|_| V031TargetComponentsError::RollbackAuthentication)?;
    if !rollback_gate.authenticates_same_original_rollback(&observed) {
        return Err(V031TargetComponentsError::RollbackAuthentication);
    }
    let inventory = authenticate_receipt_prefix(app_local_data_dir, rollback_gate)?;
    bind_v031_historical_target_components_from_authenticated_rollback_read_only(
        app_local_data_dir,
        rollback_gate,
        &inventory,
        approved_gate,
        vault_gate,
    )
}

/// Rebinds historical Gate2 while the caller is already inside the fresh
/// Original-V2 reload that produced `rollback_gate` and `inventory`.
///
/// This deliberately takes both opaque capabilities, performs no locking and
/// never calls the Original-V2 loader.  It is the only safe path for validating
/// the Receipt-3 partial-v5 startup profile: routing that profile through the
/// public binder above would recursively reload Original-V2 while the target
/// operation mutex is held.
pub(crate) fn bind_v031_historical_target_components_from_authenticated_rollback_read_only(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    inventory: &AuthenticatedLineageInventory,
    approved_gate: V031ApprovedMcpTargetComponentsGate,
    vault_gate: V031VaultTargetComponentGate,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    validate_app_root(app_local_data_dir)?;
    validate_authenticated_receipt_prefix(app_local_data_dir, rollback_gate, inventory)?;
    let receipt_two = inventory
        .final_receipts
        .get(usize::from(TARGET_COMPONENTS_STAGE.ordinal()))
        .ok_or(V031TargetComponentsError::ReceiptPrefix)?;
    let evidence_sha256 =
        target_components_evidence_sha256(rollback_gate, &approved_gate, &vault_gate)?;
    validate_receipt_two_state(
        inventory,
        rollback_gate,
        &evidence_sha256,
        &target_components_counts(),
        Some(&receipt_two.protected_file_sha256),
    )?;
    committed_gate(
        rollback_gate,
        approved_gate,
        vault_gate,
        evidence_sha256,
        receipt_two.protected_file_sha256.clone(),
    )
}

/// Read-only historical Gate2 verifier used by checkpoint and later-stage
/// restart loaders after live target inventories may legitimately be nonzero.
pub(crate) fn verify_v031_historical_target_components_receipt_gate_read_only(
    app_local_data_dir: &Path,
    expected_gate: &V031TargetComponentsPreparedGate,
) -> Result<(), V031TargetComponentsError> {
    let observed = bind_v031_historical_target_components_to_receipt_read_only(
        app_local_data_dir,
        expected_gate.rollback_gate(),
        expected_gate.approved_gate().clone(),
        expected_gate.vault_gate().clone(),
    )?;
    if &observed != expected_gate {
        return Err(V031TargetComponentsError::ReceiptPrefix);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn verify_v031_historical_target_components_receipt_gate_with_approved_workspace_for_test(
    app_local_data_dir: &Path,
    expected_gate: &V031TargetComponentsPreparedGate,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(), V031TargetComponentsError> {
    let observed = bind_v031_historical_target_components_with_approved_workspace_for_test(
        app_local_data_dir,
        expected_gate.rollback_gate(),
        expected_gate.approved_gate().clone(),
        expected_gate.vault_gate().clone(),
        approved_workspace,
    )?;
    if &observed != expected_gate {
        return Err(V031TargetComponentsError::ReceiptPrefix);
    }
    Ok(())
}

/// Revalidates a committed Step 3 capability using only authenticated rollback
/// reads, credential reads, immutable SQLite, and directory enumeration.
#[cfg(test)]
pub(crate) fn verify_v031_target_components_prepared_gate_read_only(
    app_local_data_dir: &Path,
    expected_gate: &V031TargetComponentsPreparedGate,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(), V031TargetComponentsError> {
    let _operation = V031_TARGET_COMPONENTS_OPERATION
        .lock()
        .map_err(|_| V031TargetComponentsError::InvalidInput)?;
    validate_app_root(app_local_data_dir)?;
    #[cfg(not(test))]
    let _ = approved_workspace;
    #[cfg(not(test))]
    let operations: &dyn V031TargetComponentOperations = &ProductionTargetComponentOperations;
    #[cfg(test)]
    let ephemeral_operations = EphemeralWorkspaceTargetComponentOperations {
        workspace: approved_workspace,
        writer_failure_point: None,
    };
    #[cfg(test)]
    let operations: &dyn V031TargetComponentOperations = &ephemeral_operations;
    verify_target_components_live_state(
        operations,
        app_local_data_dir,
        &expected_gate.rollback_gate,
        &expected_gate.approved_gate,
        &expected_gate.vault_gate,
        &expected_gate.target_components_evidence_sha256,
        &target_components_counts(),
        Some(&expected_gate.target_components_receipt_sha256),
    )
}

fn prepare_v031_target_components_with_operations(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    operations: &dyn V031TargetComponentOperations,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    prepare_v031_target_components_with_operations_and_failure_injector(
        app_local_data_dir,
        rollback_gate,
        operations,
        &NoV031TargetComponentsFailure,
    )
}

fn prepare_v031_target_components_with_operations_and_failure_injector(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    operations: &dyn V031TargetComponentOperations,
    failure_injector: &dyn V031TargetComponentsFailureInjector,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    let _operation = V031_TARGET_COMPONENTS_OPERATION
        .lock()
        .map_err(|_| V031TargetComponentsError::InvalidInput)?;
    validate_app_root(app_local_data_dir)?;
    authenticate_expected_rollback(operations, app_local_data_dir, rollback_gate)?;
    let initial_inventory = authenticate_receipt_prefix(app_local_data_dir, rollback_gate)?;
    let receipt_two_started = initial_inventory.final_receipts.len()
        > usize::from(TARGET_COMPONENTS_STAGE.ordinal())
        || initial_inventory
            .next_incoming_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.ordinal == TARGET_COMPONENTS_STAGE.ordinal());

    let approved_gate = if receipt_two_started {
        operations.load_approved_read_only(app_local_data_dir, rollback_gate)?
    } else {
        failure_injector.before_approved_prepare()?;
        let approved = operations.prepare_approved(app_local_data_dir, rollback_gate)?;
        failure_injector.after_approved_prepare()?;
        approved
    };
    let vault_gate = if receipt_two_started {
        operations.load_vault_read_only(app_local_data_dir, rollback_gate, &approved_gate)?
    } else {
        // A Vault write is a separate authorization boundary. Re-authenticate
        // receipt 0..1 and the rollback point after approved target creation.
        authenticate_expected_rollback(operations, app_local_data_dir, rollback_gate)?;
        let after_approved = authenticate_receipt_prefix(app_local_data_dir, rollback_gate)?;
        if after_approved.final_receipts.len() != usize::from(TARGET_COMPONENTS_STAGE.ordinal())
            || after_approved.next_incoming_receipt.is_some()
        {
            return Err(V031TargetComponentsError::ReceiptPrefix);
        }
        operations.verify_approved_read_only(app_local_data_dir, rollback_gate, &approved_gate)?;
        failure_injector.before_vault_prepare()?;
        let vault = operations.prepare_vault(app_local_data_dir, rollback_gate, &approved_gate)?;
        failure_injector.after_vault_prepare_before_receipt_two()?;
        vault
    };

    let evidence_sha256 =
        target_components_evidence_sha256(rollback_gate, &approved_gate, &vault_gate)?;
    let counts = target_components_counts();
    let context = rollback_gate.receipt_context();
    let persisted = persist_v031_receipt(
        app_local_data_dir,
        &context,
        TARGET_COMPONENTS_STAGE,
        &evidence_sha256,
        &counts,
        || {
            verify_target_components_live_state(
                operations,
                app_local_data_dir,
                rollback_gate,
                &approved_gate,
                &vault_gate,
                &evidence_sha256,
                &counts,
                None,
            )
            .map_err(|_| V031ReceiptPersistenceError::EvidenceConflict)
        },
    )
    .map_err(|_| V031TargetComponentsError::ReceiptPersistence)?;
    verify_target_components_live_state(
        operations,
        app_local_data_dir,
        rollback_gate,
        &approved_gate,
        &vault_gate,
        &evidence_sha256,
        &counts,
        Some(&persisted.receipt.protected_file_sha256),
    )?;
    committed_gate(
        rollback_gate,
        approved_gate,
        vault_gate,
        evidence_sha256,
        persisted.receipt.protected_file_sha256,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_target_components_live_state(
    operations: &dyn V031TargetComponentOperations,
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    vault_gate: &V031VaultTargetComponentGate,
    evidence_sha256: &str,
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
    expected_receipt_two_sha256: Option<&str>,
) -> Result<(), V031TargetComponentsError> {
    // The ordering is deliberate and frozen: rollback, Approved, Vault, then
    // receipt-prefix recheck. Every operation in this function is read-only.
    authenticate_expected_rollback(operations, app_local_data_dir, rollback_gate)?;
    operations.verify_approved_read_only(app_local_data_dir, rollback_gate, approved_gate)?;
    operations.verify_vault_read_only(
        app_local_data_dir,
        rollback_gate,
        approved_gate,
        vault_gate,
    )?;
    let inventory = authenticate_receipt_prefix(app_local_data_dir, rollback_gate)?;
    validate_receipt_two_state(
        &inventory,
        rollback_gate,
        evidence_sha256,
        counts,
        expected_receipt_two_sha256,
    )
}

fn authenticate_expected_rollback(
    operations: &dyn V031TargetComponentOperations,
    app_local_data_dir: &Path,
    expected: &OriginalRollbackVerifiedGate,
) -> Result<(), V031TargetComponentsError> {
    let observed = operations.reload_rollback_gate(app_local_data_dir, expected)?;
    if !expected.authenticates_same_original_rollback(&observed) {
        return Err(V031TargetComponentsError::RollbackAuthentication);
    }
    Ok(())
}

fn authenticate_receipt_prefix(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
) -> Result<AuthenticatedLineageInventory, V031TargetComponentsError> {
    let context = rollback_gate.receipt_context();
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let inventory =
        load_authenticated_v031_lineage(app_local_data_dir, rollback_gate.lineage_id(), &bridge)
            .map_err(|_| V031TargetComponentsError::ReceiptPrefix)?;
    validate_authenticated_receipt_prefix(app_local_data_dir, rollback_gate, &inventory)?;
    Ok(inventory)
}

fn validate_authenticated_receipt_prefix(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    inventory: &AuthenticatedLineageInventory,
) -> Result<(), V031TargetComponentsError> {
    let context = rollback_gate.receipt_context();
    if !inventory.authenticates(app_local_data_dir, rollback_gate.lineage_id())
        || !inventory.v2.identity_final
        || inventory.v2.identity_incoming
        || !inventory.v2.bundle_final
        || inventory.v2.bundle_incoming
        || inventory.v2.user_snapshot_incoming
        || inventory.v2.privacy_snapshot_incoming
        || inventory.final_receipts.len() < usize::from(TARGET_COMPONENTS_STAGE.ordinal())
    {
        return Err(V031TargetComponentsError::ReceiptPrefix);
    }
    let receipt_zero = inventory
        .final_receipts
        .first()
        .ok_or(V031TargetComponentsError::ReceiptPrefix)?;
    let receipt_one = inventory
        .final_receipts
        .get(1)
        .ok_or(V031TargetComponentsError::ReceiptPrefix)?;
    if receipt_zero.ordinal != V031UpgradeReceiptStage::SourcePreflightVerified.ordinal()
        || receipt_zero.stage != V031UpgradeReceiptStage::SourcePreflightVerified.as_str()
        || receipt_one.ordinal != V031UpgradeReceiptStage::OriginalRollbackVerified.ordinal()
        || receipt_one.stage != V031UpgradeReceiptStage::OriginalRollbackVerified.as_str()
        || receipt_one.protected_file_sha256 != rollback_gate.original_rollback_receipt_sha256()
        || receipt_one.metadata.previous_receipt_sha256.as_deref()
            != Some(receipt_zero.protected_file_sha256.as_str())
        || context.lineage_id != receipt_one.metadata.lineage_id
        || context.envelope_binding_id != receipt_one.metadata.envelope_binding_id
        || context.source_profile_proof_sha256 != receipt_one.metadata.source_profile_proof_sha256
    {
        return Err(V031TargetComponentsError::ReceiptPrefix);
    }
    Ok(())
}

fn validate_receipt_two_state(
    inventory: &AuthenticatedLineageInventory,
    rollback_gate: &OriginalRollbackVerifiedGate,
    evidence_sha256: &str,
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
    expected_receipt_two_sha256: Option<&str>,
) -> Result<(), V031TargetComponentsError> {
    let expected_counts = target_components_wire_counts(counts)?;
    let receipt_two = inventory
        .final_receipts
        .get(usize::from(TARGET_COMPONENTS_STAGE.ordinal()));
    if let Some(receipt) = receipt_two {
        validate_receipt_two_metadata(receipt, rollback_gate, evidence_sha256, &expected_counts)?;
        if expected_receipt_two_sha256
            .is_some_and(|expected| expected != receipt.protected_file_sha256)
        {
            return Err(V031TargetComponentsError::ReceiptPrefix);
        }
    } else if expected_receipt_two_sha256.is_some() {
        return Err(V031TargetComponentsError::ReceiptPrefix);
    }

    if let Some(incoming) = inventory.next_incoming_receipt.as_ref() {
        if incoming.ordinal == TARGET_COMPONENTS_STAGE.ordinal() {
            if receipt_two.is_some() {
                return Err(V031TargetComponentsError::ReceiptPrefix);
            }
            validate_receipt_two_metadata(
                incoming,
                rollback_gate,
                evidence_sha256,
                &expected_counts,
            )?;
        }
    }
    Ok(())
}

fn validate_receipt_two_metadata(
    receipt: &AuthenticatedReceiptFile,
    rollback_gate: &OriginalRollbackVerifiedGate,
    evidence_sha256: &str,
    expected_counts: &BTreeMap<String, u64>,
) -> Result<(), V031TargetComponentsError> {
    if receipt.ordinal != TARGET_COMPONENTS_STAGE.ordinal()
        || receipt.stage != TARGET_COMPONENTS_STAGE.as_str()
        || receipt.metadata.evidence_schema_version
            != TARGET_COMPONENTS_STAGE.evidence_schema_version()
        || receipt.metadata.evidence_sha256 != evidence_sha256
        || &receipt.metadata.counts != expected_counts
        || receipt.metadata.previous_receipt_sha256.as_deref()
            != Some(rollback_gate.original_rollback_receipt_sha256())
    {
        return Err(V031TargetComponentsError::ReceiptPrefix);
    }
    Ok(())
}

fn target_components_evidence_sha256(
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    vault_gate: &V031VaultTargetComponentGate,
) -> Result<String, V031TargetComponentsError> {
    let rollback_gate_binding_sha256 = canonical_sha256(&V031RollbackGateBindingEvidence {
        lineage_id: rollback_gate.lineage_id(),
        envelope_binding_id: rollback_gate.envelope_binding_id(),
        source_profile_proof_sha256: rollback_gate.source_profile_proof_sha256(),
        original_identity_sha256: rollback_gate.original_identity_sha256(),
        original_bundle_sha256: rollback_gate.original_bundle_sha256(),
        original_rollback_receipt_sha256: rollback_gate.original_rollback_receipt_sha256(),
    })?;
    if approved_gate.workspace_instance_id() != vault_gate.workspace_instance_id()
        || approved_gate.rollback_gate_binding_sha256() != rollback_gate_binding_sha256
        || vault_gate.rollback_gate_binding_sha256() != rollback_gate_binding_sha256
        || vault_gate.approved_target_components_evidence_sha256()
            != approved_gate.evidence_sha256()
        || approved_gate.credential_count() != TARGET_CREDENTIAL_COUNT
        || approved_gate.approved_business_rows() != 0
        || approved_gate.work_product_business_rows() != 0
        || vault_gate.metadata_rows() != 2
        || vault_gate.business_rows() != 0
        || vault_gate.key_record_count() != 0
        || vault_gate.object_root_entry_count() != 0
    {
        return Err(V031TargetComponentsError::NonemptyTarget);
    }
    for hash in [
        rollback_gate.lineage_id(),
        rollback_gate.source_profile_proof_sha256(),
        rollback_gate.original_identity_sha256(),
        rollback_gate.original_bundle_sha256(),
        rollback_gate.original_rollback_receipt_sha256(),
        &rollback_gate_binding_sha256,
        approved_gate.credential_manifest_sha256(),
        approved_gate.approved_workspace_schema_sha256(),
        approved_gate.work_products_schema_sha256(),
        approved_gate.approved_workspace_manifest_sha256(),
        approved_gate.work_products_manifest_sha256(),
        approved_gate.evidence_sha256(),
        vault_gate.vault_schema_sha256(),
        vault_gate.vault_database_sha256(),
        vault_gate.vault_layout_sha256(),
        vault_gate.vault_component_manifest_sha256(),
        vault_gate.evidence_sha256(),
    ] {
        if !is_lower_sha256(hash) {
            return Err(V031TargetComponentsError::InvalidInput);
        }
    }
    if !is_workspace_id(rollback_gate.envelope_binding_id())
        || !is_workspace_id(approved_gate.workspace_instance_id().as_str())
        || rollback_gate.envelope_binding_id() == approved_gate.workspace_instance_id().as_str()
    {
        return Err(V031TargetComponentsError::InvalidInput);
    }

    canonical_sha256(&V031TargetComponentsPreparedEvidence {
        evidence_schema_version: TARGET_COMPONENTS_STAGE.evidence_schema_version(),
        migration_id: V031_UPGRADE_RECEIPT_MIGRATION_ID,
        lineage_id: rollback_gate.lineage_id(),
        envelope_binding_id: rollback_gate.envelope_binding_id(),
        source_profile_proof_sha256: rollback_gate.source_profile_proof_sha256(),
        original_identity_sha256: rollback_gate.original_identity_sha256(),
        original_bundle_sha256: rollback_gate.original_bundle_sha256(),
        original_rollback_receipt_sha256: rollback_gate.original_rollback_receipt_sha256(),
        rollback_gate_binding_sha256: &rollback_gate_binding_sha256,
        workspace_instance_id: approved_gate.workspace_instance_id().as_str(),
        approved_credential_manifest_sha256: approved_gate.credential_manifest_sha256(),
        approved_workspace_schema_sha256: approved_gate.approved_workspace_schema_sha256(),
        approved_work_products_schema_sha256: approved_gate.work_products_schema_sha256(),
        approved_workspace_manifest_sha256: approved_gate.approved_workspace_manifest_sha256(),
        approved_work_products_manifest_sha256: approved_gate.work_products_manifest_sha256(),
        approved_target_components_evidence_sha256: approved_gate.evidence_sha256(),
        approved_credential_count: approved_gate.credential_count(),
        approved_business_rows: approved_gate.approved_business_rows(),
        approved_work_product_business_rows: approved_gate.work_product_business_rows(),
        vault_schema_sha256: vault_gate.vault_schema_sha256(),
        vault_database_sha256: vault_gate.vault_database_sha256(),
        vault_layout_sha256: vault_gate.vault_layout_sha256(),
        vault_component_manifest_sha256: vault_gate.vault_component_manifest_sha256(),
        vault_target_component_evidence_sha256: vault_gate.evidence_sha256(),
        vault_metadata_rows: vault_gate.metadata_rows(),
        vault_business_rows: vault_gate.business_rows(),
        vault_key_record_count: vault_gate.key_record_count(),
        vault_object_root_entry_count: vault_gate.object_root_entry_count(),
        target_credentials: TARGET_CREDENTIAL_COUNT,
        workspace_identities: WORKSPACE_IDENTITY_COUNT,
        empty_target_components: EMPTY_TARGET_COMPONENT_COUNT,
    })
}

fn target_components_counts() -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
    BTreeMap::from([
        (
            V031UpgradeReceiptCountKey::TargetCredentials,
            TARGET_CREDENTIAL_COUNT,
        ),
        (
            V031UpgradeReceiptCountKey::WorkspaceIdentities,
            WORKSPACE_IDENTITY_COUNT,
        ),
        (
            V031UpgradeReceiptCountKey::EmptyTargetComponents,
            EMPTY_TARGET_COMPONENT_COUNT,
        ),
    ])
}

fn target_components_wire_counts(
    counts: &BTreeMap<V031UpgradeReceiptCountKey, u64>,
) -> Result<BTreeMap<String, u64>, V031TargetComponentsError> {
    if counts != &target_components_counts() {
        return Err(V031TargetComponentsError::InvalidInput);
    }
    Ok(BTreeMap::from([
        (
            "empty_target_components".to_owned(),
            EMPTY_TARGET_COMPONENT_COUNT,
        ),
        ("target_credentials".to_owned(), TARGET_CREDENTIAL_COUNT),
        ("workspace_identities".to_owned(), WORKSPACE_IDENTITY_COUNT),
    ]))
}

fn committed_gate(
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: V031ApprovedMcpTargetComponentsGate,
    vault_gate: V031VaultTargetComponentGate,
    target_components_evidence_sha256: String,
    target_components_receipt_sha256: String,
) -> Result<V031TargetComponentsPreparedGate, V031TargetComponentsError> {
    if !is_lower_sha256(&target_components_evidence_sha256)
        || !is_lower_sha256(&target_components_receipt_sha256)
    {
        return Err(V031TargetComponentsError::InvalidInput);
    }
    Ok(V031TargetComponentsPreparedGate {
        receipt_context: rollback_gate.receipt_context(),
        rollback_gate: rollback_gate.clone(),
        approved_gate,
        vault_gate,
        target_components_evidence_sha256,
        target_components_receipt_sha256,
    })
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, V031TargetComponentsError> {
    canonical_json_v1(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| V031TargetComponentsError::EvidenceEncoding)
}

fn validate_app_root(app_local_data_dir: &Path) -> Result<(), V031TargetComponentsError> {
    if !app_local_data_dir.is_absolute() {
        return Err(V031TargetComponentsError::InvalidInput);
    }
    validate_fixed_local_directory(app_local_data_dir)
        .map_err(|_| V031TargetComponentsError::InvalidInput)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_workspace_id(value: &str) -> bool {
    value.len() == 35
        && value.starts_with("ws_")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn map_approved_error(error: crate::approved_mcp::ApprovedMcpError) -> V031TargetComponentsError {
    if error.code() == "v031_target_components_nonempty" {
        V031TargetComponentsError::NonemptyTarget
    } else {
        V031TargetComponentsError::ApprovedTarget
    }
}

fn map_vault_error(
    error: crate::privacy_workflow::V031VaultTargetComponentError,
) -> V031TargetComponentsError {
    if error.code() == "v031_vault_target_component_nonempty" {
        V031TargetComponentsError::NonemptyTarget
    } else {
        V031TargetComponentsError::VaultTarget
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        approved_mcp::{
            V031ApprovedMcpTargetComponentsGate, V031ApprovedMcpTargetNamespaceObservation,
            V031TargetWriterTestHarness,
        },
        privacy_workflow::{
            observe_v031_vault_target_absent_read_only,
            observe_v031_vault_target_namespace_read_only, V031VaultTargetComponentGate,
            V031VaultTargetNamespaceObservation,
        },
        v031_upgrade_r2::{
            self, ApprovedMcpCredentialRole, CredentialAbsenceQuery, CredentialPresenceProbe,
            DirectorySync, APPROVED_MCP_CREDENTIAL_ACCOUNT, V2_BUNDLE_FINAL, V2_IDENTITY_FINAL,
        },
    };
    use database::{
        UserMigrationSourceFileProof, UserMigrationSourceProof, ValidatedUserSourceSchema,
        V031_USER_SCHEMA_MANIFEST_SHA256,
    };
    use privacy::upgrade_receipt_v1::{
        seal_v031_upgrade_receipt_v1, V031UpgradeReceiptCreateRequest,
    };
    use rusqlite::Connection;
    use std::{
        fs, io,
        os::windows::fs::MetadataExt,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
        time::{SystemTime, UNIX_EPOCH},
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TreeEntryKind {
        File,
        Directory,
        Other,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TreeEntryProof {
        kind: TreeEntryKind,
        file_attributes: u32,
        reparse_point: bool,
        length: u64,
        modified_at: SystemTime,
        sha256: Option<String>,
    }

    struct RealTargetComponentsFixture {
        _directory: tempfile::TempDir,
        app_root: PathBuf,
        user_database_path: PathBuf,
        privacy_database_path: PathBuf,
        approved: V031TargetWriterTestHarness,
        rollback: OriginalRollbackVerifiedGate,
    }

    impl RealTargetComponentsFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("real target-component fixture");
            let app_root = directory.path().to_path_buf();
            let user_database_path = database::user_database_path(&app_root);
            let privacy_database_path = app_root.join("privacy").join("privacy-workflow.sqlite");
            create_exact_v031_user_database(&user_database_path);
            create_exact_privacy_v1_database(&privacy_database_path);

            let approved = V031TargetWriterTestHarness::new(app_root.clone());
            let credential_probe = approved.credential_probe();
            let rollback = crate::commands::original_migration_backup::
                establish_original_migration_backup_with_credential_probe_for_test(
                    &app_root,
                    &user_database_path,
                    &privacy_database_path,
                    &credential_probe,
                )
                .expect("real V2 and receipt prefix 0..1");

            Self {
                _directory: directory,
                app_root,
                user_database_path,
                privacy_database_path,
                approved,
                rollback,
            }
        }

        fn lineage_directory(&self) -> PathBuf {
            self.app_root
                .join("migration-backups")
                .join(self.rollback.lineage_id())
        }

        fn receipt_two_path(&self) -> PathBuf {
            self.lineage_directory()
                .join(TARGET_COMPONENTS_STAGE.final_basename())
        }

        fn receipt_two_incoming_path(&self) -> PathBuf {
            self.lineage_directory()
                .join(TARGET_COMPONENTS_STAGE.incoming_basename())
        }

        fn frozen_predecessor_snapshot(&self) -> BTreeMap<String, TreeEntryProof> {
            let mut snapshot = BTreeMap::new();
            merge_tree_snapshot(
                "source/user.sqlite",
                &self.user_database_path,
                &mut snapshot,
                true,
            );
            merge_tree_snapshot(
                "source/privacy.sqlite",
                &self.privacy_database_path,
                &mut snapshot,
                true,
            );
            // The lineage root mtime legitimately changes when receipt two is
            // appended. Every descendant (V2 and receipts 0..1) remains exact.
            merge_tree_snapshot("lineage", &self.lineage_directory(), &mut snapshot, false);
            snapshot
        }

        fn credential_presence(&self) -> [bool; 4] {
            let probe = self.approved.workspace.v031_credential_probe_for_test();
            ApprovedMcpCredentialRole::ALL.map(|role| {
                probe
                    .credential_exists_read_only(CredentialAbsenceQuery {
                        role,
                        target: role.target(),
                        account: APPROVED_MCP_CREDENTIAL_ACCOUNT,
                    })
                    .expect("ephemeral credential presence reads")
            })
        }
    }

    fn create_exact_v031_user_database(path: &Path) {
        let connection = Connection::open(path).expect("exact user-v10 fixture opens");
        let objects =
            include_str!("../../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
                .lines()
                .map(|line| {
                    serde_json::from_str::<serde_json::Value>(line)
                        .expect("frozen user-v10 schema object parses")
                })
                .collect::<Vec<_>>();
        for object_type in ["table", "index", "trigger", "view"] {
            for object in objects
                .iter()
                .filter(|object| object["object_type"] == object_type)
            {
                connection
                    .execute_batch(object["sql"].as_str().expect("frozen schema SQL"))
                    .expect("frozen user-v10 schema object executes");
            }
        }
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_SCHEMA_VERSION.to_string()],
            )
            .expect("user-v10 schema version inserts");
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_CANONICAL_SCHEMA_MARKER],
            )
            .expect("user-v10 canonical marker inserts");
    }

    fn create_exact_privacy_v1_database(path: &Path) {
        fs::create_dir(path.parent().expect("Privacy-v1 fixture parent"))
            .expect("Privacy-v1 fixture parent creates");
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

    fn snapshot_tree(root: &Path) -> BTreeMap<String, TreeEntryProof> {
        fn visit(root: &Path, path: &Path, snapshot: &mut BTreeMap<String, TreeEntryProof>) {
            let metadata = fs::symlink_metadata(path).expect("snapshot entry metadata");
            let file_attributes = metadata.file_attributes();
            let reparse_point = file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            let kind = if metadata.file_type().is_file() {
                TreeEntryKind::File
            } else if metadata.file_type().is_dir() {
                TreeEntryKind::Directory
            } else {
                TreeEntryKind::Other
            };
            let relative = path
                .strip_prefix(root)
                .expect("snapshot path remains beneath root");
            let relative = if relative.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                relative.to_string_lossy().replace('\\', "/")
            };
            let sha256 = if kind == TreeEntryKind::File && !reparse_point {
                Some(sha256_hex(
                    &fs::read(path).expect("snapshot regular file bytes read"),
                ))
            } else {
                None
            };
            assert!(
                snapshot
                    .insert(
                        relative,
                        TreeEntryProof {
                            kind,
                            file_attributes,
                            reparse_point,
                            length: metadata.len(),
                            modified_at: metadata.modified().expect("snapshot mtime reads"),
                            sha256,
                        },
                    )
                    .is_none(),
                "snapshot paths are unique"
            );
            if kind == TreeEntryKind::Directory && !reparse_point {
                let mut entries = fs::read_dir(path)
                    .expect("snapshot directory reads")
                    .collect::<Result<Vec<_>, _>>()
                    .expect("snapshot directory entries read");
                entries.sort_by_key(|entry| entry.file_name());
                for entry in entries {
                    visit(root, &entry.path(), snapshot);
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    fn merge_tree_snapshot(
        prefix: &str,
        root: &Path,
        destination: &mut BTreeMap<String, TreeEntryProof>,
        include_root: bool,
    ) {
        for (relative, proof) in snapshot_tree(root) {
            if relative == "." && !include_root {
                continue;
            }
            let key = if relative == "." {
                prefix.to_owned()
            } else {
                format!("{prefix}/{relative}")
            };
            assert!(
                destination.insert(key, proof).is_none(),
                "merged snapshot paths are unique"
            );
        }
    }

    #[derive(Default)]
    struct FakeState {
        events: Vec<&'static str>,
        approved_present: bool,
        vault_present: bool,
        approved_valid: bool,
        vault_valid: bool,
        approved_creations: usize,
        vault_creations: usize,
    }

    struct FakeOperations {
        rollback: OriginalRollbackVerifiedGate,
        approved: V031ApprovedMcpTargetComponentsGate,
        vault: V031VaultTargetComponentGate,
        state: Mutex<FakeState>,
        fail_approved_once: AtomicBool,
        fail_vault_once: AtomicBool,
        prepare_calls: AtomicUsize,
    }

    impl FakeOperations {
        fn new(rollback: OriginalRollbackVerifiedGate) -> Self {
            let rollback_binding = canonical_sha256(&V031RollbackGateBindingEvidence {
                lineage_id: rollback.lineage_id(),
                envelope_binding_id: rollback.envelope_binding_id(),
                source_profile_proof_sha256: rollback.source_profile_proof_sha256(),
                original_identity_sha256: rollback.original_identity_sha256(),
                original_bundle_sha256: rollback.original_bundle_sha256(),
                original_rollback_receipt_sha256: rollback.original_rollback_receipt_sha256(),
            })
            .expect("rollback binding");
            let workspace = WorkspaceInstanceId::parse(format!("ws_{}", "9".repeat(32)))
                .expect("target workspace");
            let approved =
                V031ApprovedMcpTargetComponentsGate::for_v031_target_components_orchestrator_test(
                    workspace.clone(),
                    rollback_binding.clone(),
                    b"receipt-two-test",
                );
            let vault = V031VaultTargetComponentGate::for_v031_target_components_orchestrator_test(
                workspace,
                rollback_binding,
                approved.evidence_sha256().to_owned(),
                b"receipt-two-test",
            );
            Self {
                rollback,
                approved,
                vault,
                state: Mutex::new(FakeState {
                    approved_valid: true,
                    vault_valid: true,
                    ..FakeState::default()
                }),
                fail_approved_once: AtomicBool::new(false),
                fail_vault_once: AtomicBool::new(false),
                prepare_calls: AtomicUsize::new(0),
            }
        }

        fn set_components_present(&self) {
            let mut state = self.state.lock().expect("fake state");
            state.approved_present = true;
            state.vault_present = true;
        }

        fn events(&self) -> Vec<&'static str> {
            self.state.lock().expect("fake state").events.clone()
        }

        fn creation_counts(&self) -> (usize, usize) {
            let state = self.state.lock().expect("fake state");
            (state.approved_creations, state.vault_creations)
        }

        fn invalidate_approved(&self) {
            self.state.lock().expect("fake state").approved_valid = false;
        }

        fn invalidate_vault(&self) {
            self.state.lock().expect("fake state").vault_valid = false;
        }

        fn record(&self, event: &'static str) {
            self.state.lock().expect("fake state").events.push(event);
        }
    }

    impl V031TargetComponentOperations for FakeOperations {
        fn reload_rollback_gate(
            &self,
            _app_local_data_dir: &Path,
            _expected: &OriginalRollbackVerifiedGate,
        ) -> Result<OriginalRollbackVerifiedGate, V031TargetComponentsError> {
            self.record("reload_rollback");
            Ok(self.rollback.clone())
        }

        fn prepare_approved(
            &self,
            _app_local_data_dir: &Path,
            _rollback: &OriginalRollbackVerifiedGate,
        ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError> {
            self.record("prepare_approved");
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_approved_once.swap(false, Ordering::SeqCst) {
                return Err(V031TargetComponentsError::ApprovedTarget);
            }
            let mut state = self.state.lock().expect("fake state");
            if !state.approved_present {
                state.approved_present = true;
                state.approved_creations += 1;
            }
            Ok(self.approved.clone())
        }

        fn load_approved_read_only(
            &self,
            _app_local_data_dir: &Path,
            _rollback: &OriginalRollbackVerifiedGate,
        ) -> Result<V031ApprovedMcpTargetComponentsGate, V031TargetComponentsError> {
            self.record("load_approved");
            let state = self.state.lock().expect("fake state");
            if !state.approved_present || !state.approved_valid {
                return Err(V031TargetComponentsError::NonemptyTarget);
            }
            Ok(self.approved.clone())
        }

        fn verify_approved_read_only(
            &self,
            _app_local_data_dir: &Path,
            _rollback: &OriginalRollbackVerifiedGate,
            expected: &V031ApprovedMcpTargetComponentsGate,
        ) -> Result<(), V031TargetComponentsError> {
            self.record("verify_approved");
            let state = self.state.lock().expect("fake state");
            if !state.approved_present || !state.approved_valid || expected != &self.approved {
                return Err(V031TargetComponentsError::NonemptyTarget);
            }
            Ok(())
        }

        fn prepare_vault(
            &self,
            _app_local_data_dir: &Path,
            _rollback: &OriginalRollbackVerifiedGate,
            _approved: &V031ApprovedMcpTargetComponentsGate,
        ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError> {
            self.record("prepare_vault");
            self.prepare_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_vault_once.swap(false, Ordering::SeqCst) {
                return Err(V031TargetComponentsError::VaultTarget);
            }
            let mut state = self.state.lock().expect("fake state");
            if !state.vault_present {
                state.vault_present = true;
                state.vault_creations += 1;
            }
            Ok(self.vault.clone())
        }

        fn load_vault_read_only(
            &self,
            _app_local_data_dir: &Path,
            _rollback: &OriginalRollbackVerifiedGate,
            _approved: &V031ApprovedMcpTargetComponentsGate,
        ) -> Result<V031VaultTargetComponentGate, V031TargetComponentsError> {
            self.record("load_vault");
            let state = self.state.lock().expect("fake state");
            if !state.vault_present || !state.vault_valid {
                return Err(V031TargetComponentsError::NonemptyTarget);
            }
            Ok(self.vault.clone())
        }

        fn verify_vault_read_only(
            &self,
            _app_local_data_dir: &Path,
            _rollback: &OriginalRollbackVerifiedGate,
            _approved: &V031ApprovedMcpTargetComponentsGate,
            expected: &V031VaultTargetComponentGate,
        ) -> Result<(), V031TargetComponentsError> {
            self.record("verify_vault");
            let state = self.state.lock().expect("fake state");
            if !state.vault_present || !state.vault_valid || expected != &self.vault {
                return Err(V031TargetComponentsError::NonemptyTarget);
            }
            Ok(())
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        app_root: PathBuf,
        rollback: OriginalRollbackVerifiedGate,
        operations: FakeOperations,
    }

    impl Fixture {
        fn with_receipt_one() -> Self {
            let directory = tempfile::tempdir().expect("receipt-two fixture");
            let app_root = directory.path().to_path_buf();
            let initial = OriginalRollbackVerifiedGate::from_user_source_for_test(user_proof());
            let context = initial.receipt_context();
            let lineage_directory = app_root
                .join("migration-backups")
                .join(initial.lineage_id());
            fs::create_dir(app_root.join("migration-backups")).expect("migration root");
            fs::create_dir(&lineage_directory).expect("lineage root");
            persist_v031_receipt(
                &app_root,
                &context,
                V031UpgradeReceiptStage::SourcePreflightVerified,
                initial.source_profile_proof_sha256(),
                &source_counts(),
                || Ok(()),
            )
            .expect("receipt zero");
            fs::write(
                lineage_directory.join(V2_IDENTITY_FINAL),
                b"test-v2-identity",
            )
            .expect("V2 identity");
            fs::write(lineage_directory.join(V2_BUNDLE_FINAL), b"test-v2-bundle")
                .expect("V2 bundle");
            let receipt_one = persist_v031_receipt(
                &app_root,
                &context,
                V031UpgradeReceiptStage::OriginalRollbackVerified,
                &"6".repeat(64),
                &rollback_counts(),
                || Ok(()),
            )
            .expect("receipt one");
            let rollback = initial.with_original_rollback_receipt_sha256_for_test(
                receipt_one.receipt.protected_file_sha256,
            );
            let operations = FakeOperations::new(rollback.clone());
            Self {
                _directory: directory,
                app_root,
                rollback,
                operations,
            }
        }

        fn receipt_two_path(&self) -> PathBuf {
            self.app_root
                .join("migration-backups")
                .join(self.rollback.lineage_id())
                .join(TARGET_COMPONENTS_STAGE.final_basename())
        }

        fn receipt_two_incoming_path(&self) -> PathBuf {
            self.app_root
                .join("migration-backups")
                .join(self.rollback.lineage_id())
                .join(TARGET_COMPONENTS_STAGE.incoming_basename())
        }

        fn protected_receipt_two(&self) -> Vec<u8> {
            let evidence = target_components_evidence_sha256(
                &self.rollback,
                &self.operations.approved,
                &self.operations.vault,
            )
            .expect("target evidence");
            seal_v031_upgrade_receipt_v1(&V031UpgradeReceiptCreateRequest {
                context: self.rollback.receipt_context().as_borrowed(),
                stage: TARGET_COMPONENTS_STAGE,
                previous_receipt_sha256: Some(self.rollback.original_rollback_receipt_sha256()),
                evidence_sha256: &evidence,
                counts: &target_components_counts(),
                created_at_unix: unix_now_for_test(),
            })
            .expect("seal receipt two")
            .into_protected_bytes()
        }
    }

    fn user_proof() -> UserMigrationSourceProof {
        UserMigrationSourceProof {
            schema: ValidatedUserSourceSchema::V031V10,
            database_file: UserMigrationSourceFileProof {
                identity_sha256: "1".repeat(64),
                length: 4096,
                modified_unix_nanos: None,
                sha256: "2".repeat(64),
            },
            wal: None,
            shm: None,
            journal: None,
            schema_manifest_sha256: V031_USER_SCHEMA_MANIFEST_SHA256.to_owned(),
            logical_database_manifest_sha256: "3".repeat(64),
            business_manifest_sha256: "4".repeat(64),
            business_primary_key_manifest_sha256: "5".repeat(64),
            business_row_manifest_sha256: "6".repeat(64),
            tables: Vec::new(),
            total_rows: 0,
            data_version: 1,
        }
    }

    fn source_counts() -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
        BTreeMap::from([
            (V031UpgradeReceiptCountKey::UserSchemaObjects, 74),
            (V031UpgradeReceiptCountKey::PrivacySchemaObjects, 11),
            (V031UpgradeReceiptCountKey::PresentSlots, 2),
            (V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3),
            (V031UpgradeReceiptCountKey::TargetAbsenceChecks, 26),
            (V031UpgradeReceiptCountKey::CapacityChecks, 2),
            (V031UpgradeReceiptCountKey::ProtectedPayloads, 0),
        ])
    }

    fn rollback_counts() -> BTreeMap<V031UpgradeReceiptCountKey, u64> {
        BTreeMap::from([
            (V031UpgradeReceiptCountKey::IdentityArtifacts, 1),
            (V031UpgradeReceiptCountKey::BundleArtifacts, 1),
            (V031UpgradeReceiptCountKey::RollbackSlots, 5),
            (V031UpgradeReceiptCountKey::SqliteImages, 2),
            (V031UpgradeReceiptCountKey::EncryptedChunks, 5),
            (V031UpgradeReceiptCountKey::SourceRevalidations, 2),
            (V031UpgradeReceiptCountKey::AuthenticatedAbsentSlots, 3),
        ])
    }

    fn unix_now_for_test() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_secs()
            + 1
    }

    struct FailingDirectorySync;

    impl DirectorySync for FailingDirectorySync {
        type Error = io::Error;

        fn sync_directory(&self, _directory: &Path) -> Result<(), Self::Error> {
            Err(io::Error::other("injected directory sync failure"))
        }
    }

    #[test]
    fn receipt_two_requires_receipt_one_before_any_target_write() {
        let fixture = Fixture::with_receipt_one();
        fs::remove_file(
            fixture
                .app_root
                .join("migration-backups")
                .join(fixture.rollback.lineage_id())
                .join(V031UpgradeReceiptStage::OriginalRollbackVerified.final_basename()),
        )
        .expect("remove receipt one from negative fixture");

        assert_eq!(
            prepare_v031_target_components_with_operations(
                &fixture.app_root,
                &fixture.rollback,
                &fixture.operations,
            )
            .expect_err("receipt one is mandatory"),
            V031TargetComponentsError::ReceiptPrefix
        );
        assert_eq!(fixture.operations.prepare_calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.operations.creation_counts(), (0, 0));
    }

    #[test]
    fn receipt_two_fresh_success_and_idempotent_resume_use_exact_counts_and_zero_writes() {
        let fixture = Fixture::with_receipt_one();
        let first = prepare_v031_target_components_with_operations(
            &fixture.app_root,
            &fixture.rollback,
            &fixture.operations,
        )
        .expect("fresh target components receipt");
        assert_eq!(first.receipt_context(), &fixture.rollback.receipt_context());
        assert_eq!(first.rollback_gate(), &fixture.rollback);
        assert_eq!(first.approved_gate(), &fixture.operations.approved);
        assert_eq!(first.vault_gate(), &fixture.operations.vault);
        assert_eq!(
            first.workspace_instance_id().as_str(),
            format!("ws_{}", "9".repeat(32))
        );
        assert!(is_lower_sha256(first.target_components_evidence_sha256()));
        assert!(is_lower_sha256(first.target_components_receipt_sha256()));
        assert_eq!(fixture.operations.creation_counts(), (1, 1));

        let bridge = PrivacyReceiptAuthenticationBridge::new(fixture.rollback.receipt_context());
        let inventory = load_authenticated_v031_lineage(
            &fixture.app_root,
            fixture.rollback.lineage_id(),
            &bridge,
        )
        .expect("authenticated receipt prefix");
        assert_eq!(inventory.final_receipts.len(), 3);
        let receipt_two = &inventory.final_receipts[2];
        assert_eq!(
            receipt_two.metadata.counts,
            target_components_wire_counts(&target_components_counts()).unwrap()
        );
        assert_eq!(
            receipt_two.metadata.evidence_sha256,
            first.target_components_evidence_sha256()
        );
        assert_eq!(
            receipt_two.protected_file_sha256,
            first.target_components_receipt_sha256()
        );

        let events = fixture.operations.events();
        let first_reload = events
            .iter()
            .position(|event| *event == "reload_rollback")
            .unwrap();
        let prepare_approved = events
            .iter()
            .position(|event| *event == "prepare_approved")
            .unwrap();
        let verify_approved = events
            .iter()
            .position(|event| *event == "verify_approved")
            .unwrap();
        let prepare_vault = events
            .iter()
            .position(|event| *event == "prepare_vault")
            .unwrap();
        assert!(first_reload < prepare_approved);
        assert!(prepare_approved < verify_approved);
        assert!(verify_approved < prepare_vault);

        let receipt_before = fs::read(fixture.receipt_two_path()).expect("receipt two before");
        let prepare_calls_before = fixture.operations.prepare_calls.load(Ordering::SeqCst);
        let second = prepare_v031_target_components_with_operations(
            &fixture.app_root,
            &fixture.rollback,
            &fixture.operations,
        )
        .expect("idempotent receipt two resume");
        assert_eq!(second, first);
        assert_eq!(
            fixture.operations.prepare_calls.load(Ordering::SeqCst),
            prepare_calls_before
        );
        assert_eq!(fixture.operations.creation_counts(), (1, 1));
        assert_eq!(
            fs::read(fixture.receipt_two_path()).expect("receipt two after"),
            receipt_before
        );
        let resumed_events = fixture.operations.events();
        assert!(resumed_events.contains(&"load_approved"));
        assert!(resumed_events.contains(&"load_vault"));
    }

    #[test]
    fn component_creation_failures_resume_without_duplicate_components() {
        let approved_failure = Fixture::with_receipt_one();
        approved_failure
            .operations
            .fail_approved_once
            .store(true, Ordering::SeqCst);
        assert_eq!(
            prepare_v031_target_components_with_operations(
                &approved_failure.app_root,
                &approved_failure.rollback,
                &approved_failure.operations,
            )
            .expect_err("injected approved failure"),
            V031TargetComponentsError::ApprovedTarget
        );
        assert_eq!(approved_failure.operations.creation_counts(), (0, 0));
        prepare_v031_target_components_with_operations(
            &approved_failure.app_root,
            &approved_failure.rollback,
            &approved_failure.operations,
        )
        .expect("approved failure resumes");
        assert_eq!(approved_failure.operations.creation_counts(), (1, 1));

        let vault_failure = Fixture::with_receipt_one();
        vault_failure
            .operations
            .fail_vault_once
            .store(true, Ordering::SeqCst);
        assert_eq!(
            prepare_v031_target_components_with_operations(
                &vault_failure.app_root,
                &vault_failure.rollback,
                &vault_failure.operations,
            )
            .expect_err("injected Vault failure"),
            V031TargetComponentsError::VaultTarget
        );
        assert_eq!(vault_failure.operations.creation_counts(), (1, 0));
        assert!(!vault_failure.receipt_two_path().exists());
        prepare_v031_target_components_with_operations(
            &vault_failure.app_root,
            &vault_failure.rollback,
            &vault_failure.operations,
        )
        .expect("Vault failure resumes");
        assert_eq!(vault_failure.operations.creation_counts(), (1, 1));
    }

    #[test]
    fn authenticated_incoming_and_post_rename_sync_failure_resume_read_only() {
        let incoming = Fixture::with_receipt_one();
        incoming.operations.set_components_present();
        fs::write(
            incoming.receipt_two_incoming_path(),
            incoming.protected_receipt_two(),
        )
        .expect("stage authenticated receipt two incoming");
        let incoming_prepare_calls = incoming.operations.prepare_calls.load(Ordering::SeqCst);
        prepare_v031_target_components_with_operations(
            &incoming.app_root,
            &incoming.rollback,
            &incoming.operations,
        )
        .expect("authenticated incoming resumes");
        assert_eq!(
            incoming.operations.prepare_calls.load(Ordering::SeqCst),
            incoming_prepare_calls
        );
        assert!(incoming.receipt_two_path().is_file());
        assert!(!incoming.receipt_two_incoming_path().exists());

        let sync_failure = Fixture::with_receipt_one();
        sync_failure.operations.set_components_present();
        let protected = sync_failure.protected_receipt_two();
        let bridge =
            PrivacyReceiptAuthenticationBridge::new(sync_failure.rollback.receipt_context());
        assert!(matches!(
            v031_upgrade_r2::install_next_receipt(
                &sync_failure.app_root,
                sync_failure.rollback.lineage_id(),
                TARGET_COMPONENTS_STAGE.ordinal(),
                &protected,
                &bridge,
                &FailingDirectorySync,
            ),
            Err(v031_upgrade_r2::R2InfrastructureError::DirectorySyncFailed)
        ));
        assert!(sync_failure.receipt_two_path().is_file());
        let prepare_calls = sync_failure.operations.prepare_calls.load(Ordering::SeqCst);
        let gate = prepare_v031_target_components_with_operations(
            &sync_failure.app_root,
            &sync_failure.rollback,
            &sync_failure.operations,
        )
        .expect("post-rename sync failure accepts authenticated final");
        assert_eq!(
            sync_failure.operations.prepare_calls.load(Ordering::SeqCst),
            prepare_calls
        );
        assert_eq!(
            gate.target_components_receipt_sha256(),
            sha256_hex(&protected)
        );
    }

    #[test]
    fn receipt_and_component_drift_fail_closed_without_target_writes() {
        let receipt_tamper = Fixture::with_receipt_one();
        prepare_v031_target_components_with_operations(
            &receipt_tamper.app_root,
            &receipt_tamper.rollback,
            &receipt_tamper.operations,
        )
        .expect("fresh receipt two");
        let prepare_calls = receipt_tamper
            .operations
            .prepare_calls
            .load(Ordering::SeqCst);
        let mut bytes = fs::read(receipt_tamper.receipt_two_path()).expect("receipt two bytes");
        bytes[0] ^= 0x80;
        fs::write(receipt_tamper.receipt_two_path(), bytes).expect("tamper receipt two");
        assert_eq!(
            prepare_v031_target_components_with_operations(
                &receipt_tamper.app_root,
                &receipt_tamper.rollback,
                &receipt_tamper.operations,
            )
            .expect_err("receipt tamper must fail"),
            V031TargetComponentsError::ReceiptPrefix
        );
        assert_eq!(
            receipt_tamper
                .operations
                .prepare_calls
                .load(Ordering::SeqCst),
            prepare_calls
        );

        let approved_drift = Fixture::with_receipt_one();
        prepare_v031_target_components_with_operations(
            &approved_drift.app_root,
            &approved_drift.rollback,
            &approved_drift.operations,
        )
        .expect("fresh approved fixture");
        approved_drift.operations.invalidate_approved();
        let writes_before = approved_drift
            .operations
            .prepare_calls
            .load(Ordering::SeqCst);
        assert_eq!(
            prepare_v031_target_components_with_operations(
                &approved_drift.app_root,
                &approved_drift.rollback,
                &approved_drift.operations,
            )
            .expect_err("nonempty/invalid approved target must fail"),
            V031TargetComponentsError::NonemptyTarget
        );
        assert_eq!(
            approved_drift
                .operations
                .prepare_calls
                .load(Ordering::SeqCst),
            writes_before
        );

        let vault_drift = Fixture::with_receipt_one();
        prepare_v031_target_components_with_operations(
            &vault_drift.app_root,
            &vault_drift.rollback,
            &vault_drift.operations,
        )
        .expect("fresh Vault fixture");
        vault_drift.operations.invalidate_vault();
        let writes_before = vault_drift.operations.prepare_calls.load(Ordering::SeqCst);
        assert_eq!(
            prepare_v031_target_components_with_operations(
                &vault_drift.app_root,
                &vault_drift.rollback,
                &vault_drift.operations,
            )
            .expect_err("nonempty/invalid Vault target must fail"),
            V031TargetComponentsError::NonemptyTarget
        );
        assert_eq!(
            vault_drift.operations.prepare_calls.load(Ordering::SeqCst),
            writes_before
        );
    }

    #[test]
    fn real_target_component_durable_windows_resume_through_production_coordinator_without_fake_operations(
    ) {
        for (failure_point, expected_error) in [
            (
                V031TargetComponentsFailurePoint::BeforeApprovedPrepare,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix1,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix2,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix3,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix4,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterApprovedWorkspaceClosed,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterWorkProductsClosedBeforeSync,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterApprovedPrepare,
                V031TargetComponentsError::ApprovedTarget,
            ),
            (
                V031TargetComponentsFailurePoint::BeforeVaultPrepare,
                V031TargetComponentsError::VaultTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterVaultInitializedBeforeSync,
                V031TargetComponentsError::VaultTarget,
            ),
            (
                V031TargetComponentsFailurePoint::AfterVaultPrepareBeforeReceipt2,
                V031TargetComponentsError::VaultTarget,
            ),
        ] {
            let fixture = RealTargetComponentsFixture::new();
            let predecessor_before = fixture.frozen_predecessor_snapshot();

            assert_eq!(
                prepare_v031_target_components_with_ephemeral_workspace_and_failure_for_test(
                    &fixture.app_root,
                    &fixture.rollback,
                    &fixture.approved.workspace,
                    failure_point,
                )
                .expect_err("the selected durable target-component boundary fails"),
                expected_error,
                "unexpected error at {failure_point:?}"
            );
            assert_eq!(
                fixture.frozen_predecessor_snapshot(),
                predecessor_before,
                "source databases, V2 and receipts 0..1 remain exact at {failure_point:?}"
            );
            assert!(!fixture.receipt_two_path().exists());
            assert!(!fixture.receipt_two_incoming_path().exists());

            let inventory = authenticate_receipt_prefix(&fixture.app_root, &fixture.rollback)
                .expect("the real receipt prefix remains authenticated");
            assert_eq!(inventory.final_receipts.len(), 2);
            assert!(inventory.next_incoming_receipt.is_none());

            let expected_credential_prefix = match failure_point {
                V031TargetComponentsFailurePoint::BeforeApprovedPrepare => 0,
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix1 => 1,
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix2 => 2,
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix3 => 3,
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix4 => 4,
                V031TargetComponentsFailurePoint::AfterApprovedWorkspaceClosed
                | V031TargetComponentsFailurePoint::AfterWorkProductsClosedBeforeSync
                | V031TargetComponentsFailurePoint::AfterApprovedPrepare
                | V031TargetComponentsFailurePoint::BeforeVaultPrepare
                | V031TargetComponentsFailurePoint::AfterVaultInitializedBeforeSync
                | V031TargetComponentsFailurePoint::AfterVaultPrepareBeforeReceipt2 => 4,
            };
            let provider_after_fault = fixture
                .approved
                .provider_audit()
                .expect("provider audit after injected writer failure");
            assert_eq!(
                provider_after_fault.creation_writes(),
                expected_credential_prefix,
                "only the selected credential prefix is created at {failure_point:?}"
            );
            assert_eq!(
                provider_after_fault.load_or_create_calls(),
                expected_credential_prefix,
                "the real writer stops at the selected credential boundary"
            );
            assert_eq!(provider_after_fault.rotate_calls(), 0);
            assert!(provider_after_fault.load_existing_calls() >= expected_credential_prefix);
            assert_eq!(
                provider_after_fault
                    .credential_sha256()
                    .iter()
                    .flatten()
                    .count(),
                expected_credential_prefix
            );
            let credential_digests = provider_after_fault
                .credential_sha256()
                .iter()
                .flatten()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(credential_digests.len(), expected_credential_prefix);
            assert!(credential_digests
                .iter()
                .all(|digest| is_lower_sha256(digest)));

            let before_process_observer = snapshot_tree(&fixture.app_root);
            let provider_before_process_observer = fixture
                .approved
                .provider_audit()
                .expect("provider audit before process-start observation");
            let process_start = crate::commands::v031_upgrade_complete::
                observe_v031_upgrade_at_process_start_read_only(&fixture.app_root)
                .expect("process-start observer accepts the resumable receipt prefix");
            assert_eq!(process_start.active_final_receipt_count(), Some(2));
            assert_eq!(process_start.active_next_incoming_ordinal(), None);
            assert_eq!(
                process_start.active_lineage_id(),
                Some(fixture.rollback.lineage_id())
            );
            assert_eq!(
                snapshot_tree(&fixture.app_root),
                before_process_observer,
                "process-start observation is read-only at {failure_point:?}"
            );
            let provider_after_process_observer = fixture
                .approved
                .provider_audit()
                .expect("provider audit after process-start observation");
            assert_eq!(
                provider_after_process_observer.credential_sha256(),
                provider_before_process_observer.credential_sha256()
            );
            assert_eq!(
                provider_after_process_observer.load_or_create_calls(),
                provider_before_process_observer.load_or_create_calls()
            );
            assert_eq!(
                provider_after_process_observer.creation_writes(),
                provider_before_process_observer.creation_writes()
            );
            assert_eq!(
                provider_after_process_observer.rotate_calls(),
                provider_before_process_observer.rotate_calls()
            );

            let mut durable_approved = None;
            let mut durable_vault = None;
            match failure_point {
                V031TargetComponentsFailurePoint::BeforeApprovedPrepare => {
                    assert_eq!(fixture.credential_presence(), [false; 4]);
                    assert!(!fixture
                        .app_root
                        .join("privacy")
                        .join("approved-mcp")
                        .exists());
                    observe_v031_vault_target_absent_read_only(&fixture.app_root)
                        .expect("Vault remains authenticated-absent before Approved preparation");
                }
                V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix1
                | V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix2
                | V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix3
                | V031TargetComponentsFailurePoint::AfterApprovedCredentialPrefix4 => {
                    let expected_presence: [bool; 4] =
                        std::array::from_fn(|index| index < expected_credential_prefix);
                    assert_eq!(fixture.credential_presence(), expected_presence);
                    let observed = fixture
                        .approved
                        .workspace
                        .observe_v031_target_namespace_for_checkpoint_test(&fixture.rollback)
                        .expect("credential prefix is an authenticated resumable state");
                    let V031ApprovedMcpTargetNamespaceObservation::Incomplete(incomplete) =
                        observed
                    else {
                        panic!("credential-only state cannot be a complete Approved target")
                    };
                    assert_eq!(
                        incomplete.credential_prefix_len(),
                        expected_credential_prefix
                    );
                    assert!(!fixture
                        .app_root
                        .join("privacy")
                        .join("approved-mcp")
                        .exists());
                    observe_v031_vault_target_absent_read_only(&fixture.app_root)
                        .expect("Vault remains absent during credential preparation");
                }
                V031TargetComponentsFailurePoint::AfterApprovedWorkspaceClosed => {
                    assert_eq!(fixture.credential_presence(), [true; 4]);
                    assert!(matches!(
                        fixture
                            .approved
                            .workspace
                            .observe_v031_target_namespace_for_checkpoint_test(&fixture.rollback)
                            .expect("closed Approved-only namespace is resumable"),
                        V031ApprovedMcpTargetNamespaceObservation::Incomplete(_)
                    ));
                    let approved_mcp_root = fixture.app_root.join("privacy").join("approved-mcp");
                    assert!(approved_mcp_root.join("approved-generations").is_dir());
                    assert!(!approved_mcp_root.join("work-products").exists());
                    observe_v031_vault_target_absent_read_only(&fixture.app_root)
                        .expect("Vault remains absent after the Approved database closes");
                }
                V031TargetComponentsFailurePoint::AfterWorkProductsClosedBeforeSync
                | V031TargetComponentsFailurePoint::AfterApprovedPrepare
                | V031TargetComponentsFailurePoint::BeforeVaultPrepare => {
                    assert_eq!(fixture.credential_presence(), [true; 4]);
                    let approved = fixture
                        .approved
                        .workspace
                        .load_v031_target_components_for_checkpoint_test(&fixture.rollback)
                        .expect("the real Approved/work-products component is durable");
                    assert_eq!(approved.credential_count(), 4);
                    assert_eq!(approved.approved_business_rows(), 0);
                    assert_eq!(approved.work_product_business_rows(), 0);
                    assert_ne!(
                        approved.workspace_instance_id().as_str(),
                        fixture.rollback.envelope_binding_id()
                    );
                    observe_v031_vault_target_absent_read_only(&fixture.app_root)
                        .expect("Vault remains authenticated-absent at the Approved boundary");
                    durable_approved = Some(approved);
                }
                V031TargetComponentsFailurePoint::AfterVaultInitializedBeforeSync
                | V031TargetComponentsFailurePoint::AfterVaultPrepareBeforeReceipt2 => {
                    assert_eq!(fixture.credential_presence(), [true; 4]);
                    let approved = fixture
                        .approved
                        .workspace
                        .load_v031_target_components_for_checkpoint_test(&fixture.rollback)
                        .expect("the real Approved/work-products component is durable");
                    let vault = load_v031_vault_target_component_read_only(
                        &fixture.app_root,
                        &fixture.rollback,
                        &approved,
                    )
                    .expect("the real Vault component is durable before receipt two");
                    assert_eq!(vault.metadata_rows(), 2);
                    assert_eq!(vault.business_rows(), 0);
                    assert_eq!(vault.key_record_count(), 0);
                    assert_eq!(vault.object_root_entry_count(), 0);
                    assert_eq!(
                        observe_v031_vault_target_namespace_read_only(
                            &fixture.app_root,
                            &fixture.rollback,
                            &approved,
                        )
                        .expect("initialized Vault is read-only observable"),
                        V031VaultTargetNamespaceObservation::Complete(vault.clone())
                    );
                    durable_approved = Some(approved);
                    durable_vault = Some(vault);
                }
            }

            let approved_tree_before_resume = durable_approved
                .as_ref()
                .map(|_| snapshot_tree(&fixture.app_root.join("privacy").join("approved-mcp")));
            let vault_tree_before_resume = durable_vault
                .as_ref()
                .map(|_| snapshot_tree(&fixture.app_root.join("case-vault-v2")));
            let resumed = prepare_v031_target_components_with_ephemeral_workspace_for_test(
                &fixture.app_root,
                &fixture.rollback,
                &fixture.approved.workspace,
            )
            .expect("the real production coordinator resumes the durable boundary");
            let provider_after_resume = fixture
                .approved
                .provider_audit()
                .expect("provider audit after writer resume");
            assert_eq!(provider_after_resume.creation_writes(), 4);
            assert_eq!(provider_after_resume.rotate_calls(), 0);
            let approved_was_complete = matches!(
                failure_point,
                V031TargetComponentsFailurePoint::AfterWorkProductsClosedBeforeSync
                    | V031TargetComponentsFailurePoint::AfterApprovedPrepare
                    | V031TargetComponentsFailurePoint::BeforeVaultPrepare
                    | V031TargetComponentsFailurePoint::AfterVaultInitializedBeforeSync
                    | V031TargetComponentsFailurePoint::AfterVaultPrepareBeforeReceipt2
            );
            assert_eq!(
                provider_after_resume.load_or_create_calls(),
                expected_credential_prefix + if approved_was_complete { 0 } else { 4 },
                "a complete Approved target resumes through sync plus the read-only loader"
            );
            for index in 0..expected_credential_prefix {
                assert_eq!(
                    provider_after_resume.credential_sha256()[index],
                    provider_after_fault.credential_sha256()[index],
                    "resume preserves credential {index} at {failure_point:?}"
                );
            }
            let resumed_credential_digests = provider_after_resume
                .credential_sha256()
                .iter()
                .flatten()
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(resumed_credential_digests.len(), 4);
            assert!(resumed_credential_digests
                .iter()
                .all(|digest| is_lower_sha256(digest)));
            assert_eq!(
                resumed.receipt_context(),
                &fixture.rollback.receipt_context()
            );
            assert_eq!(resumed.rollback_gate(), &fixture.rollback);
            assert_eq!(resumed.approved_gate().credential_count(), 4);
            assert_eq!(resumed.approved_gate().approved_business_rows(), 0);
            assert_eq!(resumed.approved_gate().work_product_business_rows(), 0);
            assert_eq!(resumed.vault_gate().metadata_rows(), 2);
            assert_eq!(resumed.vault_gate().business_rows(), 0);
            assert_eq!(resumed.vault_gate().key_record_count(), 0);
            assert_eq!(resumed.vault_gate().object_root_entry_count(), 0);
            if let Some(approved) = durable_approved {
                assert_eq!(resumed.approved_gate(), &approved);
            }
            if let Some(vault) = durable_vault {
                assert_eq!(resumed.vault_gate(), &vault);
            }
            if let Some(before) = approved_tree_before_resume {
                assert_eq!(
                    snapshot_tree(&fixture.app_root.join("privacy").join("approved-mcp"),),
                    before,
                    "a complete Approved/work-products target is not reinitialized"
                );
            }
            if let Some(before) = vault_tree_before_resume {
                assert_eq!(
                    snapshot_tree(&fixture.app_root.join("case-vault-v2")),
                    before,
                    "a complete Vault target is not reinitialized"
                );
            }
            assert_eq!(fixture.credential_presence(), [true; 4]);
            assert!(fixture.receipt_two_path().is_file());
            assert!(!fixture.receipt_two_incoming_path().exists());

            let inventory = authenticate_receipt_prefix(&fixture.app_root, &fixture.rollback)
                .expect("receipt two authenticates after resume");
            assert_eq!(inventory.final_receipts.len(), 3);
            assert!(inventory.next_incoming_receipt.is_none());
            assert_eq!(
                inventory.final_receipts[2].protected_file_sha256,
                resumed.target_components_receipt_sha256()
            );

            let mut predecessor_after_resume = fixture.frozen_predecessor_snapshot();
            assert!(predecessor_after_resume
                .remove(&format!(
                    "lineage/{}",
                    TARGET_COMPONENTS_STAGE.final_basename()
                ))
                .is_some());
            assert_eq!(
                predecessor_after_resume, predecessor_before,
                "resume adds only receipt two to the frozen predecessor inventory"
            );

            let before_idempotent_resume = snapshot_tree(&fixture.app_root);
            let provider_before_idempotent_resume = fixture
                .approved
                .provider_audit()
                .expect("provider audit before committed retry");
            fixture.approved.forbid_provider_mutation();
            let idempotent = prepare_v031_target_components_with_ephemeral_workspace_for_test(
                &fixture.app_root,
                &fixture.rollback,
                &fixture.approved.workspace,
            )
            .expect("committed receipt two resumes read-only");
            assert_eq!(idempotent, resumed);
            assert_eq!(
                snapshot_tree(&fixture.app_root),
                before_idempotent_resume,
                "committed target components and receipt two are a zero-write no-op"
            );
            let provider_after_idempotent_resume = fixture
                .approved
                .provider_audit()
                .expect("provider audit after committed retry");
            assert_eq!(
                provider_after_idempotent_resume.credential_sha256(),
                provider_before_idempotent_resume.credential_sha256()
            );
            assert_eq!(
                provider_after_idempotent_resume.load_or_create_calls(),
                provider_before_idempotent_resume.load_or_create_calls(),
                "committed retry never reaches the credential write API"
            );
            assert_eq!(
                provider_after_idempotent_resume.creation_writes(),
                provider_before_idempotent_resume.creation_writes()
            );
            assert_eq!(
                provider_after_idempotent_resume.rotate_calls(),
                provider_before_idempotent_resume.rotate_calls()
            );
        }
    }

    #[test]
    fn step3_resume_rejects_missing_credential_with_existing_namespace_before_any_writer_call() {
        let fixture = RealTargetComponentsFixture::new();
        assert_eq!(
            prepare_v031_target_components_with_ephemeral_workspace_and_failure_for_test(
                &fixture.app_root,
                &fixture.rollback,
                &fixture.approved.workspace,
                V031TargetComponentsFailurePoint::AfterWorkProductsClosedBeforeSync,
            )
            .expect_err("stop after both Approved databases close"),
            V031TargetComponentsError::ApprovedTarget
        );
        fixture
            .approved
            .remove_credential_for_test(3)
            .expect("remove the final credential from an existing namespace");
        let tree_before = snapshot_tree(&fixture.app_root);
        let provider_before = fixture
            .approved
            .provider_audit()
            .expect("provider audit before rejected resume");
        fixture.approved.forbid_provider_mutation();

        assert_eq!(
            prepare_v031_target_components_with_ephemeral_workspace_for_test(
                &fixture.app_root,
                &fixture.rollback,
                &fixture.approved.workspace,
            )
            .expect_err("namespace without its full credential prefix must fail closed"),
            V031TargetComponentsError::ApprovedTarget
        );
        assert_eq!(snapshot_tree(&fixture.app_root), tree_before);
        let provider_after = fixture
            .approved
            .provider_audit()
            .expect("provider audit after rejected resume");
        assert_eq!(
            provider_after.load_or_create_calls(),
            provider_before.load_or_create_calls()
        );
        assert_eq!(
            provider_after.creation_writes(),
            provider_before.creation_writes()
        );
        assert_eq!(
            provider_after.rotate_calls(),
            provider_before.rotate_calls()
        );
        assert!(!fixture.receipt_two_path().exists());
        assert!(!fixture.receipt_two_incoming_path().exists());
    }

    #[test]
    fn step3_resume_rejects_complete_vault_tamper_before_vault_sync_or_initializer() {
        let fixture = RealTargetComponentsFixture::new();
        assert_eq!(
            prepare_v031_target_components_with_ephemeral_workspace_and_failure_for_test(
                &fixture.app_root,
                &fixture.rollback,
                &fixture.approved.workspace,
                V031TargetComponentsFailurePoint::AfterVaultPrepareBeforeReceipt2,
            )
            .expect_err("stop after the complete Vault target returns"),
            V031TargetComponentsError::VaultTarget
        );
        let vault_database = fixture
            .app_root
            .join("case-vault-v2")
            .join("vault-state.sqlite");
        Connection::open(&vault_database)
            .expect("open complete Vault tamper fixture")
            .execute(
                "UPDATE vault_meta SET workspace_instance_id=?1 WHERE singleton=1",
                [format!("ws_{}", "7".repeat(32))],
            )
            .expect("tamper the complete Vault workspace identity");
        let vault_before = snapshot_tree(&fixture.app_root.join("case-vault-v2"));
        let provider_before = fixture
            .approved
            .provider_audit()
            .expect("provider audit before Vault rejection");
        fixture.approved.forbid_provider_mutation();

        assert_eq!(
            prepare_v031_target_components_with_ephemeral_workspace_for_test(
                &fixture.app_root,
                &fixture.rollback,
                &fixture.approved.workspace,
            )
            .expect_err("tampered complete Vault must fail closed"),
            V031TargetComponentsError::VaultTarget
        );
        assert_eq!(
            snapshot_tree(&fixture.app_root.join("case-vault-v2")),
            vault_before
        );
        let provider_after = fixture
            .approved
            .provider_audit()
            .expect("provider audit after Vault rejection");
        assert_eq!(
            provider_after.load_or_create_calls(),
            provider_before.load_or_create_calls()
        );
        assert_eq!(
            provider_after.creation_writes(),
            provider_before.creation_writes()
        );
        assert_eq!(
            provider_after.rotate_calls(),
            provider_before.rotate_calls()
        );
        assert!(!fixture.receipt_two_path().exists());
        assert!(!fixture.receipt_two_incoming_path().exists());
    }
}
