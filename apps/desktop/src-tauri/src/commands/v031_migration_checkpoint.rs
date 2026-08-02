//! Append-only five-component checkpoints for the v0.3.1 upgrade.
//!
//! These checkpoints deliberately reuse only the audited V3 outer wire.  The
//! Privacy component is a raw canonical migration-source SQLite image and is
//! therefore never passed to ordinary restore.  A separate DPAPI-protected
//! identity binds that exceptional meaning, both predecessor gates, the fixed
//! lineage basename and all five component hashes.

#[cfg(not(test))]
use super::v031_target_components::{
    bind_v031_historical_target_components_to_receipt_read_only,
    verify_v031_historical_target_components_receipt_gate_read_only,
};
#[cfg(test)]
use super::v031_target_components::{
    bind_v031_historical_target_components_with_approved_workspace_for_test,
    verify_v031_historical_target_components_receipt_gate_with_approved_workspace_for_test,
};
use super::{
    original_migration_backup::OriginalRollbackVerifiedGate,
    v031_target_components::{
        bind_v031_historical_target_components_from_authenticated_rollback_read_only,
        V031TargetComponentsPreparedGate,
    },
};
#[cfg(not(test))]
use crate::approved_mcp::verify_v031_approved_mcp_target_components_read_only;
use crate::{
    approved_mcp::{
        load_v031_approved_mcp_historical_target_from_checkpoint_read_only,
        verify_v031_approved_mcp_historical_target_credentials_read_only, ApprovedMcpWorkspace,
        V031ApprovedMcpHistoricalTargetRecord, V031ApprovedMcpTargetComponentsGate,
    },
    privacy_workflow::{
        load_v031_vault_historical_target_from_checkpoint_read_only,
        verify_v031_vault_target_component_read_only, PrivacyWorkflowManager,
        V031ApprovedProjectionSourceProof, V031BindingMaterialTerminalProof,
        V031VaultHistoricalTargetRecord, V031VaultTargetComponentGate,
    },
    v031_upgrade_r2::{
        self, AuthenticatedLineageInventory, CheckpointPairInventory, DirectorySync,
        PlatformDirectorySync, V031CheckpointKind,
    },
    v031_upgrade_receipts::{load_authenticated_v031_lineage, PrivacyReceiptAuthenticationBridge},
};
use privacy::{
    export_encrypted_vault_backup, open_application_backup_for_migration_recovery, protect_local,
    seal_application_backup_v3, sha256_hex, unprotect_local,
    upgrade_receipt_v1::V031UpgradeReceiptStage,
    validate_privacy_v1_sqlite_image_read_only, validate_privacy_v5_sqlite_image_read_only,
    vault_store::VaultStore,
    verify_encrypted_vault_backup_archive,
    vnext::{canonical_json_v1, strict_json_v1_from_slice, WorkspaceInstanceId},
    with_validated_privacy_v1_migration_source_read_only,
    with_validated_privacy_v5_migration_source_read_only, ApplicationBackupCreateRequestV3,
    ApplicationBackupMetadata, MigrationApplicationBackupOpenContext, OpenedApplicationBackup,
    MAX_APPLICATION_BACKUP_BYTES, MAX_PROTECTED_PLAINTEXT_BYTES,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroize;

const CHECKPOINT_IDENTITY_SCHEMA: &str =
    "lawyer-assistance-v031-five-component-checkpoint-identity-v1";
const RAW_PRIVACY_SLOT_ENCODING: &str = "raw-canonical-sqlite-migration-only";
const CHECKPOINT_EXPIRES_AT_UNIX: u64 = 253_402_300_799;
const CHECKPOINT_USER_SCHEMA_VERSION: i64 = 10;
const VAULT_DIRECTORY_NAME: &str = "case-vault-v2";
const MAX_CHECKPOINT_IDENTITY_FILE_BYTES: usize = MAX_PROTECTED_PLAINTEXT_BYTES + 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum V031MigrationCheckpointError {
    InvalidInput,
    GateMismatch,
    LineageState,
    SourceValidation,
    ComponentSnapshot,
    BackupCodec,
    IdentityProtection,
    Tampered,
    UnsafeFilesystem,
    InstallIncomplete,
}

impl V031MigrationCheckpointError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::InvalidInput => "v031_checkpoint_invalid_input",
            Self::GateMismatch => "v031_checkpoint_gate_mismatch",
            Self::LineageState => "v031_checkpoint_lineage_state_invalid",
            Self::SourceValidation => "v031_checkpoint_source_validation_failed",
            Self::ComponentSnapshot => "v031_checkpoint_component_snapshot_failed",
            Self::BackupCodec => "v031_checkpoint_backup_codec_failed",
            Self::IdentityProtection => "v031_checkpoint_identity_protection_failed",
            Self::Tampered => "v031_checkpoint_tampered",
            Self::UnsafeFilesystem => "v031_checkpoint_unsafe_filesystem",
            Self::InstallIncomplete => "v031_checkpoint_install_incomplete",
        }
    }
}

impl fmt::Display for V031MigrationCheckpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for V031MigrationCheckpointError {}

/// Path-free source/candidate evidence produced by the immediately following
/// migration.  Count zero is meaningful for an authenticated empty candidate
/// set and is not replaced with a synthetic row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031CheckpointCandidateEvidence {
    pub(crate) source_fingerprint: String,
    pub(crate) candidate_manifest_sha256: String,
    pub(crate) candidate_count: u64,
}

impl V031CheckpointCandidateEvidence {
    pub(crate) const fn candidate_count(&self) -> u64 {
        self.candidate_count
    }
}

/// Secret-free proof safe for upgrade receipts and diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031MigrationCheckpointProof {
    kind: V031CheckpointKind,
    lineage_id: String,
    original_identity_sha256: String,
    workspace_instance_id: String,
    identity_protected_sha256: String,
    bundle_sha256: String,
    user_database_sha256: String,
    user_schema_manifest_sha256: String,
    user_logical_manifest_sha256: String,
    user_business_manifest_sha256: String,
    user_total_rows: u64,
    privacy_database_sha256: String,
    privacy_schema_version: i64,
    privacy_logical_manifest_sha256: String,
    privacy_business_manifest_sha256: String,
    privacy_total_rows: u64,
    vault_bundle_sha256: String,
    approved_workspace_bundle_sha256: String,
    work_products_bundle_sha256: String,
    source_fingerprint: String,
    candidate_manifest_sha256: String,
    candidate_count: u64,
    created: bool,
}

/// Offline recovery result reconstructed inside the checkpoint boundary from
/// authenticated user-v10 and Privacy-v5 images.  No database bytes or row
/// identifiers are exposed to receipt orchestration.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031ProjectionCheckpointRecoveryProof {
    candidate: V031CheckpointCandidateEvidence,
    checkpoint: V031MigrationCheckpointProof,
    step5_terminal: V031BindingMaterialTerminalProof,
    projection_source: V031ApprovedProjectionSourceProof,
}

impl fmt::Debug for V031ProjectionCheckpointRecoveryProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031ProjectionCheckpointRecoveryProof")
            .field(
                "checkpoint_identity_sha256",
                &self.checkpoint.identity_protected_sha256(),
            )
            .field(
                "step5_terminal_manifest_sha256",
                &self.step5_terminal.terminal_manifest_sha256(),
            )
            .field(
                "projection_source_evidence_sha256",
                &self.projection_source.evidence_sha256(),
            )
            .field("candidate_count", &self.candidate.candidate_count())
            .finish_non_exhaustive()
    }
}

impl V031ProjectionCheckpointRecoveryProof {
    pub(crate) fn candidate(&self) -> &V031CheckpointCandidateEvidence {
        &self.candidate
    }

    pub(crate) fn checkpoint(&self) -> &V031MigrationCheckpointProof {
        &self.checkpoint
    }

    pub(crate) fn step5_terminal(&self) -> &V031BindingMaterialTerminalProof {
        &self.step5_terminal
    }

    pub(crate) fn projection_source(&self) -> &V031ApprovedProjectionSourceProof {
        &self.projection_source
    }
}

impl V031MigrationCheckpointProof {
    pub(crate) const fn kind(&self) -> V031CheckpointKind {
        self.kind
    }

    pub(crate) fn lineage_id(&self) -> &str {
        &self.lineage_id
    }

    pub(crate) fn original_identity_sha256(&self) -> &str {
        &self.original_identity_sha256
    }

    pub(crate) fn workspace_instance_id(&self) -> &str {
        &self.workspace_instance_id
    }

    pub(crate) fn identity_protected_sha256(&self) -> &str {
        &self.identity_protected_sha256
    }

    pub(crate) fn bundle_sha256(&self) -> &str {
        &self.bundle_sha256
    }

    pub(crate) fn user_database_sha256(&self) -> &str {
        &self.user_database_sha256
    }

    pub(crate) fn user_schema_manifest_sha256(&self) -> &str {
        &self.user_schema_manifest_sha256
    }

    pub(crate) fn user_logical_manifest_sha256(&self) -> &str {
        &self.user_logical_manifest_sha256
    }

    pub(crate) fn user_business_manifest_sha256(&self) -> &str {
        &self.user_business_manifest_sha256
    }

    pub(crate) const fn user_total_rows(&self) -> u64 {
        self.user_total_rows
    }

    pub(crate) fn privacy_database_sha256(&self) -> &str {
        &self.privacy_database_sha256
    }

    pub(crate) const fn privacy_schema_version(&self) -> i64 {
        self.privacy_schema_version
    }

    pub(crate) fn privacy_logical_manifest_sha256(&self) -> &str {
        &self.privacy_logical_manifest_sha256
    }

    pub(crate) fn privacy_business_manifest_sha256(&self) -> &str {
        &self.privacy_business_manifest_sha256
    }

    pub(crate) const fn privacy_total_rows(&self) -> u64 {
        self.privacy_total_rows
    }

    pub(crate) fn vault_bundle_sha256(&self) -> &str {
        &self.vault_bundle_sha256
    }

    pub(crate) fn approved_workspace_bundle_sha256(&self) -> &str {
        &self.approved_workspace_bundle_sha256
    }

    pub(crate) fn work_products_bundle_sha256(&self) -> &str {
        &self.work_products_bundle_sha256
    }

    pub(crate) fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    pub(crate) fn candidate_manifest_sha256(&self) -> &str {
        &self.candidate_manifest_sha256
    }

    pub(crate) const fn candidate_count(&self) -> u64 {
        self.candidate_count
    }

    #[cfg(test)]
    pub(crate) const fn created(&self) -> bool {
        self.created
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn projection_for_test(
        lineage_id: String,
        original_identity_sha256: String,
        workspace_instance_id: String,
        user_database_sha256: String,
        user_schema_manifest_sha256: String,
        user_logical_manifest_sha256: String,
        user_business_manifest_sha256: String,
        user_total_rows: u64,
        source_fingerprint: String,
        candidate_manifest_sha256: String,
        candidate_count: u64,
        privacy_logical_manifest_sha256: String,
        privacy_business_manifest_sha256: String,
        privacy_total_rows: u64,
    ) -> Self {
        Self {
            kind: V031CheckpointKind::Projection,
            lineage_id,
            original_identity_sha256,
            workspace_instance_id,
            identity_protected_sha256: "1".repeat(64),
            bundle_sha256: "2".repeat(64),
            user_database_sha256,
            user_schema_manifest_sha256,
            user_logical_manifest_sha256,
            user_business_manifest_sha256,
            user_total_rows,
            privacy_database_sha256: "4".repeat(64),
            privacy_schema_version: 5,
            privacy_logical_manifest_sha256,
            privacy_business_manifest_sha256,
            privacy_total_rows,
            vault_bundle_sha256: "5".repeat(64),
            approved_workspace_bundle_sha256: "6".repeat(64),
            work_products_bundle_sha256: "7".repeat(64),
            source_fingerprint,
            candidate_manifest_sha256,
            candidate_count,
            created: false,
        }
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn binding_material_for_test(
        kind: V031CheckpointKind,
        lineage_id: String,
        original_identity_sha256: String,
        workspace_instance_id: String,
        user_database_sha256: String,
        user_schema_manifest_sha256: String,
        user_logical_manifest_sha256: String,
        user_business_manifest_sha256: String,
        user_total_rows: u64,
        privacy_database_sha256: String,
        privacy_logical_manifest_sha256: String,
        privacy_business_manifest_sha256: String,
        privacy_total_rows: u64,
        source_fingerprint: String,
        candidate_manifest_sha256: String,
        candidate_count: u64,
        discriminator: u8,
    ) -> Self {
        assert!(matches!(
            kind,
            V031CheckpointKind::Binding | V031CheckpointKind::Materials
        ));
        let hash = |slot: u8| sha256_hex(&[discriminator, slot]);
        Self {
            kind,
            lineage_id,
            original_identity_sha256,
            workspace_instance_id,
            identity_protected_sha256: hash(1),
            bundle_sha256: hash(2),
            user_database_sha256,
            user_schema_manifest_sha256,
            user_logical_manifest_sha256,
            user_business_manifest_sha256,
            user_total_rows,
            privacy_database_sha256,
            privacy_schema_version: 1,
            privacy_logical_manifest_sha256,
            privacy_business_manifest_sha256,
            privacy_total_rows,
            vault_bundle_sha256: hash(3),
            approved_workspace_bundle_sha256: hash(4),
            work_products_bundle_sha256: hash(5),
            source_fingerprint,
            candidate_manifest_sha256,
            candidate_count,
            created: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_candidate_manifest_for_test(
        mut self,
        candidate_manifest_sha256: String,
    ) -> Self {
        self.candidate_manifest_sha256 = candidate_manifest_sha256;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_database_image_hashes_for_test(
        mut self,
        user_database_sha256: String,
        privacy_database_sha256: String,
    ) -> Self {
        assert!(is_hash(&user_database_sha256));
        assert!(is_hash(&privacy_database_sha256));
        self.user_database_sha256 = user_database_sha256;
        self.privacy_database_sha256 = privacy_database_sha256;
        self
    }
}

/// Fully re-opened Receipt-3 checkpoint set used only while authenticating the
/// two durable partial-v5 crash prefixes.  Every field is private; callers can
/// only pass the set to the Receipt-3 verifier that turns it into an opaque
/// workspace proof.
pub(crate) struct V031AuthenticatedPartialV5CheckpointSet {
    target: V031TargetComponentsPreparedGate,
    binding_candidate: V031CheckpointCandidateEvidence,
    binding: V031MigrationCheckpointProof,
    material_candidate: V031CheckpointCandidateEvidence,
    materials: V031MigrationCheckpointProof,
}

impl V031AuthenticatedPartialV5CheckpointSet {
    pub(crate) fn target(&self) -> &V031TargetComponentsPreparedGate {
        &self.target
    }

    pub(crate) fn binding_candidate(&self) -> &V031CheckpointCandidateEvidence {
        &self.binding_candidate
    }

    pub(crate) fn binding(&self) -> &V031MigrationCheckpointProof {
        &self.binding
    }

    pub(crate) fn material_candidate(&self) -> &V031CheckpointCandidateEvidence {
        &self.material_candidate
    }

    pub(crate) fn materials(&self) -> &V031MigrationCheckpointProof {
        &self.materials
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct RollbackGateBinding {
    lineage_id: String,
    envelope_binding_id: String,
    source_profile_proof_sha256: String,
    original_identity_sha256: String,
    original_bundle_sha256: String,
    original_rollback_receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckpointGateBinding {
    rollback: RollbackGateBinding,
    rollback_gate_binding_sha256: String,
    workspace_instance_id: WorkspaceInstanceId,
    approved_credential_manifest_sha256: String,
    approved_workspace_schema_sha256: String,
    approved_work_products_schema_sha256: String,
    approved_target_workspace_manifest_sha256: String,
    approved_target_work_products_manifest_sha256: String,
    approved_target_evidence_sha256: String,
    approved_credential_count: u64,
    approved_business_rows: u64,
    approved_work_product_business_rows: u64,
    vault_target_evidence_sha256: String,
    vault_component_manifest_sha256: String,
    vault_schema_sha256: String,
    vault_database_sha256: String,
    vault_layout_sha256: String,
    vault_schema_version: u32,
    vault_schema_objects: u64,
    vault_metadata_rows: u64,
    vault_business_rows: u64,
    vault_key_record_count: u64,
    vault_object_root_entry_count: u64,
    vault_directory_count: u64,
    vault_file_count: u64,
    original_user_physical_file_set_sha256: String,
    original_privacy_physical_file_set_sha256: String,
    original_user_schema_manifest_sha256: String,
    original_user_logical_manifest_sha256: String,
    original_user_business_manifest_sha256: String,
    original_user_total_rows: u64,
    original_privacy_logical_manifest_sha256: String,
    original_privacy_business_manifest_sha256: String,
    original_privacy_table_count: u64,
    original_privacy_total_rows: u64,
}

impl CheckpointGateBinding {
    fn from_gates(
        rollback: &OriginalRollbackVerifiedGate,
        approved: &V031ApprovedMcpTargetComponentsGate,
        vault: &V031VaultTargetComponentGate,
    ) -> Result<Self, V031MigrationCheckpointError> {
        let binding = Self {
            rollback: RollbackGateBinding {
                lineage_id: rollback.lineage_id().to_owned(),
                envelope_binding_id: rollback.envelope_binding_id().to_owned(),
                source_profile_proof_sha256: rollback.source_profile_proof_sha256().to_owned(),
                original_identity_sha256: rollback.original_identity_sha256().to_owned(),
                original_bundle_sha256: rollback.original_bundle_sha256().to_owned(),
                original_rollback_receipt_sha256: rollback
                    .original_rollback_receipt_sha256()
                    .to_owned(),
            },
            rollback_gate_binding_sha256: approved.rollback_gate_binding_sha256().to_owned(),
            workspace_instance_id: approved.workspace_instance_id().clone(),
            approved_credential_manifest_sha256: approved.credential_manifest_sha256().to_owned(),
            approved_workspace_schema_sha256: approved
                .approved_workspace_schema_sha256()
                .to_owned(),
            approved_work_products_schema_sha256: approved.work_products_schema_sha256().to_owned(),
            approved_target_workspace_manifest_sha256: approved
                .approved_workspace_manifest_sha256()
                .to_owned(),
            approved_target_work_products_manifest_sha256: approved
                .work_products_manifest_sha256()
                .to_owned(),
            approved_target_evidence_sha256: approved.evidence_sha256().to_owned(),
            approved_credential_count: approved.credential_count(),
            approved_business_rows: approved.approved_business_rows(),
            approved_work_product_business_rows: approved.work_product_business_rows(),
            vault_target_evidence_sha256: vault.evidence_sha256().to_owned(),
            vault_component_manifest_sha256: vault.vault_component_manifest_sha256().to_owned(),
            vault_schema_sha256: vault.vault_schema_sha256().to_owned(),
            vault_database_sha256: vault.vault_database_sha256().to_owned(),
            vault_layout_sha256: vault.vault_layout_sha256().to_owned(),
            vault_schema_version: vault.schema_version(),
            vault_schema_objects: vault.schema_objects(),
            vault_metadata_rows: vault.metadata_rows(),
            vault_business_rows: vault.business_rows(),
            vault_key_record_count: vault.key_record_count(),
            vault_object_root_entry_count: vault.object_root_entry_count(),
            vault_directory_count: vault.directory_count(),
            vault_file_count: vault.file_count(),
            original_user_physical_file_set_sha256: rollback
                .original_user_physical_file_set_sha256()
                .to_owned(),
            original_privacy_physical_file_set_sha256: rollback
                .original_privacy_physical_file_set_sha256()
                .to_owned(),
            original_user_schema_manifest_sha256: rollback
                .original_user_source_proof()
                .schema_manifest_sha256
                .clone(),
            original_user_logical_manifest_sha256: rollback
                .original_user_source_proof()
                .logical_database_manifest_sha256
                .clone(),
            original_user_business_manifest_sha256: rollback
                .original_user_source_proof()
                .business_manifest_sha256
                .clone(),
            original_user_total_rows: rollback.original_user_source_proof().total_rows,
            original_privacy_logical_manifest_sha256: rollback
                .original_privacy_logical_manifest_sha256()
                .to_owned(),
            original_privacy_business_manifest_sha256: rollback
                .original_privacy_business_manifest_sha256()
                .to_owned(),
            original_privacy_table_count: rollback.original_privacy_table_count(),
            original_privacy_total_rows: rollback.original_privacy_total_rows(),
        };
        binding.validate()?;
        if vault.workspace_instance_id() != &binding.workspace_instance_id
            || vault.rollback_gate_binding_sha256() != binding.rollback_gate_binding_sha256
            || vault.approved_target_components_evidence_sha256()
                != binding.approved_target_evidence_sha256
            || approved.approved_business_rows() != 0
            || approved.work_product_business_rows() != 0
            || vault.business_rows() != 0
            || vault.key_record_count() != 0
            || vault.object_root_entry_count() != 0
        {
            return Err(V031MigrationCheckpointError::GateMismatch);
        }
        Ok(binding)
    }

    fn validate(&self) -> Result<(), V031MigrationCheckpointError> {
        for hash in [
            self.rollback.lineage_id.as_str(),
            self.rollback.source_profile_proof_sha256.as_str(),
            self.rollback.original_identity_sha256.as_str(),
            self.rollback.original_bundle_sha256.as_str(),
            self.rollback.original_rollback_receipt_sha256.as_str(),
            self.rollback_gate_binding_sha256.as_str(),
            self.approved_credential_manifest_sha256.as_str(),
            self.approved_workspace_schema_sha256.as_str(),
            self.approved_work_products_schema_sha256.as_str(),
            self.approved_target_workspace_manifest_sha256.as_str(),
            self.approved_target_work_products_manifest_sha256.as_str(),
            self.approved_target_evidence_sha256.as_str(),
            self.vault_target_evidence_sha256.as_str(),
            self.vault_component_manifest_sha256.as_str(),
            self.vault_schema_sha256.as_str(),
            self.vault_database_sha256.as_str(),
            self.vault_layout_sha256.as_str(),
            self.original_user_physical_file_set_sha256.as_str(),
            self.original_privacy_physical_file_set_sha256.as_str(),
            self.original_user_schema_manifest_sha256.as_str(),
            self.original_user_logical_manifest_sha256.as_str(),
            self.original_user_business_manifest_sha256.as_str(),
            self.original_privacy_logical_manifest_sha256.as_str(),
            self.original_privacy_business_manifest_sha256.as_str(),
        ] {
            if !is_hash(hash) {
                return Err(V031MigrationCheckpointError::GateMismatch);
            }
        }
        if !is_workspace_id(&self.rollback.envelope_binding_id)
            || !is_workspace_id(self.workspace_instance_id.as_str())
            || self.rollback.envelope_binding_id == self.workspace_instance_id.as_str()
            || self.approved_credential_count != 4
            || self.approved_business_rows != 0
            || self.approved_work_product_business_rows != 0
            || self.vault_metadata_rows != 2
            || self.vault_business_rows != 0
            || self.vault_key_record_count != 0
            || self.vault_object_root_entry_count != 0
            || sha256_hex(
                &canonical_json_v1(&self.rollback)
                    .map_err(|_| V031MigrationCheckpointError::GateMismatch)?,
            ) != self.rollback_gate_binding_sha256
        {
            return Err(V031MigrationCheckpointError::GateMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckpointIdentityV1 {
    schema_version: String,
    checkpoint_kind: String,
    migration_id: String,
    lineage_id: String,
    envelope_binding_id: String,
    source_profile_proof_sha256: String,
    original_identity_sha256: String,
    original_bundle_sha256: String,
    original_rollback_receipt_sha256: String,
    rollback_gate_binding_sha256: String,
    workspace_instance_id: String,
    approved_credential_manifest_sha256: String,
    approved_workspace_schema_sha256: String,
    approved_work_products_schema_sha256: String,
    approved_target_workspace_manifest_sha256: String,
    approved_target_work_products_manifest_sha256: String,
    approved_target_evidence_sha256: String,
    approved_credential_count: u64,
    approved_business_rows: u64,
    approved_work_product_business_rows: u64,
    vault_target_evidence_sha256: String,
    vault_component_manifest_sha256: String,
    vault_schema_sha256: String,
    vault_database_sha256: String,
    vault_layout_sha256: String,
    vault_schema_version: u32,
    vault_schema_objects: u64,
    vault_metadata_rows: u64,
    vault_business_rows: u64,
    vault_key_record_count: u64,
    vault_object_root_entry_count: u64,
    vault_directory_count: u64,
    vault_file_count: u64,
    original_user_physical_file_set_sha256: String,
    original_privacy_physical_file_set_sha256: String,
    identity_basename: String,
    bundle_basename: String,
    backup_id: String,
    privacy_backup_id: String,
    app_version: String,
    user_schema_version: i64,
    privacy_schema_version: i64,
    privacy_slot_encoding: String,
    created_at_unix: u64,
    expires_at_unix: u64,
    bundle_bytes: u64,
    bundle_sha256: String,
    user_database_sha256: String,
    user_schema_manifest_sha256: String,
    user_logical_manifest_sha256: String,
    user_business_manifest_sha256: String,
    user_total_rows: u64,
    privacy_database_sha256: String,
    privacy_logical_manifest_sha256: String,
    privacy_business_manifest_sha256: String,
    privacy_total_rows: u64,
    vault_bundle_sha256: String,
    vault_manifest_sha256: String,
    approved_workspace_bundle_sha256: String,
    approved_workspace_manifest_sha256: String,
    work_products_bundle_sha256: String,
    work_products_manifest_sha256: String,
    source_fingerprint: String,
    candidate_manifest_sha256: String,
    candidate_count: u64,
}

struct BuiltCheckpoint {
    bundle: Vec<u8>,
    identity: CheckpointIdentityV1,
}

struct SourceImages {
    user: Vec<u8>,
    user_schema_manifest_sha256: String,
    user_logical_manifest_sha256: String,
    user_business_manifest_sha256: String,
    user_total_rows: u64,
    privacy: Vec<u8>,
    privacy_schema_version: i64,
    privacy_logical_manifest_sha256: String,
    privacy_business_manifest_sha256: String,
    privacy_total_rows: u64,
}

trait CheckpointTargetGateVerifier {
    fn verify(
        &self,
        app_local_data_dir: &Path,
        rollback_gate: &OriginalRollbackVerifiedGate,
        approved_gate: &V031ApprovedMcpTargetComponentsGate,
        vault_gate: &V031VaultTargetComponentGate,
    ) -> Result<(), V031MigrationCheckpointError>;
}

struct ProductionCheckpointTargetGateVerifier<'a> {
    approved_workspace: &'a ApprovedMcpWorkspace,
}

impl CheckpointTargetGateVerifier for ProductionCheckpointTargetGateVerifier<'_> {
    fn verify(
        &self,
        app_local_data_dir: &Path,
        rollback_gate: &OriginalRollbackVerifiedGate,
        approved_gate: &V031ApprovedMcpTargetComponentsGate,
        vault_gate: &V031VaultTargetComponentGate,
    ) -> Result<(), V031MigrationCheckpointError> {
        #[cfg(not(test))]
        {
            // The production verifier intentionally uses the fixed
            // Credential Manager provider. Keep the workspace reference only
            // so this verifier has the same lifetime-shaped API as the
            // test-only ephemeral provider path.
            let _ = self.approved_workspace;
            verify_v031_approved_mcp_target_components_read_only(
                app_local_data_dir,
                rollback_gate,
                approved_gate,
            )
            .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
        }
        #[cfg(test)]
        self.approved_workspace
            .verify_v031_target_components_for_checkpoint_test(rollback_gate, approved_gate)
            .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
        verify_v031_vault_target_component_read_only(
            app_local_data_dir,
            rollback_gate,
            approved_gate,
            vault_gate,
        )
        .map_err(|_| V031MigrationCheckpointError::GateMismatch)
    }
}

/// Historical Gate2 verification for checkpoint reads and for the Projection
/// checkpoint created after Step5. Stable credentials and receipt 2 are
/// re-authenticated, while legally evolved live business rows are left to the
/// stage-specific ledger/projection proof immediately surrounding the call.
struct HistoricalCheckpointTargetGateVerifier<'a> {
    approved_workspace: &'a ApprovedMcpWorkspace,
}

impl CheckpointTargetGateVerifier for HistoricalCheckpointTargetGateVerifier<'_> {
    fn verify(
        &self,
        app_local_data_dir: &Path,
        rollback_gate: &OriginalRollbackVerifiedGate,
        approved_gate: &V031ApprovedMcpTargetComponentsGate,
        vault_gate: &V031VaultTargetComponentGate,
    ) -> Result<(), V031MigrationCheckpointError> {
        verify_v031_approved_mcp_historical_target_credentials_read_only(
            self.approved_workspace,
            rollback_gate,
            approved_gate,
        )
        .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
        #[cfg(not(test))]
        let historical = bind_v031_historical_target_components_to_receipt_read_only(
            app_local_data_dir,
            rollback_gate,
            approved_gate.clone(),
            vault_gate.clone(),
        )
        .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
        #[cfg(test)]
        let historical = bind_v031_historical_target_components_with_approved_workspace_for_test(
            app_local_data_dir,
            rollback_gate,
            approved_gate.clone(),
            vault_gate.clone(),
            self.approved_workspace,
        )
        .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
        #[cfg(not(test))]
        verify_v031_historical_target_components_receipt_gate_read_only(
            app_local_data_dir,
            &historical,
        )
        .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
        #[cfg(test)]
        verify_v031_historical_target_components_receipt_gate_with_approved_workspace_for_test(
            app_local_data_dir,
            &historical,
            self.approved_workspace,
        )
        .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn ensure_v031_migration_checkpoint(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    vault_gate: &V031VaultTargetComponentGate,
    lineage: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031MigrationCheckpointProof, V031MigrationCheckpointError> {
    if kind == V031CheckpointKind::Projection {
        ensure_v031_migration_checkpoint_with_verifier(
            app_local_data_dir,
            user_database_path,
            privacy_database_path,
            kind,
            candidate,
            rollback_gate,
            approved_gate,
            vault_gate,
            lineage,
            approved_workspace,
            &HistoricalCheckpointTargetGateVerifier { approved_workspace },
        )
    } else {
        ensure_v031_migration_checkpoint_with_verifier(
            app_local_data_dir,
            user_database_path,
            privacy_database_path,
            kind,
            candidate,
            rollback_gate,
            approved_gate,
            vault_gate,
            lineage,
            approved_workspace,
            &ProductionCheckpointTargetGateVerifier { approved_workspace },
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn ensure_v031_migration_checkpoint_with_verifier<V: CheckpointTargetGateVerifier>(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    vault_gate: &V031VaultTargetComponentGate,
    lineage: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
    target_verifier: &V,
) -> Result<V031MigrationCheckpointProof, V031MigrationCheckpointError> {
    validate_absolute_path(app_local_data_dir)?;
    validate_checkpoint_source_paths(
        app_local_data_dir,
        user_database_path,
        privacy_database_path,
    )?;
    validate_candidate(candidate)?;
    let gates = CheckpointGateBinding::from_gates(rollback_gate, approved_gate, vault_gate)?;
    validate_inventory_for_checkpoint(app_local_data_dir, lineage, &gates, kind)?;
    target_verifier.verify(app_local_data_dir, rollback_gate, approved_gate, vault_gate)?;

    let pair = checkpoint_pair(lineage, kind);
    if pair.is_exact_final() {
        return verify_checkpoint_pair(
            app_local_data_dir,
            kind,
            candidate,
            &gates,
            approved_workspace,
            false,
        );
    }

    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &gates.rollback.lineage_id,
    )
    .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let bundle_incoming = directory.join(kind.bundle_incoming_basename());
    let identity_incoming = directory.join(kind.identity_incoming_basename());
    let bundle_final = directory.join(kind.bundle_final_basename());
    let identity_final = directory.join(kind.identity_final_basename());
    let sync = PlatformDirectorySync;

    let built = if pair.is_absent() {
        let built = build_checkpoint(
            app_local_data_dir,
            user_database_path,
            privacy_database_path,
            kind,
            candidate,
            rollback_gate,
            approved_gate,
            &gates,
            approved_workspace,
        )?;
        verify_opened_checkpoint(&built.bundle, &built.identity, &gates, approved_workspace)?;
        v031_upgrade_r2::write_create_new_sync(
            &bundle_incoming,
            &built.bundle,
            MAX_APPLICATION_BACKUP_BYTES,
        )
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
        sync.sync_directory(&directory)
            .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
        Some(built)
    } else {
        None
    };

    let bundle = if pair.bundle_incoming || built.is_some() {
        v031_upgrade_r2::read_bounded_file(&bundle_incoming, MAX_APPLICATION_BACKUP_BYTES)
            .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?
    } else {
        return Err(V031MigrationCheckpointError::LineageState);
    };

    let identity = if pair.identity_incoming {
        read_checkpoint_identity(&identity_incoming)?
    } else if pair.identity_final {
        read_checkpoint_identity(&identity_final)?
    } else if let Some(built) = built.as_ref() {
        built.identity.clone()
    } else {
        // Bundle-only is the one legal crash point without an identity.  The
        // authenticated V3 metadata and five component bytes deterministically
        // reconstruct the identity plaintext; DPAPI protection itself may use
        // fresh randomness.
        reconstruct_identity_from_bundle(&bundle, kind, candidate, &gates, approved_workspace)?
    };
    validate_identity(&identity, kind, candidate, &gates)?;
    verify_opened_checkpoint(&bundle, &identity, &gates, approved_workspace)?;

    if !pair.identity_incoming && !pair.identity_final {
        let plaintext = canonical_json_v1(&identity)
            .map_err(|_| V031MigrationCheckpointError::IdentityProtection)?;
        let protected = protect_local(&plaintext)
            .map_err(|_| V031MigrationCheckpointError::IdentityProtection)?;
        let mut plaintext = plaintext;
        plaintext.zeroize();
        v031_upgrade_r2::write_create_new_sync(
            &identity_incoming,
            &protected,
            MAX_CHECKPOINT_IDENTITY_FILE_BYTES,
        )
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
        sync.sync_directory(&directory)
            .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
        if read_checkpoint_identity(&identity_incoming)? != identity {
            return Err(V031MigrationCheckpointError::Tampered);
        }
    }

    if !pair.identity_final {
        v031_upgrade_r2::rename_new_no_replace_write_through(&identity_incoming, &identity_final)
            .map_err(|_| V031MigrationCheckpointError::InstallIncomplete)?;
        sync.sync_directory(&directory)
            .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    }
    if !pair.bundle_final {
        v031_upgrade_r2::rename_new_no_replace_write_through(&bundle_incoming, &bundle_final)
            .map_err(|_| V031MigrationCheckpointError::InstallIncomplete)?;
        sync.sync_directory(&directory)
            .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    }

    verify_checkpoint_pair(
        app_local_data_dir,
        kind,
        candidate,
        &gates,
        approved_workspace,
        true,
    )
}

/// Reopens an already committed checkpoint without accepting candidate hashes
/// from the caller.  The candidate identity is recovered only from the
/// DPAPI-authenticated final identity and is then checked against the complete
/// gate binding and V3 bundle before it is returned as a path-free proof.
/// This is the restart path used after the live Privacy source has advanced
/// beyond the checkpoint's source schema.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_v031_migration_checkpoint_read_only(
    app_local_data_dir: &Path,
    kind: V031CheckpointKind,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    vault_gate: &V031VaultTargetComponentGate,
    lineage: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<
    (
        V031CheckpointCandidateEvidence,
        V031MigrationCheckpointProof,
    ),
    V031MigrationCheckpointError,
> {
    let gates = CheckpointGateBinding::from_gates(rollback_gate, approved_gate, vault_gate)?;
    validate_inventory_for_checkpoint(app_local_data_dir, lineage, &gates, kind)?;
    if !checkpoint_pair(lineage, kind).is_exact_final() {
        return Err(V031MigrationCheckpointError::InstallIncomplete);
    }
    HistoricalCheckpointTargetGateVerifier { approved_workspace }.verify(
        app_local_data_dir,
        rollback_gate,
        approved_gate,
        vault_gate,
    )?;

    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &gates.rollback.lineage_id,
    )
    .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity_path = directory.join(kind.identity_final_basename());
    v031_upgrade_r2::verify_plain_single_link_file(&identity_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity = read_checkpoint_identity(&identity_path)?;
    let candidate = V031CheckpointCandidateEvidence {
        source_fingerprint: identity.source_fingerprint.clone(),
        candidate_manifest_sha256: identity.candidate_manifest_sha256.clone(),
        candidate_count: identity.candidate_count,
    };
    validate_candidate(&candidate)?;
    validate_identity(&identity, kind, &candidate, &gates)?;
    let proof = verify_checkpoint_pair(
        app_local_data_dir,
        kind,
        &candidate,
        &gates,
        approved_workspace,
        false,
    )?;
    Ok((candidate, proof))
}

/// Reconstructs historical Gate2 from the final Binding checkpoint identity,
/// current read-only Credential values, and authenticated receipt 2. The
/// checkpoint's five-component bundle and protected identity are fully
/// verified before the capability is returned; no evolved live target hash is
/// substituted for an early Gate2 field.
pub(crate) fn load_v031_historical_target_components_from_checkpoint_read_only(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031TargetComponentsPreparedGate, V031MigrationCheckpointError> {
    if !app_local_data_dir.is_absolute() {
        return Err(V031MigrationCheckpointError::InvalidInput);
    }
    let context = rollback_gate.receipt_context();
    let bridge = PrivacyReceiptAuthenticationBridge::new(context.clone());
    let lineage =
        load_authenticated_v031_lineage(app_local_data_dir, rollback_gate.lineage_id(), &bridge)
            .map_err(|_| V031MigrationCheckpointError::LineageState)?;
    if !lineage.authenticates(app_local_data_dir, rollback_gate.lineage_id())
        || lineage.final_receipts.len() < 4
        || !lineage.checkpoints.binding.is_exact_final()
    {
        return Err(V031MigrationCheckpointError::LineageState);
    }
    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        rollback_gate.lineage_id(),
    )
    .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity_path = directory.join(V031CheckpointKind::Binding.identity_final_basename());
    v031_upgrade_r2::verify_plain_single_link_file(&identity_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity = read_checkpoint_identity(&identity_path)?;
    let (approved, vault) = historical_target_gates_from_checkpoint_identity(
        rollback_gate,
        approved_workspace,
        &identity,
    )?;
    #[cfg(not(test))]
    let target = bind_v031_historical_target_components_to_receipt_read_only(
        app_local_data_dir,
        rollback_gate,
        approved,
        vault,
    )
    .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
    #[cfg(test)]
    let target = bind_v031_historical_target_components_with_approved_workspace_for_test(
        app_local_data_dir,
        rollback_gate,
        approved,
        vault,
        approved_workspace,
    )
    .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
    let gates = CheckpointGateBinding::from_gates(
        rollback_gate,
        target.approved_gate(),
        target.vault_gate(),
    )?;
    validate_inventory_for_checkpoint(
        app_local_data_dir,
        &lineage,
        &gates,
        V031CheckpointKind::Binding,
    )?;
    let candidate = V031CheckpointCandidateEvidence {
        source_fingerprint: identity.source_fingerprint.clone(),
        candidate_manifest_sha256: identity.candidate_manifest_sha256.clone(),
        candidate_count: identity.candidate_count,
    };
    validate_candidate(&candidate)?;
    validate_identity(&identity, V031CheckpointKind::Binding, &candidate, &gates)?;
    verify_checkpoint_pair(
        app_local_data_dir,
        V031CheckpointKind::Binding,
        &candidate,
        &gates,
        approved_workspace,
        false,
    )?;
    Ok(target)
}

/// Re-opens the exact Receipt-3 checkpoint profile without acquiring the
/// target-component mutex or recursively reloading Original-V2.  This entry
/// point is intentionally usable only with the two opaque capabilities already
/// produced by the in-progress Original-V2 reload.
pub(crate) fn load_v031_partial_v5_checkpoint_set_from_authenticated_rollback_read_only(
    app_local_data_dir: &Path,
    rollback_gate: &OriginalRollbackVerifiedGate,
    lineage: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<V031AuthenticatedPartialV5CheckpointSet, V031MigrationCheckpointError> {
    if !app_local_data_dir.is_absolute()
        || !lineage.authenticates(app_local_data_dir, rollback_gate.lineage_id())
        || lineage.final_receipts.len() != 4
        || lineage
            .next_incoming_receipt
            .as_ref()
            .is_some_and(|incoming| {
                incoming.ordinal != V031UpgradeReceiptStage::PrivacyV5Verified.ordinal()
            })
        || !lineage.v2.identity_final
        || lineage.v2.identity_incoming
        || !lineage.v2.bundle_final
        || lineage.v2.bundle_incoming
        || lineage.v2.user_snapshot_incoming
        || lineage.v2.privacy_snapshot_incoming
        || !lineage.checkpoints.binding.is_exact_final()
        || !lineage.checkpoints.materials.is_exact_final()
        || !lineage.checkpoints.projection.is_absent()
        || !lineage.step8_predecessor.is_absent()
        || !lineage.upgrade_complete_evidence.is_absent()
    {
        return Err(V031MigrationCheckpointError::LineageState);
    }

    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        rollback_gate.lineage_id(),
    )
    .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity_path = directory.join(V031CheckpointKind::Binding.identity_final_basename());
    v031_upgrade_r2::verify_plain_single_link_file(&identity_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let binding_identity = read_checkpoint_identity(&identity_path)?;
    let (approved, vault) = historical_target_gates_from_checkpoint_identity(
        rollback_gate,
        approved_workspace,
        &binding_identity,
    )?;
    let target = bind_v031_historical_target_components_from_authenticated_rollback_read_only(
        app_local_data_dir,
        rollback_gate,
        lineage,
        approved,
        vault,
    )
    .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
    let gates = CheckpointGateBinding::from_gates(
        rollback_gate,
        target.approved_gate(),
        target.vault_gate(),
    )?;
    let (binding_candidate, binding) = load_checkpoint_pair_from_authenticated_gates_read_only(
        app_local_data_dir,
        V031CheckpointKind::Binding,
        lineage,
        &gates,
        approved_workspace,
    )?;
    let (material_candidate, materials) = load_checkpoint_pair_from_authenticated_gates_read_only(
        app_local_data_dir,
        V031CheckpointKind::Materials,
        lineage,
        &gates,
        approved_workspace,
    )?;

    Ok(V031AuthenticatedPartialV5CheckpointSet {
        target,
        binding_candidate,
        binding,
        material_candidate,
        materials,
    })
}

fn historical_target_gates_from_checkpoint_identity(
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_workspace: &ApprovedMcpWorkspace,
    identity: &CheckpointIdentityV1,
) -> Result<
    (
        V031ApprovedMcpTargetComponentsGate,
        V031VaultTargetComponentGate,
    ),
    V031MigrationCheckpointError,
> {
    let workspace_instance_id = WorkspaceInstanceId::parse(&identity.workspace_instance_id)
        .map_err(|_| V031MigrationCheckpointError::Tampered)?;
    let approved = load_v031_approved_mcp_historical_target_from_checkpoint_read_only(
        approved_workspace,
        rollback_gate,
        &V031ApprovedMcpHistoricalTargetRecord {
            workspace_instance_id,
            credential_manifest_sha256: identity.approved_credential_manifest_sha256.clone(),
            approved_workspace_schema_sha256: identity.approved_workspace_schema_sha256.clone(),
            work_products_schema_sha256: identity.approved_work_products_schema_sha256.clone(),
            approved_workspace_manifest_sha256: identity
                .approved_target_workspace_manifest_sha256
                .clone(),
            work_products_manifest_sha256: identity
                .approved_target_work_products_manifest_sha256
                .clone(),
            evidence_sha256: identity.approved_target_evidence_sha256.clone(),
            credential_count: identity.approved_credential_count,
            approved_business_rows: identity.approved_business_rows,
            work_product_business_rows: identity.approved_work_product_business_rows,
        },
    )
    .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
    let vault = load_v031_vault_historical_target_from_checkpoint_read_only(
        rollback_gate,
        &approved,
        &V031VaultHistoricalTargetRecord {
            schema_version: identity.vault_schema_version,
            vault_schema_sha256: identity.vault_schema_sha256.clone(),
            vault_database_sha256: identity.vault_database_sha256.clone(),
            vault_layout_sha256: identity.vault_layout_sha256.clone(),
            vault_component_manifest_sha256: identity.vault_component_manifest_sha256.clone(),
            evidence_sha256: identity.vault_target_evidence_sha256.clone(),
            schema_objects: identity.vault_schema_objects,
            metadata_rows: identity.vault_metadata_rows,
            business_rows: identity.vault_business_rows,
            key_record_count: identity.vault_key_record_count,
            object_root_entry_count: identity.vault_object_root_entry_count,
            directory_count: identity.vault_directory_count,
            file_count: identity.vault_file_count,
        },
    )
    .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
    Ok((approved, vault))
}

fn load_checkpoint_pair_from_authenticated_gates_read_only(
    app_local_data_dir: &Path,
    kind: V031CheckpointKind,
    lineage: &AuthenticatedLineageInventory,
    gates: &CheckpointGateBinding,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<
    (
        V031CheckpointCandidateEvidence,
        V031MigrationCheckpointProof,
    ),
    V031MigrationCheckpointError,
> {
    validate_inventory_for_checkpoint(app_local_data_dir, lineage, gates, kind)?;
    if !checkpoint_pair(lineage, kind).is_exact_final() {
        return Err(V031MigrationCheckpointError::InstallIncomplete);
    }
    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &gates.rollback.lineage_id,
    )
    .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity_path = directory.join(kind.identity_final_basename());
    v031_upgrade_r2::verify_plain_single_link_file(&identity_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity = read_checkpoint_identity(&identity_path)?;
    let candidate = V031CheckpointCandidateEvidence {
        source_fingerprint: identity.source_fingerprint.clone(),
        candidate_manifest_sha256: identity.candidate_manifest_sha256.clone(),
        candidate_count: identity.candidate_count,
    };
    validate_candidate(&candidate)?;
    validate_identity(&identity, kind, &candidate, gates)?;
    let proof = verify_checkpoint_pair(
        app_local_data_dir,
        kind,
        &candidate,
        gates,
        approved_workspace,
        false,
    )?;
    Ok((candidate, proof))
}

/// Reconstructs the post-Step-5 terminal/source capabilities from the
/// authenticated Projection checkpoint itself.  This remains valid after the
/// active Privacy database has advanced to v6 or the active User database has
/// advanced to v11 because neither active source is consulted.
#[allow(clippy::too_many_arguments)]
pub(crate) fn load_v031_projection_checkpoint_recovery_proof_read_only(
    app_local_data_dir: &Path,
    target_gate: &V031TargetComponentsPreparedGate,
    binding_checkpoint: &V031MigrationCheckpointProof,
    material_checkpoint: &V031MigrationCheckpointProof,
    lineage: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
    manager: &PrivacyWorkflowManager,
) -> Result<V031ProjectionCheckpointRecoveryProof, V031MigrationCheckpointError> {
    let rollback_gate = target_gate.rollback_gate();
    let (candidate, checkpoint) = load_v031_migration_checkpoint_read_only(
        app_local_data_dir,
        V031CheckpointKind::Projection,
        rollback_gate,
        target_gate.approved_gate(),
        target_gate.vault_gate(),
        lineage,
        approved_workspace,
    )?;
    let gates = CheckpointGateBinding::from_gates(
        rollback_gate,
        target_gate.approved_gate(),
        target_gate.vault_gate(),
    )?;
    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &gates.rollback.lineage_id,
    )
    .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity_path = directory.join(V031CheckpointKind::Projection.identity_final_basename());
    let bundle_path = directory.join(V031CheckpointKind::Projection.bundle_final_basename());
    v031_upgrade_r2::verify_plain_single_link_file(&identity_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    v031_upgrade_r2::verify_plain_single_link_file(&bundle_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity = read_checkpoint_identity(&identity_path)?;
    validate_identity(
        &identity,
        V031CheckpointKind::Projection,
        &candidate,
        &gates,
    )?;
    let bundle = v031_upgrade_r2::read_bounded_file(&bundle_path, MAX_APPLICATION_BACKUP_BYTES)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let opened = verify_opened_checkpoint(&bundle, &identity, &gates, approved_workspace)?;
    if sha256_hex(&opened.user_database) != checkpoint.user_database_sha256()
        || sha256_hex(&opened.encrypted_privacy_bundle) != checkpoint.privacy_database_sha256()
    {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    let (step5_terminal, projection_source) = manager
        .v031_projection_recovery_proofs_from_verified_checkpoint_images(
            rollback_gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
            &checkpoint,
            &opened.user_database,
            &opened.encrypted_privacy_bundle,
        )
        .map_err(|_| V031MigrationCheckpointError::SourceValidation)?;
    if projection_source.checkpoint_candidate_evidence() != candidate {
        return Err(V031MigrationCheckpointError::SourceValidation);
    }
    Ok(V031ProjectionCheckpointRecoveryProof {
        candidate,
        checkpoint,
        step5_terminal,
        projection_source,
    })
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn verify_v031_migration_checkpoint_with_verifier<V: CheckpointTargetGateVerifier>(
    app_local_data_dir: &Path,
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    vault_gate: &V031VaultTargetComponentGate,
    lineage: &AuthenticatedLineageInventory,
    approved_workspace: &ApprovedMcpWorkspace,
    target_verifier: &V,
) -> Result<V031MigrationCheckpointProof, V031MigrationCheckpointError> {
    validate_candidate(candidate)?;
    let gates = CheckpointGateBinding::from_gates(rollback_gate, approved_gate, vault_gate)?;
    validate_inventory_for_checkpoint(app_local_data_dir, lineage, &gates, kind)?;
    if !checkpoint_pair(lineage, kind).is_exact_final() {
        return Err(V031MigrationCheckpointError::InstallIncomplete);
    }
    target_verifier.verify(app_local_data_dir, rollback_gate, approved_gate, vault_gate)?;
    verify_checkpoint_pair(
        app_local_data_dir,
        kind,
        candidate,
        &gates,
        approved_workspace,
        false,
    )
}

fn validate_inventory_for_checkpoint(
    app_local_data_dir: &Path,
    lineage: &AuthenticatedLineageInventory,
    gates: &CheckpointGateBinding,
    kind: V031CheckpointKind,
) -> Result<(), V031MigrationCheckpointError> {
    if !lineage.authenticates(app_local_data_dir, &gates.rollback.lineage_id) {
        return Err(V031MigrationCheckpointError::LineageState);
    }
    if !checkpoint_inventory_is_valid_for_operation(
        lineage.final_receipts.len(),
        lineage.next_incoming_receipt.is_none(),
        lineage.checkpoints,
        kind,
    ) {
        return Err(V031MigrationCheckpointError::LineageState);
    }
    Ok(())
}

fn checkpoint_inventory_is_valid_for_operation(
    final_receipt_count: usize,
    no_incoming_receipt: bool,
    checkpoints: v031_upgrade_r2::V031CheckpointInventory,
    kind: V031CheckpointKind,
) -> bool {
    if final_receipt_count > v031_upgrade_r2::V031_RECEIPTS.len()
        || (final_receipt_count == v031_upgrade_r2::V031_RECEIPTS.len() && !no_incoming_receipt)
        || V031CheckpointKind::ALL.into_iter().any(|candidate| {
            !checkpoint_pair_state_is_legal(checkpoint_pair_from(&checkpoints, candidate))
        })
        || (!checkpoints.materials.is_absent() && !checkpoints.binding.is_exact_final())
    {
        return false;
    }

    let step4_cross_state = match final_receipt_count {
        0..=2 => checkpoints.binding.is_absent() && checkpoints.materials.is_absent(),
        3 if no_incoming_receipt => true,
        _ => checkpoints.binding.is_exact_final() && checkpoints.materials.is_exact_final(),
    };
    let projection_cross_state = match final_receipt_count {
        0..=5 => checkpoints.projection.is_absent(),
        6 if no_incoming_receipt => true,
        _ => checkpoints.projection.is_exact_final(),
    };
    if !step4_cross_state || !projection_cross_state {
        return false;
    }

    match kind {
        V031CheckpointKind::Binding => {
            (checkpoints.binding.is_exact_final() && final_receipt_count >= 3)
                || (final_receipt_count == 3
                    && no_incoming_receipt
                    && checkpoints.materials.is_absent())
        }
        V031CheckpointKind::Materials => {
            checkpoints.binding.is_exact_final()
                && ((checkpoints.materials.is_exact_final() && final_receipt_count >= 3)
                    || (final_receipt_count == 3 && no_incoming_receipt))
        }
        V031CheckpointKind::Projection => {
            checkpoints.binding.is_exact_final()
                && checkpoints.materials.is_exact_final()
                && ((checkpoints.projection.is_exact_final() && final_receipt_count >= 6)
                    || (final_receipt_count == 6 && no_incoming_receipt))
        }
    }
}

fn checkpoint_pair_state_is_legal(pair: CheckpointPairInventory) -> bool {
    matches!(
        (
            pair.identity_final,
            pair.identity_incoming,
            pair.bundle_final,
            pair.bundle_incoming,
        ),
        (false, false, false, false)
            | (false, false, false, true)
            | (false, true, false, true)
            | (true, false, false, true)
            | (true, false, true, false)
    )
}

fn checkpoint_pair_from(
    checkpoints: &v031_upgrade_r2::V031CheckpointInventory,
    kind: V031CheckpointKind,
) -> CheckpointPairInventory {
    match kind {
        V031CheckpointKind::Binding => checkpoints.binding,
        V031CheckpointKind::Materials => checkpoints.materials,
        V031CheckpointKind::Projection => checkpoints.projection,
    }
}

fn checkpoint_pair(
    lineage: &AuthenticatedLineageInventory,
    kind: V031CheckpointKind,
) -> CheckpointPairInventory {
    match kind {
        V031CheckpointKind::Binding => lineage.checkpoints.binding,
        V031CheckpointKind::Materials => lineage.checkpoints.materials,
        V031CheckpointKind::Projection => lineage.checkpoints.projection,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_checkpoint(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    gates: &CheckpointGateBinding,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<BuiltCheckpoint, V031MigrationCheckpointError> {
    let (user_proof, nested) = database::with_validated_user_database_migration_source_read_only(
        user_database_path,
        |user_session| -> Result<BuiltCheckpoint, V031MigrationCheckpointError> {
            if user_session.proof() != rollback_gate.original_user_source_proof()
                || !rollback_gate.authenticates_user_physical_file_set(user_session.proof())
            {
                return Err(V031MigrationCheckpointError::SourceValidation);
            }
            match kind {
                V031CheckpointKind::Binding | V031CheckpointKind::Materials => {
                    let (privacy_proof, built) =
                        with_validated_privacy_v1_migration_source_read_only(
                            privacy_database_path,
                            |privacy_session| {
                                if !rollback_gate.authenticates_privacy_physical_file_set(
                                    privacy_session.proof(),
                                ) {
                                    return Err(V031MigrationCheckpointError::SourceValidation);
                                }
                                let images = snapshot_v1_source_images(
                                    user_session,
                                    privacy_session,
                                    gates,
                                )?;
                                build_from_source_images(
                                    app_local_data_dir,
                                    kind,
                                    candidate,
                                    rollback_gate,
                                    approved_gate,
                                    gates,
                                    approved_workspace,
                                    images,
                                )
                            },
                        )
                        .map_err(|_| V031MigrationCheckpointError::SourceValidation)?;
                    require_original_privacy_v1(&privacy_proof, gates)?;
                    if !rollback_gate.authenticates_privacy_physical_file_set(&privacy_proof) {
                        return Err(V031MigrationCheckpointError::SourceValidation);
                    }
                    built
                }
                V031CheckpointKind::Projection => {
                    let (privacy_proof, built) =
                        with_validated_privacy_v5_migration_source_read_only(
                            privacy_database_path,
                            |privacy_session| {
                                let images =
                                    snapshot_v5_source_images(user_session, privacy_session)?;
                                build_from_source_images(
                                    app_local_data_dir,
                                    kind,
                                    candidate,
                                    rollback_gate,
                                    approved_gate,
                                    gates,
                                    approved_workspace,
                                    images,
                                )
                            },
                        )
                        .map_err(|_| V031MigrationCheckpointError::SourceValidation)?;
                    if privacy_proof.schema_version != 5 {
                        return Err(V031MigrationCheckpointError::SourceValidation);
                    }
                    built
                }
            }
        },
    )
    .map_err(|_| V031MigrationCheckpointError::SourceValidation)?;
    if &user_proof != rollback_gate.original_user_source_proof()
        || !rollback_gate.authenticates_user_physical_file_set(&user_proof)
    {
        return Err(V031MigrationCheckpointError::SourceValidation);
    }
    nested
}

fn snapshot_v1_source_images(
    user_session: &database::ValidatedUserMigrationSourceSession<'_>,
    privacy_session: &privacy::ValidatedPrivacyV1ReadOnlySession<'_>,
    gates: &CheckpointGateBinding,
) -> Result<SourceImages, V031MigrationCheckpointError> {
    require_original_privacy_v1(privacy_session.proof(), gates)?;
    let mut user_destination = Connection::open_in_memory()
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    let mut privacy_destination = Connection::open_in_memory()
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    user_session
        .backup_to(&mut user_destination)
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    privacy_session
        .backup_to(&mut privacy_destination)
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    let user = serialize_backup_as_self_contained_sqlite(&user_destination)?;
    let privacy = serialize_backup_as_self_contained_sqlite(&privacy_destination)?;
    let user_proof = user_session.proof();
    let proof = privacy_session.proof();
    Ok(SourceImages {
        user,
        user_schema_manifest_sha256: user_proof.schema_manifest_sha256.clone(),
        user_logical_manifest_sha256: user_proof.logical_database_manifest_sha256.clone(),
        user_business_manifest_sha256: user_proof.business_manifest_sha256.clone(),
        user_total_rows: user_proof.total_rows,
        privacy,
        privacy_schema_version: 1,
        privacy_logical_manifest_sha256: proof.logical_manifest.sha256.clone(),
        privacy_business_manifest_sha256: proof.business_manifest.sha256.clone(),
        privacy_total_rows: proof.logical_manifest.total_row_count,
    })
}

fn snapshot_v5_source_images(
    user_session: &database::ValidatedUserMigrationSourceSession<'_>,
    privacy_session: &privacy::ValidatedPrivacyV5ReadOnlySession<'_>,
) -> Result<SourceImages, V031MigrationCheckpointError> {
    let mut user_destination = Connection::open_in_memory()
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    let mut privacy_destination = Connection::open_in_memory()
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    user_session
        .backup_to(&mut user_destination)
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    privacy_session
        .backup_to(&mut privacy_destination)
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    let user = serialize_backup_as_self_contained_sqlite(&user_destination)?;
    let privacy = serialize_backup_as_self_contained_sqlite(&privacy_destination)?;
    let user_proof = user_session.proof();
    let proof = privacy_session.proof();
    Ok(SourceImages {
        user,
        user_schema_manifest_sha256: user_proof.schema_manifest_sha256.clone(),
        user_logical_manifest_sha256: user_proof.logical_database_manifest_sha256.clone(),
        user_business_manifest_sha256: user_proof.business_manifest_sha256.clone(),
        user_total_rows: user_proof.total_rows,
        privacy,
        privacy_schema_version: proof.schema_version,
        privacy_logical_manifest_sha256: proof.logical_manifest.sha256.clone(),
        privacy_business_manifest_sha256: proof.business_manifest.sha256.clone(),
        privacy_total_rows: proof.logical_manifest.total_row_count,
    })
}

fn serialize_backup_as_self_contained_sqlite(
    destination: &Connection,
) -> Result<Vec<u8>, V031MigrationCheckpointError> {
    let mut image = destination
        .serialize(rusqlite::MAIN_DB)
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?
        .to_vec();
    if image.len() < 100 || !image.starts_with(b"SQLite format 3\0") {
        return Err(V031MigrationCheckpointError::ComponentSnapshot);
    }
    // SQLite Backup copies every committed page, including committed WAL
    // frames, into the destination main image.  It also copies the source's
    // persistent WAL read/write version bytes (18 and 19).  A detached raw
    // image has no sidecars, so canonicalize only those two mode bytes to the
    // rollback-journal value before strict, read-only deserialization.
    match (image[18], image[19]) {
        (1, 1) => {}
        (2, 2) => {
            image[18] = 1;
            image[19] = 1;
        }
        _ => return Err(V031MigrationCheckpointError::ComponentSnapshot),
    }
    Ok(image)
}

fn require_original_privacy_v1(
    proof: &privacy::ValidatedPrivacyV1Source,
    gates: &CheckpointGateBinding,
) -> Result<(), V031MigrationCheckpointError> {
    if proof.schema_version != 1
        || proof.logical_manifest.sha256 != gates.original_privacy_logical_manifest_sha256
        || proof.business_manifest.sha256 != gates.original_privacy_business_manifest_sha256
        || proof.logical_manifest.tables.len() as u64 != gates.original_privacy_table_count
        || proof.logical_manifest.total_row_count != gates.original_privacy_total_rows
    {
        return Err(V031MigrationCheckpointError::SourceValidation);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_from_source_images(
    app_local_data_dir: &Path,
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    rollback_gate: &OriginalRollbackVerifiedGate,
    approved_gate: &V031ApprovedMcpTargetComponentsGate,
    gates: &CheckpointGateBinding,
    approved_workspace: &ApprovedMcpWorkspace,
    images: SourceImages,
) -> Result<BuiltCheckpoint, V031MigrationCheckpointError> {
    validate_source_images(&images, kind, gates)?;
    let (vault, needs_upgrade) = VaultStore::open_for_application_startup(
        app_local_data_dir.join(VAULT_DIRECTORY_NAME),
        gates.workspace_instance_id.clone(),
    )
    .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    if needs_upgrade {
        return Err(V031MigrationCheckpointError::ComponentSnapshot);
    }
    let (vault_bundle, vault_summary) = export_encrypted_vault_backup(&vault)
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    let verified_vault =
        verify_encrypted_vault_backup_archive(&vault_bundle, &gates.workspace_instance_id)
            .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    if verified_vault != vault_summary {
        return Err(V031MigrationCheckpointError::ComponentSnapshot);
    }

    let approved = approved_workspace
        .snapshot_for_v031_migration_checkpoint(rollback_gate, approved_gate)
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;
    approved_workspace
        .verify_application_backup_snapshot_bytes(
            &approved.approved_workspace_bundle,
            &approved.approved_workspace_manifest_sha256,
            &approved.work_products_bundle,
            &approved.work_products_manifest_sha256,
        )
        .map_err(|_| V031MigrationCheckpointError::ComponentSnapshot)?;

    let created_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| V031MigrationCheckpointError::InvalidInput)?
        .as_secs();
    let backup_id = format!("appbkp_{}", Uuid::new_v4().simple());
    let privacy_backup_id = format!("bkp_{}", Uuid::new_v4().simple());
    let (bundle, metadata) = seal_application_backup_v3(&ApplicationBackupCreateRequestV3 {
        backup_id: &backup_id,
        privacy_backup_id: &privacy_backup_id,
        workspace_instance_id: &gates.workspace_instance_id,
        app_version: env!("CARGO_PKG_VERSION"),
        user_schema_version: CHECKPOINT_USER_SCHEMA_VERSION,
        created_at_unix,
        expires_at_unix: CHECKPOINT_EXPIRES_AT_UNIX,
        user_database: &images.user,
        // Migration-only raw SQLite. Ordinary restore is intentionally never
        // given this identity and rejects user schema 10 before staging.
        encrypted_privacy_bundle: &images.privacy,
        encrypted_vault_bundle: &vault_bundle,
        vault_manifest_sha256: vault_summary.manifest_sha256.as_str(),
        approved_workspace_bundle: &approved.approved_workspace_bundle,
        approved_workspace_manifest_sha256: &approved.approved_workspace_manifest_sha256,
        work_products_bundle: &approved.work_products_bundle,
        work_products_manifest_sha256: &approved.work_products_manifest_sha256,
    })
    .map_err(|_| V031MigrationCheckpointError::BackupCodec)?;
    let identity =
        identity_from_metadata(kind, candidate, gates, &metadata, &images, bundle.len())?;
    Ok(BuiltCheckpoint { bundle, identity })
}

fn validate_source_images(
    images: &SourceImages,
    kind: V031CheckpointKind,
    gates: &CheckpointGateBinding,
) -> Result<(), V031MigrationCheckpointError> {
    let user = database::validate_v031_user_sqlite_image_read_only(&images.user)
        .map_err(|_| V031MigrationCheckpointError::SourceValidation)?;
    if user.schema_manifest_sha256 != gates.original_user_schema_manifest_sha256
        || user.logical_database_manifest_sha256 != gates.original_user_logical_manifest_sha256
        || user.business_manifest_sha256 != gates.original_user_business_manifest_sha256
        || user.total_rows != gates.original_user_total_rows
        || images.user_schema_manifest_sha256 != user.schema_manifest_sha256
        || images.user_logical_manifest_sha256 != user.logical_database_manifest_sha256
        || images.user_business_manifest_sha256 != user.business_manifest_sha256
        || images.user_total_rows != user.total_rows
    {
        return Err(V031MigrationCheckpointError::SourceValidation);
    }
    match kind {
        V031CheckpointKind::Binding | V031CheckpointKind::Materials => {
            let privacy = validate_privacy_v1_sqlite_image_read_only(&images.privacy)
                .map_err(|_| V031MigrationCheckpointError::SourceValidation)?;
            require_original_privacy_v1(&privacy, gates)?;
            if images.privacy_schema_version != 1
                || images.privacy_logical_manifest_sha256 != privacy.logical_manifest.sha256
                || images.privacy_business_manifest_sha256 != privacy.business_manifest.sha256
                || images.privacy_total_rows != privacy.logical_manifest.total_row_count
            {
                return Err(V031MigrationCheckpointError::SourceValidation);
            }
        }
        V031CheckpointKind::Projection => {
            let privacy = validate_privacy_v5_sqlite_image_read_only(&images.privacy)
                .map_err(|_| V031MigrationCheckpointError::SourceValidation)?;
            if images.privacy_schema_version != 5
                || images.privacy_logical_manifest_sha256 != privacy.logical_manifest.sha256
                || images.privacy_business_manifest_sha256 != privacy.business_manifest.sha256
                || images.privacy_total_rows != privacy.logical_manifest.total_row_count
            {
                return Err(V031MigrationCheckpointError::SourceValidation);
            }
        }
    }
    Ok(())
}

fn identity_from_metadata(
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    gates: &CheckpointGateBinding,
    metadata: &ApplicationBackupMetadata,
    images: &SourceImages,
    bundle_len: usize,
) -> Result<CheckpointIdentityV1, V031MigrationCheckpointError> {
    let approved_workspace_bundle_sha256 = metadata
        .approved_workspace_bundle_sha256
        .clone()
        .ok_or(V031MigrationCheckpointError::BackupCodec)?;
    let approved_workspace_manifest_sha256 = metadata
        .approved_workspace_manifest_sha256
        .clone()
        .ok_or(V031MigrationCheckpointError::BackupCodec)?;
    let work_products_bundle_sha256 = metadata
        .work_products_bundle_sha256
        .clone()
        .ok_or(V031MigrationCheckpointError::BackupCodec)?;
    let work_products_manifest_sha256 = metadata
        .work_products_manifest_sha256
        .clone()
        .ok_or(V031MigrationCheckpointError::BackupCodec)?;
    if metadata.user_database_sha256 != sha256_hex(&images.user)
        || metadata.encrypted_privacy_bundle_sha256 != sha256_hex(&images.privacy)
    {
        return Err(V031MigrationCheckpointError::BackupCodec);
    }
    let identity = CheckpointIdentityV1 {
        schema_version: CHECKPOINT_IDENTITY_SCHEMA.to_owned(),
        checkpoint_kind: kind.label().to_owned(),
        migration_id: checkpoint_migration_id(kind).to_owned(),
        lineage_id: gates.rollback.lineage_id.clone(),
        envelope_binding_id: gates.rollback.envelope_binding_id.clone(),
        source_profile_proof_sha256: gates.rollback.source_profile_proof_sha256.clone(),
        original_identity_sha256: gates.rollback.original_identity_sha256.clone(),
        original_bundle_sha256: gates.rollback.original_bundle_sha256.clone(),
        original_rollback_receipt_sha256: gates.rollback.original_rollback_receipt_sha256.clone(),
        rollback_gate_binding_sha256: gates.rollback_gate_binding_sha256.clone(),
        workspace_instance_id: gates.workspace_instance_id.as_str().to_owned(),
        approved_credential_manifest_sha256: gates.approved_credential_manifest_sha256.clone(),
        approved_workspace_schema_sha256: gates.approved_workspace_schema_sha256.clone(),
        approved_work_products_schema_sha256: gates.approved_work_products_schema_sha256.clone(),
        approved_target_workspace_manifest_sha256: gates
            .approved_target_workspace_manifest_sha256
            .clone(),
        approved_target_work_products_manifest_sha256: gates
            .approved_target_work_products_manifest_sha256
            .clone(),
        approved_target_evidence_sha256: gates.approved_target_evidence_sha256.clone(),
        approved_credential_count: gates.approved_credential_count,
        approved_business_rows: gates.approved_business_rows,
        approved_work_product_business_rows: gates.approved_work_product_business_rows,
        vault_target_evidence_sha256: gates.vault_target_evidence_sha256.clone(),
        vault_component_manifest_sha256: gates.vault_component_manifest_sha256.clone(),
        vault_schema_sha256: gates.vault_schema_sha256.clone(),
        vault_database_sha256: gates.vault_database_sha256.clone(),
        vault_layout_sha256: gates.vault_layout_sha256.clone(),
        vault_schema_version: gates.vault_schema_version,
        vault_schema_objects: gates.vault_schema_objects,
        vault_metadata_rows: gates.vault_metadata_rows,
        vault_business_rows: gates.vault_business_rows,
        vault_key_record_count: gates.vault_key_record_count,
        vault_object_root_entry_count: gates.vault_object_root_entry_count,
        vault_directory_count: gates.vault_directory_count,
        vault_file_count: gates.vault_file_count,
        original_user_physical_file_set_sha256: gates
            .original_user_physical_file_set_sha256
            .clone(),
        original_privacy_physical_file_set_sha256: gates
            .original_privacy_physical_file_set_sha256
            .clone(),
        identity_basename: kind.identity_final_basename().to_owned(),
        bundle_basename: kind.bundle_final_basename().to_owned(),
        backup_id: metadata.backup_id.clone(),
        privacy_backup_id: metadata.privacy_backup_id.clone(),
        app_version: metadata.app_version.clone(),
        user_schema_version: metadata.user_schema_version,
        privacy_schema_version: images.privacy_schema_version,
        privacy_slot_encoding: RAW_PRIVACY_SLOT_ENCODING.to_owned(),
        created_at_unix: metadata.created_at_unix,
        expires_at_unix: metadata.expires_at_unix,
        bundle_bytes: u64::try_from(bundle_len)
            .map_err(|_| V031MigrationCheckpointError::BackupCodec)?,
        bundle_sha256: metadata.bundle_sha256.clone(),
        user_database_sha256: metadata.user_database_sha256.clone(),
        user_schema_manifest_sha256: images.user_schema_manifest_sha256.clone(),
        user_logical_manifest_sha256: images.user_logical_manifest_sha256.clone(),
        user_business_manifest_sha256: images.user_business_manifest_sha256.clone(),
        user_total_rows: images.user_total_rows,
        privacy_database_sha256: metadata.encrypted_privacy_bundle_sha256.clone(),
        privacy_logical_manifest_sha256: images.privacy_logical_manifest_sha256.clone(),
        privacy_business_manifest_sha256: images.privacy_business_manifest_sha256.clone(),
        privacy_total_rows: images.privacy_total_rows,
        vault_bundle_sha256: metadata.encrypted_vault_bundle_sha256.clone(),
        vault_manifest_sha256: metadata.vault_manifest_sha256.clone(),
        approved_workspace_bundle_sha256,
        approved_workspace_manifest_sha256,
        work_products_bundle_sha256,
        work_products_manifest_sha256,
        source_fingerprint: candidate.source_fingerprint.clone(),
        candidate_manifest_sha256: candidate.candidate_manifest_sha256.clone(),
        candidate_count: candidate.candidate_count,
    };
    validate_identity(&identity, kind, candidate, gates)?;
    Ok(identity)
}

fn reconstruct_identity_from_bundle(
    bundle: &[u8],
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    gates: &CheckpointGateBinding,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<CheckpointIdentityV1, V031MigrationCheckpointError> {
    let opened = open_checkpoint_bundle_from_probe(bundle, gates)?;
    let images = source_images_from_opened(&opened, kind, gates)?;
    verify_opened_components(&opened, &images, gates, approved_workspace)?;
    identity_from_metadata(
        kind,
        candidate,
        gates,
        &opened.metadata,
        &images,
        bundle.len(),
    )
}

fn verify_opened_checkpoint(
    bundle: &[u8],
    identity: &CheckpointIdentityV1,
    gates: &CheckpointGateBinding,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<OpenedApplicationBackup, V031MigrationCheckpointError> {
    let opened = open_application_backup_for_migration_recovery(
        bundle,
        &MigrationApplicationBackupOpenContext {
            expected_workspace_instance_id: &gates.workspace_instance_id,
            expected_user_schema_version: CHECKPOINT_USER_SCHEMA_VERSION,
            expected_backup_id: &identity.backup_id,
            expected_privacy_backup_id: &identity.privacy_backup_id,
            expected_app_version: &identity.app_version,
            expected_created_at_unix: identity.created_at_unix,
            expected_expires_at_unix: identity.expires_at_unix,
            expected_bundle_sha256: &identity.bundle_sha256,
        },
    )
    .map_err(|_| V031MigrationCheckpointError::Tampered)?;
    let kind = parse_checkpoint_kind(&identity.checkpoint_kind)?;
    let images = source_images_from_opened(&opened, kind, gates)?;
    verify_opened_components(&opened, &images, gates, approved_workspace)?;
    let reconstructed = identity_from_metadata(
        kind,
        &V031CheckpointCandidateEvidence {
            source_fingerprint: identity.source_fingerprint.clone(),
            candidate_manifest_sha256: identity.candidate_manifest_sha256.clone(),
            candidate_count: identity.candidate_count,
        },
        gates,
        &opened.metadata,
        &images,
        bundle.len(),
    )?;
    if &reconstructed != identity {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    Ok(opened)
}

fn source_images_from_opened(
    opened: &OpenedApplicationBackup,
    kind: V031CheckpointKind,
    gates: &CheckpointGateBinding,
) -> Result<SourceImages, V031MigrationCheckpointError> {
    let user_proof = database::validate_v031_user_sqlite_image_read_only(&opened.user_database)
        .map_err(|_| V031MigrationCheckpointError::Tampered)?;
    let (privacy_schema_version, logical, business, rows) = match kind {
        V031CheckpointKind::Binding | V031CheckpointKind::Materials => {
            let proof =
                validate_privacy_v1_sqlite_image_read_only(&opened.encrypted_privacy_bundle)
                    .map_err(|_| V031MigrationCheckpointError::Tampered)?;
            require_original_privacy_v1(&proof, gates)?;
            (
                1,
                proof.logical_manifest.sha256,
                proof.business_manifest.sha256,
                proof.logical_manifest.total_row_count,
            )
        }
        V031CheckpointKind::Projection => {
            let proof =
                validate_privacy_v5_sqlite_image_read_only(&opened.encrypted_privacy_bundle)
                    .map_err(|_| V031MigrationCheckpointError::Tampered)?;
            (
                proof.schema_version,
                proof.logical_manifest.sha256,
                proof.business_manifest.sha256,
                proof.logical_manifest.total_row_count,
            )
        }
    };
    let images = SourceImages {
        user: opened.user_database.clone(),
        user_schema_manifest_sha256: user_proof.schema_manifest_sha256,
        user_logical_manifest_sha256: user_proof.logical_database_manifest_sha256,
        user_business_manifest_sha256: user_proof.business_manifest_sha256,
        user_total_rows: user_proof.total_rows,
        privacy: opened.encrypted_privacy_bundle.clone(),
        privacy_schema_version,
        privacy_logical_manifest_sha256: logical,
        privacy_business_manifest_sha256: business,
        privacy_total_rows: rows,
    };
    validate_source_images(&images, kind, gates)?;
    Ok(images)
}

fn verify_opened_components(
    opened: &OpenedApplicationBackup,
    images: &SourceImages,
    gates: &CheckpointGateBinding,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(), V031MigrationCheckpointError> {
    if opened.metadata.user_schema_version != CHECKPOINT_USER_SCHEMA_VERSION
        || opened.metadata.user_database_sha256 != sha256_hex(&images.user)
        || opened.metadata.encrypted_privacy_bundle_sha256 != sha256_hex(&images.privacy)
    {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    let vault = verify_encrypted_vault_backup_archive(
        &opened.encrypted_vault_bundle,
        &gates.workspace_instance_id,
    )
    .map_err(|_| V031MigrationCheckpointError::Tampered)?;
    if vault.manifest_sha256.as_str() != opened.metadata.vault_manifest_sha256
        || vault.archive_sha256.as_str() != opened.metadata.encrypted_vault_bundle_sha256
    {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    let approved_bundle = opened
        .approved_workspace_bundle
        .as_deref()
        .ok_or(V031MigrationCheckpointError::Tampered)?;
    let work_products_bundle = opened
        .work_products_bundle
        .as_deref()
        .ok_or(V031MigrationCheckpointError::Tampered)?;
    let approved_manifest = opened
        .metadata
        .approved_workspace_manifest_sha256
        .as_deref()
        .ok_or(V031MigrationCheckpointError::Tampered)?;
    let work_products_manifest = opened
        .metadata
        .work_products_manifest_sha256
        .as_deref()
        .ok_or(V031MigrationCheckpointError::Tampered)?;
    approved_workspace
        .verify_application_backup_snapshot_bytes(
            approved_bundle,
            approved_manifest,
            work_products_bundle,
            work_products_manifest,
        )
        .map_err(|_| V031MigrationCheckpointError::Tampered)
}

fn open_checkpoint_bundle_from_probe(
    bundle: &[u8],
    gates: &CheckpointGateBinding,
) -> Result<OpenedApplicationBackup, V031MigrationCheckpointError> {
    if bundle.is_empty() || bundle.len() > MAX_APPLICATION_BACKUP_BYTES {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bundle).map_err(|_| V031MigrationCheckpointError::Tampered)?;
    let object = value
        .as_object()
        .ok_or(V031MigrationCheckpointError::Tampered)?;
    let text = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(V031MigrationCheckpointError::Tampered)
    };
    let number = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or(V031MigrationCheckpointError::Tampered)
    };
    let backup_id = text("backupId")?;
    let privacy_backup_id = text("privacyBackupId")?;
    let app_version = text("appVersion")?;
    let user_schema_version = object
        .get("userSchemaVersion")
        .and_then(serde_json::Value::as_i64)
        .ok_or(V031MigrationCheckpointError::Tampered)?;
    let created_at_unix = number("createdAtUnix")?;
    let expires_at_unix = number("expiresAtUnix")?;
    if app_version != env!("CARGO_PKG_VERSION")
        || user_schema_version != CHECKPOINT_USER_SCHEMA_VERSION
        || created_at_unix == 0
        || created_at_unix >= expires_at_unix
        || expires_at_unix != CHECKPOINT_EXPIRES_AT_UNIX
    {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    let bundle_sha256 = sha256_hex(bundle);
    open_application_backup_for_migration_recovery(
        bundle,
        &MigrationApplicationBackupOpenContext {
            expected_workspace_instance_id: &gates.workspace_instance_id,
            expected_user_schema_version: CHECKPOINT_USER_SCHEMA_VERSION,
            expected_backup_id: &backup_id,
            expected_privacy_backup_id: &privacy_backup_id,
            expected_app_version: &app_version,
            expected_created_at_unix: created_at_unix,
            expected_expires_at_unix: expires_at_unix,
            expected_bundle_sha256: &bundle_sha256,
        },
    )
    .map_err(|_| V031MigrationCheckpointError::Tampered)
}

fn validate_identity(
    identity: &CheckpointIdentityV1,
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    gates: &CheckpointGateBinding,
) -> Result<(), V031MigrationCheckpointError> {
    let hashes = [
        identity.source_profile_proof_sha256.as_str(),
        identity.original_identity_sha256.as_str(),
        identity.original_bundle_sha256.as_str(),
        identity.original_rollback_receipt_sha256.as_str(),
        identity.rollback_gate_binding_sha256.as_str(),
        identity.approved_credential_manifest_sha256.as_str(),
        identity.approved_workspace_schema_sha256.as_str(),
        identity.approved_work_products_schema_sha256.as_str(),
        identity.approved_target_workspace_manifest_sha256.as_str(),
        identity
            .approved_target_work_products_manifest_sha256
            .as_str(),
        identity.approved_target_evidence_sha256.as_str(),
        identity.vault_target_evidence_sha256.as_str(),
        identity.vault_component_manifest_sha256.as_str(),
        identity.vault_schema_sha256.as_str(),
        identity.vault_database_sha256.as_str(),
        identity.vault_layout_sha256.as_str(),
        identity.original_user_physical_file_set_sha256.as_str(),
        identity.original_privacy_physical_file_set_sha256.as_str(),
        identity.bundle_sha256.as_str(),
        identity.user_database_sha256.as_str(),
        identity.user_schema_manifest_sha256.as_str(),
        identity.user_logical_manifest_sha256.as_str(),
        identity.user_business_manifest_sha256.as_str(),
        identity.privacy_database_sha256.as_str(),
        identity.privacy_logical_manifest_sha256.as_str(),
        identity.privacy_business_manifest_sha256.as_str(),
        identity.vault_bundle_sha256.as_str(),
        identity.vault_manifest_sha256.as_str(),
        identity.approved_workspace_bundle_sha256.as_str(),
        identity.approved_workspace_manifest_sha256.as_str(),
        identity.work_products_bundle_sha256.as_str(),
        identity.work_products_manifest_sha256.as_str(),
        identity.source_fingerprint.as_str(),
        identity.candidate_manifest_sha256.as_str(),
    ];
    if identity.schema_version != CHECKPOINT_IDENTITY_SCHEMA
        || identity.checkpoint_kind != kind.label()
        || identity.migration_id != checkpoint_migration_id(kind)
        || identity.lineage_id != gates.rollback.lineage_id
        || identity.envelope_binding_id != gates.rollback.envelope_binding_id
        || identity.source_profile_proof_sha256 != gates.rollback.source_profile_proof_sha256
        || identity.original_identity_sha256 != gates.rollback.original_identity_sha256
        || identity.original_bundle_sha256 != gates.rollback.original_bundle_sha256
        || identity.original_rollback_receipt_sha256
            != gates.rollback.original_rollback_receipt_sha256
        || identity.rollback_gate_binding_sha256 != gates.rollback_gate_binding_sha256
        || identity.workspace_instance_id != gates.workspace_instance_id.as_str()
        || identity.approved_credential_manifest_sha256 != gates.approved_credential_manifest_sha256
        || identity.approved_workspace_schema_sha256 != gates.approved_workspace_schema_sha256
        || identity.approved_work_products_schema_sha256
            != gates.approved_work_products_schema_sha256
        || identity.approved_target_workspace_manifest_sha256
            != gates.approved_target_workspace_manifest_sha256
        || identity.approved_target_work_products_manifest_sha256
            != gates.approved_target_work_products_manifest_sha256
        || identity.approved_target_evidence_sha256 != gates.approved_target_evidence_sha256
        || identity.approved_credential_count != gates.approved_credential_count
        || identity.approved_business_rows != gates.approved_business_rows
        || identity.approved_work_product_business_rows != gates.approved_work_product_business_rows
        || identity.vault_target_evidence_sha256 != gates.vault_target_evidence_sha256
        || identity.vault_component_manifest_sha256 != gates.vault_component_manifest_sha256
        || identity.vault_schema_sha256 != gates.vault_schema_sha256
        || identity.vault_database_sha256 != gates.vault_database_sha256
        || identity.vault_layout_sha256 != gates.vault_layout_sha256
        || identity.vault_schema_version != gates.vault_schema_version
        || identity.vault_schema_objects != gates.vault_schema_objects
        || identity.vault_metadata_rows != gates.vault_metadata_rows
        || identity.vault_business_rows != gates.vault_business_rows
        || identity.vault_key_record_count != gates.vault_key_record_count
        || identity.vault_object_root_entry_count != gates.vault_object_root_entry_count
        || identity.vault_directory_count != gates.vault_directory_count
        || identity.vault_file_count != gates.vault_file_count
        || identity.original_user_physical_file_set_sha256
            != gates.original_user_physical_file_set_sha256
        || identity.original_privacy_physical_file_set_sha256
            != gates.original_privacy_physical_file_set_sha256
        || identity.identity_basename != kind.identity_final_basename()
        || identity.bundle_basename != kind.bundle_final_basename()
        || !identity.backup_id.starts_with("appbkp_")
        || !identity.privacy_backup_id.starts_with("bkp_")
        || identity.app_version != env!("CARGO_PKG_VERSION")
        || identity.user_schema_version != CHECKPOINT_USER_SCHEMA_VERSION
        || identity.privacy_schema_version != checkpoint_privacy_schema(kind)
        || identity.privacy_slot_encoding != RAW_PRIVACY_SLOT_ENCODING
        || identity.created_at_unix == 0
        || identity.created_at_unix >= identity.expires_at_unix
        || identity.expires_at_unix != CHECKPOINT_EXPIRES_AT_UNIX
        || identity.bundle_bytes == 0
        || identity.bundle_bytes > MAX_APPLICATION_BACKUP_BYTES as u64
        || identity.user_schema_manifest_sha256 != gates.original_user_schema_manifest_sha256
        || identity.user_logical_manifest_sha256 != gates.original_user_logical_manifest_sha256
        || identity.user_business_manifest_sha256 != gates.original_user_business_manifest_sha256
        || identity.user_total_rows != gates.original_user_total_rows
        || identity.source_fingerprint != candidate.source_fingerprint
        || identity.candidate_manifest_sha256 != candidate.candidate_manifest_sha256
        || identity.candidate_count != candidate.candidate_count
        || hashes.iter().any(|hash| !is_hash(hash))
    {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    Ok(())
}

fn read_checkpoint_identity(
    path: &Path,
) -> Result<CheckpointIdentityV1, V031MigrationCheckpointError> {
    let protected = v031_upgrade_r2::read_bounded_file(path, MAX_CHECKPOINT_IDENTITY_FILE_BYTES)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let mut plaintext = unprotect_local(&protected)
        .map_err(|_| V031MigrationCheckpointError::IdentityProtection)?;
    let identity = strict_json_v1_from_slice::<CheckpointIdentityV1>(&plaintext)
        .map_err(|_| V031MigrationCheckpointError::Tampered)
        .and_then(|identity| {
            let canonical =
                canonical_json_v1(&identity).map_err(|_| V031MigrationCheckpointError::Tampered)?;
            if canonical != plaintext {
                return Err(V031MigrationCheckpointError::Tampered);
            }
            Ok(identity)
        });
    plaintext.zeroize();
    identity
}

fn verify_checkpoint_pair(
    app_local_data_dir: &Path,
    kind: V031CheckpointKind,
    candidate: &V031CheckpointCandidateEvidence,
    gates: &CheckpointGateBinding,
    approved_workspace: &ApprovedMcpWorkspace,
    created: bool,
) -> Result<V031MigrationCheckpointProof, V031MigrationCheckpointError> {
    let directory = v031_upgrade_r2::canonical_lineage_directory(
        app_local_data_dir,
        &gates.rollback.lineage_id,
    )
    .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity_path = directory.join(kind.identity_final_basename());
    let bundle_path = directory.join(kind.bundle_final_basename());
    v031_upgrade_r2::verify_plain_single_link_file(&identity_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    v031_upgrade_r2::verify_plain_single_link_file(&bundle_path)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let protected_identity =
        v031_upgrade_r2::read_bounded_file(&identity_path, MAX_CHECKPOINT_IDENTITY_FILE_BYTES)
            .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    let identity = read_checkpoint_identity(&identity_path)?;
    validate_identity(&identity, kind, candidate, gates)?;
    let bundle = v031_upgrade_r2::read_bounded_file(&bundle_path, MAX_APPLICATION_BACKUP_BYTES)
        .map_err(|_| V031MigrationCheckpointError::UnsafeFilesystem)?;
    if identity.bundle_bytes != bundle.len() as u64 || identity.bundle_sha256 != sha256_hex(&bundle)
    {
        return Err(V031MigrationCheckpointError::Tampered);
    }
    verify_opened_checkpoint(&bundle, &identity, gates, approved_workspace)?;
    Ok(V031MigrationCheckpointProof {
        kind,
        lineage_id: identity.lineage_id.clone(),
        original_identity_sha256: identity.original_identity_sha256.clone(),
        workspace_instance_id: identity.workspace_instance_id.clone(),
        identity_protected_sha256: sha256_hex(&protected_identity),
        bundle_sha256: identity.bundle_sha256.clone(),
        user_database_sha256: identity.user_database_sha256.clone(),
        user_schema_manifest_sha256: identity.user_schema_manifest_sha256.clone(),
        user_logical_manifest_sha256: identity.user_logical_manifest_sha256.clone(),
        user_business_manifest_sha256: identity.user_business_manifest_sha256.clone(),
        user_total_rows: identity.user_total_rows,
        privacy_database_sha256: identity.privacy_database_sha256.clone(),
        privacy_schema_version: identity.privacy_schema_version,
        privacy_logical_manifest_sha256: identity.privacy_logical_manifest_sha256.clone(),
        privacy_business_manifest_sha256: identity.privacy_business_manifest_sha256.clone(),
        privacy_total_rows: identity.privacy_total_rows,
        vault_bundle_sha256: identity.vault_bundle_sha256.clone(),
        approved_workspace_bundle_sha256: identity.approved_workspace_bundle_sha256.clone(),
        work_products_bundle_sha256: identity.work_products_bundle_sha256.clone(),
        source_fingerprint: identity.source_fingerprint.clone(),
        candidate_manifest_sha256: identity.candidate_manifest_sha256.clone(),
        candidate_count: identity.candidate_count,
        created,
    })
}

fn checkpoint_migration_id(kind: V031CheckpointKind) -> &'static str {
    match kind {
        V031CheckpointKind::Binding => "project-privacy-case-binding-v1",
        V031CheckpointKind::Materials => "case-material-unification-v1",
        V031CheckpointKind::Projection => "approved-case-projection-v1",
    }
}

const fn checkpoint_privacy_schema(kind: V031CheckpointKind) -> i64 {
    match kind {
        V031CheckpointKind::Binding | V031CheckpointKind::Materials => 1,
        V031CheckpointKind::Projection => 5,
    }
}

fn parse_checkpoint_kind(value: &str) -> Result<V031CheckpointKind, V031MigrationCheckpointError> {
    V031CheckpointKind::ALL
        .into_iter()
        .find(|kind| kind.label() == value)
        .ok_or(V031MigrationCheckpointError::Tampered)
}

fn validate_candidate(
    candidate: &V031CheckpointCandidateEvidence,
) -> Result<(), V031MigrationCheckpointError> {
    if !is_hash(&candidate.source_fingerprint) || !is_hash(&candidate.candidate_manifest_sha256) {
        return Err(V031MigrationCheckpointError::InvalidInput);
    }
    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), V031MigrationCheckpointError> {
    if !path.is_absolute() {
        return Err(V031MigrationCheckpointError::InvalidInput);
    }
    Ok(())
}

fn validate_checkpoint_source_paths(
    app_local_data_dir: &Path,
    user_database_path: &Path,
    privacy_database_path: &Path,
) -> Result<(), V031MigrationCheckpointError> {
    validate_absolute_path(app_local_data_dir)?;
    let expected_user = database::user_database_path(app_local_data_dir);
    let expected_privacy = app_local_data_dir
        .join("privacy")
        .join("privacy-workflow.sqlite");
    // Deliberately compare the lexical fixed paths. A spelling containing
    // `.`/`..`, an alias, or another same-content file is not canonical and
    // must not be normalized into acceptance.
    if user_database_path != expected_user || privacy_database_path != expected_privacy {
        return Err(V031MigrationCheckpointError::InvalidInput);
    }
    Ok(())
}

fn is_hash(value: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approved_mcp::ApplicationBackupTestHarness;
    use privacy::{open_application_backup, ApplicationBackupError, ApplicationBackupOpenContext};
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::PathBuf,
    };

    #[derive(Deserialize)]
    struct FrozenUserSchemaObject {
        object_type: String,
        sql: String,
    }

    struct FixtureTargetVerifier<'a> {
        workspace: &'a ApprovedMcpWorkspace,
    }

    impl CheckpointTargetGateVerifier for FixtureTargetVerifier<'_> {
        fn verify(
            &self,
            app_local_data_dir: &Path,
            rollback_gate: &OriginalRollbackVerifiedGate,
            approved_gate: &V031ApprovedMcpTargetComponentsGate,
            vault_gate: &V031VaultTargetComponentGate,
        ) -> Result<(), V031MigrationCheckpointError> {
            self.workspace
                .verify_v031_target_components_for_checkpoint_test(rollback_gate, approved_gate)
                .map_err(|_| V031MigrationCheckpointError::GateMismatch)?;
            verify_v031_vault_target_component_read_only(
                app_local_data_dir,
                rollback_gate,
                approved_gate,
                vault_gate,
            )
            .map_err(|_| V031MigrationCheckpointError::GateMismatch)
        }
    }

    struct FixtureReceiptBridge<'a> {
        rollback_gate: &'a OriginalRollbackVerifiedGate,
    }

    impl v031_upgrade_r2::ReceiptAuthenticationBridge for FixtureReceiptBridge<'_> {
        type Error = ();

        fn authenticate_protected_receipt(
            &self,
            _protected_file_bytes: &[u8],
            expectation: v031_upgrade_r2::ReceiptExpectation<'_>,
        ) -> Result<v031_upgrade_r2::AuthenticatedReceiptMetadata, Self::Error> {
            Ok(v031_upgrade_r2::AuthenticatedReceiptMetadata {
                schema_version: v031_upgrade_r2::V031_RECEIPT_SCHEMA.to_owned(),
                migration_id: v031_upgrade_r2::V031_MIGRATION_ID.to_owned(),
                lineage_id: expectation.lineage_id.to_owned(),
                envelope_binding_id: self.rollback_gate.envelope_binding_id().to_owned(),
                ordinal: expectation.descriptor.ordinal,
                stage: expectation.descriptor.stage.to_owned(),
                previous_receipt_sha256: expectation.previous_receipt_sha256.map(str::to_owned),
                source_profile_proof_sha256: self
                    .rollback_gate
                    .source_profile_proof_sha256()
                    .to_owned(),
                evidence_schema_version: "checkpoint-production-fixture-v1".to_owned(),
                evidence_sha256: sha256_hex(expectation.descriptor.stage.as_bytes()),
                counts: BTreeMap::from([("items".to_owned(), 1)]),
                created_at_unix: 1_784_476_800,
                result_code: "ok".to_owned(),
            })
        }
    }

    fn create_exact_v031_user_source(root: &Path) -> PathBuf {
        let path = database::user_database_path(root);
        let connection = Connection::open(&path).expect("exact user fixture opens");
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
        path
    }

    fn create_exact_privacy_v1_source(root: &Path) -> PathBuf {
        let privacy_root = root.join("privacy");
        fs::create_dir(&privacy_root).expect("Privacy source directory creates");
        let path = privacy_root.join("privacy-workflow.sqlite");
        let connection = Connection::open(&path).expect("exact Privacy fixture opens");
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
        path
    }

    fn fixture_file_tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn visit(base: &Path, current: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
            for entry in fs::read_dir(current).expect("fixture tree enumerates") {
                let entry = entry.expect("fixture tree entry");
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("fixture tree metadata");
                if metadata.is_dir() {
                    visit(base, &path, files);
                } else if metadata.is_file() {
                    let relative = path
                        .strip_prefix(base)
                        .expect("fixture file remains below root")
                        .to_string_lossy()
                        .replace('\\', "/");
                    files.insert(relative, fs::read(path).expect("fixture file reads"));
                }
            }
        }

        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    fn fixture_file_tree_observation(root: &Path) -> BTreeMap<String, (u64, SystemTime, String)> {
        fn visit(
            base: &Path,
            current: &Path,
            files: &mut BTreeMap<String, (u64, SystemTime, String)>,
        ) {
            for entry in fs::read_dir(current).expect("fixture observation tree enumerates") {
                let entry = entry.expect("fixture observation tree entry");
                let path = entry.path();
                let metadata =
                    fs::symlink_metadata(&path).expect("fixture observation metadata reads");
                if metadata.is_dir() {
                    visit(base, &path, files);
                } else if metadata.is_file() {
                    let relative = path
                        .strip_prefix(base)
                        .expect("fixture observation remains below root")
                        .to_string_lossy()
                        .replace('\\', "/");
                    let bytes = fs::read(&path).expect("fixture observation file reads");
                    files.insert(
                        relative,
                        (
                            metadata.len(),
                            metadata.modified().expect("fixture modified time reads"),
                            sha256_hex(&bytes),
                        ),
                    );
                }
            }
        }

        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ExactFixtureTreeEntry {
        Directory {
            modified: SystemTime,
        },
        File {
            modified: SystemTime,
            bytes: Vec<u8>,
        },
    }

    fn exact_fixture_tree_observation(root: &Path) -> BTreeMap<String, ExactFixtureTreeEntry> {
        fn visit(
            root: &Path,
            directory: &Path,
            entries: &mut BTreeMap<String, ExactFixtureTreeEntry>,
        ) {
            let mut children = fs::read_dir(directory)
                .expect("exact fixture tree enumerates")
                .collect::<Result<Vec<_>, _>>()
                .expect("exact fixture tree entries enumerate");
            children.sort_by_key(|entry| entry.file_name());
            for child in children {
                let path = child.path();
                let metadata =
                    fs::symlink_metadata(&path).expect("exact fixture tree metadata reads");
                let relative = path
                    .strip_prefix(root)
                    .expect("exact fixture entry remains below root")
                    .to_string_lossy()
                    .replace('\\', "/");
                let modified = metadata
                    .modified()
                    .expect("exact fixture entry modified time reads");
                let observation = if metadata.is_dir() {
                    ExactFixtureTreeEntry::Directory { modified }
                } else if metadata.is_file() {
                    ExactFixtureTreeEntry::File {
                        modified,
                        bytes: fs::read(&path).expect("exact fixture file reads"),
                    }
                } else {
                    panic!("exact fixture entry must be a plain file or directory")
                };
                assert!(
                    entries.insert(relative, observation).is_none(),
                    "exact fixture paths are unique"
                );
                if metadata.is_dir() {
                    visit(root, &path, entries);
                }
            }
        }

        let root_metadata = fs::symlink_metadata(root).expect("exact fixture root metadata reads");
        let mut entries = BTreeMap::from([(
            ".".to_owned(),
            ExactFixtureTreeEntry::Directory {
                modified: root_metadata
                    .modified()
                    .expect("exact fixture root modified time reads"),
            },
        )]);
        visit(root, root, &mut entries);
        entries
    }

    fn sqlite_file_set_observation(
        database_path: &Path,
    ) -> BTreeMap<String, (u64, SystemTime, String)> {
        let mut files = BTreeMap::new();
        let database_name = database_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture database basename is Unicode");
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let path = database_path.with_file_name(format!("{database_name}{suffix}"));
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    let bytes = fs::read(&path).expect("fixture SQLite file reads");
                    files.insert(
                        suffix.to_owned(),
                        (
                            metadata.len(),
                            metadata.modified().expect("SQLite modified time reads"),
                            sha256_hex(&bytes),
                        ),
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => panic!("fixture SQLite file-set contains a non-plain file"),
                Err(error) => panic!("fixture SQLite file-set cannot be observed: {error}"),
            }
        }
        files
    }

    fn fixture_direct_child_basenames(root: &Path) -> BTreeSet<String> {
        fs::read_dir(root)
            .expect("fixture root enumerates")
            .map(|entry| {
                entry
                    .expect("fixture root entry")
                    .file_name()
                    .into_string()
                    .expect("fixture root basename is Unicode")
            })
            .collect()
    }

    fn write_checkpoint_receipt_prefix(
        root: &Path,
        rollback_gate: &OriginalRollbackVerifiedGate,
        final_count: usize,
    ) {
        let lineage =
            v031_upgrade_r2::canonical_lineage_directory(root, rollback_gate.lineage_id())
                .expect("lineage path");
        fs::create_dir_all(&lineage).expect("lineage creates");
        for (basename, bytes) in [
            (
                v031_upgrade_r2::V2_IDENTITY_FINAL,
                b"authenticated-test-v2-identity".as_slice(),
            ),
            (
                v031_upgrade_r2::V2_BUNDLE_FINAL,
                b"authenticated-test-v2-bundle".as_slice(),
            ),
        ] {
            let path = lineage.join(basename);
            if !path.exists() {
                fs::write(path, bytes).expect("V2 fixture evidence creates");
            }
        }
        for descriptor in v031_upgrade_r2::V031_RECEIPTS.iter().take(final_count) {
            let path = lineage.join(descriptor.final_basename);
            if !path.exists() {
                fs::write(path, format!("protected-receipt-{}", descriptor.ordinal))
                    .expect("receipt prefix creates");
            }
        }
    }

    fn setup_checkpoint_receipt_prefix(root: &Path, rollback_gate: &OriginalRollbackVerifiedGate) {
        write_checkpoint_receipt_prefix(root, rollback_gate, 3);
    }

    fn authenticate_checkpoint_fixture_lineage(
        root: &Path,
        rollback_gate: &OriginalRollbackVerifiedGate,
    ) -> AuthenticatedLineageInventory {
        v031_upgrade_r2::enumerate_and_authenticate_lineage(
            root,
            rollback_gate.lineage_id(),
            &FixtureReceiptBridge { rollback_gate },
        )
        .expect("checkpoint fixture lineage authenticates")
    }

    struct RealCheckpointCrashFixture {
        directory: tempfile::TempDir,
        user_path: PathBuf,
        privacy_path: PathBuf,
        rollback_gate: OriginalRollbackVerifiedGate,
        approved_harness: ApplicationBackupTestHarness,
        approved_gate: V031ApprovedMcpTargetComponentsGate,
        vault_gate: V031VaultTargetComponentGate,
        candidate: V031CheckpointCandidateEvidence,
    }

    impl RealCheckpointCrashFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("real checkpoint crash fixture");
            let root = directory.path();
            let user_path = create_exact_v031_user_source(root);
            let privacy_path = create_exact_privacy_v1_source(root);
            let (user_proof, ()) =
                database::with_validated_user_database_migration_source_read_only(
                    &user_path,
                    |_| (),
                )
                .expect("exact user source validates");
            let privacy_proof =
                privacy::validate_privacy_v1_migration_source_read_only(&privacy_path)
                    .expect("exact Privacy source validates");
            let rollback_gate = OriginalRollbackVerifiedGate::from_user_source_for_test(user_proof)
                .with_privacy_source_for_checkpoint_test(privacy_proof);
            let approved_harness = ApplicationBackupTestHarness::new(root.to_path_buf());
            let approved_gate = approved_harness
                .workspace
                .prepare_v031_target_components_for_checkpoint_test(&rollback_gate)
                .expect("exact empty Approved target prepares");
            let vault_gate = crate::privacy_workflow::prepare_v031_vault_target_component(
                root,
                &rollback_gate,
                &approved_gate,
            )
            .expect("exact empty Vault target prepares");
            setup_checkpoint_receipt_prefix(root, &rollback_gate);
            Self {
                directory,
                user_path,
                privacy_path,
                rollback_gate,
                approved_harness,
                approved_gate,
                vault_gate,
                candidate: candidate(),
            }
        }

        fn root(&self) -> &Path {
            self.directory.path()
        }

        fn verifier(&self) -> FixtureTargetVerifier<'_> {
            FixtureTargetVerifier {
                workspace: &self.approved_harness.workspace,
            }
        }

        fn inventory(&self) -> AuthenticatedLineageInventory {
            authenticate_checkpoint_fixture_lineage(self.root(), &self.rollback_gate)
        }

        fn ensure(&self, kind: V031CheckpointKind) -> V031MigrationCheckpointProof {
            ensure_v031_migration_checkpoint_with_verifier(
                self.root(),
                &self.user_path,
                &self.privacy_path,
                kind,
                &self.candidate,
                &self.rollback_gate,
                &self.approved_gate,
                &self.vault_gate,
                &self.inventory(),
                &self.approved_harness.workspace,
                &self.verifier(),
            )
            .expect("real checkpoint precursor ensures")
        }

        fn prepare_for(&self, kind: V031CheckpointKind) {
            match kind {
                V031CheckpointKind::Binding => {}
                V031CheckpointKind::Materials => {
                    self.ensure(V031CheckpointKind::Binding);
                }
                V031CheckpointKind::Projection => {
                    self.ensure(V031CheckpointKind::Binding);
                    self.ensure(V031CheckpointKind::Materials);
                    write_checkpoint_receipt_prefix(self.root(), &self.rollback_gate, 6);
                    let mut privacy =
                        Connection::open(&self.privacy_path).expect("Privacy v1 fixture reopens");
                    privacy::PrivacyStore::upgrade_exact_v031_schema_to_v5_after_backup(&privacy)
                        .expect("Privacy fixture advances to strict v5");
                    privacy::PrivacyLifecycle::initialize(
                        &mut privacy,
                        self.approved_gate.workspace_instance_id().clone(),
                        1_784_476_800,
                    )
                    .expect("Privacy lifecycle v5 initializes");
                    privacy::ProjectPrivacyCaseBindingStore::initialize(&mut privacy)
                        .expect("project-case binding v5 initializes");
                    drop(privacy);
                    with_validated_privacy_v5_migration_source_read_only(
                        &self.privacy_path,
                        |_| (),
                    )
                    .expect("strict Privacy v5 source validates");
                }
            }
        }

        fn build(&self, kind: V031CheckpointKind) -> BuiltCheckpoint {
            let gates = CheckpointGateBinding::from_gates(
                &self.rollback_gate,
                &self.approved_gate,
                &self.vault_gate,
            )
            .expect("real checkpoint gates bind");
            build_checkpoint(
                self.root(),
                &self.user_path,
                &self.privacy_path,
                kind,
                &self.candidate,
                &self.rollback_gate,
                &self.approved_gate,
                &gates,
                &self.approved_harness.workspace,
            )
            .expect("real checkpoint crash bytes build")
        }

        fn immutable_component_observation(
            &self,
        ) -> [BTreeMap<String, (u64, SystemTime, String)>; 4] {
            [
                sqlite_file_set_observation(&self.user_path),
                sqlite_file_set_observation(&self.privacy_path),
                fixture_file_tree_observation(&self.root().join("privacy").join("approved-mcp")),
                fixture_file_tree_observation(&self.root().join(VAULT_DIRECTORY_NAME)),
            ]
        }

        fn ensure_binding_from_fresh_filesystem_inventory(
            &self,
        ) -> Result<V031MigrationCheckpointProof, V031MigrationCheckpointError> {
            crate::commands::v031_checkpoint_receipts::with_v031_checkpoint_receipt_operation_for_test(
                || {
                    let inventory = v031_upgrade_r2::enumerate_and_authenticate_lineage(
                        self.root(),
                        self.rollback_gate.lineage_id(),
                        &FixtureReceiptBridge {
                            rollback_gate: &self.rollback_gate,
                        },
                    )
                    .map_err(|_| V031MigrationCheckpointError::LineageState)?;
                    ensure_v031_migration_checkpoint_with_verifier(
                        self.root(),
                        &self.user_path,
                        &self.privacy_path,
                        V031CheckpointKind::Binding,
                        &self.candidate,
                        &self.rollback_gate,
                        &self.approved_gate,
                        &self.vault_gate,
                        &inventory,
                        &self.approved_harness.workspace,
                        &self.verifier(),
                    )
                },
            )
        }
    }

    fn workspace() -> WorkspaceInstanceId {
        WorkspaceInstanceId::parse(format!("ws_{}", "a".repeat(32))).expect("workspace id")
    }

    fn synthetic_v3() -> (Vec<u8>, ApplicationBackupMetadata, SourceImages) {
        let workspace = workspace();
        let images = SourceImages {
            user: b"raw-user-schema-10".to_vec(),
            user_schema_manifest_sha256: "8".repeat(64),
            user_logical_manifest_sha256: "9".repeat(64),
            user_business_manifest_sha256: "a".repeat(64),
            user_total_rows: 0,
            privacy: b"raw-privacy-migration-sqlite".to_vec(),
            privacy_schema_version: 1,
            privacy_logical_manifest_sha256: "1".repeat(64),
            privacy_business_manifest_sha256: "2".repeat(64),
            privacy_total_rows: 0,
        };
        let (bundle, metadata) = seal_application_backup_v3(&ApplicationBackupCreateRequestV3 {
            backup_id: "appbkp_checkpoint_test",
            privacy_backup_id: "bkp_checkpoint_test",
            workspace_instance_id: &workspace,
            app_version: env!("CARGO_PKG_VERSION"),
            user_schema_version: CHECKPOINT_USER_SCHEMA_VERSION,
            created_at_unix: 1_784_476_800,
            expires_at_unix: CHECKPOINT_EXPIRES_AT_UNIX,
            user_database: &images.user,
            encrypted_privacy_bundle: &images.privacy,
            encrypted_vault_bundle: b"vault-archive",
            vault_manifest_sha256: &"3".repeat(64),
            approved_workspace_bundle: b"approved-archive",
            approved_workspace_manifest_sha256: &"4".repeat(64),
            work_products_bundle: b"work-products-archive",
            work_products_manifest_sha256: &"5".repeat(64),
        })
        .expect("synthetic checkpoint outer wire seals");
        (bundle, metadata, images)
    }

    fn gates() -> CheckpointGateBinding {
        let rollback = RollbackGateBinding {
            lineage_id: "b".repeat(64),
            envelope_binding_id: format!("ws_{}", "c".repeat(32)),
            source_profile_proof_sha256: "d".repeat(64),
            original_identity_sha256: "e".repeat(64),
            original_bundle_sha256: "f".repeat(64),
            original_rollback_receipt_sha256: "1".repeat(64),
        };
        let rollback_gate_binding_sha256 =
            sha256_hex(&canonical_json_v1(&rollback).expect("rollback binding encodes"));
        CheckpointGateBinding {
            rollback,
            rollback_gate_binding_sha256,
            workspace_instance_id: workspace(),
            approved_credential_manifest_sha256: "1".repeat(64),
            approved_workspace_schema_sha256: "2".repeat(64),
            approved_work_products_schema_sha256: "3".repeat(64),
            approved_target_workspace_manifest_sha256: "4".repeat(64),
            approved_target_work_products_manifest_sha256: "5".repeat(64),
            approved_target_evidence_sha256: "2".repeat(64),
            approved_credential_count: 4,
            approved_business_rows: 0,
            approved_work_product_business_rows: 0,
            vault_target_evidence_sha256: "3".repeat(64),
            vault_component_manifest_sha256: "4".repeat(64),
            vault_schema_sha256: "5".repeat(64),
            vault_database_sha256: "6".repeat(64),
            vault_layout_sha256: "7".repeat(64),
            vault_schema_version: 1,
            vault_schema_objects: 10,
            vault_metadata_rows: 2,
            vault_business_rows: 0,
            vault_key_record_count: 0,
            vault_object_root_entry_count: 0,
            vault_directory_count: 3,
            vault_file_count: 1,
            original_user_physical_file_set_sha256: "6".repeat(64),
            original_privacy_physical_file_set_sha256: "7".repeat(64),
            original_user_schema_manifest_sha256: "8".repeat(64),
            original_user_logical_manifest_sha256: "9".repeat(64),
            original_user_business_manifest_sha256: "a".repeat(64),
            original_user_total_rows: 0,
            original_privacy_logical_manifest_sha256: "1".repeat(64),
            original_privacy_business_manifest_sha256: "2".repeat(64),
            original_privacy_table_count: 5,
            original_privacy_total_rows: 0,
        }
    }

    fn candidate() -> V031CheckpointCandidateEvidence {
        V031CheckpointCandidateEvidence {
            source_fingerprint: "8".repeat(64),
            candidate_manifest_sha256: "9".repeat(64),
            candidate_count: 2,
        }
    }

    #[test]
    fn ordinary_restore_rejects_schema10_checkpoint_before_privacy_interpretation() {
        let (bundle, _, _) = synthetic_v3();
        let result = open_application_backup(
            &bundle,
            &ApplicationBackupOpenContext {
                expected_workspace_instance_id: &workspace(),
                expected_app_version: env!("CARGO_PKG_VERSION"),
                expected_user_schema_version: database::USER_SCHEMA_VERSION,
                now_unix: 1_784_476_801,
            },
        );
        assert_eq!(result, Err(ApplicationBackupError::EnvironmentMismatch));
    }

    #[cfg(windows)]
    #[test]
    fn checkpoint_identity_is_canonical_dpapi_bound_and_tamper_evident() {
        let (bundle, metadata, images) = synthetic_v3();
        let gates = gates();
        gates.validate().expect("test gates validate");
        let candidate = candidate();
        let identity = identity_from_metadata(
            V031CheckpointKind::Binding,
            &candidate,
            &gates,
            &metadata,
            &images,
            bundle.len(),
        )
        .expect("identity builds");
        let plaintext = canonical_json_v1(&identity).expect("identity is canonical");
        let protected = protect_local(&plaintext).expect("identity protects");
        let opened = unprotect_local(&protected).expect("identity unprotects");
        let decoded: CheckpointIdentityV1 =
            strict_json_v1_from_slice(&opened).expect("identity parses strictly");
        assert_eq!(decoded, identity);

        let noncanonical_directory = tempfile::tempdir().expect("noncanonical identity directory");
        let noncanonical_path = noncanonical_directory
            .path()
            .join("checkpoint.identity.dpapi");
        let noncanonical = serde_json::to_vec_pretty(&identity).expect("pretty identity encodes");
        let protected_noncanonical =
            protect_local(&noncanonical).expect("pretty identity protects");
        fs::write(&noncanonical_path, protected_noncanonical)
            .expect("pretty protected identity writes");
        assert_eq!(
            read_checkpoint_identity(&noncanonical_path),
            Err(V031MigrationCheckpointError::Tampered)
        );

        let mut gate2_tampers = Vec::new();
        let mut approved_credential = identity.clone();
        approved_credential.approved_credential_manifest_sha256 = "0".repeat(64);
        gate2_tampers.push(approved_credential);
        let mut approved_manifest = identity.clone();
        approved_manifest.approved_target_workspace_manifest_sha256 = "0".repeat(64);
        gate2_tampers.push(approved_manifest);
        let mut vault_database = identity.clone();
        vault_database.vault_database_sha256 = "0".repeat(64);
        gate2_tampers.push(vault_database);
        let mut vault_count = identity.clone();
        vault_count.vault_business_rows = 1;
        gate2_tampers.push(vault_count);
        for tampered_identity in gate2_tampers {
            assert_eq!(
                validate_identity(
                    &tampered_identity,
                    V031CheckpointKind::Binding,
                    &candidate,
                    &gates,
                ),
                Err(V031MigrationCheckpointError::Tampered)
            );
        }

        let mut tampered = protected;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(unprotect_local(&tampered).is_err());

        let mut wrong_candidate = candidate;
        wrong_candidate.candidate_count += 1;
        assert!(validate_identity(
            &identity,
            V031CheckpointKind::Binding,
            &wrong_candidate,
            &gates
        )
        .is_err());
    }

    #[test]
    fn identity_parser_rejects_unknown_fields_and_kind_substitution() {
        let (bundle, metadata, images) = synthetic_v3();
        let gates = gates();
        let candidate = candidate();
        let identity = identity_from_metadata(
            V031CheckpointKind::Binding,
            &candidate,
            &gates,
            &metadata,
            &images,
            bundle.len(),
        )
        .expect("identity builds");
        assert!(
            validate_identity(&identity, V031CheckpointKind::Materials, &candidate, &gates)
                .is_err()
        );
        let mut semantic_substitution = identity.clone();
        semantic_substitution.user_logical_manifest_sha256 = "0".repeat(64);
        assert!(validate_identity(
            &semantic_substitution,
            V031CheckpointKind::Binding,
            &candidate,
            &gates,
        )
        .is_err());
        let mut value = serde_json::to_value(&identity).expect("identity value");
        value.as_object_mut().expect("identity object").insert(
            "secretPath".to_owned(),
            serde_json::Value::String("x".to_owned()),
        );
        let bytes = serde_json::to_vec(&value).expect("tampered identity encodes");
        assert!(strict_json_v1_from_slice::<CheckpointIdentityV1>(&bytes).is_err());
    }

    #[test]
    fn checkpoint_sources_require_the_two_exact_fixed_lexical_paths() {
        let root = std::env::temp_dir().join(format!("v031-checkpoint-path-{}", Uuid::new_v4()));
        let user = database::user_database_path(&root);
        let privacy = root.join("privacy").join("privacy-workflow.sqlite");
        validate_checkpoint_source_paths(&root, &user, &privacy)
            .expect("fixed source paths validate");
        assert_eq!(
            validate_checkpoint_source_paths(&root, &root.join("alias-user.sqlite"), &privacy),
            Err(V031MigrationCheckpointError::InvalidInput)
        );
        assert_eq!(
            validate_checkpoint_source_paths(
                &root,
                &root.join("nested").join("..").join("user.sqlite"),
                &privacy
            ),
            Err(V031MigrationCheckpointError::InvalidInput)
        );
        assert_eq!(
            validate_checkpoint_source_paths(&root, &user, &root.join("privacy-workflow.sqlite")),
            Err(V031MigrationCheckpointError::InvalidInput)
        );
    }

    #[cfg(windows)]
    #[test]
    #[allow(unsafe_code)]
    fn checkpoint_backup_serializer_turns_a_persistent_wal_snapshot_into_a_detached_image() {
        let directory = tempfile::tempdir().expect("WAL serializer fixture");
        let source_path = directory.path().join("source.sqlite");
        let source = Connection::open(&source_path).expect("WAL source opens");
        source
            .execute_batch("CREATE TABLE evidence(id INTEGER PRIMARY KEY,value TEXT);")
            .expect("WAL source schema creates");
        let mode: String = source
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .expect("WAL mode enables");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        source
            .pragma_update(None, "wal_autocheckpoint", 0)
            .expect("automatic checkpoint disables");
        let mut persist = 1_i32;
        let status = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                source.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_PERSIST_WAL,
                (&mut persist as *mut i32).cast(),
            )
        };
        assert_eq!(status, rusqlite::ffi::SQLITE_OK);
        source
            .execute(
                "INSERT INTO evidence(value) VALUES('committed-wal-row')",
                [],
            )
            .expect("WAL row commits");

        let mut destination = Connection::open_in_memory().expect("backup destination opens");
        rusqlite::backup::Backup::new(&source, &mut destination)
            .expect("Backup API starts")
            .run_to_completion(64, std::time::Duration::from_millis(1), None)
            .expect("Backup API completes");
        drop(source);
        assert!(source_path.with_file_name("source.sqlite-wal").is_file());
        assert!(source_path.with_file_name("source.sqlite-shm").is_file());
        let raw = destination
            .serialize(rusqlite::MAIN_DB)
            .expect("raw Backup destination serializes")
            .to_vec();
        assert_eq!(raw.get(18..20), Some([2_u8, 2_u8].as_slice()));
        let detached = serialize_backup_as_self_contained_sqlite(&destination)
            .expect("WAL header canonicalizes");
        assert_eq!(detached.get(18..20), Some([1_u8, 1_u8].as_slice()));
        let mut verified = Connection::open_in_memory().expect("detached verifier opens");
        verified
            .deserialize_read_exact(
                rusqlite::MAIN_DB,
                std::io::Cursor::new(&detached),
                detached.len(),
                true,
            )
            .expect("detached image attaches without sidecars");
        let value: String = verified
            .query_row("SELECT value FROM evidence WHERE id=1", [], |row| {
                row.get(0)
            })
            .expect("committed WAL row is present in detached image");
        assert_eq!(value, "committed-wal-row");
    }

    #[cfg(windows)]
    #[test]
    fn production_checkpoint_core_ensures_verifies_and_resumes_idempotently() {
        let directory = tempfile::tempdir().expect("production checkpoint fixture");
        let root = directory.path();
        let user_path = create_exact_v031_user_source(root);
        let privacy_path = create_exact_privacy_v1_source(root);
        let (user_proof, ()) =
            database::with_validated_user_database_migration_source_read_only(&user_path, |_| ())
                .expect("exact user source validates");
        let privacy_proof = privacy::validate_privacy_v1_migration_source_read_only(&privacy_path)
            .expect("exact Privacy source validates");
        let rollback_gate =
            OriginalRollbackVerifiedGate::from_user_source_for_test(user_proof.clone())
                .with_privacy_source_for_checkpoint_test(privacy_proof.clone());

        let approved_harness = ApplicationBackupTestHarness::new(root.to_path_buf());
        let approved_gate = approved_harness
            .workspace
            .prepare_v031_target_components_for_checkpoint_test(&rollback_gate)
            .expect("exact empty Approved target prepares");
        let vault_gate = crate::privacy_workflow::prepare_v031_vault_target_component(
            root,
            &rollback_gate,
            &approved_gate,
        )
        .expect("exact empty Vault target prepares");
        let target_verifier = FixtureTargetVerifier {
            workspace: &approved_harness.workspace,
        };
        let approved_target_root = root.join("privacy").join("approved-mcp");
        let vault_target_root = root.join(VAULT_DIRECTORY_NAME);
        let approved_bytes_before = fixture_file_tree(&approved_target_root);
        let vault_bytes_before = fixture_file_tree(&vault_target_root);
        setup_checkpoint_receipt_prefix(root, &rollback_gate);
        let root_basenames_before = fixture_direct_child_basenames(root);
        assert!(root_basenames_before
            .iter()
            .all(|basename| !basename.starts_with(".application-backup-")));
        let candidate = candidate();

        let initial = authenticate_checkpoint_fixture_lineage(root, &rollback_gate);
        let created = ensure_v031_migration_checkpoint_with_verifier(
            root,
            &user_path,
            &privacy_path,
            V031CheckpointKind::Binding,
            &candidate,
            &rollback_gate,
            &approved_gate,
            &vault_gate,
            &initial,
            &approved_harness.workspace,
            &target_verifier,
        )
        .expect("production checkpoint core installs five-component checkpoint");
        assert!(created.created());
        let root_basenames_after = fixture_direct_child_basenames(root);
        assert_eq!(root_basenames_after, root_basenames_before);
        assert!(root_basenames_after
            .iter()
            .all(|basename| !basename.starts_with(".application-backup-")));
        assert_eq!(
            fixture_file_tree(&approved_target_root),
            approved_bytes_before
        );
        assert_eq!(fixture_file_tree(&vault_target_root), vault_bytes_before);
        assert_eq!(
            created.user_schema_manifest_sha256(),
            user_proof.schema_manifest_sha256
        );
        assert_eq!(
            created.user_logical_manifest_sha256(),
            user_proof.logical_database_manifest_sha256
        );
        assert_eq!(
            created.user_business_manifest_sha256(),
            user_proof.business_manifest_sha256
        );
        assert_eq!(created.user_total_rows(), user_proof.total_rows);
        assert_eq!(
            created.privacy_schema_version(),
            privacy::PRIVACY_V1_SCHEMA_VERSION
        );
        assert_eq!(
            created.privacy_logical_manifest_sha256(),
            privacy_proof.logical_manifest.sha256
        );
        assert_eq!(
            created.privacy_business_manifest_sha256(),
            privacy_proof.business_manifest.sha256
        );
        assert_eq!(
            created.privacy_total_rows(),
            privacy_proof.logical_manifest.total_row_count
        );

        let installed = authenticate_checkpoint_fixture_lineage(root, &rollback_gate);
        assert!(installed.checkpoints.binding.is_exact_final());
        approved_harness
            .workspace
            .verify_v031_target_components_for_checkpoint_test(&rollback_gate, &approved_gate)
            .expect("Approved target remains exact after checkpoint snapshot");
        verify_v031_vault_target_component_read_only(
            root,
            &rollback_gate,
            &approved_gate,
            &vault_gate,
        )
        .expect("Vault target remains exact after checkpoint snapshot");
        let verified = verify_v031_migration_checkpoint_with_verifier(
            root,
            V031CheckpointKind::Binding,
            &candidate,
            &rollback_gate,
            &approved_gate,
            &vault_gate,
            &installed,
            &approved_harness.workspace,
            &target_verifier,
        )
        .expect("installed checkpoint strictly verifies all five components");
        assert!(!verified.created());
        let idempotent = ensure_v031_migration_checkpoint_with_verifier(
            root,
            &user_path,
            &privacy_path,
            V031CheckpointKind::Binding,
            &candidate,
            &rollback_gate,
            &approved_gate,
            &vault_gate,
            &installed,
            &approved_harness.workspace,
            &target_verifier,
        )
        .expect("final checkpoint ensure is an idempotent strict verify");
        assert_eq!(idempotent, verified);
        let mut normalized_created = created.clone();
        normalized_created.created = false;
        assert_eq!(normalized_created, verified);

        let lineage =
            v031_upgrade_r2::canonical_lineage_directory(root, rollback_gate.lineage_id())
                .expect("lineage path");
        let identity_before =
            fs::read(lineage.join(V031CheckpointKind::Binding.identity_final_basename()))
                .expect("checkpoint identity reads");
        let bundle_before =
            fs::read(lineage.join(V031CheckpointKind::Binding.bundle_final_basename()))
                .expect("checkpoint bundle reads");
        approved_harness
            .publish_generation(&format!("case_{}", "9".repeat(32)), '9')
            .expect("synthetic Approved target drift commits");
        assert_eq!(
            ensure_v031_migration_checkpoint_with_verifier(
                root,
                &user_path,
                &privacy_path,
                V031CheckpointKind::Binding,
                &candidate,
                &rollback_gate,
                &approved_gate,
                &vault_gate,
                &installed,
                &approved_harness.workspace,
                &target_verifier,
            ),
            Err(V031MigrationCheckpointError::GateMismatch)
        );
        assert_eq!(
            fs::read(lineage.join(V031CheckpointKind::Binding.identity_final_basename()))
                .expect("identity remains readable"),
            identity_before
        );
        assert_eq!(
            fs::read(lineage.join(V031CheckpointKind::Binding.bundle_final_basename()))
                .expect("bundle remains readable"),
            bundle_before
        );
    }

    #[cfg(windows)]
    #[derive(Clone, Copy, Debug)]
    #[allow(clippy::enum_variant_names)]
    enum RealCheckpointCrashState {
        BundleIncoming,
        IdentityAndBundleIncoming,
        IdentityFinalAndBundleIncoming,
    }

    #[cfg(windows)]
    #[test]
    fn production_checkpoints_resume_every_real_v3_dpapi_crash_window_for_all_three_kinds() {
        for kind in V031CheckpointKind::ALL {
            for state in [
                RealCheckpointCrashState::BundleIncoming,
                RealCheckpointCrashState::IdentityAndBundleIncoming,
                RealCheckpointCrashState::IdentityFinalAndBundleIncoming,
            ] {
                let fixture = RealCheckpointCrashFixture::new();
                fixture.prepare_for(kind);
                let built = fixture.build(kind);
                let identity_plaintext =
                    canonical_json_v1(&built.identity).expect("checkpoint identity is canonical");
                let protected_identity =
                    protect_local(&identity_plaintext).expect("checkpoint identity DPAPI protects");
                let lineage = v031_upgrade_r2::canonical_lineage_directory(
                    fixture.root(),
                    fixture.rollback_gate.lineage_id(),
                )
                .expect("checkpoint lineage resolves");
                let bundle_incoming = lineage.join(kind.bundle_incoming_basename());
                let bundle_final = lineage.join(kind.bundle_final_basename());
                let identity_incoming = lineage.join(kind.identity_incoming_basename());
                let identity_final = lineage.join(kind.identity_final_basename());
                fs::write(&bundle_incoming, &built.bundle)
                    .expect("real V3 checkpoint bundle incoming stages");
                match state {
                    RealCheckpointCrashState::BundleIncoming => {}
                    RealCheckpointCrashState::IdentityAndBundleIncoming => {
                        fs::write(&identity_incoming, &protected_identity)
                            .expect("real DPAPI checkpoint identity incoming stages");
                    }
                    RealCheckpointCrashState::IdentityFinalAndBundleIncoming => {
                        fs::write(&identity_final, &protected_identity)
                            .expect("real DPAPI checkpoint identity installs before bundle final");
                    }
                }
                assert!(
                    !bundle_final.exists(),
                    "the V3 bundle may be incoming first but cannot be final before identity: {kind:?}/{state:?}"
                );

                let immutable_before = fixture.immutable_component_observation();
                let resumed = ensure_v031_migration_checkpoint_with_verifier(
                    fixture.root(),
                    &fixture.user_path,
                    &fixture.privacy_path,
                    kind,
                    &fixture.candidate,
                    &fixture.rollback_gate,
                    &fixture.approved_gate,
                    &fixture.vault_gate,
                    &fixture.inventory(),
                    &fixture.approved_harness.workspace,
                    &fixture.verifier(),
                )
                .expect("real V3+DPAPI checkpoint crash state resumes");
                assert!(resumed.created());
                assert_eq!(
                    fixture.immutable_component_observation(),
                    immutable_before,
                    "checkpoint resume cannot modify source or live target components: {kind:?}/{state:?}"
                );
                assert_eq!(
                    fs::read(&bundle_final).expect("final checkpoint bundle reads"),
                    built.bundle
                );
                let final_identity_bytes =
                    fs::read(&identity_final).expect("final checkpoint identity reads");
                if !matches!(state, RealCheckpointCrashState::BundleIncoming) {
                    assert_eq!(
                        final_identity_bytes, protected_identity,
                        "an existing protected identity is installed without replacement: {kind:?}/{state:?}"
                    );
                }
                assert_eq!(
                    read_checkpoint_identity(&identity_final)
                        .expect("final checkpoint identity decrypts"),
                    built.identity
                );
                assert!(!bundle_incoming.exists());
                assert!(!identity_incoming.exists());

                let verified = verify_v031_migration_checkpoint_with_verifier(
                    fixture.root(),
                    kind,
                    &fixture.candidate,
                    &fixture.rollback_gate,
                    &fixture.approved_gate,
                    &fixture.vault_gate,
                    &fixture.inventory(),
                    &fixture.approved_harness.workspace,
                    &fixture.verifier(),
                )
                .expect("resumed checkpoint reopens from exact final bytes");
                let mut expected = resumed;
                expected.created = false;
                assert_eq!(verified, expected);
                assert_eq!(fixture.immutable_component_observation(), immutable_before);
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn production_checkpoint_rejects_every_gate2_identity_field_tamper_without_writes() {
        type IdentityTamper = fn(&mut CheckpointIdentityV1);
        let tampers: [(&str, IdentityTamper); 24] = [
            ("rollbackGateBindingSha256", |identity| {
                identity.rollback_gate_binding_sha256 = "0".repeat(64);
            }),
            ("workspaceInstanceId", |identity| {
                identity.workspace_instance_id = format!("ws_{}", "0".repeat(32));
            }),
            ("approvedCredentialManifestSha256", |identity| {
                identity.approved_credential_manifest_sha256 = "0".repeat(64);
            }),
            ("approvedWorkspaceSchemaSha256", |identity| {
                identity.approved_workspace_schema_sha256 = "0".repeat(64);
            }),
            ("approvedWorkProductsSchemaSha256", |identity| {
                identity.approved_work_products_schema_sha256 = "0".repeat(64);
            }),
            ("approvedTargetWorkspaceManifestSha256", |identity| {
                identity.approved_target_workspace_manifest_sha256 = "0".repeat(64);
            }),
            ("approvedTargetWorkProductsManifestSha256", |identity| {
                identity.approved_target_work_products_manifest_sha256 = "0".repeat(64);
            }),
            ("approvedTargetEvidenceSha256", |identity| {
                identity.approved_target_evidence_sha256 = "0".repeat(64);
            }),
            ("approvedCredentialCount", |identity| {
                identity.approved_credential_count += 1;
            }),
            ("approvedBusinessRows", |identity| {
                identity.approved_business_rows += 1;
            }),
            ("approvedWorkProductBusinessRows", |identity| {
                identity.approved_work_product_business_rows += 1;
            }),
            ("vaultTargetEvidenceSha256", |identity| {
                identity.vault_target_evidence_sha256 = "0".repeat(64);
            }),
            ("vaultComponentManifestSha256", |identity| {
                identity.vault_component_manifest_sha256 = "0".repeat(64);
            }),
            ("vaultSchemaSha256", |identity| {
                identity.vault_schema_sha256 = "0".repeat(64);
            }),
            ("vaultDatabaseSha256", |identity| {
                identity.vault_database_sha256 = "0".repeat(64);
            }),
            ("vaultLayoutSha256", |identity| {
                identity.vault_layout_sha256 = "0".repeat(64);
            }),
            ("vaultSchemaVersion", |identity| {
                identity.vault_schema_version += 1;
            }),
            ("vaultSchemaObjects", |identity| {
                identity.vault_schema_objects += 1;
            }),
            ("vaultMetadataRows", |identity| {
                identity.vault_metadata_rows += 1;
            }),
            ("vaultBusinessRows", |identity| {
                identity.vault_business_rows += 1;
            }),
            ("vaultKeyRecordCount", |identity| {
                identity.vault_key_record_count += 1;
            }),
            ("vaultObjectRootEntryCount", |identity| {
                identity.vault_object_root_entry_count += 1;
            }),
            ("vaultDirectoryCount", |identity| {
                identity.vault_directory_count += 1;
            }),
            ("vaultFileCount", |identity| {
                identity.vault_file_count += 1;
            }),
        ];

        let fixture = RealCheckpointCrashFixture::new();
        fixture.ensure(V031CheckpointKind::Binding);
        let kind = V031CheckpointKind::Binding;
        let lineage = v031_upgrade_r2::canonical_lineage_directory(
            fixture.root(),
            fixture.rollback_gate.lineage_id(),
        )
        .expect("Gate2 tamper lineage resolves");
        let identity_path = lineage.join(kind.identity_final_basename());
        let original_protected =
            fs::read(&identity_path).expect("original protected checkpoint identity reads");
        let original_identity =
            read_checkpoint_identity(&identity_path).expect("original checkpoint identity opens");

        for (field, tamper) in tampers {
            let mut tampered_identity = original_identity.clone();
            tamper(&mut tampered_identity);
            let plaintext = canonical_json_v1(&tampered_identity)
                .expect("tampered checkpoint identity remains canonical JSON");
            let protected =
                protect_local(&plaintext).expect("tampered checkpoint identity DPAPI protects");
            fs::write(&identity_path, &protected)
                .expect("tampered protected checkpoint identity installs in fixture");
            assert_eq!(
                read_checkpoint_identity(&identity_path)
                    .expect("tampered identity decrypts before gate validation"),
                tampered_identity,
                "the intended Gate2 field is present in protected identity: {field}"
            );
            let directory_before = fixture_file_tree_observation(fixture.root());
            let result = verify_v031_migration_checkpoint_with_verifier(
                fixture.root(),
                kind,
                &fixture.candidate,
                &fixture.rollback_gate,
                &fixture.approved_gate,
                &fixture.vault_gate,
                &fixture.inventory(),
                &fixture.approved_harness.workspace,
                &fixture.verifier(),
            );
            assert!(result.is_err(), "Gate2 field tamper must fail: {field}");
            assert_eq!(
                fixture_file_tree_observation(fixture.root()),
                directory_before,
                "Gate2 field tamper must fail without any directory write: {field}"
            );
            assert_eq!(
                fs::read(&identity_path).expect("tampered protected identity remains readable"),
                protected,
                "the verifier cannot repair or replace tampered evidence: {field}"
            );
            fs::write(&identity_path, &original_protected)
                .expect("original protected checkpoint identity restores for next case");
        }

        verify_v031_migration_checkpoint_with_verifier(
            fixture.root(),
            kind,
            &fixture.candidate,
            &fixture.rollback_gate,
            &fixture.approved_gate,
            &fixture.vault_gate,
            &fixture.inventory(),
            &fixture.approved_harness.workspace,
            &fixture.verifier(),
        )
        .expect("restored original checkpoint identity verifies");
    }

    #[cfg(windows)]
    #[test]
    fn production_checkpoint_fresh_inventory_rejects_illegal_or_unknown_evidence_without_cleanup() {
        #[derive(Clone, Copy, Debug)]
        enum IllegalEvidenceState {
            BundleFinalBeforeIdentity,
            DifferentFinalAndIncomingBytes,
            UniqueBundleIncomingWithUnknownSibling,
        }

        for state in [
            IllegalEvidenceState::BundleFinalBeforeIdentity,
            IllegalEvidenceState::DifferentFinalAndIncomingBytes,
            IllegalEvidenceState::UniqueBundleIncomingWithUnknownSibling,
        ] {
            let fixture = RealCheckpointCrashFixture::new();
            let kind = V031CheckpointKind::Binding;
            let first = fixture.build(kind);
            let first_identity = protect_local(
                &canonical_json_v1(&first.identity)
                    .expect("first illegal-state identity is canonical"),
            )
            .expect("first illegal-state identity DPAPI protects");
            let lineage = v031_upgrade_r2::canonical_lineage_directory(
                fixture.root(),
                fixture.rollback_gate.lineage_id(),
            )
            .expect("illegal-state lineage resolves");

            match state {
                IllegalEvidenceState::BundleFinalBeforeIdentity => {
                    fs::write(lineage.join(kind.bundle_final_basename()), &first.bundle)
                        .expect("orphan final bundle stages");
                }
                IllegalEvidenceState::DifferentFinalAndIncomingBytes => {
                    let second = fixture.build(kind);
                    let second_identity = protect_local(
                        &canonical_json_v1(&second.identity)
                            .expect("second illegal-state identity is canonical"),
                    )
                    .expect("second illegal-state identity DPAPI protects");
                    assert_ne!(first.bundle, second.bundle);
                    assert_ne!(first_identity, second_identity);
                    fs::write(
                        lineage.join(kind.identity_final_basename()),
                        &first_identity,
                    )
                    .expect("first identity final stages");
                    fs::write(
                        lineage.join(kind.identity_incoming_basename()),
                        &second_identity,
                    )
                    .expect("different identity incoming stages");
                    fs::write(lineage.join(kind.bundle_final_basename()), &first.bundle)
                        .expect("first bundle final stages");
                    fs::write(
                        lineage.join(kind.bundle_incoming_basename()),
                        &second.bundle,
                    )
                    .expect("different bundle incoming stages");
                }
                IllegalEvidenceState::UniqueBundleIncomingWithUnknownSibling => {
                    fs::write(lineage.join(kind.bundle_incoming_basename()), &first.bundle)
                        .expect("unique valid bundle incoming stages");
                    fs::write(
                        lineage.join("unknown-checkpoint-sibling.bin"),
                        b"unique-unknown-evidence-must-be-preserved",
                    )
                    .expect("unknown sibling stages");
                }
            }

            let before = exact_fixture_tree_observation(fixture.root());
            assert_eq!(
                fixture.ensure_binding_from_fresh_filesystem_inventory(),
                Err(V031MigrationCheckpointError::LineageState),
                "fresh authenticated enumeration must reject before ensure writes: {state:?}"
            );
            assert_eq!(
                exact_fixture_tree_observation(fixture.root()),
                before,
                "illegal or unknown evidence cannot be cleaned, replaced, renamed, or timestamped: {state:?}"
            );
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum PairState {
        Absent,
        BundleIncoming,
        IdentityAndBundleIncoming,
        IdentityFinalBundleIncoming,
        Final,
    }

    fn pair_from_bits(bits: u8) -> CheckpointPairInventory {
        CheckpointPairInventory {
            identity_final: bits & 0b0001 != 0,
            identity_incoming: bits & 0b0010 != 0,
            bundle_final: bits & 0b0100 != 0,
            bundle_incoming: bits & 0b1000 != 0,
        }
    }

    fn classify_pair(bits: u8) -> Option<PairState> {
        match bits {
            0b0000 => Some(PairState::Absent),
            0b1000 => Some(PairState::BundleIncoming),
            0b1010 => Some(PairState::IdentityAndBundleIncoming),
            0b1001 => Some(PairState::IdentityFinalBundleIncoming),
            0b0101 => Some(PairState::Final),
            _ => None,
        }
    }

    #[test]
    fn checkpoint_operation_inventory_exhaustively_matches_the_frozen_state_machine() {
        for final_receipt_count in 0..=v031_upgrade_r2::V031_RECEIPTS.len() {
            for no_incoming_receipt in [false, true] {
                for binding_bits in 0_u8..16 {
                    for materials_bits in 0_u8..16 {
                        for projection_bits in 0_u8..16 {
                            let binding = classify_pair(binding_bits);
                            let materials = classify_pair(materials_bits);
                            let projection = classify_pair(projection_bits);
                            let inventory = v031_upgrade_r2::V031CheckpointInventory {
                                binding: pair_from_bits(binding_bits),
                                materials: pair_from_bits(materials_bits),
                                projection: pair_from_bits(projection_bits),
                            };
                            for kind in V031CheckpointKind::ALL {
                                let legal_pairs = binding.is_some()
                                    && materials.is_some()
                                    && projection.is_some();
                                let ordered = materials == Some(PairState::Absent)
                                    || binding == Some(PairState::Final);
                                let terminal_has_no_incoming = final_receipt_count
                                    != v031_upgrade_r2::V031_RECEIPTS.len()
                                    || no_incoming_receipt;
                                let step4_cross_state = match final_receipt_count {
                                    0..=2 => {
                                        binding == Some(PairState::Absent)
                                            && materials == Some(PairState::Absent)
                                    }
                                    3 if no_incoming_receipt => true,
                                    _ => {
                                        binding == Some(PairState::Final)
                                            && materials == Some(PairState::Final)
                                    }
                                };
                                let projection_cross_state = match final_receipt_count {
                                    0..=5 => projection == Some(PairState::Absent),
                                    6 if no_incoming_receipt => true,
                                    _ => projection == Some(PairState::Final),
                                };
                                let operation_window = match kind {
                                    V031CheckpointKind::Binding => {
                                        (binding == Some(PairState::Final)
                                            && final_receipt_count >= 3)
                                            || (final_receipt_count == 3
                                                && no_incoming_receipt
                                                && materials == Some(PairState::Absent))
                                    }
                                    V031CheckpointKind::Materials => {
                                        binding == Some(PairState::Final)
                                            && ((materials == Some(PairState::Final)
                                                && final_receipt_count >= 3)
                                                || (final_receipt_count == 3
                                                    && no_incoming_receipt))
                                    }
                                    V031CheckpointKind::Projection => {
                                        binding == Some(PairState::Final)
                                            && materials == Some(PairState::Final)
                                            && ((projection == Some(PairState::Final)
                                                && final_receipt_count >= 6)
                                                || (final_receipt_count == 6
                                                    && no_incoming_receipt))
                                    }
                                };
                                let expected = legal_pairs
                                    && ordered
                                    && terminal_has_no_incoming
                                    && step4_cross_state
                                    && projection_cross_state
                                    && operation_window;
                                assert_eq!(
                                    checkpoint_inventory_is_valid_for_operation(
                                        final_receipt_count,
                                        no_incoming_receipt,
                                        inventory,
                                        kind,
                                    ),
                                    expected,
                                    "receipt_count={final_receipt_count} no_incoming={no_incoming_receipt} binding={binding_bits:04b} materials={materials_bits:04b} projection={projection_bits:04b} kind={kind:?}"
                                );
                            }
                        }
                    }
                }
            }
        }

        let final_pair = pair_from_bits(0b0101);
        let all_step4_final = v031_upgrade_r2::V031CheckpointInventory {
            binding: final_pair,
            materials: final_pair,
            projection: CheckpointPairInventory::default(),
        };
        assert!(checkpoint_inventory_is_valid_for_operation(
            3,
            false,
            all_step4_final,
            V031CheckpointKind::Binding,
        ));
        assert!(checkpoint_inventory_is_valid_for_operation(
            3,
            false,
            all_step4_final,
            V031CheckpointKind::Materials,
        ));
        let all_final = v031_upgrade_r2::V031CheckpointInventory {
            projection: final_pair,
            ..all_step4_final
        };
        assert!(checkpoint_inventory_is_valid_for_operation(
            6,
            false,
            all_final,
            V031CheckpointKind::Projection,
        ));
    }
}
