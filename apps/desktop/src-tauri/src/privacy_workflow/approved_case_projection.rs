use super::case_material_migration::V031BindingMaterialTerminalProof;
use super::{
    canonical_redacted_bytes, reject_normalized_canaries, validate_loaded_review, ApprovedPayload,
    CanonicalRedactedPage, OwnedApprovedPayload, PrivacyWorkflowError, PrivacyWorkflowManager,
    StoredReviewPayload, APPROVED_PAYLOAD_SCHEMA_VERSION,
};
use crate::{
    commands::{
        original_migration_backup::OriginalRollbackVerifiedGate,
        v031_migration_checkpoint::{
            V031CheckpointCandidateEvidence, V031MigrationCheckpointProof,
        },
        v031_user_upgrade::V031CommittedUserV11ResumeProof,
    },
    v031_upgrade_r2::V031CheckpointKind,
};
use privacy::{
    compute_privacy_v5_manifests_read_only, compute_privacy_v6_manifests_read_only,
    compute_privacy_v6_pre_audit_manifests_read_only, scan_residual, ApprovedProjectionBackfill,
    PrivacyCaseId, PrivacyStore, PrivacyStoreSchemaStatus, PrivacyV5ManifestProof,
    PrivacyV6ManifestProof, ProjectId, ProjectPrivacyCaseBindingStore,
    APPROVED_CASE_PROJECTION_MIGRATION_ID, PRIVACY_V5_SCHEMA_MANIFEST_SHA256,
    PRIVACY_V5_SCHEMA_OBJECT_COUNT,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, sync::atomic::Ordering};

const PROJECTED_DATABASE_HEADROOM_BYTES: u64 = 1024 * 1024;
const READY_PROJECTION_ROW_HEADROOM_PAGES: u64 = 3;
const BLOCKED_PROJECTION_ROW_HEADROOM_PAGES: u64 = 2;
const PROJECTION_CHECKPOINT_SCHEMA_VERSION: i64 = 5;
const PROJECTION_TARGET_SCHEMA_VERSION: i64 = 6;
const PROJECTION_SOURCE_EVIDENCE_DOMAIN: &[u8] = b"v031-approved-projection-source-proof-v1\0";
const PROJECTION_CANDIDATE_MANIFEST_DOMAIN: &[u8] =
    b"v031-approved-projection-candidate-manifest-v1\0";
const PROJECTION_TERMINAL_MANIFEST_DOMAIN: &[u8] = b"v031-approved-projection-terminal-proof-v1\0";
const PROJECTION_SOURCE_STORE: &str = "privacy-workflow.sqlite";
const PROJECTION_SOURCE_TABLE: &str = "privacy_redactions";
const V6_SECURITY_TRIGGER_NAMES: [&str; 8] = [
    "trg_privacy_redaction_approved_immutable",
    "trg_privacy_redaction_projection_shape_insert",
    "trg_privacy_redaction_projection_shape_update",
    "trg_privacy_redaction_projection_no_delete",
    "trg_privacy_redaction_no_replace",
    "trg_privacy_risk_review_no_delete",
    "trg_privacy_risk_review_no_replace",
    "trg_case_material_selection_no_replace",
];

/// Opaque source/candidate capability for the frozen v0.3.1 projection step.
/// It contains hashes and canonical manifests only; no review or approved
/// plaintext is retained in the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031ApprovedProjectionSourceProof {
    evidence_sha256: String,
    source_fingerprint: String,
    candidate_manifest_sha256: String,
    candidate_count: u64,
    privacy_v5: PrivacyV5ManifestProof,
    step5_terminal_manifest_sha256: String,
}

impl V031ApprovedProjectionSourceProof {
    pub(crate) fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
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
    pub(crate) fn privacy_v5(&self) -> &PrivacyV5ManifestProof {
        &self.privacy_v5
    }

    pub(crate) fn checkpoint_candidate_evidence(&self) -> V031CheckpointCandidateEvidence {
        V031CheckpointCandidateEvidence {
            source_fingerprint: self.source_fingerprint.clone(),
            candidate_manifest_sha256: self.candidate_manifest_sha256.clone(),
            candidate_count: self.candidate_count,
        }
    }
}

/// Committed-state-only proof of the canonical Privacy-v6 projection target.
/// The proof is rebuilt under a query-only snapshot and never accepts mutable
/// invocation counters from the writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031PrivacyV6TerminalProof {
    source_evidence_sha256: String,
    v5_source_fingerprint: String,
    candidate_manifest_sha256: String,
    approved_generation_count: u64,
    projection_rows: u64,
    blocked_rows: u64,
    risk_head_rows: u64,
    revocation_rows: u64,
    binding_verified_rows: u64,
    security_trigger_count: u64,
    schema_object_count: u64,
    privacy_v6: PrivacyV6ManifestProof,
    terminal_manifest_sha256: String,
}

impl V031PrivacyV6TerminalProof {
    pub(crate) fn source_evidence_sha256(&self) -> &str {
        &self.source_evidence_sha256
    }

    pub(crate) fn v5_source_fingerprint(&self) -> &str {
        &self.v5_source_fingerprint
    }

    pub(crate) fn candidate_manifest_sha256(&self) -> &str {
        &self.candidate_manifest_sha256
    }

    pub(crate) const fn approved_generation_count(&self) -> u64 {
        self.approved_generation_count
    }

    pub(crate) const fn projection_rows(&self) -> u64 {
        self.projection_rows
    }

    pub(crate) const fn blocked_rows(&self) -> u64 {
        self.blocked_rows
    }

    pub(crate) const fn risk_head_rows(&self) -> u64 {
        self.risk_head_rows
    }

    pub(crate) const fn revocation_rows(&self) -> u64 {
        self.revocation_rows
    }

    pub(crate) const fn binding_verified_rows(&self) -> u64 {
        self.binding_verified_rows
    }

    pub(crate) const fn security_trigger_count(&self) -> u64 {
        self.security_trigger_count
    }

    pub(crate) const fn schema_object_count(&self) -> u64 {
        self.schema_object_count
    }

    pub(crate) fn privacy_v6(&self) -> &PrivacyV6ManifestProof {
        &self.privacy_v6
    }

    pub(crate) fn terminal_manifest_sha256(&self) -> &str {
        &self.terminal_manifest_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(super) enum ProjectionFailurePoint {
    BeforePrepare,
    AfterPrepare,
    BeforeBatch(usize),
    AfterBatch(usize),
    BeforeFinalize,
    AfterFinalize,
}

#[derive(Debug)]
struct PreparedProjection {
    redaction_id: String,
    source_fingerprint: String,
    canonical_payload: Vec<u8>,
    risk_head: String,
    protected_size: u64,
}

#[derive(Debug)]
enum ProjectionMigrationCandidate {
    Ready(PreparedProjection),
    Blocked {
        redaction_id: String,
        source_fingerprint: String,
        error_code: String,
    },
}

impl PrivacyWorkflowManager {
    pub(crate) fn approved_projection_migration_required(
        &self,
    ) -> Result<bool, PrivacyWorkflowError> {
        Ok(matches!(
            self.preflight_privacy_store_schema_read_only()?,
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 }
        ))
    }

    /// Computes a migration-specific fingerprint from a query-only Privacy
    /// snapshot. It is stable across projection backfill, blocking decisions and
    /// migration-ledger writes, but changes if any v5 source, risk, binding or
    /// Vault provenance changes.
    pub(crate) fn approved_projection_migration_source_fingerprint(
        &self,
    ) -> Result<String, PrivacyWorkflowError> {
        let connection = self.open_projection_migration_read_snapshot()?;
        connection
            .execute_batch("BEGIN DEFERRED")
            .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"))?;
        let result = PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
            .map_err(PrivacyWorkflowError::store);
        let rollback = connection
            .execute_batch("ROLLBACK")
            .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"));
        rollback?;
        result
    }

    /// Captures the exact canonical-v5 source and the complete deterministic
    /// projection candidate manifest before the authenticated projection
    /// checkpoint is created.
    pub(crate) fn v031_approved_projection_source_proof(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        step5_terminal: &V031BindingMaterialTerminalProof,
    ) -> Result<V031ApprovedProjectionSourceProof, PrivacyWorkflowError> {
        let _guard = self.gate();
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        validate_step5_terminal_proof(step5_terminal)?;
        let connection = self.open_projection_migration_read_snapshot()?;
        let schema_status =
            PrivacyStore::preflight_schema(&connection).map_err(PrivacyWorkflowError::store)?;
        let (live_v5, canonical_v5) = match schema_status {
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 } => {
                match compute_privacy_v5_manifests_read_only(&connection) {
                    Ok(live_v5) => (live_v5, true),
                    Err(_) => {
                        validate_prepared_projection_schema(&connection)?;
                        (step5_terminal.privacy_v5().clone(), false)
                    }
                }
            }
            PrivacyStoreSchemaStatus::Current => {
                compute_privacy_v6_manifests_read_only(&connection).map_err(|_| {
                    projection_migration_error("v031_projection_terminal_manifest_invalid")
                })?;
                (step5_terminal.privacy_v5().clone(), false)
            }
            PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                return Err(projection_migration_error("v031_projection_v5_required"));
            }
        };
        if &live_v5 != step5_terminal.privacy_v5() {
            return Err(projection_migration_error(
                "v031_projection_step5_terminal_mismatch",
            ));
        }
        let source_fingerprint =
            PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
                .map_err(PrivacyWorkflowError::store)?;
        let candidates = self.prepare_projection_candidates_for_resume(&connection)?;
        let candidate_manifest_sha256 = projection_candidate_manifest(&candidates)?;
        let candidate_count = u64::try_from(candidates.len())
            .map_err(|_| projection_migration_error("v031_projection_candidate_invalid"))?;
        let post_source_fingerprint =
            PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
                .map_err(PrivacyWorkflowError::store)?;
        let post_candidates = self.prepare_projection_candidates_for_resume(&connection)?;
        if post_source_fingerprint != source_fingerprint
            || projection_candidate_manifest(&post_candidates)? != candidate_manifest_sha256
            || post_candidates.len() != candidates.len()
        {
            return Err(projection_migration_error("v031_projection_source_changed"));
        }
        if canonical_v5 {
            let post_v5 = compute_privacy_v5_manifests_read_only(&connection)
                .map_err(|_| projection_migration_error("v031_projection_v5_source_invalid"))?;
            if post_v5 != live_v5 {
                return Err(projection_migration_error("v031_projection_source_changed"));
            }
        } else if schema_status == (PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 })
        {
            validate_prepared_projection_schema(&connection)?;
        }
        let evidence_sha256 = projection_source_evidence(
            self,
            rollback_gate,
            step5_terminal,
            &live_v5,
            &source_fingerprint,
            &candidate_manifest_sha256,
            candidate_count,
        )?;
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        Ok(V031ApprovedProjectionSourceProof {
            evidence_sha256,
            source_fingerprint,
            candidate_manifest_sha256,
            candidate_count,
            privacy_v5: live_v5,
            step5_terminal_manifest_sha256: step5_terminal.terminal_manifest_sha256().to_owned(),
        })
    }

    /// Executes only the fixed `approved-case-projection-v1` transition after
    /// authenticating the Original gate, committed Step-5 proof, source proof,
    /// and Projection checkpoint as one lineage-bound capability chain.
    pub(crate) fn run_v031_approved_projection_migration_after_checkpoint(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        step5_terminal: &V031BindingMaterialTerminalProof,
        source: &V031ApprovedProjectionSourceProof,
        checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<V031PrivacyV6TerminalProof, PrivacyWorkflowError> {
        self.run_v031_approved_projection_migration_inner(
            rollback_gate,
            step5_terminal,
            source,
            checkpoint,
            None,
        )
    }

    #[cfg(test)]
    pub(super) fn run_v031_approved_projection_migration_with_failure(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        step5_terminal: &V031BindingMaterialTerminalProof,
        source: &V031ApprovedProjectionSourceProof,
        checkpoint: &V031MigrationCheckpointProof,
        failure_point: ProjectionFailurePoint,
    ) -> Result<V031PrivacyV6TerminalProof, PrivacyWorkflowError> {
        self.run_v031_approved_projection_migration_inner(
            rollback_gate,
            step5_terminal,
            source,
            checkpoint,
            Some(failure_point),
        )
    }

    fn run_v031_approved_projection_migration_inner(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        step5_terminal: &V031BindingMaterialTerminalProof,
        source: &V031ApprovedProjectionSourceProof,
        checkpoint: &V031MigrationCheckpointProof,
        failure_point: Option<ProjectionFailurePoint>,
    ) -> Result<V031PrivacyV6TerminalProof, PrivacyWorkflowError> {
        let _guard = self.gate();
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        validate_projection_gate_chain(self, rollback_gate, step5_terminal, source, checkpoint)?;

        let mut connection = self.open_raw_connection()?;
        match PrivacyStore::preflight_schema(&connection).map_err(PrivacyWorkflowError::store)? {
            PrivacyStoreSchemaStatus::Current => {
                verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
                let terminal = compute_v031_privacy_v6_terminal_proof(
                    self,
                    rollback_gate,
                    step5_terminal,
                    source,
                    checkpoint,
                    &connection,
                )?;
                self.revalidate_v031_user_source_read_only(rollback_gate)?;
                self.shared
                    .schema_upgrade_required
                    .store(false, Ordering::Release);
                return Ok(terminal);
            }
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 } => {}
            PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                return Err(projection_migration_error("v031_projection_v5_required"));
            }
        }

        validate_v031_projection_v5_state(&connection, source)?;
        verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
        let candidates = self.prepare_projection_candidates_for_resume(&connection)?;
        verify_projection_candidates(source, &candidates)?;
        verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
        verify_projected_database_capacity(&connection, &candidates)?;
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;

        inject_projection_failure(failure_point, ProjectionFailurePoint::BeforePrepare)?;
        PrivacyStore::prepare_approved_projection_schema_after_backup(&connection)
            .map_err(PrivacyWorkflowError::store)?;
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
        inject_projection_failure(failure_point, ProjectionFailurePoint::AfterPrepare)?;

        for (index, candidate) in candidates.iter().enumerate() {
            self.revalidate_v031_user_source_read_only(rollback_gate)?;
            verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
            inject_projection_failure(failure_point, ProjectionFailurePoint::BeforeBatch(index))?;
            write_projection_candidate(&mut connection, candidate)?;
            verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
            self.revalidate_v031_user_source_read_only(rollback_gate)?;
            inject_projection_failure(failure_point, ProjectionFailurePoint::AfterBatch(index))?;
        }

        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
        inject_projection_failure(failure_point, ProjectionFailurePoint::BeforeFinalize)?;
        PrivacyStore::finalize_approved_projection_schema_after_backup(&connection)
            .map_err(PrivacyWorkflowError::store)?;
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        verify_projection_source_fingerprint(&connection, &source.source_fingerprint)?;
        inject_projection_failure(failure_point, ProjectionFailurePoint::AfterFinalize)?;

        let terminal = compute_v031_privacy_v6_terminal_proof(
            self,
            rollback_gate,
            step5_terminal,
            source,
            checkpoint,
            &connection,
        )?;
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        self.shared
            .schema_upgrade_required
            .store(false, Ordering::Release);
        Ok(terminal)
    }

    /// Rebuilds the Step-6 terminal proof from current committed state only.
    pub(crate) fn v031_privacy_v6_terminal_proof(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        step5_terminal: &V031BindingMaterialTerminalProof,
        source: &V031ApprovedProjectionSourceProof,
        checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<V031PrivacyV6TerminalProof, PrivacyWorkflowError> {
        let _guard = self.gate();
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        validate_projection_gate_chain(self, rollback_gate, step5_terminal, source, checkpoint)?;
        let connection = self.open_projection_migration_read_snapshot()?;
        let proof = compute_v031_privacy_v6_terminal_proof(
            self,
            rollback_gate,
            step5_terminal,
            source,
            checkpoint,
            &connection,
        )?;
        self.revalidate_v031_user_source_read_only(rollback_gate)?;
        Ok(proof)
    }

    /// Rebuilds the receipt-7 terminal proof after the User-v11 transaction
    /// has committed. The only skipped check is the no-longer-possible active
    /// User-v10 physical read; the opaque resume proof has already authenticated
    /// the exact v11 audit against receipt 7 and the Original V2 semantic proof.
    pub(crate) fn v031_privacy_v6_terminal_proof_for_committed_user_v11_resume(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        step5_terminal: &V031BindingMaterialTerminalProof,
        source: &V031ApprovedProjectionSourceProof,
        checkpoint: &V031MigrationCheckpointProof,
        resume: &V031CommittedUserV11ResumeProof,
    ) -> Result<V031PrivacyV6TerminalProof, PrivacyWorkflowError> {
        let _guard = self.gate();
        if !rollback_gate.authenticates_same_original_rollback(resume.rollback_gate())
            || resume.receipt_context().lineage_id != rollback_gate.lineage_id()
            || resume.receipt_context().envelope_binding_id != rollback_gate.envelope_binding_id()
            || resume.receipt_context().source_profile_proof_sha256
                != rollback_gate.source_profile_proof_sha256()
            || !is_lower_hash(resume.privacy_v6_receipt_sha256())
            || !is_lower_hash(resume.privacy_v6_evidence_sha256())
        {
            return Err(projection_migration_error(
                "v031_projection_user_v11_resume_gate_invalid",
            ));
        }
        validate_projection_gate_chain(self, rollback_gate, step5_terminal, source, checkpoint)?;
        let connection = self.open_projection_migration_read_snapshot()?;
        let privacy_v6 = if resume.privacy_lineage_sha256().is_some() {
            compute_privacy_v6_pre_audit_manifests_read_only(
                &connection,
                rollback_gate.lineage_id(),
            )
        } else {
            compute_privacy_v6_manifests_read_only(&connection)
        }
        .map_err(|_| projection_migration_error("v031_projection_terminal_manifest_invalid"))?;
        if privacy_v6.logical_manifest.sha256
            != resume.target_privacy_pre_audit_logical_manifest_sha256()
            || privacy_v6.business_manifest.sha256
                != resume.target_privacy_pre_audit_business_manifest_sha256()
            || u64::try_from(privacy_v6.logical_manifest.tables.len()).ok()
                != Some(resume.target_privacy_pre_audit_table_count())
            || privacy_v6.logical_manifest.total_row_count
                != resume.target_privacy_pre_audit_total_rows()
        {
            return Err(projection_migration_error(
                "v031_projection_user_v11_resume_manifest_invalid",
            ));
        }
        compute_v031_privacy_v6_terminal_proof_with_manifest(
            self,
            rollback_gate,
            step5_terminal,
            source,
            checkpoint,
            &connection,
            Some(privacy_v6),
        )
    }

    /// Performs the v5->v6 approved-only projection backfill after the caller
    /// has established the source-bound five-component backup.
    pub(crate) fn run_approved_projection_migration_after_backup_for_source(
        &self,
        expected_source_fingerprint: &str,
    ) -> Result<(), PrivacyWorkflowError> {
        if !is_lower_hash(expected_source_fingerprint) {
            return Err(projection_migration_error(
                "approved_projection_source_fingerprint_invalid",
            ));
        }
        let _guard = self.gate();
        let mut connection = self.open_raw_connection()?;
        match PrivacyStore::preflight_schema(&connection).map_err(PrivacyWorkflowError::store)? {
            PrivacyStoreSchemaStatus::Current => {
                let current =
                    PrivacyStore::approved_projection_migration_source_fingerprint(&connection)
                        .map_err(PrivacyWorkflowError::store)?;
                if current != expected_source_fingerprint {
                    return Err(projection_migration_error(
                        "approved_projection_source_changed",
                    ));
                }
                self.shared
                    .schema_upgrade_required
                    .store(false, Ordering::Release);
                return Ok(());
            }
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 } => {}
            PrivacyStoreSchemaStatus::Empty | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                return Err(projection_migration_error(
                    "approved_projection_v5_required",
                ))
            }
        }
        verify_projection_source_fingerprint(&connection, expected_source_fingerprint)?;
        let candidates = self.prepare_projection_candidates(&connection)?;
        verify_projected_database_capacity(&connection, &candidates)?;
        verify_projection_source_fingerprint(&connection, expected_source_fingerprint)?;

        PrivacyStore::prepare_approved_projection_schema_after_backup(&connection)
            .map_err(PrivacyWorkflowError::store)?;
        for candidate in candidates {
            match candidate {
                ProjectionMigrationCandidate::Ready(candidate) => {
                    PrivacyStore::backfill_approved_projection_after_backup(
                        &mut connection,
                        &ApprovedProjectionBackfill {
                            redaction_id: &candidate.redaction_id,
                            source_fingerprint: &candidate.source_fingerprint,
                            approved_payload_plaintext: &candidate.canonical_payload,
                            approved_risk_revision_hash: &candidate.risk_head,
                        },
                    )
                    .map_err(PrivacyWorkflowError::store)?;
                }
                ProjectionMigrationCandidate::Blocked {
                    redaction_id,
                    source_fingerprint,
                    error_code,
                } => {
                    PrivacyStore::block_approved_projection_after_backup(
                        &mut connection,
                        &redaction_id,
                        &source_fingerprint,
                        &error_code,
                    )
                    .map_err(PrivacyWorkflowError::store)?;
                }
            }
        }
        verify_projection_source_fingerprint(&connection, expected_source_fingerprint)?;
        PrivacyStore::finalize_approved_projection_schema_after_backup(&connection)
            .map_err(PrivacyWorkflowError::store)?;
        self.shared
            .schema_upgrade_required
            .store(false, Ordering::Release);
        Ok(())
    }

    fn prepare_projection_candidates(
        &self,
        connection: &Connection,
    ) -> Result<Vec<ProjectionMigrationCandidate>, PrivacyWorkflowError> {
        let redaction_ids = active_approved_projection_candidate_ids(connection)?;
        let mut candidates = Vec::with_capacity(redaction_ids.len());
        for redaction_id in redaction_ids {
            let source_fingerprint = PrivacyStore::approved_projection_migration_row_fingerprint(
                connection,
                &redaction_id,
            )
            .map_err(PrivacyWorkflowError::store)?;
            match self.prepare_projection_candidate(connection, &redaction_id) {
                Ok(mut candidate) => {
                    candidate.source_fingerprint = source_fingerprint;
                    candidates.push(ProjectionMigrationCandidate::Ready(candidate));
                }
                Err(error_code) => candidates.push(ProjectionMigrationCandidate::Blocked {
                    redaction_id,
                    source_fingerprint,
                    error_code: error_code.to_owned(),
                }),
            }
        }
        Ok(candidates)
    }

    /// Reconstructs the original deterministic candidate set after any
    /// committed batch by taking the union of still-active candidates and the
    /// append-only projection ledger. A blocked row is never re-opened through
    /// the legacy full-review loader during resume.
    fn prepare_projection_candidates_for_resume(
        &self,
        connection: &Connection,
    ) -> Result<Vec<ProjectionMigrationCandidate>, PrivacyWorkflowError> {
        let mut redaction_ids = active_approved_projection_candidate_ids(connection)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        for redaction_id in projection_migration_ledger_candidate_ids(connection)? {
            redaction_ids.insert(redaction_id);
        }
        let mut candidates = Vec::with_capacity(redaction_ids.len());
        for redaction_id in redaction_ids {
            let source_fingerprint = PrivacyStore::approved_projection_migration_row_fingerprint(
                connection,
                &redaction_id,
            )
            .map_err(PrivacyWorkflowError::store)?;
            match load_existing_projection_ledger(connection, &redaction_id)? {
                Some(existing) => {
                    if existing.source_fingerprint != source_fingerprint {
                        return Err(projection_migration_error(
                            "v031_projection_ledger_source_mismatch",
                        ));
                    }
                    verify_existing_projection_event(connection, &redaction_id, &existing)?;
                    match (existing.result_state.as_str(), existing.error_code) {
                        ("migrated", None) => {
                            let mut candidate = self
                                .prepare_projection_candidate(connection, &redaction_id)
                                .map_err(|_| {
                                    projection_migration_error(
                                        "v031_projection_committed_candidate_invalid",
                                    )
                                })?;
                            candidate.source_fingerprint = source_fingerprint;
                            candidates.push(ProjectionMigrationCandidate::Ready(candidate));
                        }
                        ("blocked", Some(error_code)) => {
                            if !valid_projection_identifier(&error_code) {
                                return Err(projection_migration_error(
                                    "v031_projection_ledger_invalid",
                                ));
                            }
                            candidates.push(ProjectionMigrationCandidate::Blocked {
                                redaction_id,
                                source_fingerprint,
                                error_code,
                            });
                        }
                        _ => {
                            return Err(projection_migration_error(
                                "v031_projection_ledger_invalid",
                            ));
                        }
                    }
                }
                None => match self.prepare_projection_candidate(connection, &redaction_id) {
                    Ok(mut candidate) => {
                        candidate.source_fingerprint = source_fingerprint;
                        candidates.push(ProjectionMigrationCandidate::Ready(candidate));
                    }
                    Err(error_code) => candidates.push(ProjectionMigrationCandidate::Blocked {
                        redaction_id,
                        source_fingerprint,
                        error_code: error_code.to_owned(),
                    }),
                },
            }
        }
        Ok(candidates)
    }

    fn prepare_projection_candidate(
        &self,
        connection: &Connection,
        redaction_id: &str,
    ) -> Result<PreparedProjection, &'static str> {
        let loaded = PrivacyStore::load_review_draft(connection, redaction_id)
            .map_err(|_| "approved_projection_full_blob_invalid")?;
        let stored: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| "approved_projection_full_blob_invalid")?;
        validate_loaded_review(&loaded, &stored)
            .map_err(|_| "approved_projection_review_identity_mismatch")?;
        self.verify_stored_vault_source(connection, &stored)
            .map_err(|_| "approved_projection_vault_mismatch")?;
        let project_id = connection
            .query_row(
                "SELECT project_id
                 FROM privacy_materials
                 WHERE material_id=?1 AND migration_status='ready'
                   AND deleted_at IS NULL",
                [&stored.material_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| "approved_projection_project_binding_invalid")?
            .flatten()
            .ok_or("approved_projection_project_binding_invalid")?;
        let project_id = ProjectId::parse(project_id)
            .map_err(|_| "approved_projection_project_binding_invalid")?;
        let privacy_case_id = stored
            .case_id
            .as_ref()
            .ok_or("approved_projection_project_binding_invalid")
            .and_then(|case_id| {
                PrivacyCaseId::parse(case_id.clone())
                    .map_err(|_| "approved_projection_project_binding_invalid")
            })?;
        ProjectPrivacyCaseBindingStore::validate_pair(connection, &project_id, &privacy_case_id)
            .map_err(|_| "approved_projection_project_binding_invalid")?;

        let pages = stored
            .pages
            .iter()
            .map(|page| CanonicalRedactedPage {
                page_number: page.page_number,
                text: page.suggested_redacted_text.clone(),
            })
            .collect::<Vec<_>>();
        if pages.is_empty()
            || pages.len() != stored.page_count as usize
            || pages
                .windows(2)
                .any(|pair| pair[0].page_number >= pair[1].page_number)
        {
            return Err("approved_projection_page_mismatch");
        }
        let redacted_content =
            canonical_redacted_bytes(&pages).map_err(|_| "approved_projection_payload_invalid")?;
        if privacy::sha256_hex(&redacted_content) != stored.suggested_redacted_content_sha256 {
            return Err("approved_projection_redacted_hash_mismatch");
        }
        reject_normalized_canaries(&pages, &stored.forbidden_canaries)
            .map_err(|_| "approved_projection_canary_detected")?;
        let canonical_payload = serde_json::to_vec(&ApprovedPayload {
            schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
            source_sha256: &stored.source_sha256,
            extraction_sha256: &stored.extraction_sha256,
            media_type: &stored.media_type,
            pages: &pages,
        })
        .map_err(|_| "approved_projection_payload_invalid")?;
        let residual = scan_residual(&canonical_payload)
            .map_err(|_| "approved_projection_residual_scan_failed")?;
        if !residual.passed {
            return Err("approved_projection_residual_detected");
        }
        let indexed_hash = connection
            .query_row(
                "SELECT approved_payload_sha256
                 FROM privacy_redactions
                 WHERE redaction_id=?1 AND review_state='approved'
                   AND generation_status='ready'
                   AND revocation_state='active'
                   AND revoked_at IS NULL
                   AND unresolved_high_risk_count=0",
                [redaction_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(|_| "approved_projection_index_invalid")?
            .flatten()
            .ok_or("approved_projection_index_invalid")?;
        if privacy::sha256_hex(&canonical_payload) != indexed_hash {
            return Err("approved_projection_payload_hash_mismatch");
        }
        let (risk_revision, risk_head) =
            PrivacyStore::verify_complete_risk_review_chain(connection, redaction_id)
                .map_err(|_| "approved_projection_risk_chain_invalid")?;
        let indexed_revision = connection
            .query_row(
                "SELECT risk_revision FROM privacy_redactions WHERE redaction_id=?1",
                [redaction_id],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| "approved_projection_risk_chain_invalid")
            .and_then(|value| {
                u64::try_from(value).map_err(|_| "approved_projection_risk_chain_invalid")
            })?;
        if indexed_revision != risk_revision {
            return Err("approved_projection_risk_chain_invalid");
        }
        let protected_size = privacy::protect_local(&canonical_payload)
            .map_err(|_| "approved_projection_protection_failed")?
            .len() as u64;
        Ok(PreparedProjection {
            redaction_id: redaction_id.to_owned(),
            source_fingerprint: String::new(),
            canonical_payload,
            risk_head,
            protected_size,
        })
    }

    fn open_projection_migration_read_snapshot(&self) -> Result<Connection, PrivacyWorkflowError> {
        let connection = Connection::open_with_flags(
            &self.shared.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"))?;
        connection
            .execute_batch(
                "PRAGMA query_only=ON;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;",
            )
            .map_err(|_| projection_migration_error("approved_projection_snapshot_failed"))?;
        Ok(connection)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExistingProjectionLedger {
    source_fingerprint: String,
    target_material_id: String,
    target_redaction_id: String,
    assigned_generation_number: u64,
    result_state: String,
    error_code: Option<String>,
}

fn validate_step5_terminal_proof(
    proof: &V031BindingMaterialTerminalProof,
) -> Result<(), PrivacyWorkflowError> {
    let privacy_v5 = proof.privacy_v5();
    if !is_lower_hash(proof.source_evidence_sha256())
        || !is_lower_hash(proof.terminal_manifest_sha256())
        || privacy_v5.schema_version != PROJECTION_CHECKPOINT_SCHEMA_VERSION
        || privacy_v5.schema_manifest_sha256 != PRIVACY_V5_SCHEMA_MANIFEST_SHA256
        || privacy_v5.schema_object_count != PRIVACY_V5_SCHEMA_OBJECT_COUNT
        || privacy_v5.table_count != privacy::PRIVACY_V5_APPLICATION_TABLES.len() as u64
        || privacy_v5.total_row_count != privacy_v5.logical_manifest.total_row_count
        || privacy_v5.business_manifest.total_row_count > privacy_v5.total_row_count
        || proof.terminal_rows() != proof.material_ledger_rows()
        || proof.blocked_rows() > proof.terminal_rows()
        || proof.privacy_migration_batches() != 1
        || proof.bindings_verified() > proof.binding_ledger_rows()
    {
        return Err(projection_migration_error(
            "v031_projection_step5_terminal_invalid",
        ));
    }
    Ok(())
}

/// Rebuilds the projection source capability from an already authenticated
/// checkpoint Privacy-v5 image. The caller owns validation of the paired
/// checkpoint User-v10 image; this function validates the complete v5
/// manifest, deterministic candidate set, and Projection checkpoint chain.
pub(super) fn v031_projection_source_proof_from_verified_v5_connection(
    manager: &PrivacyWorkflowManager,
    rollback_gate: &OriginalRollbackVerifiedGate,
    step5_terminal: &V031BindingMaterialTerminalProof,
    projection_checkpoint: &V031MigrationCheckpointProof,
    connection: &Connection,
) -> Result<V031ApprovedProjectionSourceProof, PrivacyWorkflowError> {
    validate_step5_terminal_proof(step5_terminal)?;
    let schema_status =
        PrivacyStore::preflight_schema(connection).map_err(PrivacyWorkflowError::store)?;
    if schema_status != (PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 5 }) {
        return Err(projection_migration_error("v031_projection_v5_required"));
    }
    let privacy_v5 = compute_privacy_v5_manifests_read_only(connection)
        .map_err(|_| projection_migration_error("v031_projection_v5_source_invalid"))?;
    if &privacy_v5 != step5_terminal.privacy_v5() {
        return Err(projection_migration_error(
            "v031_projection_step5_terminal_mismatch",
        ));
    }
    let source_fingerprint =
        PrivacyStore::approved_projection_migration_source_fingerprint(connection)
            .map_err(PrivacyWorkflowError::store)?;
    let candidates = manager.prepare_projection_candidates_for_resume(connection)?;
    let candidate_manifest_sha256 = projection_candidate_manifest(&candidates)?;
    let candidate_count = u64::try_from(candidates.len())
        .map_err(|_| projection_migration_error("v031_projection_candidate_invalid"))?;
    let evidence_sha256 = projection_source_evidence(
        manager,
        rollback_gate,
        step5_terminal,
        &privacy_v5,
        &source_fingerprint,
        &candidate_manifest_sha256,
        candidate_count,
    )?;
    let proof = V031ApprovedProjectionSourceProof {
        evidence_sha256,
        source_fingerprint,
        candidate_manifest_sha256,
        candidate_count,
        privacy_v5,
        step5_terminal_manifest_sha256: step5_terminal.terminal_manifest_sha256().to_owned(),
    };
    validate_projection_gate_chain(
        manager,
        rollback_gate,
        step5_terminal,
        &proof,
        projection_checkpoint,
    )?;
    Ok(proof)
}

fn validate_v031_projection_v5_state(
    connection: &Connection,
    source: &V031ApprovedProjectionSourceProof,
) -> Result<(), PrivacyWorkflowError> {
    let projection_columns = connection
        .prepare("PRAGMA table_info(privacy_redactions)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .map_err(|_| projection_migration_error("v031_projection_v5_source_invalid"))?;
    let present = [
        "approved_payload_schema_version",
        "protected_approved_payload_blob",
        "approved_payload_protection_scheme",
        "approved_risk_revision_hash",
    ]
    .into_iter()
    .filter(|column| projection_columns.contains(*column))
    .count();
    match present {
        0 => {
            let live = compute_privacy_v5_manifests_read_only(connection)
                .map_err(|_| projection_migration_error("v031_projection_v5_source_invalid"))?;
            if live != source.privacy_v5 {
                return Err(projection_migration_error(
                    "v031_projection_v5_source_changed",
                ));
            }
        }
        4 => validate_prepared_projection_schema(connection)?,
        _ => {
            return Err(projection_migration_error(
                "v031_projection_prepared_schema_invalid",
            ));
        }
    }
    Ok(())
}

fn validate_prepared_projection_schema(
    connection: &Connection,
) -> Result<(), PrivacyWorkflowError> {
    let metadata = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| projection_migration_error("v031_projection_prepared_schema_invalid"))?;
    let projection_columns = connection
        .prepare("PRAGMA table_info(privacy_redactions)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .map_err(|_| projection_migration_error("v031_projection_prepared_schema_invalid"))?;
    let all_projection_columns = [
        "approved_payload_schema_version",
        "protected_approved_payload_blob",
        "approved_payload_protection_scheme",
        "approved_risk_revision_hash",
    ]
    .into_iter()
    .all(|column| projection_columns.contains(column));
    let guard_count = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type='trigger' AND name IN (
               'trg_privacy_v6_approval_blocked',
               'trg_privacy_risk_review_no_delete',
               'trg_privacy_risk_review_no_replace',
               'trg_case_material_selection_no_replace'
             )",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| projection_migration_error("v031_projection_prepared_schema_invalid"))?;
    if metadata != "5" || !all_projection_columns || guard_count != 4 {
        return Err(projection_migration_error(
            "v031_projection_prepared_schema_invalid",
        ));
    }
    Ok(())
}

fn projection_source_evidence(
    manager: &PrivacyWorkflowManager,
    rollback_gate: &OriginalRollbackVerifiedGate,
    step5_terminal: &V031BindingMaterialTerminalProof,
    privacy_v5: &PrivacyV5ManifestProof,
    source_fingerprint: &str,
    candidate_manifest_sha256: &str,
    candidate_count: u64,
) -> Result<String, PrivacyWorkflowError> {
    if !is_lower_hash(source_fingerprint) || !is_lower_hash(candidate_manifest_sha256) {
        return Err(projection_migration_error(
            "v031_projection_source_proof_invalid",
        ));
    }
    let mut fingerprint = ProjectionFingerprint::new(PROJECTION_SOURCE_EVIDENCE_DOMAIN);
    for value in [
        APPROVED_CASE_PROJECTION_MIGRATION_ID,
        rollback_gate.lineage_id(),
        rollback_gate.source_profile_proof_sha256(),
        rollback_gate.original_identity_sha256(),
        manager.shared.workspace_instance_id.as_str(),
        step5_terminal.source_evidence_sha256(),
        step5_terminal.terminal_manifest_sha256(),
        &privacy_v5.schema_manifest_sha256,
        &privacy_v5.internal_schema_manifest_sha256,
        &privacy_v5.logical_manifest.sha256,
        &privacy_v5.business_manifest.sha256,
        source_fingerprint,
        candidate_manifest_sha256,
    ] {
        fingerprint.text(value);
    }
    for count in [
        privacy_v5.schema_version,
        i64::try_from(privacy_v5.schema_object_count)
            .map_err(|_| projection_migration_error("v031_projection_source_proof_invalid"))?,
        i64::try_from(privacy_v5.table_count)
            .map_err(|_| projection_migration_error("v031_projection_source_proof_invalid"))?,
        i64::try_from(privacy_v5.total_row_count)
            .map_err(|_| projection_migration_error("v031_projection_source_proof_invalid"))?,
        i64::try_from(candidate_count)
            .map_err(|_| projection_migration_error("v031_projection_source_proof_invalid"))?,
    ] {
        fingerprint.integer(count);
    }
    Ok(fingerprint.finish())
}

fn validate_projection_gate_chain(
    manager: &PrivacyWorkflowManager,
    rollback_gate: &OriginalRollbackVerifiedGate,
    step5_terminal: &V031BindingMaterialTerminalProof,
    source: &V031ApprovedProjectionSourceProof,
    checkpoint: &V031MigrationCheckpointProof,
) -> Result<(), PrivacyWorkflowError> {
    validate_step5_terminal_proof(step5_terminal)?;
    let expected_source_evidence = projection_source_evidence(
        manager,
        rollback_gate,
        step5_terminal,
        &source.privacy_v5,
        &source.source_fingerprint,
        &source.candidate_manifest_sha256,
        source.candidate_count,
    )?;
    let checkpoint_hashes = [
        checkpoint.identity_protected_sha256(),
        checkpoint.bundle_sha256(),
        checkpoint.user_database_sha256(),
        checkpoint.privacy_database_sha256(),
        checkpoint.vault_bundle_sha256(),
        checkpoint.approved_workspace_bundle_sha256(),
        checkpoint.work_products_bundle_sha256(),
    ];
    let original_user = rollback_gate.original_user_source_proof();
    if source.evidence_sha256 != expected_source_evidence
        || source.step5_terminal_manifest_sha256 != step5_terminal.terminal_manifest_sha256()
        || source.privacy_v5 != *step5_terminal.privacy_v5()
        || !is_lower_hash(&source.evidence_sha256)
        || !is_lower_hash(&source.source_fingerprint)
        || !is_lower_hash(&source.candidate_manifest_sha256)
        || checkpoint.kind() != V031CheckpointKind::Projection
        || checkpoint.lineage_id() != rollback_gate.lineage_id()
        || checkpoint.original_identity_sha256() != rollback_gate.original_identity_sha256()
        || checkpoint.workspace_instance_id() != manager.shared.workspace_instance_id.as_str()
        || checkpoint.user_schema_manifest_sha256() != original_user.schema_manifest_sha256
        || checkpoint.user_logical_manifest_sha256()
            != original_user.logical_database_manifest_sha256
        || checkpoint.user_business_manifest_sha256() != original_user.business_manifest_sha256
        || checkpoint.user_total_rows() != original_user.total_rows
        || checkpoint.privacy_schema_version() != PROJECTION_CHECKPOINT_SCHEMA_VERSION
        || checkpoint.privacy_logical_manifest_sha256() != source.privacy_v5.logical_manifest.sha256
        || checkpoint.privacy_business_manifest_sha256()
            != source.privacy_v5.business_manifest.sha256
        || checkpoint.privacy_total_rows() != source.privacy_v5.total_row_count
        || checkpoint.source_fingerprint() != source.source_fingerprint
        || checkpoint.candidate_manifest_sha256() != source.candidate_manifest_sha256
        || checkpoint.candidate_count() != source.candidate_count
        || checkpoint_hashes
            .into_iter()
            .any(|hash| !is_lower_hash(hash))
    {
        return Err(projection_migration_error(
            "v031_projection_checkpoint_gate_mismatch",
        ));
    }
    Ok(())
}

fn projection_candidate_manifest(
    candidates: &[ProjectionMigrationCandidate],
) -> Result<String, PrivacyWorkflowError> {
    let mut fingerprint = ProjectionFingerprint::new(PROJECTION_CANDIDATE_MANIFEST_DOMAIN);
    fingerprint.integer(
        i64::try_from(candidates.len())
            .map_err(|_| projection_migration_error("v031_projection_candidate_invalid"))?,
    );
    let mut previous = None::<&str>;
    for candidate in candidates {
        let redaction_id = candidate.redaction_id();
        if previous.is_some_and(|value| value >= redaction_id) {
            return Err(projection_migration_error(
                "v031_projection_candidate_invalid",
            ));
        }
        previous = Some(redaction_id);
        fingerprint.text(redaction_id);
        fingerprint.text(candidate.source_fingerprint());
        match candidate {
            ProjectionMigrationCandidate::Ready(candidate) => {
                fingerprint.text("migrated");
                fingerprint.text(&privacy::sha256_hex(&candidate.canonical_payload));
                fingerprint.text(&candidate.risk_head);
                fingerprint.text("");
            }
            ProjectionMigrationCandidate::Blocked { error_code, .. } => {
                fingerprint.text("blocked");
                fingerprint.text("");
                fingerprint.text("");
                fingerprint.text(error_code);
            }
        }
    }
    Ok(fingerprint.finish())
}

impl ProjectionMigrationCandidate {
    fn redaction_id(&self) -> &str {
        match self {
            Self::Ready(candidate) => &candidate.redaction_id,
            Self::Blocked { redaction_id, .. } => redaction_id,
        }
    }

    fn source_fingerprint(&self) -> &str {
        match self {
            Self::Ready(candidate) => &candidate.source_fingerprint,
            Self::Blocked {
                source_fingerprint, ..
            } => source_fingerprint,
        }
    }
}

fn verify_projection_candidates(
    source: &V031ApprovedProjectionSourceProof,
    candidates: &[ProjectionMigrationCandidate],
) -> Result<(), PrivacyWorkflowError> {
    let candidate_count = u64::try_from(candidates.len())
        .map_err(|_| projection_migration_error("v031_projection_candidate_invalid"))?;
    if candidate_count != source.candidate_count
        || projection_candidate_manifest(candidates)? != source.candidate_manifest_sha256
    {
        return Err(projection_migration_error(
            "v031_projection_candidate_manifest_mismatch",
        ));
    }
    Ok(())
}

fn write_projection_candidate(
    connection: &mut Connection,
    candidate: &ProjectionMigrationCandidate,
) -> Result<(), PrivacyWorkflowError> {
    match candidate {
        ProjectionMigrationCandidate::Ready(candidate) => {
            PrivacyStore::backfill_approved_projection_after_backup(
                connection,
                &ApprovedProjectionBackfill {
                    redaction_id: &candidate.redaction_id,
                    source_fingerprint: &candidate.source_fingerprint,
                    approved_payload_plaintext: &candidate.canonical_payload,
                    approved_risk_revision_hash: &candidate.risk_head,
                },
            )
            .map_err(PrivacyWorkflowError::store)
        }
        ProjectionMigrationCandidate::Blocked {
            redaction_id,
            source_fingerprint,
            error_code,
        } => PrivacyStore::block_approved_projection_after_backup(
            connection,
            redaction_id,
            source_fingerprint,
            error_code,
        )
        .map_err(PrivacyWorkflowError::store),
    }
}

fn inject_projection_failure(
    requested: Option<ProjectionFailurePoint>,
    current: ProjectionFailurePoint,
) -> Result<(), PrivacyWorkflowError> {
    if requested == Some(current) {
        return Err(projection_migration_error(
            "v031_projection_injected_failure",
        ));
    }
    Ok(())
}

fn projection_migration_ledger_candidate_ids(
    connection: &Connection,
) -> Result<Vec<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT source_store,source_table,source_key,target_material_id,
                    target_redaction_id,assigned_generation_number,result_state,error_code
             FROM case_material_migration_ledger
             WHERE migration_id=?1
             ORDER BY source_key ASC",
        )
        .map_err(|_| projection_migration_error("v031_projection_ledger_invalid"))?;
    let rows = statement
        .query_map([APPROVED_CASE_PROJECTION_MIGRATION_ID], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<i64>>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
            ))
        })
        .map_err(|_| projection_migration_error("v031_projection_ledger_invalid"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| projection_migration_error("v031_projection_ledger_invalid"))?;
    let mut ids = Vec::with_capacity(rows.len());
    for (store, table, key, material, target, generation, result, error) in rows {
        let valid_result = matches!(
            (result.as_str(), error.as_deref()),
            ("migrated", None) | ("blocked", Some(_))
        );
        if store != PROJECTION_SOURCE_STORE
            || table != PROJECTION_SOURCE_TABLE
            || target.as_deref() != Some(key.as_str())
            || generation.is_none_or(|value| value <= 0)
            || !valid_projection_identifier(&key)
            || !valid_projection_identifier(&material)
            || !valid_result
        {
            return Err(projection_migration_error("v031_projection_ledger_invalid"));
        }
        ids.push(key);
    }
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(projection_migration_error("v031_projection_ledger_invalid"));
    }
    Ok(ids)
}

fn load_existing_projection_ledger(
    connection: &Connection,
    redaction_id: &str,
) -> Result<Option<ExistingProjectionLedger>, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT source_fingerprint,target_material_id,target_redaction_id,
                    assigned_generation_number,result_state,error_code
             FROM case_material_migration_ledger
             WHERE migration_id=?1
               AND source_store=?2 AND source_table=?3 AND source_key=?4",
            (
                APPROVED_CASE_PROJECTION_MIGRATION_ID,
                PROJECTION_SOURCE_STORE,
                PROJECTION_SOURCE_TABLE,
                redaction_id,
            ),
            |row| {
                let generation = row.get::<_, i64>(3)?;
                Ok(ExistingProjectionLedger {
                    source_fingerprint: row.get(0)?,
                    target_material_id: row.get(1)?,
                    target_redaction_id: row.get(2)?,
                    assigned_generation_number: u64::try_from(generation)
                        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(3, generation))?,
                    result_state: row.get(4)?,
                    error_code: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|_| projection_migration_error("v031_projection_ledger_invalid"))
}

fn verify_existing_projection_event(
    connection: &Connection,
    redaction_id: &str,
    ledger: &ExistingProjectionLedger,
) -> Result<(), PrivacyWorkflowError> {
    let (total, matching) = connection
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(
                event_type='approved_projection_backfill'
                AND source_fingerprint=?5
                AND target_material_id=?6
                AND target_redaction_id=?4
                AND assigned_generation_number=?7
                AND result_state=?8
                AND error_code IS ?9
             ),0)
             FROM case_material_migration_events
             WHERE migration_id=?1
               AND source_store=?2 AND source_table=?3 AND source_key=?4",
            rusqlite::params![
                APPROVED_CASE_PROJECTION_MIGRATION_ID,
                PROJECTION_SOURCE_STORE,
                PROJECTION_SOURCE_TABLE,
                redaction_id,
                ledger.source_fingerprint,
                ledger.target_material_id,
                i64::try_from(ledger.assigned_generation_number).map_err(|_| {
                    projection_migration_error("v031_projection_ledger_invalid")
                })?,
                ledger.result_state,
                ledger.error_code,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .map_err(|_| projection_migration_error("v031_projection_event_invalid"))?;
    if (total, matching) != (1, 1) {
        return Err(projection_migration_error("v031_projection_event_invalid"));
    }
    Ok(())
}

fn valid_projection_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn load_terminal_projection_candidates(
    connection: &Connection,
) -> Result<Vec<ProjectionMigrationCandidate>, PrivacyWorkflowError> {
    let redaction_ids = projection_migration_ledger_candidate_ids(connection)?;
    let mut candidates = Vec::with_capacity(redaction_ids.len());
    for redaction_id in redaction_ids {
        let ledger = load_existing_projection_ledger(connection, &redaction_id)?
            .ok_or_else(|| projection_migration_error("v031_projection_ledger_invalid"))?;
        verify_existing_projection_event(connection, &redaction_id, &ledger)?;
        let source_fingerprint =
            PrivacyStore::approved_projection_migration_row_fingerprint(connection, &redaction_id)
                .map_err(PrivacyWorkflowError::store)?;
        if ledger.source_fingerprint != source_fingerprint
            || ledger.target_redaction_id != redaction_id
        {
            return Err(projection_migration_error(
                "v031_projection_ledger_source_mismatch",
            ));
        }
        match (ledger.result_state.as_str(), ledger.error_code) {
            ("migrated", None) => {
                let row = connection
                    .query_row(
                        "SELECT material.project_id,binding.privacy_case_id,
                                generation.material_id,generation.generation_number,
                                generation.generation_status,generation.review_state,
                                generation.revocation_state,generation.revoked_at,
                                generation.unresolved_high_risk_count,
                                generation.risk_revision,generation.approved_payload_sha256,
                                generation.approved_payload_schema_version,
                                generation.protected_approved_payload_blob,
                                generation.approved_payload_protection_scheme,
                                generation.approved_risk_revision_hash,
                                material.source_sha256,generation.extraction_sha256,
                                material.media_type,material.page_count
                         FROM privacy_redactions AS generation
                         JOIN privacy_materials AS material
                           ON material.material_id=generation.material_id
                         JOIN project_privacy_case_bindings AS binding
                           ON binding.project_id=material.project_id
                         WHERE generation.redaction_id=?1",
                        [&redaction_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, Option<String>>(7)?,
                                row.get::<_, i64>(8)?,
                                row.get::<_, i64>(9)?,
                                row.get::<_, Option<String>>(10)?,
                                row.get::<_, Option<i64>>(11)?,
                                row.get::<_, Option<Vec<u8>>>(12)?,
                                row.get::<_, Option<String>>(13)?,
                                row.get::<_, Option<String>>(14)?,
                                row.get::<_, Option<String>>(15)?,
                                row.get::<_, String>(16)?,
                                row.get::<_, Option<String>>(17)?,
                                row.get::<_, Option<i64>>(18)?,
                            ))
                        },
                    )
                    .map_err(|_| {
                        projection_migration_error("v031_projection_terminal_row_invalid")
                    })?;
                let generation_number = u64::try_from(row.3).map_err(|_| {
                    projection_migration_error("v031_projection_terminal_row_invalid")
                })?;
                let approved_payload_sha256 = row.10.ok_or_else(|| {
                    projection_migration_error("v031_projection_terminal_row_invalid")
                })?;
                let protected_payload = row.12.ok_or_else(|| {
                    projection_migration_error("v031_projection_terminal_row_invalid")
                })?;
                let risk_head = row.14.ok_or_else(|| {
                    projection_migration_error("v031_projection_terminal_row_invalid")
                })?;
                if ledger.target_material_id != row.2
                    || ledger.assigned_generation_number != generation_number
                    || row.4 != "ready"
                    || row.5 != "approved"
                    || row.6 != "active"
                    || row.7.is_some()
                    || row.8 != 0
                    || row.9 <= 0
                    || row.11 != Some(i64::from(APPROVED_PAYLOAD_SCHEMA_VERSION))
                    || row.13.as_deref() != Some(privacy::LOCAL_PROTECTION_SCHEME)
                    || !is_lower_hash(&approved_payload_sha256)
                    || !is_lower_hash(&risk_head)
                    || row.15.as_deref().is_none_or(|value| !is_lower_hash(value))
                    || row.17.as_deref().is_none_or(str::is_empty)
                    || row.18.is_none_or(|value| value <= 0)
                {
                    return Err(projection_migration_error(
                        "v031_projection_terminal_row_invalid",
                    ));
                }
                let canonical_payload =
                    privacy::unprotect_local(&protected_payload).map_err(|_| {
                        projection_migration_error("v031_projection_terminal_payload_invalid")
                    })?;
                if privacy::sha256_hex(&canonical_payload) != approved_payload_sha256 {
                    return Err(projection_migration_error(
                        "v031_projection_terminal_payload_invalid",
                    ));
                }
                let payload = serde_json::from_slice::<OwnedApprovedPayload>(&canonical_payload)
                    .map_err(|_| {
                        projection_migration_error("v031_projection_terminal_payload_invalid")
                    })?;
                let expected_canonical = serde_json::to_vec(&ApprovedPayload {
                    schema_version: payload.schema_version,
                    source_sha256: &payload.source_sha256,
                    extraction_sha256: &payload.extraction_sha256,
                    media_type: &payload.media_type,
                    pages: &payload.pages,
                })
                .map_err(|_| {
                    projection_migration_error("v031_projection_terminal_payload_invalid")
                })?;
                if expected_canonical != canonical_payload
                    || payload.schema_version != APPROVED_PAYLOAD_SCHEMA_VERSION
                    || row.15.as_deref() != Some(payload.source_sha256.as_str())
                    || row.16 != payload.extraction_sha256
                    || row.17.as_deref() != Some(payload.media_type.as_str())
                    || usize::try_from(row.18.unwrap_or_default()).ok() != Some(payload.pages.len())
                    || payload.pages.is_empty()
                    || payload
                        .pages
                        .windows(2)
                        .any(|pair| pair[0].page_number >= pair[1].page_number)
                {
                    return Err(projection_migration_error(
                        "v031_projection_terminal_payload_invalid",
                    ));
                }
                let residual = scan_residual(&canonical_payload).map_err(|_| {
                    projection_migration_error("v031_projection_terminal_payload_invalid")
                })?;
                if !residual.passed {
                    return Err(projection_migration_error(
                        "v031_projection_terminal_payload_invalid",
                    ));
                }
                let (risk_revision, verified_risk_head) =
                    PrivacyStore::verify_complete_risk_review_chain(connection, &redaction_id)
                        .map_err(PrivacyWorkflowError::store)?;
                if u64::try_from(row.9).ok() != Some(risk_revision)
                    || verified_risk_head != risk_head
                {
                    return Err(projection_migration_error(
                        "v031_projection_terminal_risk_invalid",
                    ));
                }
                let project_id = ProjectId::parse(row.0.clone()).map_err(|_| {
                    projection_migration_error("v031_projection_terminal_binding_invalid")
                })?;
                let privacy_case_id = PrivacyCaseId::parse(row.1).map_err(|_| {
                    projection_migration_error("v031_projection_terminal_binding_invalid")
                })?;
                ProjectPrivacyCaseBindingStore::validate_pair(
                    connection,
                    &project_id,
                    &privacy_case_id,
                )
                .map_err(|_| {
                    projection_migration_error("v031_projection_terminal_binding_invalid")
                })?;
                let current =
                    PrivacyStore::list_current_approved_case_generations(connection, &project_id)
                        .map_err(PrivacyWorkflowError::store)?;
                if !current
                    .iter()
                    .any(|generation| generation.redaction_generation_id == redaction_id)
                {
                    return Err(projection_migration_error(
                        "v031_projection_terminal_generation_not_current",
                    ));
                }
                candidates.push(ProjectionMigrationCandidate::Ready(PreparedProjection {
                    redaction_id,
                    source_fingerprint,
                    canonical_payload,
                    risk_head,
                    protected_size: u64::try_from(protected_payload.len()).map_err(|_| {
                        projection_migration_error("v031_projection_terminal_payload_invalid")
                    })?,
                }));
            }
            ("blocked", Some(error_code)) => {
                let terminal = connection
                    .query_row(
                        "SELECT material_id,generation_number,generation_status='blocked'
                                AND review_state='approved'
                                AND revocation_state='active' AND revoked_at IS NULL
                                AND approved_payload_schema_version IS NULL
                                AND protected_approved_payload_blob IS NULL
                                AND approved_payload_protection_scheme IS NULL
                                AND approved_risk_revision_hash IS NULL
                         FROM privacy_redactions WHERE redaction_id=?1",
                        [&redaction_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, i64>(1)?,
                                row.get::<_, bool>(2)?,
                            ))
                        },
                    )
                    .map_err(|_| {
                        projection_migration_error("v031_projection_terminal_row_invalid")
                    })?;
                if terminal.0 != ledger.target_material_id
                    || u64::try_from(terminal.1).ok() != Some(ledger.assigned_generation_number)
                    || !terminal.2
                    || !valid_projection_identifier(&error_code)
                {
                    return Err(projection_migration_error(
                        "v031_projection_terminal_row_invalid",
                    ));
                }
                candidates.push(ProjectionMigrationCandidate::Blocked {
                    redaction_id,
                    source_fingerprint,
                    error_code,
                });
            }
            _ => {
                return Err(projection_migration_error("v031_projection_ledger_invalid"));
            }
        }
    }
    Ok(candidates)
}

fn compute_v031_privacy_v6_terminal_proof(
    manager: &PrivacyWorkflowManager,
    rollback_gate: &OriginalRollbackVerifiedGate,
    step5_terminal: &V031BindingMaterialTerminalProof,
    source: &V031ApprovedProjectionSourceProof,
    checkpoint: &V031MigrationCheckpointProof,
    connection: &Connection,
) -> Result<V031PrivacyV6TerminalProof, PrivacyWorkflowError> {
    compute_v031_privacy_v6_terminal_proof_with_manifest(
        manager,
        rollback_gate,
        step5_terminal,
        source,
        checkpoint,
        connection,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn compute_v031_privacy_v6_terminal_proof_with_manifest(
    manager: &PrivacyWorkflowManager,
    rollback_gate: &OriginalRollbackVerifiedGate,
    step5_terminal: &V031BindingMaterialTerminalProof,
    source: &V031ApprovedProjectionSourceProof,
    checkpoint: &V031MigrationCheckpointProof,
    connection: &Connection,
    authenticated_pre_audit_manifest: Option<PrivacyV6ManifestProof>,
) -> Result<V031PrivacyV6TerminalProof, PrivacyWorkflowError> {
    validate_projection_gate_chain(manager, rollback_gate, step5_terminal, source, checkpoint)?;
    if PrivacyStore::preflight_schema(connection).map_err(PrivacyWorkflowError::store)?
        != PrivacyStoreSchemaStatus::Current
    {
        return Err(projection_migration_error(
            "v031_projection_terminal_v6_required",
        ));
    }
    verify_projection_source_fingerprint(connection, &source.source_fingerprint)?;
    let candidates = load_terminal_projection_candidates(connection)?;
    verify_projection_candidates(source, &candidates)?;
    let approved_generation_count = u64::try_from(candidates.len())
        .map_err(|_| projection_migration_error("v031_projection_terminal_invalid"))?;
    let projection_rows = u64::try_from(
        candidates
            .iter()
            .filter(|candidate| matches!(candidate, ProjectionMigrationCandidate::Ready(_)))
            .count(),
    )
    .map_err(|_| projection_migration_error("v031_projection_terminal_invalid"))?;
    let blocked_rows = approved_generation_count
        .checked_sub(projection_rows)
        .ok_or_else(|| projection_migration_error("v031_projection_terminal_invalid"))?;
    let projected_ids = connection
        .prepare(
            "SELECT redaction_id FROM privacy_redactions
             WHERE approved_payload_schema_version IS NOT NULL
                OR protected_approved_payload_blob IS NOT NULL
                OR approved_payload_protection_scheme IS NOT NULL
                OR approved_risk_revision_hash IS NOT NULL
             ORDER BY redaction_id",
        )
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<BTreeSet<_>, _>>()
        })
        .map_err(|_| projection_migration_error("v031_projection_terminal_invalid"))?;
    let expected_projected_ids = candidates
        .iter()
        .filter_map(|candidate| match candidate {
            ProjectionMigrationCandidate::Ready(candidate) => Some(candidate.redaction_id.clone()),
            ProjectionMigrationCandidate::Blocked { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    if projected_ids != expected_projected_ids {
        return Err(projection_migration_error(
            "v031_projection_terminal_extra_projection",
        ));
    }
    let projection_event_count = connection
        .query_row(
            "SELECT COUNT(*) FROM case_material_migration_events WHERE migration_id=?1",
            [APPROVED_CASE_PROJECTION_MIGRATION_ID],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| projection_migration_error("v031_projection_event_invalid"))?;
    if u64::try_from(projection_event_count).ok() != Some(approved_generation_count) {
        return Err(projection_migration_error("v031_projection_event_invalid"));
    }
    let revocation_rows = connection
        .query_row(
            "SELECT COUNT(*) FROM privacy_redactions
             WHERE revocation_state IN ('revoked','revoked_legacy_time_unknown')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| projection_migration_error("v031_projection_terminal_invalid"))
        .and_then(|count| {
            u64::try_from(count)
                .map_err(|_| projection_migration_error("v031_projection_terminal_invalid"))
        })?;
    let mut security_trigger_count = 0_u64;
    for name in V6_SECURITY_TRIGGER_NAMES {
        let count = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
                [name],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| projection_migration_error("v031_projection_security_invalid"))?;
        if count != 1 {
            return Err(projection_migration_error(
                "v031_projection_security_invalid",
            ));
        }
        security_trigger_count = security_trigger_count
            .checked_add(1)
            .ok_or_else(|| projection_migration_error("v031_projection_terminal_invalid"))?;
    }
    let privacy_v6 = match authenticated_pre_audit_manifest {
        Some(manifest) => manifest,
        None => compute_privacy_v6_manifests_read_only(connection)
            .map_err(|_| projection_migration_error("v031_projection_terminal_manifest_invalid"))?,
    };
    if privacy_v6.schema_version != PROJECTION_TARGET_SCHEMA_VERSION {
        return Err(projection_migration_error(
            "v031_projection_terminal_manifest_invalid",
        ));
    }
    let schema_object_count = u64::try_from(privacy_v6.schema_object_count)
        .map_err(|_| projection_migration_error("v031_projection_terminal_invalid"))?;
    let risk_head_rows = projection_rows;
    let binding_verified_rows = projection_rows;
    let mut terminal = ProjectionFingerprint::new(PROJECTION_TERMINAL_MANIFEST_DOMAIN);
    for value in [
        &source.evidence_sha256,
        &source.source_fingerprint,
        &source.candidate_manifest_sha256,
        &privacy_v6.logical_manifest.sha256,
        &privacy_v6.business_manifest.sha256,
    ] {
        terminal.text(value);
    }
    for count in [
        approved_generation_count,
        projection_rows,
        blocked_rows,
        risk_head_rows,
        revocation_rows,
        binding_verified_rows,
        security_trigger_count,
        schema_object_count,
        privacy_v6.logical_manifest.total_row_count,
        privacy_v6.business_manifest.total_row_count,
    ] {
        terminal.integer(
            i64::try_from(count)
                .map_err(|_| projection_migration_error("v031_projection_terminal_invalid"))?,
        );
    }
    Ok(V031PrivacyV6TerminalProof {
        source_evidence_sha256: source.evidence_sha256.clone(),
        v5_source_fingerprint: source.source_fingerprint.clone(),
        candidate_manifest_sha256: source.candidate_manifest_sha256.clone(),
        approved_generation_count,
        projection_rows,
        blocked_rows,
        risk_head_rows,
        revocation_rows,
        binding_verified_rows,
        security_trigger_count,
        schema_object_count,
        privacy_v6,
        terminal_manifest_sha256: terminal.finish(),
    })
}

struct ProjectionFingerprint(Sha256);

impl ProjectionFingerprint {
    fn new(domain: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(domain);
        Self(digest)
    }

    fn text(&mut self, value: &str) {
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value.as_bytes());
    }

    fn integer(&mut self, value: i64) {
        self.0.update(value.to_be_bytes());
    }

    fn finish(self) -> String {
        format!("{:x}", self.0.finalize())
    }
}

fn active_approved_projection_candidate_ids(
    connection: &Connection,
) -> Result<Vec<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT redaction_id
             FROM privacy_redactions
             WHERE review_state='approved'
               AND generation_status='ready'
               AND revocation_state='active'
               AND revoked_at IS NULL
               AND generation_number=(
                   SELECT MAX(current_generation.generation_number)
                   FROM privacy_redactions AS current_generation
                   WHERE current_generation.material_id=privacy_redactions.material_id
               )
             ORDER BY material_id ASC,generation_number ASC,redaction_id ASC",
        )
        .map_err(|_| projection_migration_error("approved_projection_source_invalid"))?;
    let redaction_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| projection_migration_error("approved_projection_source_invalid"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| projection_migration_error("approved_projection_source_invalid"))?;
    Ok(redaction_ids)
}

fn verify_projection_source_fingerprint(
    connection: &Connection,
    expected: &str,
) -> Result<(), PrivacyWorkflowError> {
    let current = PrivacyStore::approved_projection_migration_source_fingerprint(connection)
        .map_err(PrivacyWorkflowError::store)?;
    if current != expected {
        return Err(projection_migration_error(
            "approved_projection_source_changed",
        ));
    }
    Ok(())
}

fn verify_projected_database_capacity(
    connection: &Connection,
    candidates: &[ProjectionMigrationCandidate],
) -> Result<(), PrivacyWorkflowError> {
    let page_count = connection
        .pragma_query_value(None, "page_count", |row| row.get::<_, i64>(0))
        .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        .and_then(|value| {
            u64::try_from(value)
                .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        })?;
    let page_size = connection
        .pragma_query_value(None, "page_size", |row| row.get::<_, i64>(0))
        .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        .and_then(|value| {
            u64::try_from(value)
                .map_err(|_| projection_migration_error("approved_projection_capacity_unknown"))
        })?;
    let current_bytes = page_count
        .checked_mul(page_size)
        .ok_or_else(|| projection_migration_error("approved_projection_capacity_exceeded"))?;
    let projection_bytes = candidates.iter().try_fold(0_u64, |total, candidate| {
        let next = match candidate {
            ProjectionMigrationCandidate::Ready(candidate) => {
                let row_headroom = page_size
                    .checked_mul(READY_PROJECTION_ROW_HEADROOM_PAGES)
                    .ok_or_else(|| {
                        projection_migration_error("approved_projection_capacity_exceeded")
                    })?;
                candidate
                    .protected_size
                    .checked_add(row_headroom)
                    .ok_or_else(|| {
                        projection_migration_error("approved_projection_capacity_exceeded")
                    })?
            }
            ProjectionMigrationCandidate::Blocked { .. } => page_size
                .checked_mul(BLOCKED_PROJECTION_ROW_HEADROOM_PAGES)
                .ok_or_else(|| {
                    projection_migration_error("approved_projection_capacity_exceeded")
                })?,
        };
        total
            .checked_add(next)
            .ok_or_else(|| projection_migration_error("approved_projection_capacity_exceeded"))
    })?;
    let estimated = current_bytes
        .checked_add(projection_bytes)
        .and_then(|value| value.checked_add(PROJECTED_DATABASE_HEADROOM_BYTES))
        .ok_or_else(|| projection_migration_error("approved_projection_capacity_exceeded"))?;
    let maximum = u64::try_from(privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES)
        .map_err(|_| projection_migration_error("approved_projection_capacity_exceeded"))?;
    if estimated > maximum {
        return Err(projection_migration_error(
            "approved_projection_capacity_exceeded",
        ));
    }
    Ok(())
}

fn is_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn projection_migration_error(code: &'static str) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(
        code,
        "The approved-only case projection migration failed closed.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_query_selects_only_active_ready_approved_generations() {
        let connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch(
                "CREATE TABLE privacy_redactions(
                    redaction_id TEXT PRIMARY KEY,
                    material_id TEXT NOT NULL,
                    generation_number INTEGER NOT NULL,
                    generation_status TEXT NOT NULL,
                    review_state TEXT NOT NULL,
                    revocation_state TEXT NOT NULL,
                    revoked_at TEXT
                 );
                 INSERT INTO privacy_redactions VALUES
                    ('active-approved','material-a',1,'ready','approved','active',NULL),
                    ('revoked-approved','material-b',1,'ready','approved','revoked',
                     '2026-07-30 00:00:00'),
                    ('legacy-revoked-approved','material-c',1,'ready','approved',
                     'revoked_legacy_time_unknown',NULL),
                    ('review-state-revoked','material-d',1,'ready','revoked','active',NULL),
                    ('stale','material-e',1,'ready','stale','active',NULL),
                    ('pending','material-f',1,'ready','review_required','active',NULL),
                    ('blocked','material-g',1,'blocked','approved','active',NULL),
                    ('inconsistent-active','material-h',1,'ready','approved','active',
                     '2026-07-30 00:00:00');",
            )
            .expect("candidate rows");

        assert_eq!(
            active_approved_projection_candidate_ids(&connection).expect("candidate query"),
            vec!["active-approved".to_owned()]
        );
    }

    #[test]
    fn capacity_gate_accepts_ready_ciphertext_and_blocked_ledger_headroom() {
        let connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch("CREATE TABLE capacity_test(value TEXT);")
            .expect("capacity schema");
        let candidates = vec![
            ProjectionMigrationCandidate::Ready(PreparedProjection {
                redaction_id: "redaction-1".to_owned(),
                source_fingerprint: "a".repeat(64),
                canonical_payload: vec![1],
                risk_head: "b".repeat(64),
                protected_size: 4096,
            }),
            ProjectionMigrationCandidate::Blocked {
                redaction_id: "redaction-2".to_owned(),
                source_fingerprint: "c".repeat(64),
                error_code: "approved_projection_test_blocked".to_owned(),
            },
        ];
        verify_projected_database_capacity(&connection, &candidates)
            .expect("small migration capacity");
    }

    #[test]
    fn capacity_gate_rejects_projected_database_over_raw_limit() {
        let connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch("CREATE TABLE capacity_test(value TEXT);")
            .expect("capacity schema");
        let candidates = vec![ProjectionMigrationCandidate::Ready(PreparedProjection {
            redaction_id: "redaction-too-large".to_owned(),
            source_fingerprint: "a".repeat(64),
            canonical_payload: vec![1],
            risk_head: "b".repeat(64),
            protected_size: u64::try_from(privacy::lifecycle::MAX_BACKUP_DATABASE_BYTES)
                .expect("raw database maximum fits u64"),
        })];
        assert_eq!(
            verify_projected_database_capacity(&connection, &candidates)
                .expect_err("oversized projected database")
                .code(),
            "approved_projection_capacity_exceeded"
        );
    }
}
