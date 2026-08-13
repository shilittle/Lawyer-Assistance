//! Coordinated Phase-3 backfill for the unified case-material model.
//!
//! The migration deliberately treats `user.sqlite` as an immutable source. All
//! durable writes (bindings, unified material projections, protected legacy
//! references, and append-preserving migration evidence) are made in the
//! Privacy database only.

use super::{
    validate_loaded_review, validate_vault_isolation, vault_broker, PrivacyWorkflowError,
    PrivacyWorkflowManager, StoredReviewPayload, APPROVED_PAYLOAD_SCHEMA_VERSION,
    REVIEW_PAYLOAD_SCHEMA_VERSION,
};
use crate::{
    commands::{
        original_migration_backup::OriginalRollbackVerifiedGate,
        v031_migration_checkpoint::{
            V031CheckpointCandidateEvidence, V031MigrationCheckpointProof,
        },
        v031_target_components::V031TargetComponentsPreparedGate,
    },
    v031_upgrade_r2::V031CheckpointKind,
};
use database::{
    UserMigrationSourceProof, ValidatedUserMigrationSourceSession, ValidatedUserSourceSchema,
};
use privacy::{
    classify_privacy_v5_partial_in_transaction, classify_privacy_v5_partial_read_only,
    compute_privacy_v5_manifests_read_only, protect_local, sha256_hex, unprotect_local,
    verify_initial_privacy_v5_before_receipt4_read_only,
    with_validated_privacy_v1_migration_source_read_only, BindingCreationSource,
    BindingLifecycleContext, PrivacyCaseId, PrivacyLifecycle, PrivacyStore,
    PrivacyStoreSchemaStatus, PrivacyV5InitialFullExpectation, PrivacyV5ManifestProof,
    PrivacyV5PartialProof, PrivacyV5PartialStage, ProjectId, ProjectPrivacyCaseBindingError,
    ProjectPrivacyCaseBindingStore, ValidatedPrivacyV1Source, LOCAL_PROTECTION_SCHEME,
};
use rusqlite::{
    params, types::ValueRef, Connection, OpenFlags, OptionalExtension, Transaction,
    TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::File,
    io::{Cursor, Read},
    path::Path,
};
use uuid::Uuid;

pub(crate) const CASE_MATERIAL_MIGRATION_ID: &str = "case-material-unification-v1";
pub(crate) const PROJECT_CASE_BINDING_MIGRATION_ID: &str = "project-privacy-case-binding-v1";

const SOURCE_STORE_USER: &str = "user.sqlite";
const SOURCE_STORE_PRIVACY: &str = "privacy-workflow.sqlite";
const MATERIAL_ID_DOMAIN: &[u8] = b"case-material-migration-v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"case-material-source-fingerprint-v1\0";
const RISK_REVISION_PROFILE: &str = "privacy-risk-review-revision-v1";
const MAX_SOURCE_ID_BYTES: usize = 256;
const CASE_MATERIAL_TARGET_SCHEMA_VERSION: i64 = 5;
const CASE_MATERIAL_SOURCE_SCHEMA_CONTRACT: &str = concat!(
    "case-material-read-contract-v1\0",
    "projects(project_id,title,case_type,status,opened_on,summary,created_at,updated_at)\0",
    "case_files(file_id,project_id,title,file_type,storage_reference,summary,created_at)\0",
    "attachments(attachment_id,project_id,original_name,extension,detected_mime,sha256,",
    "size_bytes,extraction_status,extracted_text,segments_json,error_code,created_at)"
);

/// Shape-only parser for the exact protected review wire emitted by peeled
/// v0.3.1. `IgnoredAny` avoids making a second in-memory copy of case content
/// while `deny_unknown_fields` prevents a generic empty current display name
/// from being misclassified as legacy-compatible.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactV031StoredReviewShape {
    schema_version: serde::de::IgnoredAny,
    material_id: serde::de::IgnoredAny,
    redaction_id: serde::de::IgnoredAny,
    source_sha256: serde::de::IgnoredAny,
    extraction_sha256: serde::de::IgnoredAny,
    suggested_redacted_content_sha256: serde::de::IgnoredAny,
    processing_version: serde::de::IgnoredAny,
    media_type: serde::de::IgnoredAny,
    page_count: serde::de::IgnoredAny,
    backend_trace: serde::de::IgnoredAny,
    summary: serde::de::IgnoredAny,
    forbidden_canaries: serde::de::IgnoredAny,
    pages: serde::de::IgnoredAny,
}

/// The only application transition permitted for a v0.3.1 review whose
/// original display name was never persisted: assignment adds the audited
/// Privacy CaseId, but it must not manufacture a source display name or any
/// newer optional payload field.
#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExactV031AssignedReviewShape {
    schema_version: serde::de::IgnoredAny,
    material_id: serde::de::IgnoredAny,
    redaction_id: serde::de::IgnoredAny,
    source_sha256: serde::de::IgnoredAny,
    extraction_sha256: serde::de::IgnoredAny,
    suggested_redacted_content_sha256: serde::de::IgnoredAny,
    processing_version: serde::de::IgnoredAny,
    media_type: serde::de::IgnoredAny,
    page_count: serde::de::IgnoredAny,
    backend_trace: serde::de::IgnoredAny,
    summary: serde::de::IgnoredAny,
    forbidden_canaries: serde::de::IgnoredAny,
    pages: serde::de::IgnoredAny,
    case_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CaseMaterialMigrationReport {
    pub privacy_materials_migrated: u64,
    pub redaction_generations_migrated: u64,
    pub case_files_migrated: u64,
    pub legacy_references: u64,
    pub blocked: u64,
    pub bindings_created_or_verified: u64,
    pub idempotent_noops: u64,
    pub source_unchanged_verified: bool,
}

/// Opaque, gate-bound source identity for the frozen v0.3.1 Step-5 writer.
/// Callers can persist the path-free hash but cannot construct a token from a
/// raw string or use it with the ordinary current-schema migration API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031CaseMaterialSourceFingerprint {
    evidence_sha256: String,
    migration_source_fingerprint: String,
}

impl V031CaseMaterialSourceFingerprint {
    pub(crate) fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }
}

/// Opaque Step-4 source/candidate proof captured before the live Privacy-v1
/// source is upgraded.  It deliberately exposes only path-free hashes and
/// counts: project identifiers, historical Privacy CaseIds, and the outcome
/// attached to an individual project never cross this capability boundary.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct V031CaseMigrationCheckpointSourceProof {
    evidence_sha256: String,
    source_fingerprint: String,
    binding_candidate_manifest_sha256: String,
    binding_candidate_count: u64,
    material_candidate_manifest_sha256: String,
    material_candidate_count: u64,
    original_user_physical_file_set_sha256: String,
    original_privacy_physical_file_set_sha256: String,
    privacy_v1_logical_manifest_sha256: String,
    privacy_v1_business_manifest_sha256: String,
    privacy_v1_total_rows: u64,
    target_gate_manifest_sha256: String,
}

impl fmt::Debug for V031CaseMigrationCheckpointSourceProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V031CaseMigrationCheckpointSourceProof")
            .field("evidence_sha256", &self.evidence_sha256)
            .field("source_fingerprint", &self.source_fingerprint)
            .field(
                "binding_candidate_manifest_sha256",
                &self.binding_candidate_manifest_sha256,
            )
            .field("binding_candidate_count", &self.binding_candidate_count)
            .field(
                "material_candidate_manifest_sha256",
                &self.material_candidate_manifest_sha256,
            )
            .field("material_candidate_count", &self.material_candidate_count)
            .field(
                "original_user_physical_file_set_sha256",
                &self.original_user_physical_file_set_sha256,
            )
            .field(
                "original_privacy_physical_file_set_sha256",
                &self.original_privacy_physical_file_set_sha256,
            )
            .field(
                "target_gate_manifest_sha256",
                &self.target_gate_manifest_sha256,
            )
            .finish_non_exhaustive()
    }
}

impl V031CaseMigrationCheckpointSourceProof {
    pub(crate) fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub(crate) fn source_fingerprint(&self) -> &str {
        &self.source_fingerprint
    }

    pub(crate) fn binding_checkpoint_candidate_evidence(&self) -> V031CheckpointCandidateEvidence {
        V031CheckpointCandidateEvidence {
            source_fingerprint: self.source_fingerprint.clone(),
            candidate_manifest_sha256: self.binding_candidate_manifest_sha256.clone(),
            candidate_count: self.binding_candidate_count,
        }
    }

    pub(crate) fn material_checkpoint_candidate_evidence(&self) -> V031CheckpointCandidateEvidence {
        V031CheckpointCandidateEvidence {
            source_fingerprint: self.source_fingerprint.clone(),
            candidate_manifest_sha256: self.material_candidate_manifest_sha256.clone(),
            candidate_count: self.material_candidate_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct V031CandidateManifests {
    binding_manifest_sha256: String,
    binding_count: u64,
    material_manifest_sha256: String,
    material_count: u64,
}

/// Private authorization consumed only after an IMMEDIATE Privacy-v5
/// transaction has recomputed both frozen candidate sets.  Keeping this type
/// private prevents the ordinary current-schema migration entry point from
/// being used as a Step-5 writer capability.
struct V031BindingMaterialWriterGate {
    source: V031CaseMaterialSourceFingerprint,
    candidates: V031CandidateManifests,
    binding_checkpoint_identity_sha256: String,
    material_checkpoint_identity_sha256: String,
}

/// Opaque, one-use authorization for resuming one of the two exact durable
/// pre-binding v5 prefixes.  It is constructed only after both authenticated
/// Step-4 checkpoints, the target workspace gate, the frozen User-v10 source,
/// and the complete partial-store proof agree.  The writer reclassifies the
/// live store and compares this value immediately before its first mutation.
#[derive(Clone, PartialEq, Eq)]
struct V031PrivacyV5PartialResumeCapability {
    checkpoint_source_evidence_sha256: String,
    workspace_instance_id: String,
    partial: PrivacyV5PartialProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct V031BindingMaterialTerminalProof {
    source_evidence_sha256: String,
    privacy_v5: PrivacyV5ManifestProof,
    binding_ledger_rows: u64,
    material_ledger_rows: u64,
    terminal_rows: u64,
    blocked_rows: u64,
    privacy_migration_batches: u64,
    bindings_verified: u64,
    terminal_manifest_sha256: String,
}

impl V031BindingMaterialTerminalProof {
    pub(crate) fn source_evidence_sha256(&self) -> &str {
        &self.source_evidence_sha256
    }

    pub(crate) fn privacy_v5(&self) -> &PrivacyV5ManifestProof {
        &self.privacy_v5
    }

    pub(crate) const fn binding_ledger_rows(&self) -> u64 {
        self.binding_ledger_rows
    }

    pub(crate) const fn material_ledger_rows(&self) -> u64 {
        self.material_ledger_rows
    }

    pub(crate) const fn terminal_rows(&self) -> u64 {
        self.terminal_rows
    }

    pub(crate) const fn blocked_rows(&self) -> u64 {
        self.blocked_rows
    }

    pub(crate) const fn privacy_migration_batches(&self) -> u64 {
        self.privacy_migration_batches
    }

    pub(crate) const fn bindings_verified(&self) -> u64 {
        self.bindings_verified
    }

    pub(crate) fn terminal_manifest_sha256(&self) -> &str {
        &self.terminal_manifest_sha256
    }

    #[cfg(test)]
    pub(crate) fn for_projection_test(privacy_v5: PrivacyV5ManifestProof) -> Self {
        Self {
            source_evidence_sha256: "8".repeat(64),
            privacy_v5,
            binding_ledger_rows: 1,
            material_ledger_rows: 1,
            terminal_rows: 1,
            blocked_rows: 0,
            privacy_migration_batches: 1,
            bindings_verified: 1,
            terminal_manifest_sha256: "9".repeat(64),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceProof {
    file_sha256: String,
    // Capture first validates the exact whole-database v10 or v11 profile.
    // Those two allowlisted profiles then map to the same frozen `UserSnapshot`
    // read contract so the canonical rebuild after Step 5 is restart-stable.
    schema_manifest_sha256: String,
    project_primary_keys_sha256: String,
    case_file_primary_keys_sha256: String,
    attachment_primary_keys_sha256: String,
    source_rows_sha256: String,
    wal_file_sha256: Option<String>,
    data_version: i64,
}

struct V031UserCheckpointImageExpectations<'a> {
    database_sha256: &'a str,
    schema_manifest_sha256: &'a str,
    logical_manifest_sha256: &'a str,
    business_manifest_sha256: &'a str,
    total_rows: u64,
    rollback_semantic_proof: &'a UserMigrationSourceProof,
}

/// Private capability returned only when one self-contained checkpoint image
/// has passed the byte-level exact-v10 validator and all checkpoint/rollback
/// semantic bindings. Raw hashes and arbitrary in-memory connections cannot
/// construct this authorization.
struct VerifiedV031UserCheckpointImage {
    connection: Connection,
    proof: UserMigrationSourceProof,
}

impl VerifiedV031UserCheckpointImage {
    fn connection(&self) -> &Connection {
        &self.connection
    }

    fn capture_source_proof(&self) -> Result<SourceProof, PrivacyWorkflowError> {
        SourceProof::capture_verified_image(self)
    }
}

#[derive(Debug, Clone)]
struct ProjectSource {
    project_id: String,
    title: String,
    case_type: String,
    status: String,
    opened_on: Option<String>,
    summary: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone)]
struct CaseFileSource {
    file_id: String,
    project_id: String,
    title: String,
    file_type: String,
    storage_reference: String,
    summary: String,
    created_at: String,
}

#[derive(Debug, Clone)]
struct AttachmentSource {
    attachment_id: String,
    project_id: Option<String>,
    original_name: String,
    extension: String,
    detected_mime: String,
    sha256: String,
    size_bytes: i64,
    extraction_status: String,
    extracted_text_sha256: Option<String>,
    segments_json_sha256: String,
    error_code: Option<String>,
    created_at: String,
}

#[derive(Debug)]
struct UserSnapshot {
    projects: BTreeMap<String, ProjectSource>,
    case_files: Vec<CaseFileSource>,
    attachments: BTreeMap<String, AttachmentSource>,
}

#[derive(Debug, Clone)]
struct PrivacyMaterialSource {
    material_id: String,
    project_id: Option<String>,
    legacy_case_id: Option<String>,
    attachment_id: Option<String>,
    protected_display_name: Option<Vec<u8>>,
    display_name_sha256: Option<String>,
    display_name_protection_scheme: Option<String>,
    source_sha256: Option<String>,
    source_name_sha256: Option<String>,
    media_type: Option<String>,
    page_count: Option<i64>,
    source_kind: String,
    extraction_status: String,
    migration_status: String,
    state: String,
    row_version: i64,
    created_at: String,
    updated_at: String,
    deleted_at: Option<String>,
    vault_binding: Option<vault_broker::VaultImportBinding>,
    redactions: Vec<PrivacyRedactionSource>,
}

#[derive(Debug, Clone)]
struct HistoricalVaultRef {
    case_id: String,
    object_id: String,
    object_version: i64,
    source_sha256: String,
    envelope_sha256: String,
    content_bytes: i64,
    import_state: String,
    failure_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ProjectDeletionEvidenceScope {
    schema_version: String,
    project_id: String,
    privacy_case_id: Option<String>,
    material_ids: Vec<String>,
    generation_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct PrivacyRedactionSource {
    redaction_id: String,
    material_id: String,
    generation_number: i64,
    generation_status: String,
    extraction_sha256: String,
    redacted_content_sha256: String,
    approved_payload_sha256: Option<String>,
    policy_id: String,
    policy_version: i64,
    detector_version: String,
    unresolved_high_risk_count: i64,
    review_state: String,
    risk_revision: i64,
    protected_review_blob: Vec<u8>,
    protection_scheme: String,
    reviewed_by_sha256: Option<String>,
    approved_at: Option<String>,
    revocation_state: String,
    revoked_at: Option<String>,
    row_version: i64,
    created_at: String,
    reviewed_at: Option<String>,
}

#[derive(Debug, Clone)]
struct ValidatedRedaction {
    source: PrivacyRedactionSource,
    verified_risk_revision: Option<i64>,
    generation_status: &'static str,
    error_code: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct PrivacyMaterialPlan {
    source: PrivacyMaterialSource,
    privacy_case_id: Option<PrivacyCaseId>,
    provenance_projects: BTreeSet<String>,
    display_name: Option<String>,
    redactions: Vec<ValidatedRedaction>,
    validation_error: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct MaterialProjection {
    project_id: Option<String>,
    legacy_case_id: Option<String>,
    source_kind: &'static str,
    migration_status: &'static str,
    state: String,
    display_name: Option<String>,
    error_code: Option<&'static str>,
}

#[derive(Debug, Default)]
struct CleanupAuthorizationSnapshot {
    redactions: BTreeMap<String, (String, i64)>,
    tombstoned_material_ids: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct LedgerEntry {
    source_fingerprint: String,
    target_material_id: String,
    target_redaction_id: Option<String>,
    assigned_generation_number: Option<i64>,
    result_state: String,
    error_code: Option<String>,
}

#[derive(Debug, Clone)]
struct EffectiveLedgerEvidence {
    source_fingerprint: String,
    target_material_id: Option<String>,
    target_redaction_id: Option<String>,
    assigned_generation_number: Option<i64>,
    result_state: String,
    error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TerminalLedgerKey {
    migration_id: String,
    source_store: String,
    source_table: String,
    source_key: String,
}

struct BindingCandidateGraph {
    projects_by_case: BTreeMap<String, BTreeSet<String>>,
    cases_by_project: BTreeMap<String, BTreeSet<String>>,
    blocked_projects: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LedgerWrite {
    Inserted,
    EventAppended,
    Noop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackfillFailurePoint {
    BeforeTransaction,
    AfterProjectBindings,
    BeforeCommit,
    AfterCommit,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V031PrivacyV5UpgradeFailurePoint {
    AfterSchemaCommitBeforeLifecycleInitialize,
    AfterLifecycleCommitBeforeBindingInitialize,
}

#[derive(Debug)]
enum AttachmentResolution<'a> {
    Exact(&'a AttachmentSource),
    Legacy(&'static str),
    Blocked(&'static str),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalApprovedPayload<'a> {
    schema_version: u16,
    source_sha256: &'a str,
    extraction_sha256: &'a str,
    media_type: &'a str,
    pages: Vec<CanonicalApprovedPage<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CanonicalApprovedPage<'a> {
    page_number: u32,
    text: &'a str,
}

impl PrivacyWorkflowManager {
    /// Revalidates the complete active user-v10 source proof against the
    /// authenticated Original rollback gate without opening a writable user
    /// handle. Later coordinated stages call this immediately around every
    /// independently committed target batch.
    pub(super) fn revalidate_v031_user_source_read_only(
        &self,
        gate: &OriginalRollbackVerifiedGate,
    ) -> Result<(), PrivacyWorkflowError> {
        super::validate_ordinary_database_file(&self.shared.user_database_path)?;
        let expected = gate.original_user_source_proof();
        let (post_source, nested) =
            database::with_validated_user_database_migration_source_read_only(
                &self.shared.user_database_path,
                |source_session| {
                    if gate.authenticates_user_physical_file_set(source_session.proof())
                        && same_v031_user_source_content(expected, source_session.proof())
                    {
                        Ok(())
                    } else {
                        Err(v031_user_source_gate_error())
                    }
                },
            )
            .map_err(|_| v031_user_source_gate_error())?;
        if !gate.authenticates_user_physical_file_set(&post_source)
            || !same_v031_user_source_content(expected, &post_source)
        {
            return Err(v031_user_source_gate_error());
        }
        nested
    }

    /// Strictly read-only startup probe. It returns `false` only when the
    /// persisted source manifest, all source-row fingerprints, terminal ledger
    /// targets, and project/case bindings still satisfy the migration contract.
    pub(crate) fn case_material_migration_required(&self) -> Result<bool, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        super::validate_ordinary_database_file(&self.shared.user_database_path)?;
        let user = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| source_snapshot_error())?;
        database::validate_open_user_database(&user).map_err(|_| source_snapshot_error())?;
        assert_read_only_source(&user)?;
        user.execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(|_| source_snapshot_error())?;
        let before = SourceProof::capture(&self.shared.user_database_path, &user)?;
        let result = case_material_migration_required_for_pinned_user(self, &user, &before);
        let after = SourceProof::capture(&self.shared.user_database_path, &user);
        let _ = user.execute_batch("ROLLBACK");
        match (result, after) {
            (Ok(value), Ok(after)) if after == before => Ok(value),
            (Ok(_), Ok(_)) => Err(migration_error(
                "case_material_source_changed",
                "The read-only user database changed during the migration probe.",
            )),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Runs the target backfill after the caller has successfully installed and
    /// verified the coordinated five-component backup and, when necessary,
    /// explicitly upgraded the Privacy store to schema v5.
    #[allow(dead_code)]
    pub(crate) fn run_case_material_migration_after_backup(
        &self,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        let source_fingerprint = self.case_material_migration_source_fingerprint()?;
        self.run_case_material_migration_after_backup_for_source(&source_fingerprint)
    }

    /// Captures only the semantic migration source identity. Unrelated user
    /// database rows do not invalidate a completed migration or a backup token.
    pub(crate) fn case_material_migration_source_fingerprint(
        &self,
    ) -> Result<String, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        super::validate_ordinary_database_file(&self.shared.user_database_path)?;
        let user = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| source_snapshot_error())?;
        database::validate_open_user_database(&user).map_err(|_| source_snapshot_error())?;
        assert_read_only_source(&user)?;
        user.execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(|_| source_snapshot_error())?;
        let before = SourceProof::capture(&self.shared.user_database_path, &user)?;
        let fingerprint = before.persistent_fingerprint();
        let after = SourceProof::capture(&self.shared.user_database_path, &user);
        let _ = user.execute_batch("ROLLBACK");
        match after {
            Ok(after) if after == before => Ok(fingerprint),
            Ok(_) => Err(migration_error(
                "case_material_source_changed",
                "The read-only user database changed while its migration identity was captured.",
            )),
            Err(error) => Err(error),
        }
    }

    /// Runs the backfill only for the exact semantic source identity sealed into
    /// the coordinated backup. The comparison happens inside the pinned user
    /// read transaction before any target database is opened for writes.
    pub(crate) fn run_case_material_migration_after_backup_for_source(
        &self,
        expected_source_fingerprint: &str,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        let schema_status = self.preflight_privacy_store_schema_read_only()?;
        let privacy_schema_ready = matches!(
            schema_status,
            PrivacyStoreSchemaStatus::Current
                | PrivacyStoreSchemaStatus::UpgradeRequired {
                    found_version: CASE_MATERIAL_TARGET_SCHEMA_VERSION
                }
        );
        if !privacy_schema_ready || self.vault_startup_write_required() {
            return Err(migration_error(
                "privacy_store_backup_required",
                "The case-material migration cannot run before the coordinated backup and all required storage schema upgrades.",
            ));
        }

        super::validate_ordinary_database_file(&self.shared.user_database_path)?;
        let user = database::open_user_database_read_only(&self.shared.user_database_path)
            .map_err(|_| {
                migration_error(
                    "case_material_source_unavailable",
                    "The user database could not be opened as a read-only migration source.",
                )
            })?;
        database::validate_open_user_database(&user).map_err(|_| {
            migration_error(
                "case_material_source_schema_invalid",
                "The read-only user database does not match the canonical schema contract.",
            )
        })?;
        assert_read_only_source(&user)?;
        user.execute_batch("BEGIN DEFERRED TRANSACTION")
            .map_err(|_| source_snapshot_error())?;

        let result = (|| {
            let before = SourceProof::capture(&self.shared.user_database_path, &user)?;
            if before.persistent_fingerprint() != expected_source_fingerprint {
                return Err(migration_error(
                    "case_material_backup_source_mismatch",
                    "The migration source no longer matches the semantic identity sealed into the coordinated backup.",
                ));
            }
            let snapshot = UserSnapshot::load(&user)?;
            let mut privacy = match schema_status {
                PrivacyStoreSchemaStatus::Current => self.open_connection()?,
                PrivacyStoreSchemaStatus::UpgradeRequired {
                    found_version: CASE_MATERIAL_TARGET_SCHEMA_VERSION,
                } => self.open_raw_connection()?,
                PrivacyStoreSchemaStatus::Empty
                | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                    return Err(migration_error(
                        "privacy_store_backup_required",
                        "The case-material migration cannot run before the coordinated backup and all required storage schema upgrades.",
                    ));
                }
            };
            preflight_privacy_store(&privacy)?;
            preflight_vault_state(self)?;

            let mut report = run_backfill(
                self,
                &mut privacy,
                &user,
                &self.shared.user_database_path,
                &before,
                &snapshot,
                &self.shared.workspace_instance_id,
            )?;
            report.source_unchanged_verified = true;
            Ok(report)
        })();

        let _ = user.execute_batch("ROLLBACK");
        result
    }

    /// Captures the frozen Step-4 source and both candidate sets while the live
    /// User-v10 and Privacy-v1 sources are simultaneously pinned read-only.
    /// Privacy-v1 is upgraded only inside a private SQLite Backup-API copy so
    /// the exact Step-5 planner can be reused without touching the live source.
    pub(crate) fn v031_case_migration_checkpoint_source_proof(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
    ) -> Result<V031CaseMigrationCheckpointSourceProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        validate_v031_target_components_gate(self, gate, target_gate)?;
        with_v031_pinned_user_snapshot(self, gate, |user, _snapshot_path, source| {
            compute_v031_pre_v5_checkpoint_source_proof(self, gate, target_gate, user, source)
        })
    }

    /// Reconstructs the non-secret Step-4 proof after a process restart from
    /// two already authenticated checkpoint proofs.  This never inspects a
    /// post-upgrade Privacy-v5 store as if it were the original v1 source.
    pub(crate) fn v031_case_migration_checkpoint_source_proof_from_verified_checkpoints(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<V031CaseMigrationCheckpointSourceProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        validate_v031_target_components_gate(self, gate, target_gate)?;
        reconstruct_v031_step4_source_proof_from_authenticated_checkpoints_read_only(
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
        )
    }

    /// Executes the frozen Privacy v1->v5 transition only after the two Step-4
    /// checkpoints have authenticated the exact pre-v5 proof.  On the initial
    /// path the simultaneous live sources are recomputed immediately before
    /// the schema write; schema-v5 is accepted only as an idempotent restart.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        source_proof: &V031CaseMigrationCheckpointSourceProof,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        self.upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints_inner(
            gate,
            target_gate,
            source_proof,
            binding_checkpoint,
            material_checkpoint,
            None,
        )
    }

    #[cfg(test)]
    fn upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints_with_failure(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        source_proof: &V031CaseMigrationCheckpointSourceProof,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
        failure_point: V031PrivacyV5UpgradeFailurePoint,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        self.upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints_inner(
            gate,
            target_gate,
            source_proof,
            binding_checkpoint,
            material_checkpoint,
            Some(failure_point),
        )
    }

    #[cfg(test)]
    pub(crate) fn upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_schema_for_test(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        source_proof: &V031CaseMigrationCheckpointSourceProof,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        self.upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints_with_failure(
            gate,
            target_gate,
            source_proof,
            binding_checkpoint,
            material_checkpoint,
            V031PrivacyV5UpgradeFailurePoint::AfterSchemaCommitBeforeLifecycleInitialize,
        )
    }

    #[cfg(test)]
    pub(crate) fn upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_lifecycle_for_test(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        source_proof: &V031CaseMigrationCheckpointSourceProof,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        self.upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints_with_failure(
            gate,
            target_gate,
            source_proof,
            binding_checkpoint,
            material_checkpoint,
            V031PrivacyV5UpgradeFailurePoint::AfterLifecycleCommitBeforeBindingInitialize,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints_inner(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        source_proof: &V031CaseMigrationCheckpointSourceProof,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
        #[cfg(test)] failure_point: Option<V031PrivacyV5UpgradeFailurePoint>,
        #[cfg(not(test))] _failure_point: Option<()>,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        let reconstructed = reconstruct_v031_step4_source_proof_from_checkpoints(
            self,
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
        )?;
        if &reconstructed != source_proof {
            return Err(v031_checkpoint_source_proof_error());
        }

        match self.preflight_privacy_store_schema_read_only()? {
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 1 } => {
                with_v031_pinned_user_snapshot(self, gate, |user, _snapshot_path, source| {
                    let live = compute_v031_pre_v5_checkpoint_source_proof(
                        self,
                        gate,
                        target_gate,
                        user,
                        source,
                    )?;
                    if &live != source_proof {
                        return Err(v031_checkpoint_source_proof_error());
                    }
                    upgrade_and_initialize_v031_privacy_v5(
                        self,
                        gate,
                        source_proof,
                        #[cfg(test)]
                        failure_point,
                        #[cfg(not(test))]
                        None,
                    )
                })
            }
            PrivacyStoreSchemaStatus::Empty
            | PrivacyStoreSchemaStatus::Current
            | PrivacyStoreSchemaStatus::UpgradeRequired { .. } => {
                Err(v031_privacy_v5_proof_error())
            }
        }
    }

    /// Resumes only a strictly classified pre-binding schema-5 prefix.  The
    /// opaque capability is created and consumed inside this manager gate, so
    /// callers cannot authorize a raw schema-version-5 store or replay a proof
    /// across a workspace/checkpoint identity.
    pub(crate) fn resume_v031_privacy_store_to_v5_after_binding_material_checkpoints(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        source_proof: &V031CaseMigrationCheckpointSourceProof,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        self.resume_v031_privacy_store_to_v5_after_binding_material_checkpoints_inner(
            gate,
            target_gate,
            source_proof,
            binding_checkpoint,
            material_checkpoint,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn resume_v031_privacy_store_to_v5_after_binding_material_checkpoints_inner(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        source_proof: &V031CaseMigrationCheckpointSourceProof,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        let capability = authorize_v031_privacy_v5_partial_resume(
            self,
            gate,
            target_gate,
            source_proof,
            binding_checkpoint,
            material_checkpoint,
        )?;
        resume_and_initialize_v031_privacy_v5(self, &capability, |_| Ok(()))
    }

    /// Executes only the frozen schema-1 to schema-5 portion of the Privacy
    /// upgrade while the exact v0.3.1 user source remains pinned and read-only.
    /// This compatibility helper is test-only; production Step 5 must present
    /// both authenticated Step-4 checkpoints through the method above.
    #[cfg(test)]
    pub(crate) fn upgrade_v031_privacy_store_to_v5_after_original_rollback(
        &self,
        gate: &OriginalRollbackVerifiedGate,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        with_v031_pinned_user_snapshot(self, gate, |_user, _path, _proof| {
            let mut privacy = self.open_raw_connection()?;
            PrivacyStore::upgrade_exact_v031_schema_to_v5_after_backup(&privacy)
                .map_err(PrivacyWorkflowError::store)?;
            PrivacyLifecycle::initialize(
                &mut privacy,
                self.shared.workspace_instance_id.clone(),
                self.current_unix()?,
            )
            .map_err(PrivacyWorkflowError::lifecycle)?;
            ProjectPrivacyCaseBindingStore::initialize(&mut privacy)
                .map_err(PrivacyWorkflowError::project_case_binding)?;
            compute_privacy_v5_manifests_read_only(&privacy)
                .map_err(|_| v031_privacy_v5_proof_error())
        })
    }

    /// Strict Step-5 probe. The active user database is validated and pinned by
    /// the database crate, copied with SQLite Backup API to a private snapshot,
    /// and never opened through a writable handle.
    #[cfg(test)]
    pub(crate) fn v031_case_material_migration_required(
        &self,
        gate: &OriginalRollbackVerifiedGate,
    ) -> Result<bool, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        with_v031_pinned_user_snapshot(self, gate, |user, _path, source| {
            require_exact_privacy_v5(self)?;
            case_material_migration_required_for_pinned_user(self, user, source)
        })
    }

    #[cfg(test)]
    pub(crate) fn v031_case_material_migration_source_fingerprint(
        &self,
        gate: &OriginalRollbackVerifiedGate,
    ) -> Result<V031CaseMaterialSourceFingerprint, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        with_v031_pinned_user_snapshot(self, gate, |_user, _path, source| {
            require_exact_privacy_v5(self)?;
            Ok(v031_source_fingerprint(
                gate,
                gate.original_user_source_proof(),
                source,
            ))
        })
    }

    #[cfg(test)]
    pub(crate) fn run_v031_case_material_migration_after_backup_for_source(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        expected: &V031CaseMaterialSourceFingerprint,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        self.run_v031_case_material_migration_inner(gate, expected)
    }

    #[cfg(test)]
    fn run_v031_case_material_migration_inner(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        expected: &V031CaseMaterialSourceFingerprint,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        with_v031_pinned_user_snapshot(self, gate, |user, snapshot_path, source| {
            require_exact_privacy_v5(self)?;
            let current = v031_source_fingerprint(gate, gate.original_user_source_proof(), source);
            if &current != expected {
                return Err(migration_error(
                    "case_material_backup_source_mismatch",
                    "The exact v0.3.1 migration source no longer matches the authenticated Step-5 checkpoint.",
                ));
            }
            let snapshot = UserSnapshot::load(user)?;
            let mut privacy = self.open_raw_connection()?;
            preflight_privacy_store(&privacy)?;
            preflight_vault_state(self)?;
            let mut report = run_backfill_inner(
                self,
                &mut privacy,
                user,
                snapshot_path,
                source,
                &snapshot,
                &self.shared.workspace_instance_id,
                None,
                None,
            )?;
            compute_privacy_v5_manifests_read_only(&privacy)
                .map_err(|_| v031_privacy_v5_proof_error())?;
            report.source_unchanged_verified = true;
            Ok(report)
        })
    }

    /// Strict Step-5 writer. Both authenticated Step-4 checkpoint proofs are
    /// bound to the Original/target gates and the stable user source before a
    /// writable Privacy handle is opened. Their candidate commitments are
    /// then recomputed inside the IMMEDIATE transaction before its first row
    /// mutation.
    pub(crate) fn run_v031_case_material_migration_after_checkpoints(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        self.run_v031_case_material_migration_after_checkpoints_inner(
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
            None,
        )
    }

    /// Test-only entry into the exact production checkpoint-gated writer. The
    /// injected boundary is carried through the same gate reconstruction,
    /// preflight, transaction, and committed-state path as production.
    #[cfg(test)]
    pub(crate) fn run_v031_case_material_migration_after_checkpoints_with_failure(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
        failure_point: BackfillFailurePoint,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        self.run_v031_case_material_migration_after_checkpoints_inner(
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
            Some(failure_point),
        )
    }

    fn run_v031_case_material_migration_after_checkpoints_inner(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
        failure_point: Option<BackfillFailurePoint>,
    ) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        let checkpoint_source = reconstruct_v031_step4_source_proof_from_checkpoints(
            self,
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
        )?;
        with_v031_pinned_user_snapshot(self, gate, |user, snapshot_path, source| {
            require_exact_privacy_v5(self)?;
            let current = v031_source_fingerprint(gate, gate.original_user_source_proof(), source);
            if current.evidence_sha256 != checkpoint_source.source_fingerprint {
                return Err(v031_checkpoint_source_proof_error());
            }
            let writer_gate = V031BindingMaterialWriterGate {
                source: current,
                candidates: V031CandidateManifests {
                    binding_manifest_sha256: checkpoint_source
                        .binding_candidate_manifest_sha256
                        .clone(),
                    binding_count: checkpoint_source.binding_candidate_count,
                    material_manifest_sha256: checkpoint_source
                        .material_candidate_manifest_sha256
                        .clone(),
                    material_count: checkpoint_source.material_candidate_count,
                },
                binding_checkpoint_identity_sha256: binding_checkpoint
                    .identity_protected_sha256()
                    .to_owned(),
                material_checkpoint_identity_sha256: material_checkpoint
                    .identity_protected_sha256()
                    .to_owned(),
            };
            let snapshot = UserSnapshot::load(user)?;
            let privacy = open_privacy_read_only(&self.shared.database_path)?;
            compute_privacy_v5_manifests_read_only(&privacy)
                .map_err(|_| v031_privacy_v5_proof_error())?;
            preflight_privacy_store(&privacy)?;
            preflight_vault_state(self)?;

            // The production seam validates the complete candidate commitment
            // before the first Privacy IMMEDIATE transaction. The transaction
            // repeats the same validation below to close the TOCTOU window.
            let cleanup = load_cleanup_authorization_snapshot(self, &privacy)?;
            let plans = load_migration_plans(self, &privacy, &snapshot, &cleanup)?;
            let pre_transaction_source = SourceProof::capture(snapshot_path, user)?;
            let pre_transaction_candidates = compute_v031_candidate_manifests(
                &snapshot,
                &pre_transaction_source,
                &plans,
                self.shared.workspace_instance_id.as_str(),
            )?;
            validate_v031_writer_gate(
                &writer_gate,
                &pre_transaction_source,
                &pre_transaction_candidates,
            )?;

            // A crash immediately after commit returns here on restart. Prove
            // terminal state from read-only handles and return without opening
            // a writable Privacy connection or starting another transaction.
            if !case_material_migration_required_for_validated_target(
                self, &privacy, source, &snapshot,
            )? {
                let terminal = compute_v031_terminal_proof_with_privacy_connection(
                    self,
                    user,
                    source,
                    &writer_gate.source,
                    &privacy,
                )?;
                let idempotent_noops = terminal
                    .binding_ledger_rows()
                    .checked_add(terminal.material_ledger_rows())
                    .ok_or_else(v031_terminal_proof_error)?;
                return Ok(CaseMaterialMigrationReport {
                    idempotent_noops,
                    source_unchanged_verified: true,
                    ..CaseMaterialMigrationReport::default()
                });
            }

            inject_backfill_failure(failure_point, BackfillFailurePoint::BeforeTransaction)?;
            drop(privacy);

            let mut privacy = self.open_raw_connection()?;
            compute_privacy_v5_manifests_read_only(&privacy)
                .map_err(|_| v031_privacy_v5_proof_error())?;
            preflight_privacy_store(&privacy)?;
            preflight_vault_state(self)?;

            let mut report = run_backfill_inner(
                self,
                &mut privacy,
                user,
                snapshot_path,
                source,
                &snapshot,
                &self.shared.workspace_instance_id,
                failure_point,
                Some(&writer_gate),
            )?;
            compute_privacy_v5_manifests_read_only(&privacy)
                .map_err(|_| v031_privacy_v5_proof_error())?;
            report.source_unchanged_verified = true;
            Ok(report)
        })
    }

    /// Proves the one exact full-v5 state that may be authenticated by Receipt
    /// 4. Unlike the general v5 manifest loader, this also binds the evolved
    /// rows back to Original V2, requires the target workspace's initial
    /// lifecycle, and rejects every post-v1/binding row before any receipt
    /// write is authorized.
    pub(crate) fn v031_initial_privacy_v5_proof_before_receipt4_read_only(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        let checkpoint_source = reconstruct_v031_step4_source_proof_from_checkpoints(
            self,
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
        )?;
        if checkpoint_source.privacy_v1_business_manifest_sha256
            != gate.original_privacy_business_manifest_sha256()
            || checkpoint_source.privacy_v1_total_rows != gate.original_privacy_total_rows()
        {
            return Err(v031_checkpoint_source_proof_error());
        }
        with_v031_pinned_user_snapshot(self, gate, |_user, _snapshot_path, source| {
            let current = v031_source_fingerprint(gate, gate.original_user_source_proof(), source);
            if current.evidence_sha256 != checkpoint_source.source_fingerprint {
                return Err(v031_checkpoint_source_proof_error());
            }
            let privacy = open_privacy_read_only(&self.shared.database_path)?;
            verify_initial_privacy_v5_before_receipt4_read_only(
                &privacy,
                &PrivacyV5InitialFullExpectation {
                    expected_workspace_instance_id: &self.shared.workspace_instance_id,
                    expected_source_business_manifest_sha256: &checkpoint_source
                        .privacy_v1_business_manifest_sha256,
                    expected_source_total_row_count: checkpoint_source.privacy_v1_total_rows,
                    expected_protected_review_payload_count: gate
                        .original_privacy_protected_review_payload_count(),
                },
            )
            .map(privacy::PrivacyV5InitialFullProof::into_manifest)
            .map_err(|_| v031_privacy_v5_proof_error())
        })
    }

    /// Rebuilds the general exact Privacy-v5 manifest under the same
    /// authenticated Step-4 checkpoint chain without opening either live
    /// database writable. This remains necessary after Receipt 4 because the
    /// authorized binding/material stage legitimately adds v5 business rows.
    pub(crate) fn v031_privacy_v5_manifest_proof_after_checkpoints_read_only(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        let checkpoint_source = reconstruct_v031_step4_source_proof_from_checkpoints(
            self,
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
        )?;
        with_v031_pinned_user_snapshot(self, gate, |_user, _snapshot_path, source| {
            let current = v031_source_fingerprint(gate, gate.original_user_source_proof(), source);
            if current.evidence_sha256 != checkpoint_source.source_fingerprint {
                return Err(v031_checkpoint_source_proof_error());
            }
            require_exact_privacy_v5(self)
        })
    }

    /// Reconstructs the historical Step-5 terminal and Step-6 source proofs
    /// from the DPAPI/V3-authenticated Projection checkpoint images. Both
    /// SQLite images are deserialized read-only into SQLite-owned memory; the
    /// active User/Privacy slots are never consulted as historical v10/v5
    /// sources and are never mutated.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn v031_projection_recovery_proofs_from_verified_checkpoint_images(
        &self,
        rollback_gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
        projection_checkpoint: &V031MigrationCheckpointProof,
        user_v10_image: &[u8],
        privacy_v5_image: &[u8],
    ) -> Result<
        (
            V031BindingMaterialTerminalProof,
            super::approved_case_projection::V031ApprovedProjectionSourceProof,
        ),
        PrivacyWorkflowError,
    > {
        let _operation_guard = self.gate();
        let step4_source = reconstruct_v031_step4_source_proof_from_checkpoints(
            self,
            rollback_gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
        )?;
        if projection_checkpoint.kind() != V031CheckpointKind::Projection
            || projection_checkpoint.lineage_id() != rollback_gate.lineage_id()
            || projection_checkpoint.original_identity_sha256()
                != rollback_gate.original_identity_sha256()
            || projection_checkpoint.workspace_instance_id()
                != target_gate.workspace_instance_id().as_str()
            || projection_checkpoint.user_database_sha256() != sha256_hex(user_v10_image)
            || projection_checkpoint.privacy_database_sha256() != sha256_hex(privacy_v5_image)
        {
            return Err(v031_checkpoint_source_proof_error());
        }

        let verified_user_image = open_verified_v031_user_checkpoint_image_read_only(
            user_v10_image,
            V031UserCheckpointImageExpectations {
                database_sha256: projection_checkpoint.user_database_sha256(),
                schema_manifest_sha256: projection_checkpoint.user_schema_manifest_sha256(),
                logical_manifest_sha256: projection_checkpoint.user_logical_manifest_sha256(),
                business_manifest_sha256: projection_checkpoint.user_business_manifest_sha256(),
                total_rows: projection_checkpoint.user_total_rows(),
                rollback_semantic_proof: rollback_gate.original_user_source_proof(),
            },
        )?;
        let user = verified_user_image.connection();

        let validated_privacy_v5 =
            privacy::validate_privacy_v5_sqlite_image_read_only(privacy_v5_image)
                .map_err(|_| v031_privacy_v5_proof_error())?;
        if validated_privacy_v5.schema_version != 5
            || validated_privacy_v5.logical_manifest.sha256
                != projection_checkpoint.privacy_logical_manifest_sha256()
            || validated_privacy_v5.business_manifest.sha256
                != projection_checkpoint.privacy_business_manifest_sha256()
            || validated_privacy_v5.total_row_count != projection_checkpoint.privacy_total_rows()
        {
            return Err(v031_privacy_v5_proof_error());
        }

        let source = verified_user_image.capture_source_proof()?;
        let source_fingerprint = v031_source_fingerprint(
            rollback_gate,
            rollback_gate.original_user_source_proof(),
            &source,
        );
        if source_fingerprint.evidence_sha256 != step4_source.source_fingerprint {
            return Err(v031_checkpoint_source_proof_error());
        }

        let privacy = open_verified_checkpoint_image_read_only(privacy_v5_image)?;
        let observed_privacy_v5 = compute_privacy_v5_manifests_read_only(&privacy)
            .map_err(|_| v031_privacy_v5_proof_error())?;
        if observed_privacy_v5 != validated_privacy_v5 {
            return Err(v031_privacy_v5_proof_error());
        }
        let step5_terminal = compute_v031_terminal_proof_with_privacy_connection(
            self,
            user,
            &source,
            &source_fingerprint,
            &privacy,
        )?;
        let projection_source = super::approved_case_projection::
            v031_projection_source_proof_from_verified_v5_connection(
                self,
                rollback_gate,
                &step5_terminal,
                projection_checkpoint,
                &privacy,
            )?;

        let post_source = verified_user_image.capture_source_proof()?;
        let post_privacy_v5 = compute_privacy_v5_manifests_read_only(&privacy)
            .map_err(|_| v031_privacy_v5_proof_error())?;
        if post_source.persistent_fingerprint() != source.persistent_fingerprint()
            || post_privacy_v5 != observed_privacy_v5
        {
            return Err(v031_checkpoint_source_proof_error());
        }
        Ok((step5_terminal, projection_source))
    }

    /// Reconstructs receipt-5 counts and evidence exclusively from committed
    /// schema-5 state. Invocation counters are intentionally not accepted.
    #[cfg(test)]
    pub(crate) fn v031_binding_material_terminal_proof(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        expected: &V031CaseMaterialSourceFingerprint,
    ) -> Result<V031BindingMaterialTerminalProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        with_v031_pinned_user_snapshot(self, gate, |user, _snapshot_path, source| {
            let current = v031_source_fingerprint(gate, gate.original_user_source_proof(), source);
            if &current != expected {
                return Err(migration_error(
                    "case_material_backup_source_mismatch",
                    "The exact v0.3.1 source does not match the terminal-proof checkpoint.",
                ));
            }
            require_exact_privacy_v5(self)?;
            if case_material_migration_required_for_pinned_user(self, user, source)? {
                return Err(v031_terminal_proof_error());
            }
            compute_v031_terminal_proof(self, user, source, expected)
        })
    }

    /// Restart-safe receipt-5 proof reconstruction using the two authenticated
    /// Step-4 checkpoints rather than an invocation counter or caller-created
    /// raw source string.
    pub(crate) fn v031_binding_material_terminal_proof_after_checkpoints(
        &self,
        gate: &OriginalRollbackVerifiedGate,
        target_gate: &V031TargetComponentsPreparedGate,
        binding_checkpoint: &V031MigrationCheckpointProof,
        material_checkpoint: &V031MigrationCheckpointProof,
    ) -> Result<V031BindingMaterialTerminalProof, PrivacyWorkflowError> {
        let _operation_guard = self.gate();
        let checkpoint_source = reconstruct_v031_step4_source_proof_from_checkpoints(
            self,
            gate,
            target_gate,
            binding_checkpoint,
            material_checkpoint,
        )?;
        with_v031_pinned_user_snapshot(self, gate, |user, _snapshot_path, source| {
            let current = v031_source_fingerprint(gate, gate.original_user_source_proof(), source);
            if current.evidence_sha256 != checkpoint_source.source_fingerprint {
                return Err(v031_checkpoint_source_proof_error());
            }
            require_exact_privacy_v5(self)?;
            if case_material_migration_required_for_pinned_user(self, user, source)? {
                return Err(v031_terminal_proof_error());
            }
            compute_v031_terminal_proof(self, user, source, &current)
        })
    }
}

fn upgrade_and_initialize_v031_privacy_v5(
    manager: &PrivacyWorkflowManager,
    gate: &OriginalRollbackVerifiedGate,
    source_proof: &V031CaseMigrationCheckpointSourceProof,
    #[cfg(test)] failure_point: Option<V031PrivacyV5UpgradeFailurePoint>,
    #[cfg(not(test))] _failure_point: Option<()>,
) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
    let privacy = manager.open_raw_connection()?;
    PrivacyStore::upgrade_exact_v031_schema_to_v5_after_backup(&privacy)
        .map_err(PrivacyWorkflowError::store)?;
    #[cfg(test)]
    inject_v031_privacy_v5_upgrade_failure(
        failure_point,
        V031PrivacyV5UpgradeFailurePoint::AfterSchemaCommitBeforeLifecycleInitialize,
    )?;
    let partial =
        classify_privacy_v5_partial_read_only(&privacy, &manager.shared.workspace_instance_id)
            .map_err(|_| v031_privacy_v5_proof_error())?;
    validate_v031_partial_source(gate, source_proof, &partial)?;
    let capability = V031PrivacyV5PartialResumeCapability {
        checkpoint_source_evidence_sha256: source_proof.evidence_sha256.clone(),
        workspace_instance_id: manager.shared.workspace_instance_id.as_str().to_owned(),
        partial,
    };
    drop(privacy);
    resume_and_initialize_v031_privacy_v5(manager, &capability, |stage| {
        #[cfg(test)]
        if stage == PrivacyV5PartialStage::LifecycleCommittedBeforeBinding
            && failure_point
                == Some(
                    V031PrivacyV5UpgradeFailurePoint::AfterLifecycleCommitBeforeBindingInitialize,
                )
        {
            return Err(v031_privacy_v5_proof_error());
        }
        #[cfg(not(test))]
        let _ = stage;
        Ok(())
    })
}

#[allow(clippy::too_many_arguments)]
fn authorize_v031_privacy_v5_partial_resume(
    manager: &PrivacyWorkflowManager,
    gate: &OriginalRollbackVerifiedGate,
    target_gate: &V031TargetComponentsPreparedGate,
    source_proof: &V031CaseMigrationCheckpointSourceProof,
    binding_checkpoint: &V031MigrationCheckpointProof,
    material_checkpoint: &V031MigrationCheckpointProof,
) -> Result<V031PrivacyV5PartialResumeCapability, PrivacyWorkflowError> {
    let reconstructed = reconstruct_v031_step4_source_proof_from_checkpoints(
        manager,
        gate,
        target_gate,
        binding_checkpoint,
        material_checkpoint,
    )?;
    if &reconstructed != source_proof
        || source_proof.privacy_v1_business_manifest_sha256
            != gate.original_privacy_business_manifest_sha256()
        || source_proof.privacy_v1_total_rows != gate.original_privacy_total_rows()
    {
        return Err(v031_checkpoint_source_proof_error());
    }

    with_v031_pinned_user_snapshot(manager, gate, |_user, _snapshot_path, source| {
        let current = v031_source_fingerprint(gate, gate.original_user_source_proof(), source);
        if current.evidence_sha256 != source_proof.source_fingerprint {
            return Err(v031_checkpoint_source_proof_error());
        }
        let privacy = open_privacy_read_only(&manager.shared.database_path)?;
        let partial =
            classify_privacy_v5_partial_read_only(&privacy, &manager.shared.workspace_instance_id)
                .map_err(|_| v031_privacy_v5_proof_error())?;
        validate_v031_partial_source(gate, source_proof, &partial)?;
        Ok(V031PrivacyV5PartialResumeCapability {
            checkpoint_source_evidence_sha256: source_proof.evidence_sha256.clone(),
            workspace_instance_id: manager.shared.workspace_instance_id.as_str().to_owned(),
            partial,
        })
    })
}

fn validate_v031_partial_source(
    gate: &OriginalRollbackVerifiedGate,
    source_proof: &V031CaseMigrationCheckpointSourceProof,
    partial: &PrivacyV5PartialProof,
) -> Result<(), PrivacyWorkflowError> {
    if partial.source_business_manifest_sha256() != source_proof.privacy_v1_business_manifest_sha256
        || partial.source_total_row_count() != source_proof.privacy_v1_total_rows
        || partial.protected_review_payload_count()
            != gate.original_privacy_protected_review_payload_count()
    {
        return Err(v031_privacy_v5_proof_error());
    }
    Ok(())
}

fn resume_and_initialize_v031_privacy_v5<F>(
    manager: &PrivacyWorkflowManager,
    capability: &V031PrivacyV5PartialResumeCapability,
    mut before_write: F,
) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError>
where
    F: FnMut(PrivacyV5PartialStage) -> Result<(), PrivacyWorkflowError>,
{
    if capability.workspace_instance_id != manager.shared.workspace_instance_id.as_str()
        || capability.checkpoint_source_evidence_sha256.len() != 64
        || !capability
            .checkpoint_source_evidence_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(v031_checkpoint_source_proof_error());
    }
    let mut privacy = manager.open_raw_connection()?;
    let mut expected = capability.partial.clone();
    if expected.stage() == PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle {
        let transaction = privacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| v031_privacy_v5_proof_error())?;
        let observed = classify_privacy_v5_partial_in_transaction(
            &transaction,
            &manager.shared.workspace_instance_id,
        )
        .map_err(|_| v031_privacy_v5_proof_error())?;
        if observed != expected {
            return Err(v031_privacy_v5_proof_error());
        }
        before_write(PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle)?;
        PrivacyLifecycle::initialize_state_in_transaction(
            &transaction,
            manager.shared.workspace_instance_id.clone(),
            manager.current_unix()?,
        )
        .map_err(PrivacyWorkflowError::lifecycle)?;
        expected = classify_privacy_v5_partial_in_transaction(
            &transaction,
            &manager.shared.workspace_instance_id,
        )
        .map_err(|_| v031_privacy_v5_proof_error())?;
        if expected.stage() != PrivacyV5PartialStage::LifecycleCommittedBeforeBinding
            || expected.source_business_manifest_sha256()
                != capability.partial.source_business_manifest_sha256()
            || expected.source_total_row_count() != capability.partial.source_total_row_count()
            || expected.protected_review_payload_count()
                != capability.partial.protected_review_payload_count()
        {
            return Err(v031_privacy_v5_proof_error());
        }
        transaction
            .commit()
            .map_err(|_| v031_privacy_v5_proof_error())?;
    }

    let transaction = privacy
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| v031_privacy_v5_proof_error())?;
    let observed = classify_privacy_v5_partial_in_transaction(
        &transaction,
        &manager.shared.workspace_instance_id,
    )
    .map_err(|_| v031_privacy_v5_proof_error())?;
    if observed != expected
        || observed.stage() != PrivacyV5PartialStage::LifecycleCommittedBeforeBinding
    {
        return Err(v031_privacy_v5_proof_error());
    }
    before_write(PrivacyV5PartialStage::LifecycleCommittedBeforeBinding)?;
    ProjectPrivacyCaseBindingStore::initialize_in_transaction(&transaction)
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    transaction
        .commit()
        .map_err(|_| v031_privacy_v5_proof_error())?;

    verify_initial_privacy_v5_before_receipt4_read_only(
        &privacy,
        &PrivacyV5InitialFullExpectation {
            expected_workspace_instance_id: &manager.shared.workspace_instance_id,
            expected_source_business_manifest_sha256: capability
                .partial
                .source_business_manifest_sha256(),
            expected_source_total_row_count: capability.partial.source_total_row_count(),
            expected_protected_review_payload_count: capability
                .partial
                .protected_review_payload_count(),
        },
    )
    .map(privacy::PrivacyV5InitialFullProof::into_manifest)
    .map_err(|_| v031_privacy_v5_proof_error())
}

#[cfg(test)]
fn inject_v031_privacy_v5_upgrade_failure(
    requested: Option<V031PrivacyV5UpgradeFailurePoint>,
    boundary: V031PrivacyV5UpgradeFailurePoint,
) -> Result<(), PrivacyWorkflowError> {
    if requested == Some(boundary) {
        Err(v031_privacy_v5_proof_error())
    } else {
        Ok(())
    }
}

fn validate_v031_target_components_gate(
    manager: &PrivacyWorkflowManager,
    rollback: &OriginalRollbackVerifiedGate,
    target: &V031TargetComponentsPreparedGate,
) -> Result<(), PrivacyWorkflowError> {
    if target.workspace_instance_id() != &manager.shared.workspace_instance_id {
        return Err(v031_checkpoint_source_proof_error());
    }
    validate_v031_target_components_gate_path_free(rollback, target)
}

fn validate_v031_target_components_gate_path_free(
    rollback: &OriginalRollbackVerifiedGate,
    target: &V031TargetComponentsPreparedGate,
) -> Result<(), PrivacyWorkflowError> {
    let approved = target.approved_gate();
    let vault = target.vault_gate();
    let hashes = [
        target.target_components_evidence_sha256(),
        target.target_components_receipt_sha256(),
        approved.rollback_gate_binding_sha256(),
        approved.credential_manifest_sha256(),
        approved.approved_workspace_schema_sha256(),
        approved.work_products_schema_sha256(),
        approved.approved_workspace_manifest_sha256(),
        approved.work_products_manifest_sha256(),
        approved.evidence_sha256(),
        vault.rollback_gate_binding_sha256(),
        vault.approved_target_components_evidence_sha256(),
        vault.vault_schema_sha256(),
        vault.vault_database_sha256(),
        vault.vault_layout_sha256(),
        vault.vault_component_manifest_sha256(),
        vault.evidence_sha256(),
    ];
    if !target
        .rollback_gate()
        .authenticates_same_original_rollback(rollback)
        || target.receipt_context() != &rollback.receipt_context()
        || approved.workspace_instance_id() != target.workspace_instance_id()
        || vault.workspace_instance_id() != target.workspace_instance_id()
        || approved.rollback_gate_binding_sha256() != vault.rollback_gate_binding_sha256()
        || approved.evidence_sha256() != vault.approved_target_components_evidence_sha256()
        || approved.credential_count() != 4
        || approved.approved_business_rows() != 0
        || approved.work_product_business_rows() != 0
        || vault.metadata_rows() == 0
        || vault.business_rows() != 0
        || vault.key_record_count() != 0
        || vault.object_root_entry_count() != 0
        || hashes.into_iter().any(|hash| !valid_hash(hash))
    {
        return Err(v031_checkpoint_source_proof_error());
    }
    Ok(())
}

fn v031_target_gate_manifest_sha256(target: &V031TargetComponentsPreparedGate) -> String {
    let approved = target.approved_gate();
    let vault = target.vault_gate();
    let mut manifest = Fingerprint::new(b"v031-target-components-gate-manifest-v1");
    for value in [
        target.target_components_evidence_sha256(),
        target.target_components_receipt_sha256(),
        approved.rollback_gate_binding_sha256(),
        approved.credential_manifest_sha256(),
        approved.approved_workspace_schema_sha256(),
        approved.work_products_schema_sha256(),
        approved.approved_workspace_manifest_sha256(),
        approved.work_products_manifest_sha256(),
        approved.evidence_sha256(),
        vault.vault_schema_sha256(),
        vault.vault_database_sha256(),
        vault.vault_layout_sha256(),
        vault.vault_component_manifest_sha256(),
        vault.evidence_sha256(),
    ] {
        manifest.text(value);
    }
    manifest.finish()
}

fn compute_v031_pre_v5_checkpoint_source_proof(
    manager: &PrivacyWorkflowManager,
    rollback: &OriginalRollbackVerifiedGate,
    target: &V031TargetComponentsPreparedGate,
    user_connection: &Connection,
    user_source: &SourceProof,
) -> Result<V031CaseMigrationCheckpointSourceProof, PrivacyWorkflowError> {
    let user = UserSnapshot::load(user_connection)?;
    let source =
        v031_source_fingerprint(rollback, rollback.original_user_source_proof(), user_source);
    let (post_privacy, nested) = with_validated_privacy_v1_migration_source_read_only(
        &manager.shared.database_path,
        |privacy_session| {
            if !v031_privacy_v1_source_matches_original(rollback, privacy_session.proof()) {
                return Err(v031_checkpoint_source_proof_error());
            }
            compute_v031_candidates_from_isolated_privacy_v1(
                manager,
                privacy_session,
                &user,
                user_source,
            )
        },
    )
    .map_err(|_| v031_checkpoint_source_proof_error())?;
    if !v031_privacy_v1_source_matches_original(rollback, &post_privacy) {
        return Err(v031_checkpoint_source_proof_error());
    }
    let candidates = nested?;
    Ok(build_v031_checkpoint_source_proof(
        rollback,
        target,
        source.evidence_sha256,
        &candidates,
        post_privacy.logical_manifest.sha256,
        post_privacy.business_manifest.sha256,
        post_privacy.logical_manifest.total_row_count,
    ))
}

fn compute_v031_candidates_from_isolated_privacy_v1(
    manager: &PrivacyWorkflowManager,
    privacy_session: &privacy::ValidatedPrivacyV1ReadOnlySession<'_>,
    user: &UserSnapshot,
    user_source: &SourceProof,
) -> Result<V031CandidateManifests, PrivacyWorkflowError> {
    let directory = tempfile::Builder::new()
        .prefix("lawyer-assistance-v031-privacy-planner-")
        .tempdir()
        .map_err(|_| v031_checkpoint_source_proof_error())?;
    let snapshot_path = directory.path().join("privacy-v1-planner.sqlite");
    let mut snapshot = Connection::open_with_flags(
        &snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| v031_checkpoint_source_proof_error())?;
    privacy_session
        .backup_to(&mut snapshot)
        .map_err(|_| v031_checkpoint_source_proof_error())?;
    PrivacyStore::upgrade_exact_v031_schema_to_v5_after_backup(&snapshot)
        .map_err(PrivacyWorkflowError::store)?;
    PrivacyLifecycle::initialize(
        &mut snapshot,
        manager.shared.workspace_instance_id.clone(),
        manager.current_unix()?,
    )
    .map_err(PrivacyWorkflowError::lifecycle)?;
    ProjectPrivacyCaseBindingStore::initialize(&mut snapshot)
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    compute_privacy_v5_manifests_read_only(&snapshot).map_err(|_| v031_privacy_v5_proof_error())?;
    let cleanup = load_cleanup_authorization_snapshot(manager, &snapshot)?;
    if !cleanup.redactions.is_empty() || !cleanup.tombstoned_material_ids.is_empty() {
        return Err(v031_checkpoint_source_proof_error());
    }
    let plans = load_migration_plans(manager, &snapshot, user, &cleanup)?;
    compute_v031_candidate_manifests(
        user,
        user_source,
        &plans,
        manager.shared.workspace_instance_id.as_str(),
    )
}

fn v031_privacy_v1_source_matches_original(
    rollback: &OriginalRollbackVerifiedGate,
    source: &ValidatedPrivacyV1Source,
) -> bool {
    source.schema_version == 1
        && rollback.authenticates_privacy_physical_file_set(source)
        && source.logical_manifest.sha256 == rollback.original_privacy_logical_manifest_sha256()
        && source.business_manifest.sha256 == rollback.original_privacy_business_manifest_sha256()
        && source.logical_manifest.total_row_count == rollback.original_privacy_total_rows()
        && u64::try_from(source.logical_manifest.tables.len()).ok()
            == Some(rollback.original_privacy_table_count())
}

#[allow(clippy::too_many_arguments)]
fn build_v031_checkpoint_source_proof(
    rollback: &OriginalRollbackVerifiedGate,
    target: &V031TargetComponentsPreparedGate,
    source_fingerprint: String,
    candidates: &V031CandidateManifests,
    privacy_v1_logical_manifest_sha256: String,
    privacy_v1_business_manifest_sha256: String,
    privacy_v1_total_rows: u64,
) -> V031CaseMigrationCheckpointSourceProof {
    let target_gate_manifest_sha256 = v031_target_gate_manifest_sha256(target);
    let mut evidence = Fingerprint::new(b"v031-step4-checkpoint-source-proof-v1");
    for value in [
        rollback.lineage_id(),
        rollback.source_profile_proof_sha256(),
        rollback.original_identity_sha256(),
        rollback.original_user_physical_file_set_sha256(),
        rollback.original_privacy_physical_file_set_sha256(),
        source_fingerprint.as_str(),
        candidates.binding_manifest_sha256.as_str(),
        candidates.material_manifest_sha256.as_str(),
        privacy_v1_logical_manifest_sha256.as_str(),
        privacy_v1_business_manifest_sha256.as_str(),
        target_gate_manifest_sha256.as_str(),
    ] {
        evidence.text(value);
    }
    evidence.text(target.workspace_instance_id().as_str());
    evidence.text(&candidates.binding_count.to_string());
    evidence.text(&candidates.material_count.to_string());
    evidence.text(&privacy_v1_total_rows.to_string());
    V031CaseMigrationCheckpointSourceProof {
        evidence_sha256: evidence.finish(),
        source_fingerprint,
        binding_candidate_manifest_sha256: candidates.binding_manifest_sha256.clone(),
        binding_candidate_count: candidates.binding_count,
        material_candidate_manifest_sha256: candidates.material_manifest_sha256.clone(),
        material_candidate_count: candidates.material_count,
        original_user_physical_file_set_sha256: rollback
            .original_user_physical_file_set_sha256()
            .to_owned(),
        original_privacy_physical_file_set_sha256: rollback
            .original_privacy_physical_file_set_sha256()
            .to_owned(),
        privacy_v1_logical_manifest_sha256,
        privacy_v1_business_manifest_sha256,
        privacy_v1_total_rows,
        target_gate_manifest_sha256,
    }
}

fn reconstruct_v031_step4_source_proof_from_checkpoints(
    manager: &PrivacyWorkflowManager,
    rollback: &OriginalRollbackVerifiedGate,
    target: &V031TargetComponentsPreparedGate,
    binding: &V031MigrationCheckpointProof,
    materials: &V031MigrationCheckpointProof,
) -> Result<V031CaseMigrationCheckpointSourceProof, PrivacyWorkflowError> {
    validate_v031_target_components_gate(manager, rollback, target)?;
    reconstruct_v031_step4_source_proof_from_authenticated_checkpoints_read_only(
        rollback, target, binding, materials,
    )
}

/// Reconstructs the exact historical Step-4 source proof from two fully
/// authenticated checkpoint capabilities without consulting a manager or any
/// evolved live component. The target capability must already be rebound to
/// receipt 2 by the startup/checkpoint boundary.
pub(crate) fn reconstruct_v031_step4_source_proof_from_authenticated_checkpoints_read_only(
    rollback: &OriginalRollbackVerifiedGate,
    target: &V031TargetComponentsPreparedGate,
    binding: &V031MigrationCheckpointProof,
    materials: &V031MigrationCheckpointProof,
) -> Result<V031CaseMigrationCheckpointSourceProof, PrivacyWorkflowError> {
    validate_v031_target_components_gate_path_free(rollback, target)?;
    validate_v031_step4_checkpoint_common(rollback, target, binding, V031CheckpointKind::Binding)?;
    validate_v031_step4_checkpoint_common(
        rollback,
        target,
        materials,
        V031CheckpointKind::Materials,
    )?;
    if binding.source_fingerprint() != materials.source_fingerprint()
        || binding.identity_protected_sha256() == materials.identity_protected_sha256()
    {
        return Err(v031_checkpoint_source_proof_error());
    }
    let candidates = V031CandidateManifests {
        binding_manifest_sha256: binding.candidate_manifest_sha256().to_owned(),
        binding_count: binding.candidate_count(),
        material_manifest_sha256: materials.candidate_manifest_sha256().to_owned(),
        material_count: materials.candidate_count(),
    };
    Ok(build_v031_checkpoint_source_proof(
        rollback,
        target,
        binding.source_fingerprint().to_owned(),
        &candidates,
        binding.privacy_logical_manifest_sha256().to_owned(),
        binding.privacy_business_manifest_sha256().to_owned(),
        binding.privacy_total_rows(),
    ))
}

fn validate_v031_step4_checkpoint_common(
    rollback: &OriginalRollbackVerifiedGate,
    target: &V031TargetComponentsPreparedGate,
    checkpoint: &V031MigrationCheckpointProof,
    expected_kind: V031CheckpointKind,
) -> Result<(), PrivacyWorkflowError> {
    let user = rollback.original_user_source_proof();
    let hash_fields = [
        checkpoint.identity_protected_sha256(),
        checkpoint.bundle_sha256(),
        checkpoint.user_database_sha256(),
        checkpoint.user_schema_manifest_sha256(),
        checkpoint.user_logical_manifest_sha256(),
        checkpoint.user_business_manifest_sha256(),
        checkpoint.privacy_database_sha256(),
        checkpoint.privacy_logical_manifest_sha256(),
        checkpoint.privacy_business_manifest_sha256(),
        checkpoint.vault_bundle_sha256(),
        checkpoint.approved_workspace_bundle_sha256(),
        checkpoint.work_products_bundle_sha256(),
        checkpoint.source_fingerprint(),
        checkpoint.candidate_manifest_sha256(),
    ];
    if checkpoint.kind() != expected_kind
        || checkpoint.lineage_id() != rollback.lineage_id()
        || checkpoint.original_identity_sha256() != rollback.original_identity_sha256()
        || checkpoint.workspace_instance_id() != target.workspace_instance_id().as_str()
        || checkpoint.user_schema_manifest_sha256() != user.schema_manifest_sha256
        || checkpoint.user_logical_manifest_sha256() != user.logical_database_manifest_sha256
        || checkpoint.user_business_manifest_sha256() != user.business_manifest_sha256
        || checkpoint.user_total_rows() != user.total_rows
        || checkpoint.privacy_schema_version() != 1
        || checkpoint.privacy_logical_manifest_sha256()
            != rollback.original_privacy_logical_manifest_sha256()
        || checkpoint.privacy_business_manifest_sha256()
            != rollback.original_privacy_business_manifest_sha256()
        || checkpoint.privacy_total_rows() != rollback.original_privacy_total_rows()
        || hash_fields.into_iter().any(|hash| !valid_hash(hash))
    {
        return Err(v031_checkpoint_source_proof_error());
    }
    Ok(())
}

fn opaque_candidate_key_commitment(
    profile: &[u8],
    source_fingerprint: &str,
    value: &str,
) -> String {
    let mut commitment = Fingerprint::new(profile);
    commitment.text(source_fingerprint);
    commitment.text(value);
    commitment.finish()
}

fn compute_v031_candidate_manifests(
    user: &UserSnapshot,
    source: &SourceProof,
    plans: &[PrivacyMaterialPlan],
    workspace_instance_id: &str,
) -> Result<V031CandidateManifests, PrivacyWorkflowError> {
    let source_fingerprint = source.persistent_fingerprint();
    let graph = binding_candidate_graph(user, plans);
    let mut privacy_state_projects = graph.blocked_projects.clone();
    for plan in plans {
        privacy_state_projects.extend(plan.provenance_projects.iter().cloned());
        if let Some(project_id) = plan.source.project_id.as_ref() {
            privacy_state_projects.insert(project_id.clone());
        }
    }

    let mut binding = Fingerprint::new(b"v031-binding-candidate-manifest-v1");
    for project in user.projects.values() {
        ProjectId::parse(project.project_id.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        let cases = graph.cases_by_project.get(project.project_id.as_str());
        let (outcome, historical_case) = if graph.blocked_projects.contains(&project.project_id) {
            ("blocked:ambiguous_legacy_binding", None)
        } else if let Some(case_id) = cases.and_then(|values| {
            (values.len() == 1).then(|| values.first().expect("one historical case was checked"))
        }) {
            ("trusted_historical_binding", Some(case_id.as_str()))
        } else if privacy_state_projects.contains(&project.project_id) {
            ("blocked:project_privacy_case_unbound", None)
        } else {
            // No PrivacyCaseId is generated or derived here. The real writer
            // creates it with the binding store's CSPRNG inside the same
            // transaction that persists the binding, audit, and ledger.
            ("new_random_required", None)
        };
        binding.text("project");
        binding.text(&opaque_candidate_key_commitment(
            b"v031-binding-project-key-v1",
            &source_fingerprint,
            &project.project_id,
        ));
        binding.text(&project_binding_fingerprint(project, cases));
        binding.text(outcome);
        binding.optional_text(
            historical_case
                .map(|case_id| {
                    opaque_candidate_key_commitment(
                        b"v031-binding-historical-case-v1",
                        &source_fingerprint,
                        case_id,
                    )
                })
                .as_deref(),
        );
        binding.text(&opaque_candidate_key_commitment(
            b"v031-binding-ledger-target-v1",
            &source_fingerprint,
            &binding_target_id(&project.project_id),
        ));
    }

    let mut material = Fingerprint::new(b"v031-material-candidate-manifest-v1");
    let mut material_count = 1_u64;
    material.text("source_manifest");
    material.text(&source_fingerprint);
    material.text("migrated");
    for plan in plans {
        material_count = material_count
            .checked_add(1)
            .and_then(|value| value.checked_add(plan.redactions.len() as u64))
            .ok_or_else(v031_checkpoint_source_proof_error)?;
        material.text("privacy_materials");
        material.text(&opaque_candidate_key_commitment(
            b"v031-material-source-key-v1",
            &source_fingerprint,
            &plan.source.material_id,
        ));
        material.text(&privacy_material_fingerprint(&plan.source));
        material.text(plan.validation_error.unwrap_or("candidate"));
        for redaction in &plan.redactions {
            material.text("privacy_redactions");
            material.text(&opaque_candidate_key_commitment(
                b"v031-redaction-source-key-v1",
                &source_fingerprint,
                &redaction.source.redaction_id,
            ));
            material.text(&privacy_redaction_fingerprint(redaction));
            material.text(redaction.generation_status);
            material.optional_text(redaction.error_code);
        }
    }
    for case_file in &user.case_files {
        material_count = material_count
            .checked_add(1)
            .ok_or_else(v031_checkpoint_source_proof_error)?;
        let resolution = user.resolve_attachment(case_file);
        let outcome = match &resolution {
            AttachmentResolution::Exact(_) => "attachment_exact",
            AttachmentResolution::Legacy(error) => error,
            AttachmentResolution::Blocked(error) => error,
        };
        material.text("case_files");
        material.text(&opaque_candidate_key_commitment(
            b"v031-case-file-source-key-v1",
            &source_fingerprint,
            &case_file.file_id,
        ));
        material.text(&case_file_fingerprint(case_file, user, &resolution));
        material.text(outcome);
        material.text(&opaque_candidate_key_commitment(
            b"v031-case-file-target-v1",
            &source_fingerprint,
            &deterministic_case_file_material_id(workspace_instance_id, &case_file.file_id),
        ));
    }

    Ok(V031CandidateManifests {
        binding_manifest_sha256: binding.finish(),
        binding_count: u64::try_from(user.projects.len())
            .map_err(|_| v031_checkpoint_source_proof_error())?,
        material_manifest_sha256: material.finish(),
        material_count,
    })
}

fn case_material_migration_required_for_pinned_user(
    manager: &PrivacyWorkflowManager,
    user: &Connection,
    source: &SourceProof,
) -> Result<bool, PrivacyWorkflowError> {
    let snapshot = UserSnapshot::load(user)?;
    preflight_vault_state(manager)?;
    let schema_status = manager.preflight_privacy_store_schema_read_only()?;
    if schema_status == PrivacyStoreSchemaStatus::Empty {
        preflight_empty_privacy_vault_inventory(manager)?;
        return Ok(true);
    }
    let privacy = open_privacy_read_only(&manager.shared.database_path)?;
    if !manager.startup_vault_present() {
        preflight_missing_vault_privacy_identity(&privacy)?;
    }
    if let PrivacyStoreSchemaStatus::UpgradeRequired { found_version } = schema_status {
        if found_version != CASE_MATERIAL_TARGET_SCHEMA_VERSION {
            preflight_privacy_integrity_and_cleanup(&privacy)?;
            return Ok(true);
        }
    }
    case_material_migration_required_for_validated_target(manager, &privacy, source, &snapshot)
}

fn case_material_migration_required_for_validated_target(
    manager: &PrivacyWorkflowManager,
    privacy: &Connection,
    source: &SourceProof,
    snapshot: &UserSnapshot,
) -> Result<bool, PrivacyWorkflowError> {
    preflight_privacy_store(privacy)?;
    if manager.vault_startup_write_required() {
        return Ok(true);
    }
    if !source_manifest_terminal_matches(privacy, &source.persistent_fingerprint())? {
        return Ok(true);
    }

    let cleanup = load_cleanup_authorization_snapshot(manager, privacy)?;
    let plans = load_migration_plans(manager, privacy, snapshot, &cleanup)?;
    let graph = binding_candidate_graph(snapshot, &plans);
    for plan in &plans {
        if !privacy_plan_terminal_matches(privacy, snapshot, plan, &graph.blocked_projects)? {
            return Ok(true);
        }
    }
    for case_file in &snapshot.case_files {
        if !case_file_terminal_matches(
            manager,
            privacy,
            snapshot,
            manager.shared.workspace_instance_id.as_str(),
            case_file,
        )? {
            return Ok(true);
        }
    }
    for project in snapshot.projects.values() {
        if !project_binding_terminal_matches(
            privacy,
            project,
            graph.cases_by_project.get(project.project_id.as_str()),
        )? {
            return Ok(true);
        }
    }
    validate_target_invariants(privacy, snapshot, &cleanup)?;
    Ok(false)
}

fn with_v031_pinned_user_snapshot<T>(
    manager: &PrivacyWorkflowManager,
    gate: &OriginalRollbackVerifiedGate,
    operation: impl FnOnce(&Connection, &Path, &SourceProof) -> Result<T, PrivacyWorkflowError>,
) -> Result<T, PrivacyWorkflowError> {
    super::validate_ordinary_database_file(&manager.shared.user_database_path)?;
    let expected = gate.original_user_source_proof();
    let (post_source, nested) = database::with_validated_user_database_migration_source_read_only(
        &manager.shared.user_database_path,
        |source_session| {
            if !gate.authenticates_user_physical_file_set(source_session.proof())
                || !same_v031_user_source_content(expected, source_session.proof())
            {
                return Err(v031_user_source_gate_error());
            }
            with_isolated_v031_user_snapshot(source_session, operation)
        },
    )
    .map_err(|_| v031_user_source_gate_error())?;
    if !gate.authenticates_user_physical_file_set(&post_source)
        || !same_v031_user_source_content(expected, &post_source)
    {
        return Err(v031_user_source_gate_error());
    }
    nested
}

fn with_isolated_v031_user_snapshot<T>(
    source_session: &ValidatedUserMigrationSourceSession<'_>,
    operation: impl FnOnce(&Connection, &Path, &SourceProof) -> Result<T, PrivacyWorkflowError>,
) -> Result<T, PrivacyWorkflowError> {
    let directory = tempfile::Builder::new()
        .prefix("lawyer-assistance-v031-user-snapshot-")
        .tempdir()
        .map_err(|_| source_snapshot_error())?;
    let snapshot_path = directory.path().join("user-v031.sqlite");
    let mut destination = Connection::open_with_flags(
        &snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| source_snapshot_error())?;
    source_session
        .backup_to(&mut destination)
        .map_err(|_| source_snapshot_error())?;
    drop(destination);
    super::validate_ordinary_database_file(&snapshot_path)?;
    if ["-wal", "-shm", "-journal"]
        .into_iter()
        .map(|suffix| sqlite_sidecar_sha256(&snapshot_path, suffix))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|proof| proof.is_some())
    {
        return Err(source_snapshot_error());
    }

    let snapshot = Connection::open_with_flags(
        &snapshot_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|_| source_snapshot_error())?;
    snapshot
        .execute_batch(
            "PRAGMA query_only=ON;
             PRAGMA foreign_keys=ON;
             PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| source_snapshot_error())?;
    if database::validate_open_user_database_migration_source_read_only(&snapshot)
        .map_err(|_| v031_user_source_gate_error())?
        != ValidatedUserSourceSchema::V031V10
    {
        return Err(v031_user_source_gate_error());
    }
    assert_read_only_source(&snapshot)?;
    snapshot
        .execute_batch("BEGIN DEFERRED TRANSACTION")
        .map_err(|_| source_snapshot_error())?;
    let before = SourceProof::capture(&snapshot_path, &snapshot)?;
    let result = operation(&snapshot, &snapshot_path, &before);
    let after = SourceProof::capture(&snapshot_path, &snapshot);
    let _ = snapshot.execute_batch("ROLLBACK");
    match (result, after) {
        (Ok(value), Ok(after)) if after == before => Ok(value),
        (Ok(_), Ok(_)) => Err(migration_error(
            "case_material_source_changed",
            "The isolated exact-v0.3.1 user snapshot changed during Step 5.",
        )),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn same_v031_user_source_content(
    expected: &UserMigrationSourceProof,
    actual: &UserMigrationSourceProof,
) -> bool {
    expected.schema == ValidatedUserSourceSchema::V031V10
        && actual.schema == ValidatedUserSourceSchema::V031V10
        && expected.schema_manifest_sha256 == actual.schema_manifest_sha256
        && expected.logical_database_manifest_sha256 == actual.logical_database_manifest_sha256
        && expected.business_manifest_sha256 == actual.business_manifest_sha256
        && expected.business_primary_key_manifest_sha256
            == actual.business_primary_key_manifest_sha256
        && expected.business_row_manifest_sha256 == actual.business_row_manifest_sha256
        && expected.tables == actual.tables
        && expected.total_rows == actual.total_rows
}

fn v031_source_fingerprint(
    gate: &OriginalRollbackVerifiedGate,
    user_source: &UserMigrationSourceProof,
    case_source: &SourceProof,
) -> V031CaseMaterialSourceFingerprint {
    let migration_source_fingerprint = case_source.persistent_fingerprint();
    let mut fingerprint = Fingerprint::new(b"v031-case-material-source-gate-v1");
    fingerprint.text(gate.lineage_id());
    fingerprint.text(gate.source_profile_proof_sha256());
    fingerprint.text(gate.original_identity_sha256());
    fingerprint.text(gate.original_user_physical_file_set_sha256());
    fingerprint.text(gate.original_privacy_physical_file_set_sha256());
    fingerprint.text(&user_source.schema_manifest_sha256);
    fingerprint.text(&user_source.logical_database_manifest_sha256);
    fingerprint.text(&user_source.business_manifest_sha256);
    fingerprint.text(&user_source.business_primary_key_manifest_sha256);
    fingerprint.text(&user_source.business_row_manifest_sha256);
    fingerprint.text(&user_source.total_rows.to_string());
    // `PRAGMA data_version` is scoped to the observing SQLite connection. A
    // fresh read-only connection after process restart can therefore report a
    // different value for the exact same durable source. It remains useful as
    // an in-connection change detector while capturing the proof, but it must
    // not be sealed into a restart-persistent checkpoint identity.
    fingerprint.text(&migration_source_fingerprint);
    V031CaseMaterialSourceFingerprint {
        evidence_sha256: fingerprint.finish(),
        migration_source_fingerprint,
    }
}

fn require_exact_privacy_v5(
    manager: &PrivacyWorkflowManager,
) -> Result<PrivacyV5ManifestProof, PrivacyWorkflowError> {
    let privacy = open_privacy_read_only(&manager.shared.database_path)?;
    compute_privacy_v5_manifests_read_only(&privacy).map_err(|_| v031_privacy_v5_proof_error())
}

fn compute_v031_terminal_proof(
    manager: &PrivacyWorkflowManager,
    user_connection: &Connection,
    source: &SourceProof,
    source_fingerprint: &V031CaseMaterialSourceFingerprint,
) -> Result<V031BindingMaterialTerminalProof, PrivacyWorkflowError> {
    let privacy = open_privacy_read_only(&manager.shared.database_path)?;
    compute_v031_terminal_proof_with_privacy_connection(
        manager,
        user_connection,
        source,
        source_fingerprint,
        &privacy,
    )
}

fn compute_v031_terminal_proof_with_privacy_connection(
    manager: &PrivacyWorkflowManager,
    user_connection: &Connection,
    source: &SourceProof,
    source_fingerprint: &V031CaseMaterialSourceFingerprint,
    privacy: &Connection,
) -> Result<V031BindingMaterialTerminalProof, PrivacyWorkflowError> {
    let user = UserSnapshot::load(user_connection)?;
    let privacy_v5 = compute_privacy_v5_manifests_read_only(privacy)
        .map_err(|_| v031_privacy_v5_proof_error())?;
    let cleanup = load_cleanup_authorization_snapshot(manager, privacy)?;
    if !cleanup.redactions.is_empty() || !cleanup.tombstoned_material_ids.is_empty() {
        return Err(v031_terminal_proof_error());
    }
    let plans = load_migration_plans(manager, privacy, &user, &cleanup)?;

    let expected_binding = user
        .projects
        .keys()
        .map(|project_id| TerminalLedgerKey {
            migration_id: PROJECT_CASE_BINDING_MIGRATION_ID.to_owned(),
            source_store: SOURCE_STORE_USER.to_owned(),
            source_table: "projects".to_owned(),
            source_key: project_id.clone(),
        })
        .collect::<BTreeSet<_>>();
    let mut expected_material = BTreeSet::from([TerminalLedgerKey {
        migration_id: CASE_MATERIAL_MIGRATION_ID.to_owned(),
        source_store: SOURCE_STORE_USER.to_owned(),
        source_table: "source_manifest".to_owned(),
        source_key: SOURCE_STORE_USER.to_owned(),
    }]);
    for plan in &plans {
        expected_material.insert(TerminalLedgerKey {
            migration_id: CASE_MATERIAL_MIGRATION_ID.to_owned(),
            source_store: SOURCE_STORE_PRIVACY.to_owned(),
            source_table: "privacy_materials".to_owned(),
            source_key: plan.source.material_id.clone(),
        });
        for redaction in &plan.redactions {
            expected_material.insert(TerminalLedgerKey {
                migration_id: CASE_MATERIAL_MIGRATION_ID.to_owned(),
                source_store: SOURCE_STORE_PRIVACY.to_owned(),
                source_table: "privacy_redactions".to_owned(),
                source_key: redaction.source.redaction_id.clone(),
            });
        }
    }
    for case_file in &user.case_files {
        expected_material.insert(TerminalLedgerKey {
            migration_id: CASE_MATERIAL_MIGRATION_ID.to_owned(),
            source_store: SOURCE_STORE_USER.to_owned(),
            source_table: "case_files".to_owned(),
            source_key: case_file.file_id.clone(),
        });
    }

    let actual = load_all_terminal_ledger_keys(privacy)?;
    let actual_binding = actual
        .iter()
        .filter(|key| key.migration_id == PROJECT_CASE_BINDING_MIGRATION_ID)
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual_material = actual
        .iter()
        .filter(|key| key.migration_id == CASE_MATERIAL_MIGRATION_ID)
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_binding != expected_binding
        || actual_material != expected_material
        || actual.len() != actual_binding.len() + actual_material.len()
    {
        return Err(v031_terminal_proof_error());
    }

    let mut blocked_rows = 0_u64;
    for key in &actual_binding {
        let (_, effective_result) = effective_ledger_state(
            privacy,
            &key.migration_id,
            &key.source_store,
            &key.source_table,
            &key.source_key,
        )?
        .ok_or_else(v031_terminal_proof_error)?;
        if !matches!(effective_result.as_str(), "migrated" | "blocked") {
            return Err(v031_terminal_proof_error());
        }
    }
    for key in &actual_material {
        let (_, effective_result) = effective_ledger_state(
            privacy,
            &key.migration_id,
            &key.source_store,
            &key.source_table,
            &key.source_key,
        )?
        .ok_or_else(v031_terminal_proof_error)?;
        match effective_result.as_str() {
            "migrated" | "legacy_reference" => {}
            "blocked" => {
                blocked_rows = blocked_rows
                    .checked_add(1)
                    .ok_or_else(v031_terminal_proof_error)?;
            }
            _ => return Err(v031_terminal_proof_error()),
        }
    }

    let bindings_verified = validate_all_audited_bindings_read_only(privacy)?;
    let binding_ledger_rows =
        u64::try_from(actual_binding.len()).map_err(|_| v031_terminal_proof_error())?;
    let material_ledger_rows =
        u64::try_from(actual_material.len()).map_err(|_| v031_terminal_proof_error())?;
    let terminal_rows = material_ledger_rows;
    if blocked_rows > terminal_rows || bindings_verified > binding_ledger_rows {
        return Err(v031_terminal_proof_error());
    }

    let ledger_manifest_sha256 = query_manifest(
        privacy,
        "SELECT migration_id,source_store,source_table,source_key,source_fingerprint,
                target_material_id,target_redaction_id,assigned_generation_number,
                result_state,error_code,started_at,completed_at
         FROM case_material_migration_ledger
         ORDER BY migration_id,source_store,source_table,source_key",
        12,
    )?;
    let event_manifest_sha256 = query_manifest(
        privacy,
        "SELECT migration_event_id,migration_id,source_store,source_table,source_key,
                event_type,source_fingerprint,target_material_id,target_redaction_id,
                assigned_generation_number,result_state,error_code,occurred_at
         FROM case_material_migration_events
         ORDER BY migration_id,source_store,source_table,source_key,rowid",
        13,
    )?;
    let binding_manifest_sha256 = query_manifest(
        privacy,
        "SELECT project_id,privacy_case_id,binding_version,creation_source,
                creation_audit_id,migration_id,created_at,updated_at
         FROM project_privacy_case_bindings
         ORDER BY project_id",
        8,
    )?;
    let audit_manifest_sha256 = query_manifest(
        privacy,
        "SELECT creation_audit_id,project_id,privacy_case_id,binding_version,
                creation_source,migration_id,result,created_at
         FROM project_privacy_case_binding_audit
         ORDER BY creation_audit_id",
        8,
    )?;
    let mut terminal = Fingerprint::new(b"v031-binding-material-terminal-proof-v1");
    terminal.text(source_fingerprint.evidence_sha256());
    terminal.text(&source.persistent_fingerprint());
    terminal.text(&privacy_v5.schema_manifest_sha256);
    terminal.text(&privacy_v5.logical_manifest.sha256);
    terminal.text(&privacy_v5.business_manifest.sha256);
    terminal.text(&ledger_manifest_sha256);
    terminal.text(&event_manifest_sha256);
    terminal.text(&binding_manifest_sha256);
    terminal.text(&audit_manifest_sha256);
    for count in [
        binding_ledger_rows,
        material_ledger_rows,
        terminal_rows,
        blocked_rows,
        1,
        bindings_verified,
    ] {
        let count = i64::try_from(count).map_err(|_| v031_terminal_proof_error())?;
        terminal.integer(count);
    }

    Ok(V031BindingMaterialTerminalProof {
        source_evidence_sha256: source_fingerprint.evidence_sha256.clone(),
        privacy_v5,
        binding_ledger_rows,
        material_ledger_rows,
        terminal_rows,
        blocked_rows,
        privacy_migration_batches: 1,
        bindings_verified,
        terminal_manifest_sha256: terminal.finish(),
    })
}

fn load_all_terminal_ledger_keys(
    connection: &Connection,
) -> Result<BTreeSet<TerminalLedgerKey>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT migration_id,source_store,source_table,source_key
             FROM case_material_migration_ledger
             ORDER BY migration_id,source_store,source_table,source_key",
        )
        .map_err(|_| v031_terminal_proof_error())?;
    let rows = statement
        .query_map([], |row| {
            Ok(TerminalLedgerKey {
                migration_id: row.get(0)?,
                source_store: row.get(1)?,
                source_table: row.get(2)?,
                source_key: row.get(3)?,
            })
        })
        .map_err(|_| v031_terminal_proof_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| v031_terminal_proof_error())?;
    let set = rows.iter().cloned().collect::<BTreeSet<_>>();
    if set.len() != rows.len() {
        return Err(v031_terminal_proof_error());
    }
    Ok(set)
}

fn validate_all_audited_bindings_read_only(
    connection: &Connection,
) -> Result<u64, PrivacyWorkflowError> {
    let bindings = {
        let mut statement = connection
            .prepare(
                "SELECT project_id,privacy_case_id
                 FROM project_privacy_case_bindings
                 ORDER BY project_id",
            )
            .map_err(|_| v031_terminal_proof_error())?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| v031_terminal_proof_error())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| v031_terminal_proof_error())?;
        rows
    };
    for (project_value, case_value) in &bindings {
        let project =
            ProjectId::parse(project_value.clone()).map_err(|_| v031_terminal_proof_error())?;
        let case_id =
            PrivacyCaseId::parse(case_value.clone()).map_err(|_| v031_terminal_proof_error())?;
        if ProjectPrivacyCaseBindingStore::resolve(connection, &project)
            .map_err(|_| v031_terminal_proof_error())?
            .as_ref()
            != Some(&case_id)
            || ProjectPrivacyCaseBindingStore::reverse_resolve(connection, &case_id)
                .map_err(|_| v031_terminal_proof_error())?
                .as_ref()
                != Some(&project)
            || ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, &case_id)
                .is_err()
        {
            return Err(v031_terminal_proof_error());
        }
    }
    let (binding_count, distinct_projects, distinct_cases, distinct_audits, audit_count, orphaned) =
        connection
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM project_privacy_case_bindings),
                   (SELECT COUNT(DISTINCT project_id) FROM project_privacy_case_bindings),
                   (SELECT COUNT(DISTINCT privacy_case_id) FROM project_privacy_case_bindings),
                   (SELECT COUNT(DISTINCT creation_audit_id) FROM project_privacy_case_bindings),
                   (SELECT COUNT(*) FROM project_privacy_case_binding_audit),
                   (SELECT COUNT(*)
                    FROM project_privacy_case_binding_audit AS audit
                    LEFT JOIN project_privacy_case_bindings AS binding
                      ON binding.creation_audit_id=audit.creation_audit_id
                     AND binding.project_id=audit.project_id
                     AND binding.privacy_case_id=audit.privacy_case_id
                    WHERE binding.project_id IS NULL)",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(|_| v031_terminal_proof_error())?;
    if binding_count < 0
        || binding_count != distinct_projects
        || binding_count != distinct_cases
        || binding_count != distinct_audits
        || binding_count != audit_count
        || orphaned != 0
        || usize::try_from(binding_count).ok() != Some(bindings.len())
    {
        return Err(v031_terminal_proof_error());
    }
    u64::try_from(binding_count).map_err(|_| v031_terminal_proof_error())
}

impl SourceProof {
    fn capture(path: &Path, connection: &Connection) -> Result<Self, PrivacyWorkflowError> {
        Ok(Self {
            file_sha256: file_sha256(path)?,
            schema_manifest_sha256: case_material_source_schema_manifest(connection)?,
            project_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT project_id FROM projects ORDER BY project_id",
            )?,
            case_file_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT file_id FROM case_files ORDER BY file_id",
            )?,
            attachment_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT attachment_id FROM attachments ORDER BY attachment_id",
            )?,
            source_rows_sha256: source_rows_manifest(connection)?,
            wal_file_sha256: sqlite_sidecar_sha256(path, "-wal")?,
            data_version: connection
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| source_snapshot_error())?,
        })
    }

    fn capture_verified_image(
        verified_image: &VerifiedV031UserCheckpointImage,
    ) -> Result<Self, PrivacyWorkflowError> {
        let proof = &verified_image.proof;
        let connection = &verified_image.connection;
        if proof.schema != ValidatedUserSourceSchema::V031V10
            || !valid_hash(&proof.database_file.sha256)
            || proof.schema_manifest_sha256 != database::V031_USER_SCHEMA_MANIFEST_SHA256
            || proof.database_file.modified_unix_nanos.is_some()
            || proof.wal.is_some()
            || proof.shm.is_some()
            || proof.journal.is_some()
        {
            return Err(source_snapshot_error());
        }
        let query_only = connection
            .pragma_query_value(None, "query_only", |row| row.get::<_, i64>(0))
            .map_err(|_| source_snapshot_error())?;
        if query_only != 1 {
            return Err(source_snapshot_error());
        }
        Ok(Self {
            file_sha256: proof.database_file.sha256.clone(),
            schema_manifest_sha256: case_material_source_schema_contract(proof.schema)?,
            project_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT project_id FROM projects ORDER BY project_id",
            )?,
            case_file_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT file_id FROM case_files ORDER BY file_id",
            )?,
            attachment_primary_keys_sha256: primary_key_manifest(
                connection,
                "SELECT attachment_id FROM attachments ORDER BY attachment_id",
            )?,
            source_rows_sha256: source_rows_manifest(connection)?,
            wal_file_sha256: None,
            data_version: connection
                .pragma_query_value(None, "data_version", |row| row.get(0))
                .map_err(|_| source_snapshot_error())?,
        })
    }

    fn persistent_fingerprint(&self) -> String {
        let mut fingerprint = Fingerprint::new(b"user-source-manifest");
        fingerprint.text(&self.schema_manifest_sha256);
        fingerprint.text(&self.project_primary_keys_sha256);
        fingerprint.text(&self.case_file_primary_keys_sha256);
        fingerprint.text(&self.attachment_primary_keys_sha256);
        fingerprint.text(&self.source_rows_sha256);
        fingerprint.finish()
    }
}

impl UserSnapshot {
    fn load(connection: &Connection) -> Result<Self, PrivacyWorkflowError> {
        let projects = {
            let mut statement = connection
                .prepare(
                    "SELECT project_id,title,case_type,status,opened_on,summary,created_at,updated_at
                     FROM projects ORDER BY project_id",
                )
                .map_err(|_| source_snapshot_error())?;
            let collected = statement
                .query_map([], |row| {
                    let source = ProjectSource {
                        project_id: row.get(0)?,
                        title: row.get(1)?,
                        case_type: row.get(2)?,
                        status: row.get(3)?,
                        opened_on: row.get(4)?,
                        summary: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                    };
                    Ok((source.project_id.clone(), source))
                })
                .map_err(|_| source_snapshot_error())?
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map_err(|_| source_snapshot_error())?;
            collected
        };
        let case_files = {
            let mut statement = connection
                .prepare(
                    "SELECT file_id,project_id,title,file_type,storage_reference,summary,created_at
                     FROM case_files ORDER BY file_id",
                )
                .map_err(|_| source_snapshot_error())?;
            let collected = statement
                .query_map([], |row| {
                    Ok(CaseFileSource {
                        file_id: row.get(0)?,
                        project_id: row.get(1)?,
                        title: row.get(2)?,
                        file_type: row.get(3)?,
                        storage_reference: row.get(4)?,
                        summary: row.get(5)?,
                        created_at: row.get(6)?,
                    })
                })
                .map_err(|_| source_snapshot_error())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| source_snapshot_error())?;
            collected
        };
        let attachments = {
            let mut statement = connection
                .prepare(
                    "SELECT attachment_id,project_id,original_name,extension,detected_mime,sha256,
                            size_bytes,extraction_status,extracted_text,segments_json,error_code,
                            created_at
                     FROM attachments ORDER BY attachment_id",
                )
                .map_err(|_| source_snapshot_error())?;
            let collected = statement
                .query_map([], |row| {
                    let extracted_text = row.get::<_, Option<String>>(8)?;
                    let segments_json = row.get::<_, String>(9)?;
                    let source = AttachmentSource {
                        attachment_id: row.get(0)?,
                        project_id: row.get(1)?,
                        original_name: row.get(2)?,
                        extension: row.get(3)?,
                        detected_mime: row.get(4)?,
                        sha256: row.get(5)?,
                        size_bytes: row.get(6)?,
                        extraction_status: row.get(7)?,
                        extracted_text_sha256: extracted_text
                            .as_deref()
                            .map(|value| sha256_hex(value.as_bytes())),
                        segments_json_sha256: sha256_hex(segments_json.as_bytes()),
                        error_code: row.get(10)?,
                        created_at: row.get(11)?,
                    };
                    Ok((source.attachment_id.clone(), source))
                })
                .map_err(|_| source_snapshot_error())?
                .collect::<Result<BTreeMap<_, _>, _>>()
                .map_err(|_| source_snapshot_error())?;
            collected
        };
        Ok(Self {
            projects,
            case_files,
            attachments,
        })
    }

    fn exact_attachment_provenance_projects(
        &self,
        source_sha256: &str,
        source_name_sha256: &str,
    ) -> BTreeSet<String> {
        let attachment_ids = self
            .attachments
            .values()
            .filter(|attachment| {
                attachment.sha256 == source_sha256
                    && sha256_hex(attachment.original_name.as_bytes()) == source_name_sha256
            })
            .map(|attachment| attachment.attachment_id.as_str())
            .collect::<BTreeSet<_>>();
        self.case_files
            .iter()
            .filter_map(|case_file| {
                let resolution = self.resolve_attachment(case_file);
                match resolution {
                    AttachmentResolution::Exact(attachment)
                        if attachment_ids.contains(attachment.attachment_id.as_str()) =>
                    {
                        Some(case_file.project_id.clone())
                    }
                    _ => None,
                }
            })
            .collect()
    }

    fn resolve_attachment<'a>(&'a self, case_file: &CaseFileSource) -> AttachmentResolution<'a> {
        let raw = case_file.storage_reference.as_str();
        if raw.is_empty() {
            return AttachmentResolution::Legacy("legacy_reference_empty");
        }
        let candidates = attachment_reference_candidate_ids(raw)
            .into_iter()
            .filter_map(|identifier| self.attachments.get(identifier))
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return AttachmentResolution::Legacy("legacy_reference_unresolved");
        }
        if candidates.len() != 1 {
            return AttachmentResolution::Blocked("attachment_reference_ambiguous");
        }
        let attachment = candidates[0];
        match attachment.project_id.as_deref() {
            Some(owner) if owner == case_file.project_id => AttachmentResolution::Exact(attachment),
            Some(_) => AttachmentResolution::Blocked("attachment_project_conflict"),
            None => AttachmentResolution::Blocked("attachment_owner_unknown"),
        }
    }
}

fn assert_read_only_source(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    let query_only: i64 = connection
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .map_err(|_| source_snapshot_error())?;
    if query_only != 1 || !connection.is_autocommit() {
        return Err(source_snapshot_error());
    }
    Ok(())
}

fn preflight_privacy_store(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    if !matches!(
        PrivacyStore::preflight_schema(connection).map_err(PrivacyWorkflowError::store)?,
        PrivacyStoreSchemaStatus::Current
            | PrivacyStoreSchemaStatus::UpgradeRequired {
                found_version: CASE_MATERIAL_TARGET_SCHEMA_VERSION
            }
    ) {
        return Err(migration_error(
            "privacy_store_schema_upgrade_required",
            "The case-material coordinator accepts only the backed-up unified Privacy schema.",
        ));
    }
    preflight_privacy_integrity_and_cleanup(connection)?;
    let orphaned: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM privacy_redactions AS redaction
                LEFT JOIN privacy_materials AS material
                  ON material.material_id=redaction.material_id
                WHERE material.material_id IS NULL
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    let vault_conflict =
        if optional_v5_auxiliary_table_present(connection, "privacy_vault_material_refs")? {
            connection
                .query_row(
                    "SELECT EXISTS(
                    SELECT 1
                    FROM privacy_vault_material_refs AS vault
                    JOIN privacy_materials AS material
                      ON material.material_id=vault.material_id
                    WHERE vault.source_sha256<>material.source_sha256
                       OR vault.object_version<=0
                       OR vault.import_state NOT IN(
                           'vault_committed','review_ready','processing_failed','revoked'
                       )
                 )",
                    [],
                    |row| row.get(0),
                )
                .map_err(|_| privacy_preflight_error())?
        } else {
            false
        };
    if orphaned || vault_conflict {
        return Err(privacy_preflight_error());
    }
    Ok(())
}

fn preflight_privacy_integrity_and_cleanup(
    connection: &Connection,
) -> Result<(), PrivacyWorkflowError> {
    let integrity = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .map_err(|_| privacy_preflight_error())?;
    if integrity != "ok" {
        return Err(privacy_preflight_error());
    }
    let mut foreign_keys = connection
        .prepare("PRAGMA foreign_key_check")
        .map_err(|_| privacy_preflight_error())?;
    if foreign_keys
        .query([])
        .map_err(|_| privacy_preflight_error())?
        .next()
        .map_err(|_| privacy_preflight_error())?
        .is_some()
    {
        return Err(privacy_preflight_error());
    }
    let cleanup_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='privacy_cleanup_journal'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    let pending_cleanup = cleanup_table_exists
        && connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM privacy_cleanup_journal WHERE state='prepared'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| cleanup_preflight_error())?;
    if pending_cleanup {
        return Err(cleanup_pending_error());
    }
    Ok(())
}

fn preflight_vault_state(manager: &PrivacyWorkflowManager) -> Result<(), PrivacyWorkflowError> {
    if !manager.startup_vault_present() {
        return Ok(());
    }
    let status = manager
        .shared
        .vault_broker
        .inspect_cleanup_status_read_only()
        .map_err(|_| cleanup_preflight_error())?;
    if status.has_unfinished_cleanup() {
        return Err(cleanup_pending_error());
    }
    let isolation = manager
        .shared
        .vault_broker
        .isolation_status()
        .map_err(PrivacyWorkflowError::vault)?;
    validate_vault_isolation(&isolation)?;
    Ok(())
}

fn preflight_empty_privacy_vault_inventory(
    manager: &PrivacyWorkflowManager,
) -> Result<(), PrivacyWorkflowError> {
    let inventory = manager
        .shared
        .vault_broker
        .inspect_inventory_read_only()
        .map_err(PrivacyWorkflowError::vault)?;
    if !inventory.is_empty() {
        return Err(migration_error(
            "case_material_unbound_vault_inventory",
            "An existing non-empty Vault cannot be paired with an empty Privacy identity store.",
        ));
    }
    Ok(())
}

fn preflight_missing_vault_privacy_identity(
    connection: &Connection,
) -> Result<(), PrivacyWorkflowError> {
    let vault_ref_table_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type='table' AND name='privacy_vault_material_refs'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    if vault_ref_table_exists {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_vault_material_refs",
                [],
                |row| row.get(0),
            )
            .map_err(|_| privacy_preflight_error())?;
        if count != 0 {
            return Err(missing_vault_history_error());
        }
    }
    let material_source_kind_exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM pragma_table_info('privacy_materials')
                WHERE name='source_kind'
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    if material_source_kind_exists {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM privacy_materials WHERE source_kind='vault'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| privacy_preflight_error())?;
        if count != 0 {
            return Err(missing_vault_history_error());
        }
    }
    let mut statement = connection
        .prepare("SELECT redaction_id FROM privacy_redactions ORDER BY redaction_id")
        .map_err(|_| privacy_preflight_error())?;
    let redaction_ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| privacy_preflight_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_preflight_error())?;
    drop(statement);
    for redaction_id in redaction_ids {
        let loaded = PrivacyStore::load_review_draft(connection, &redaction_id)
            .map_err(|_| missing_vault_history_error())?;
        let payload: StoredReviewPayload = serde_json::from_slice(&loaded.review_payload_plaintext)
            .map_err(|_| missing_vault_history_error())?;
        if payload.vault_object_id.is_some()
            || payload.vault_object_version.is_some()
            || payload.vault_isolation.is_some()
        {
            return Err(missing_vault_history_error());
        }
    }
    Ok(())
}

fn open_privacy_read_only(path: &Path) -> Result<Connection, PrivacyWorkflowError> {
    super::validate_ordinary_database_file(path)?;
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| privacy_migration_store_error())?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA query_only=ON;
             PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let query_only: i64 = connection
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .map_err(|_| privacy_migration_store_error())?;
    if query_only != 1 {
        return Err(privacy_migration_store_error());
    }
    Ok(connection)
}

fn open_verified_checkpoint_image_read_only(
    sqlite_image: &[u8],
) -> Result<Connection, PrivacyWorkflowError> {
    let mut connection = Connection::open_in_memory().map_err(|_| source_snapshot_error())?;
    connection
        .deserialize_read_exact(
            rusqlite::MAIN_DB,
            Cursor::new(sqlite_image),
            sqlite_image.len(),
            true,
        )
        .map_err(|_| source_snapshot_error())?;
    connection
        .execute_batch(
            "PRAGMA foreign_keys=ON;
             PRAGMA query_only=ON;
             PRAGMA trusted_schema=OFF;",
        )
        .map_err(|_| source_snapshot_error())?;
    let query_only: i64 = connection
        .pragma_query_value(None, "query_only", |row| row.get(0))
        .map_err(|_| source_snapshot_error())?;
    if query_only != 1 {
        return Err(source_snapshot_error());
    }
    Ok(connection)
}

fn open_verified_v031_user_checkpoint_image_read_only(
    sqlite_image: &[u8],
    expected: V031UserCheckpointImageExpectations<'_>,
) -> Result<VerifiedV031UserCheckpointImage, PrivacyWorkflowError> {
    let proof = database::validate_v031_user_sqlite_image_read_only(sqlite_image)
        .map_err(|_| v031_user_source_gate_error())?;
    let image_length = u64::try_from(sqlite_image.len()).map_err(|_| source_snapshot_error())?;
    if proof.schema != ValidatedUserSourceSchema::V031V10
        || proof.database_file.sha256 != expected.database_sha256
        || proof.database_file.sha256 != sha256_hex(sqlite_image)
        || proof.database_file.length != image_length
        || proof.database_file.modified_unix_nanos.is_some()
        || !valid_hash(&proof.database_file.identity_sha256)
        || proof.wal.is_some()
        || proof.shm.is_some()
        || proof.journal.is_some()
        || proof.schema_manifest_sha256 != database::V031_USER_SCHEMA_MANIFEST_SHA256
        || proof.schema_manifest_sha256 != expected.schema_manifest_sha256
        || proof.logical_database_manifest_sha256 != expected.logical_manifest_sha256
        || proof.business_manifest_sha256 != expected.business_manifest_sha256
        || proof.total_rows != expected.total_rows
        || !same_v031_user_source_content(expected.rollback_semantic_proof, &proof)
    {
        return Err(v031_user_source_gate_error());
    }
    let connection = open_verified_checkpoint_image_read_only(sqlite_image)?;
    Ok(VerifiedV031UserCheckpointImage { connection, proof })
}

fn run_backfill(
    manager: &PrivacyWorkflowManager,
    privacy: &mut Connection,
    user_connection: &Connection,
    user_database_path: &Path,
    expected_source_proof: &SourceProof,
    user: &UserSnapshot,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
    run_backfill_inner(
        manager,
        privacy,
        user_connection,
        user_database_path,
        expected_source_proof,
        user,
        workspace_instance_id,
        None,
        None,
    )
}

fn validate_v031_writer_gate(
    writer_gate: &V031BindingMaterialWriterGate,
    current_source: &SourceProof,
    current_candidates: &V031CandidateManifests,
) -> Result<(), PrivacyWorkflowError> {
    if current_candidates != &writer_gate.candidates
        || current_source.persistent_fingerprint()
            != writer_gate.source.migration_source_fingerprint
        || !valid_hash(&writer_gate.binding_checkpoint_identity_sha256)
        || !valid_hash(&writer_gate.material_checkpoint_identity_sha256)
        || writer_gate.binding_checkpoint_identity_sha256
            == writer_gate.material_checkpoint_identity_sha256
    {
        return Err(v031_checkpoint_source_proof_error());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_backfill_inner(
    manager: &PrivacyWorkflowManager,
    privacy: &mut Connection,
    user_connection: &Connection,
    user_database_path: &Path,
    expected_source_proof: &SourceProof,
    user: &UserSnapshot,
    workspace_instance_id: &privacy::vnext::WorkspaceInstanceId,
    failure_point: Option<BackfillFailurePoint>,
    v031_writer_gate: Option<&V031BindingMaterialWriterGate>,
) -> Result<CaseMaterialMigrationReport, PrivacyWorkflowError> {
    let transaction = privacy
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| privacy_migration_store_error())?;
    let cleanup = load_cleanup_authorization_snapshot(manager, &transaction)?;
    let mut plans = load_migration_plans(manager, &transaction, user, &cleanup)?;
    if let Some(writer_gate) = v031_writer_gate {
        let current_source = SourceProof::capture(user_database_path, user_connection)?;
        let current = compute_v031_candidate_manifests(
            user,
            &current_source,
            &plans,
            workspace_instance_id.as_str(),
        )?;
        validate_v031_writer_gate(writer_gate, &current_source, &current)?;
    }
    let mut report = CaseMaterialMigrationReport::default();

    let blocked_binding_projects =
        backfill_recovered_bindings(&transaction, user, &plans, &mut report)?;

    for plan in &mut plans {
        migrate_privacy_material(
            manager,
            &transaction,
            user,
            plan,
            &blocked_binding_projects,
            &mut report,
        )?;
    }

    create_bindings_for_projects_without_privacy_state(
        &transaction,
        user,
        &plans,
        &blocked_binding_projects,
        &mut report,
    )?;
    inject_backfill_failure(failure_point, BackfillFailurePoint::AfterProjectBindings)?;

    for case_file in &user.case_files {
        migrate_case_file(
            manager,
            &transaction,
            user,
            workspace_instance_id.as_str(),
            case_file,
            &mut report,
        )?;
    }
    validate_target_invariants(&transaction, user, &cleanup)?;
    preflight_vault_state(manager)?;
    for binding in plans
        .iter()
        .filter_map(|plan| plan.source.vault_binding.as_ref())
    {
        validate_vault_binding_content(manager, binding)?;
    }
    let final_source_proof = SourceProof::capture(user_database_path, user_connection)?;
    if &final_source_proof != expected_source_proof {
        return Err(migration_error(
            "case_material_source_changed",
            "The read-only user database changed during migration; the complete target transaction was rolled back.",
        ));
    }
    record_source_manifest(&transaction, &final_source_proof, &mut report)?;
    inject_backfill_failure(failure_point, BackfillFailurePoint::BeforeCommit)?;
    transaction
        .commit()
        .map_err(|_| privacy_migration_store_error())?;
    // Keep this boundary immediately adjacent to commit: an injected error is
    // returned to the command coordinator before it can append Receipt 5.
    inject_backfill_failure(failure_point, BackfillFailurePoint::AfterCommit)?;
    Ok(report)
}

fn load_privacy_sources(
    connection: &Connection,
) -> Result<Vec<PrivacyMaterialSource>, PrivacyWorkflowError> {
    let vault_links_present =
        optional_v5_auxiliary_table_present(connection, "privacy_vault_material_refs")?;
    let mut material_statement = connection
        .prepare(
            "SELECT material_id,project_id,legacy_case_id,attachment_id,
                    protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,
                    media_type,page_count,source_kind,extraction_status,migration_status,
                    state,row_version,created_at,updated_at,deleted_at
             FROM privacy_materials
             ORDER BY material_id",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let material_rows = material_statement
        .query_map([], |row| {
            Ok(PrivacyMaterialSource {
                material_id: row.get(0)?,
                project_id: row.get(1)?,
                legacy_case_id: row.get(2)?,
                attachment_id: row.get(3)?,
                protected_display_name: row.get(4)?,
                display_name_sha256: row.get(5)?,
                display_name_protection_scheme: row.get(6)?,
                source_sha256: row.get(7)?,
                source_name_sha256: row.get(8)?,
                media_type: row.get(9)?,
                page_count: row.get(10)?,
                source_kind: row.get(11)?,
                extraction_status: row.get(12)?,
                migration_status: row.get(13)?,
                state: row.get(14)?,
                row_version: row.get(15)?,
                created_at: row.get(16)?,
                updated_at: row.get(17)?,
                deleted_at: row.get(18)?,
                vault_binding: None,
                redactions: Vec::new(),
            })
        })
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    drop(material_statement);

    let mut sources = Vec::with_capacity(material_rows.len());
    for mut material in material_rows {
        material.vault_binding = if vault_links_present {
            vault_broker::load_vault_binding_for_material(connection, &material.material_id)
                .map_err(PrivacyWorkflowError::vault)?
        } else {
            None
        };
        let mut redaction_statement = connection
            .prepare(
                "SELECT redaction_id,material_id,generation_number,generation_status,
                        extraction_sha256,redacted_content_sha256,approved_payload_sha256,
                        policy_id,policy_version,detector_version,unresolved_high_risk_count,
                        review_state,risk_revision,protected_review_blob,protection_scheme,
                        reviewed_by_sha256,approved_at,revocation_state,revoked_at,row_version,
                        created_at,reviewed_at
                 FROM privacy_redactions
                 WHERE material_id=?1
                 ORDER BY generation_number,redaction_id",
            )
            .map_err(|_| privacy_migration_store_error())?;
        material.redactions = redaction_statement
            .query_map([&material.material_id], |row| {
                Ok(PrivacyRedactionSource {
                    redaction_id: row.get(0)?,
                    material_id: row.get(1)?,
                    generation_number: row.get(2)?,
                    generation_status: row.get(3)?,
                    extraction_sha256: row.get(4)?,
                    redacted_content_sha256: row.get(5)?,
                    approved_payload_sha256: row.get(6)?,
                    policy_id: row.get(7)?,
                    policy_version: row.get(8)?,
                    detector_version: row.get(9)?,
                    unresolved_high_risk_count: row.get(10)?,
                    review_state: row.get(11)?,
                    risk_revision: row.get(12)?,
                    protected_review_blob: row.get(13)?,
                    protection_scheme: row.get(14)?,
                    reviewed_by_sha256: row.get(15)?,
                    approved_at: row.get(16)?,
                    revocation_state: row.get(17)?,
                    revoked_at: row.get(18)?,
                    row_version: row.get(19)?,
                    created_at: row.get(20)?,
                    reviewed_at: row.get(21)?,
                })
            })
            .map_err(|_| privacy_migration_store_error())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| privacy_migration_store_error())?;
        sources.push(material);
    }
    Ok(sources)
}

fn load_migration_plans(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    user: &UserSnapshot,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<Vec<PrivacyMaterialPlan>, PrivacyWorkflowError> {
    let mut plans = Vec::new();
    for source in load_privacy_sources(connection)?
        .into_iter()
        .filter(|source| matches!(source.source_kind.as_str(), "vault" | "local_review"))
    {
        if completed_project_deletion_tombstone(connection, user, &source, cleanup)?
            || completed_retention_tombstone(connection, user, &source, cleanup)?
        {
            continue;
        }
        plans.push(validate_privacy_material(
            manager, connection, user, source,
        )?);
    }
    Ok(plans)
}

fn load_cleanup_authorization_snapshot(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
) -> Result<CleanupAuthorizationSnapshot, PrivacyWorkflowError> {
    let lifecycle =
        PrivacyLifecycle::open(connection, manager.shared.workspace_instance_id.clone())
            .map_err(|_| migration_target_mismatch())?;
    let verified = lifecycle
        .cleanup_authorization_snapshot(connection)
        .map_err(|_| migration_target_mismatch())?;
    let mut redactions = BTreeMap::new();
    for entry in verified.redactions {
        if redactions
            .insert(
                entry.redaction_id,
                (entry.material_id, entry.generation_number),
            )
            .is_some()
        {
            return Err(migration_target_mismatch());
        }
    }
    Ok(CleanupAuthorizationSnapshot {
        redactions,
        tombstoned_material_ids: verified.tombstoned_material_ids.into_iter().collect(),
    })
}

fn historical_vault_ref(
    connection: &Connection,
    material_id: &str,
) -> Result<Option<HistoricalVaultRef>, PrivacyWorkflowError> {
    if !optional_v5_auxiliary_table_present(connection, "privacy_vault_material_refs")? {
        return Ok(None);
    }
    connection
        .query_row(
            "SELECT case_id,object_id,object_version,source_sha256,envelope_sha256,
                    content_bytes,import_state,failure_code
             FROM privacy_vault_material_refs
             WHERE material_id=?1",
            [material_id],
            |row| {
                Ok(HistoricalVaultRef {
                    case_id: row.get(0)?,
                    object_id: row.get(1)?,
                    object_version: row.get(2)?,
                    source_sha256: row.get(3)?,
                    envelope_sha256: row.get(4)?,
                    content_bytes: row.get(5)?,
                    import_state: row.get(6)?,
                    failure_code: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())
}

fn valid_historical_vault_ref(source: &PrivacyMaterialSource, vault: &HistoricalVaultRef) -> bool {
    PrivacyCaseId::parse(vault.case_id.clone()).is_ok()
        && valid_prefixed_hex_id(&vault.object_id, "obj_")
        && vault.object_version > 0
        && valid_hash(&vault.source_sha256)
        && valid_hash(&vault.envelope_sha256)
        && vault.content_bytes > 0
        && source.source_sha256.as_deref() == Some(vault.source_sha256.as_str())
}

fn valid_prefixed_hex_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + 32
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn completed_retention_tombstone(
    connection: &Connection,
    user: &UserSnapshot,
    source: &PrivacyMaterialSource,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<bool, PrivacyWorkflowError> {
    if !source.redactions.is_empty()
        || source.state != "revoked"
        || source
            .deleted_at
            .as_deref()
            .is_none_or(|value| !sqlite_datetime_is_valid(connection, value))
    {
        return Ok(false);
    }
    let ledger_references_material: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM case_material_migration_ledger
                WHERE migration_id=?1 AND target_material_id=?2
             )",
            params![CASE_MATERIAL_MIGRATION_ID, source.material_id],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if !ledger_references_material {
        return Ok(false);
    }
    if source.protected_display_name.is_some()
        || source.display_name_sha256.is_some()
        || source.display_name_protection_scheme.is_some()
    {
        return Err(migration_target_mismatch());
    }
    if !cleanup
        .tombstoned_material_ids
        .contains(&source.material_id)
    {
        return Err(migration_target_mismatch());
    }
    let vault = historical_vault_ref(connection, &source.material_id)?;
    match (source.source_kind.as_str(), vault.as_ref()) {
        ("vault", Some(vault))
            if valid_historical_vault_ref(source, vault)
                && vault.import_state == "revoked"
                && vault.failure_code.as_deref() == Some("retention_expired") => {}
        ("local_review", None) => {}
        _ => return Err(migration_target_mismatch()),
    }
    if let Some(project_value) = source.project_id.as_deref() {
        if !user.projects.contains_key(project_value) {
            return Err(migration_target_mismatch());
        }
        let project = ProjectId::parse(project_value.to_owned())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id = ProjectPrivacyCaseBindingStore::resolve(connection, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .ok_or_else(migration_target_mismatch)?;
        ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, &case_id)
            .map_err(|_| migration_target_mismatch())?;
        if source
            .legacy_case_id
            .as_deref()
            .is_some_and(|legacy| legacy != case_id.as_str())
        {
            return Err(migration_target_mismatch());
        }
        if vault
            .as_ref()
            .is_some_and(|vault| vault.case_id != case_id.as_str())
        {
            return Err(migration_target_mismatch());
        }
    }
    if let Some(legacy_case_id) = source.legacy_case_id.as_deref() {
        if PrivacyCaseId::parse(legacy_case_id.to_owned()).is_err()
            || vault
                .as_ref()
                .is_some_and(|vault| legacy_case_id != vault.case_id)
        {
            return Err(migration_target_mismatch());
        }
    }
    Ok(true)
}

fn completed_project_deletion_tombstone(
    connection: &Connection,
    user: &UserSnapshot,
    source: &PrivacyMaterialSource,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<bool, PrivacyWorkflowError> {
    let Some(project_value) = source.project_id.as_deref() else {
        return Ok(false);
    };
    if user.projects.contains_key(project_value) {
        return Ok(false);
    }
    if !optional_v5_auxiliary_table_present(connection, "project_deletion_journal")? {
        return Ok(false);
    }
    let journal = connection
        .query_row(
            "SELECT privacy_case_id,scope_json,scope_sha256,state,completed_at_unix
             FROM project_deletion_journal
             WHERE project_id=?1",
            [project_value],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| migration_target_mismatch())?
        .ok_or_else(migration_target_mismatch)?;
    if journal.3 != "completed" || journal.4.is_none() {
        return Err(migration_target_mismatch());
    }
    let scope = serde_json::from_str::<ProjectDeletionEvidenceScope>(&journal.1)
        .map_err(|_| migration_target_mismatch())?;
    let canonical_scope = serde_json::to_vec(&scope).map_err(|_| migration_target_mismatch())?;
    if canonical_scope != journal.1.as_bytes()
        || sha256_hex(&canonical_scope) != journal.2
        || scope.schema_version != "project-deletion-journal-v1"
        || scope.project_id != project_value
        || scope.privacy_case_id != journal.0
        || !strictly_sorted_unique_scope(&scope.material_ids)
        || !strictly_sorted_unique_scope(&scope.generation_ids)
        || scope
            .material_ids
            .iter()
            .chain(scope.generation_ids.iter())
            .any(|value| !valid_scope_identifier(value))
        || !scope.material_ids.contains(&source.material_id)
    {
        return Err(migration_target_mismatch());
    }
    let case_value = scope
        .privacy_case_id
        .as_deref()
        .ok_or_else(migration_target_mismatch)?;
    let project = ProjectId::parse(project_value.to_owned())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    let case_id = PrivacyCaseId::parse(case_value.to_owned())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    if ProjectPrivacyCaseBindingStore::resolve(connection, &project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
        .as_ref()
        != Some(&case_id)
        || ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, &case_id).is_err()
        || source.state != "revoked"
        || source
            .deleted_at
            .as_deref()
            .is_none_or(|value| !sqlite_datetime_is_valid(connection, value))
        || source
            .legacy_case_id
            .as_deref()
            .is_some_and(|legacy| legacy != case_value)
    {
        return Err(migration_target_mismatch());
    }
    let current_materials = collect_string_set(
        connection,
        "SELECT material_id FROM privacy_materials
         WHERE project_id=?1 ORDER BY material_id",
        project_value,
    )?;
    let current_generations = collect_string_set(
        connection,
        "SELECT generation.redaction_id
         FROM privacy_redactions AS generation
         JOIN privacy_materials AS material
           ON material.material_id=generation.material_id
         WHERE material.project_id=?1
         ORDER BY generation.redaction_id",
        project_value,
    )?;
    let mut covered_generations = current_generations.clone();
    if scope
        .generation_ids
        .iter()
        .any(|redaction_id| !current_generations.contains(redaction_id))
    {
        for redaction_id in scope
            .generation_ids
            .iter()
            .filter(|redaction_id| !current_generations.contains(*redaction_id))
        {
            let evidence = cleanup
                .redactions
                .get(redaction_id)
                .ok_or_else(migration_target_mismatch)?;
            if !scope.material_ids.contains(&evidence.0) {
                return Err(migration_target_mismatch());
            }
            covered_generations.insert(redaction_id.clone());
        }
    }
    if current_materials != scope.material_ids.iter().cloned().collect()
        || covered_generations != scope.generation_ids.iter().cloned().collect()
    {
        return Err(migration_target_mismatch());
    }
    let retention_cleanup_authorized = source.redactions.is_empty()
        && cleanup
            .tombstoned_material_ids
            .contains(&source.material_id);
    if retention_cleanup_authorized
        && (source.protected_display_name.is_some()
            || source.display_name_sha256.is_some()
            || source.display_name_protection_scheme.is_some())
    {
        return Err(migration_target_mismatch());
    }
    let vault = historical_vault_ref(connection, &source.material_id)?;
    match (source.source_kind.as_str(), vault.as_ref()) {
        ("vault", Some(vault))
            if valid_historical_vault_ref(source, vault)
                && vault.case_id == case_value
                && vault.import_state == "revoked"
                && (vault.failure_code.as_deref() == Some("project_deleted")
                    || (vault.failure_code.as_deref() == Some("retention_expired")
                        && retention_cleanup_authorized)) => {}
        ("local_review", None) => {}
        _ => return Err(migration_target_mismatch()),
    }
    validate_project_deletion_payloads(connection, source, case_value, vault.as_ref())?;
    Ok(true)
}

fn validate_project_deletion_payloads(
    connection: &Connection,
    source: &PrivacyMaterialSource,
    case_id: &str,
    vault: Option<&HistoricalVaultRef>,
) -> Result<(), PrivacyWorkflowError> {
    let existing_display = decode_existing_display_name(source)?;
    let mut payload_displays = BTreeSet::new();
    for redaction in &source.redactions {
        let revocation_valid = match (
            redaction.revocation_state.as_str(),
            redaction.revoked_at.as_deref(),
        ) {
            ("revoked", Some(value)) => sqlite_datetime_is_valid(connection, value),
            ("revoked_legacy_time_unknown", None) => true,
            _ => false,
        };
        if !revocation_valid {
            return Err(migration_target_mismatch());
        }
        let loaded = PrivacyStore::load_review_draft(connection, &redaction.redaction_id)
            .map_err(|_| migration_target_mismatch())?;
        let payload =
            serde_json::from_slice::<StoredReviewPayload>(&loaded.review_payload_plaintext)
                .map_err(|_| migration_target_mismatch())?;
        if validate_loaded_review(&loaded, &payload).is_err()
            || payload.schema_version != REVIEW_PAYLOAD_SCHEMA_VERSION
            || payload.case_id.as_deref() != Some(case_id)
            || payload.source_sha256 != source.source_sha256.as_deref().unwrap_or("")
            || payload.media_type != source.media_type.as_deref().unwrap_or("")
            || source.page_count != Some(i64::from(payload.page_count))
            || payload.page_count as usize != payload.pages.len()
        {
            return Err(migration_target_mismatch());
        }
        match vault {
            Some(vault)
                if payload.vault_object_id.as_deref() == Some(vault.object_id.as_str())
                    && payload.vault_object_version == u64::try_from(vault.object_version).ok() => {
            }
            None if payload.vault_object_id.is_none() && payload.vault_object_version.is_none() => {
            }
            _ => return Err(migration_target_mismatch()),
        }
        payload_displays.insert(payload.source_display_name.clone());
        let verified_risk_revision =
            validate_risk_revision_chain(connection, &redaction.redaction_id)?;
        if redaction.review_state == "approved" {
            validate_approved_generation(
                connection,
                redaction,
                &payload,
                Some(verified_risk_revision),
            )?;
        }
    }
    if payload_displays.len() > 1
        || payload_displays
            .first()
            .is_some_and(|display| existing_display.as_deref() != Some(display.as_str()))
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn collect_string_set(
    connection: &Connection,
    query: &str,
    parameter: &str,
) -> Result<BTreeSet<String>, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(query)
        .map_err(|_| migration_target_mismatch())?;
    let values = statement
        .query_map([parameter], |row| row.get::<_, String>(0))
        .map_err(|_| migration_target_mismatch())?
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|_| migration_target_mismatch())?;
    Ok(values)
}

fn strictly_sorted_unique_scope(values: &[String]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str())
}

fn valid_scope_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_privacy_material(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    user: &UserSnapshot,
    source: PrivacyMaterialSource,
) -> Result<PrivacyMaterialPlan, PrivacyWorkflowError> {
    let mut validation_error = None;
    let mut redactions = Vec::with_capacity(source.redactions.len());
    let mut case_values = BTreeSet::new();
    let mut display_values = BTreeSet::new();
    let mut vault_tuples = BTreeSet::new();
    let mut exact_v031_missing_display_count = 0_usize;
    let mut exact_v031_assigned_missing_display_count = 0_usize;
    let mut invalid_current_display_count = 0_usize;

    if source
        .source_sha256
        .as_deref()
        .is_none_or(|value| !valid_hash(value))
        || source
            .source_name_sha256
            .as_deref()
            .is_none_or(|value| !valid_hash(value))
        || source.media_type.as_deref().is_none_or(str::is_empty)
    {
        validation_error = Some("privacy_material_source_invalid");
    }

    for redaction_source in source.redactions.iter().cloned() {
        let mut generation_error = None;
        let loaded = PrivacyStore::load_review_draft(connection, &redaction_source.redaction_id);
        let payload = match loaded {
            Ok(loaded) => {
                let exact_v031_payload =
                    is_exact_v031_stored_review_payload(&loaded.review_payload_plaintext);
                let decoded =
                    serde_json::from_slice::<StoredReviewPayload>(&loaded.review_payload_plaintext);
                match decoded {
                    Ok(payload) => {
                        if validate_loaded_review(&loaded, &payload).is_err()
                            || payload.schema_version != REVIEW_PAYLOAD_SCHEMA_VERSION
                            || payload.source_sha256
                                != source.source_sha256.as_deref().unwrap_or("")
                            || payload.media_type != source.media_type.as_deref().unwrap_or("")
                            || source.page_count != Some(i64::from(payload.page_count))
                            || payload.page_count as usize != payload.pages.len()
                        {
                            generation_error = Some("privacy_payload_mismatch");
                            None
                        } else {
                            if let Some(case_id) = payload.case_id.as_deref() {
                                case_values.insert(case_id.to_owned());
                            }
                            let exact_v031_assigned_payload =
                                payload.case_id.as_deref().is_some_and(|case_id| {
                                    is_exact_v031_assigned_review_payload(
                                        &loaded.review_payload_plaintext,
                                        case_id,
                                    )
                                });
                            if exact_v031_payload && payload.source_display_name.is_empty() {
                                exact_v031_missing_display_count += 1;
                            } else if exact_v031_assigned_payload
                                && payload.source_display_name.is_empty()
                            {
                                exact_v031_assigned_missing_display_count += 1;
                            } else {
                                if payload.source_display_name.is_empty() {
                                    invalid_current_display_count += 1;
                                }
                                display_values.insert(payload.source_display_name.clone());
                            }
                            vault_tuples.insert((
                                payload.case_id.clone(),
                                payload.vault_object_id.clone(),
                                payload.vault_object_version,
                                payload.source_sha256.clone(),
                            ));
                            let vault_identity_valid = if source.vault_binding.is_some() {
                                manager
                                    .verify_stored_vault_source(connection, &payload)
                                    .is_ok()
                            } else {
                                payload.vault_object_id.is_none()
                                    && payload.vault_object_version.is_none()
                                    && payload.vault_isolation.is_none()
                            };
                            if !vault_identity_valid {
                                generation_error = Some("privacy_vault_binding_invalid");
                            }
                            Some(payload)
                        }
                    }
                    Err(_) => {
                        generation_error = Some("privacy_payload_invalid");
                        None
                    }
                }
            }
            Err(_) => {
                generation_error = Some("privacy_payload_unprotect_failed");
                None
            }
        };

        let verified_risk_revision =
            match validate_risk_revision_chain(connection, &redaction_source.redaction_id) {
                Ok(revision) => Some(revision),
                Err(_) => {
                    generation_error.get_or_insert("privacy_risk_chain_invalid");
                    None
                }
            };

        if let Some(payload) = payload.as_ref() {
            if redaction_source.review_state == "approved"
                && validate_approved_generation(
                    connection,
                    &redaction_source,
                    payload,
                    verified_risk_revision,
                )
                .is_err()
            {
                generation_error.get_or_insert("privacy_approved_generation_invalid");
            }
        } else if redaction_source.review_state == "approved" {
            generation_error.get_or_insert("privacy_approved_generation_invalid");
        }
        let revocation_valid = match (
            redaction_source.review_state.as_str(),
            redaction_source.revocation_state.as_str(),
            redaction_source.revoked_at.as_deref(),
        ) {
            ("revoked", "revoked_legacy_time_unknown", None) => true,
            (_, "active", None) if redaction_source.review_state != "revoked" => true,
            (_, "revoked", Some(value)) => sqlite_datetime_is_valid(connection, value),
            _ => false,
        };
        if !revocation_valid {
            generation_error.get_or_insert("privacy_generation_revocation_invalid");
        }

        let generation_status = if generation_error.is_some() {
            "blocked"
        } else if !valid_redaction_id(&redaction_source.redaction_id) {
            "legacy_id"
        } else {
            "ready"
        };
        if generation_error.is_some() {
            validation_error.get_or_insert("privacy_material_generation_invalid");
        }
        redactions.push(ValidatedRedaction {
            source: redaction_source,
            verified_risk_revision,
            generation_status,
            error_code: generation_error,
        });
    }

    if case_values.len() > 1 || display_values.len() > 1 || vault_tuples.len() > 1 {
        validation_error = Some("privacy_material_payload_conflict");
    }
    let privacy_case_id = if case_values.len() == 1 {
        let value = case_values
            .first()
            .expect("one case value was checked")
            .clone();
        match PrivacyCaseId::parse(value) {
            Ok(case_id) => Some(case_id),
            Err(_) => {
                validation_error = Some("privacy_case_id_invalid");
                None
            }
        }
    } else {
        source
            .vault_binding
            .as_ref()
            .map(|binding| PrivacyCaseId::from(binding.case_id.clone()))
    };
    let authenticated_assigned_v031_missing_display = if exact_v031_assigned_missing_display_count
        == source.redactions.len()
        && !source.redactions.is_empty()
        && exact_v031_missing_display_count == 0
        && invalid_current_display_count == 0
    {
        match privacy_case_id.as_ref() {
            Some(case_id) => authenticates_assigned_exact_v031_missing_display_source(
                connection, &source, case_id,
            )?,
            None => false,
        }
    } else {
        false
    };
    if invalid_current_display_count > 0
        || (exact_v031_assigned_missing_display_count > 0
            && !authenticated_assigned_v031_missing_display)
        || (exact_v031_missing_display_count > 0
            && exact_v031_missing_display_count != source.redactions.len())
    {
        validation_error = Some("privacy_display_name_invalid");
    }

    if let (Some(legacy), Some(case_id)) =
        (source.legacy_case_id.as_deref(), privacy_case_id.as_ref())
    {
        if legacy != case_id.as_str() {
            validation_error = Some("privacy_legacy_case_conflict");
        }
    }
    if let (Some(vault), Some(case_id)) = (source.vault_binding.as_ref(), privacy_case_id.as_ref())
    {
        if vault.case_id.as_str() != case_id.as_str()
            || source.source_sha256.as_deref() != Some(vault.source_sha256.as_str())
        {
            validation_error = Some("privacy_vault_binding_invalid");
        } else if validate_vault_binding_content(manager, vault).is_err() {
            validation_error = Some("privacy_vault_source_invalid");
        }
    } else if source.vault_binding.is_some() != privacy_case_id.is_some()
        && source.vault_binding.is_some()
    {
        validation_error = Some("privacy_vault_case_missing");
    }

    let display_name = if display_values.len() == 1 {
        display_values.first().cloned().filter(|value| {
            !value.is_empty() && value.len() <= 4_096 && !value.chars().any(char::is_control)
        })
    } else {
        None
    };
    let display_name = match (
        decode_existing_display_name(&source),
        display_name,
        source.redactions.is_empty(),
    ) {
        (Ok(Some(existing)), Some(payload), _) if existing != payload => {
            validation_error = Some("privacy_display_name_conflict");
            Some(existing)
        }
        (Ok(Some(existing)), _, _) => Some(existing),
        (Ok(None), payload @ Some(_), _) => payload,
        (Ok(None), None, true) => None,
        (Ok(None), None, false)
            if exact_v031_missing_display_count == source.redactions.len()
                || authenticated_assigned_v031_missing_display =>
        {
            None
        }
        (Ok(None), None, false) => {
            validation_error = Some("privacy_display_name_invalid");
            None
        }
        (Err(_), _, _) => {
            validation_error = Some("privacy_display_name_invalid");
            None
        }
    };

    let provenance_projects = if validation_error.is_none() {
        match (
            source.source_sha256.as_deref(),
            source.source_name_sha256.as_deref(),
        ) {
            (Some(source_hash), Some(name_hash)) => {
                user.exact_attachment_provenance_projects(source_hash, name_hash)
            }
            _ => BTreeSet::new(),
        }
    } else {
        BTreeSet::new()
    };

    Ok(PrivacyMaterialPlan {
        source,
        privacy_case_id,
        provenance_projects,
        display_name,
        redactions,
        validation_error,
    })
}

pub(super) fn is_exact_v031_stored_review_payload(plaintext: &[u8]) -> bool {
    serde_json::from_slice::<ExactV031StoredReviewShape>(plaintext).is_ok()
}

pub(super) fn is_exact_v031_assigned_review_payload(
    plaintext: &[u8],
    expected_case_id: &str,
) -> bool {
    serde_json::from_slice::<ExactV031AssignedReviewShape>(plaintext)
        .is_ok_and(|shape| shape.case_id == expected_case_id)
}

pub(super) fn authenticates_exact_v031_unassigned_missing_display_material(
    connection: &Connection,
    material_id: &privacy::vnext::MaterialId,
) -> Result<bool, PrivacyWorkflowError> {
    let Some(source) = load_privacy_sources_for_one(connection, material_id.as_str())?
        .into_iter()
        .next()
    else {
        return Ok(false);
    };
    if source.project_id.is_some()
        || source.legacy_case_id.is_some()
        || source.attachment_id.is_some()
        || source.source_kind != "local_review"
        || source.migration_status != "unassigned"
        || source.deleted_at.is_some()
        || !display_tuple_is_absent(&source)
        || source.vault_binding.is_some()
        || source.redactions.is_empty()
        || connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM case_material_assignment_audit WHERE material_id=?1
                 )",
                [material_id.as_str()],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(|_| privacy_migration_store_error())?
            .unwrap_or(false)
    {
        return Ok(false);
    }
    for redaction in &source.redactions {
        let loaded = PrivacyStore::load_review_draft(connection, &redaction.redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        let stored =
            serde_json::from_slice::<StoredReviewPayload>(&loaded.review_payload_plaintext)
                .map_err(|_| migration_target_mismatch())?;
        if !is_exact_v031_stored_review_payload(&loaded.review_payload_plaintext)
            || stored.case_id.is_some()
            || !stored.source_display_name.is_empty()
            || stored.vault_object_id.is_some()
            || stored.vault_object_version.is_some()
            || stored.vault_isolation.is_some()
            || validate_loaded_review(&loaded, &stored).is_err()
        {
            return Ok(false);
        }
    }
    authenticates_v031_origin_ledgers(connection, &source, true)
}

pub(super) fn authenticates_assigned_exact_v031_missing_display_material(
    connection: &Connection,
    material_id: &str,
    project_id: &ProjectId,
) -> Result<bool, PrivacyWorkflowError> {
    let mut sources = load_privacy_sources_for_one(connection, material_id)?;
    if sources.len() != 1 {
        return Ok(false);
    }
    let source = sources.pop().expect("one source was checked");
    if source.project_id.as_deref() != Some(project_id.as_str()) {
        return Ok(false);
    }
    let Some(case_id) = assigned_exact_v031_case_id(connection, &source, project_id)? else {
        return Ok(false);
    };
    authenticates_assigned_exact_v031_missing_display_source(connection, &source, &case_id)
}

fn authenticates_assigned_exact_v031_missing_display_source(
    connection: &Connection,
    source: &PrivacyMaterialSource,
    expected_case_id: &PrivacyCaseId,
) -> Result<bool, PrivacyWorkflowError> {
    let Some(project_value) = source.project_id.as_deref() else {
        return Ok(false);
    };
    let project_id = match ProjectId::parse(project_value.to_owned()) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let Some(audit_case_id) = assigned_exact_v031_case_id(connection, source, &project_id)? else {
        return Ok(false);
    };
    if &audit_case_id != expected_case_id || source.redactions.is_empty() {
        return Ok(false);
    }
    for redaction in &source.redactions {
        let loaded = PrivacyStore::load_review_draft(connection, &redaction.redaction_id)
            .map_err(PrivacyWorkflowError::store)?;
        let stored =
            serde_json::from_slice::<StoredReviewPayload>(&loaded.review_payload_plaintext)
                .map_err(|_| migration_target_mismatch())?;
        if !is_exact_v031_assigned_review_payload(
            &loaded.review_payload_plaintext,
            expected_case_id.as_str(),
        ) || stored.case_id.as_deref() != Some(expected_case_id.as_str())
            || !stored.source_display_name.is_empty()
            || stored.vault_object_id.is_some()
            || stored.vault_object_version.is_some()
            || stored.vault_isolation.is_some()
            || validate_loaded_review(&loaded, &stored).is_err()
        {
            return Ok(false);
        }
    }
    authenticates_v031_origin_ledgers(connection, source, false)
}

fn assigned_exact_v031_case_id(
    connection: &Connection,
    source: &PrivacyMaterialSource,
    project_id: &ProjectId,
) -> Result<Option<PrivacyCaseId>, PrivacyWorkflowError> {
    if source.project_id.as_deref() != Some(project_id.as_str())
        || source.legacy_case_id.is_some()
        || source.attachment_id.is_some()
        || source.source_kind != "local_review"
        || source.migration_status != "ready"
        || source.deleted_at.is_some()
        || !display_tuple_is_absent(source)
        || source.vault_binding.is_some()
    {
        return Ok(None);
    }
    super::case_materials::validate_assignment_schema(connection)?;
    let audit = connection
        .query_row(
            "SELECT assignment_id,privacy_case_id,assignment_mode,binding_action,
                    assigned_material_row_version,previous_migration_status,
                    previous_state,result
             FROM case_material_assignment_audit
             WHERE material_id=?1 AND project_id=?2",
            params![source.material_id, project_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    let Some((
        assignment_id,
        case_value,
        mode,
        binding_action,
        assigned_version,
        previous,
        previous_state,
        result,
    )) = audit
    else {
        return Ok(None);
    };
    let expected_assignment_id = format!(
        "asn_{}",
        sha256_hex(
            format!(
                "case-material-assignment-v1\0{}\0{}",
                source.material_id,
                project_id.as_str()
            )
            .as_bytes()
        )
    );
    if assignment_id != expected_assignment_id
        || mode != "initialize_null_case"
        || !matches!(binding_action.as_str(), "created" | "reused")
        || assigned_version < 0
        || source.row_version < assigned_version
        || previous != "unassigned"
        || previous_state != source.state
        || result != "assigned"
    {
        return Ok(None);
    }
    let case_id = match PrivacyCaseId::parse(case_value) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    if ProjectPrivacyCaseBindingStore::validate_pair(connection, project_id, &case_id).is_err()
        || ProjectPrivacyCaseBindingStore::reverse_resolve(connection, &case_id)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .as_ref()
            != Some(project_id)
    {
        return Ok(None);
    }
    Ok(Some(case_id))
}

fn display_tuple_is_absent(source: &PrivacyMaterialSource) -> bool {
    source.protected_display_name.is_none()
        && source.display_name_sha256.is_none()
        && source.display_name_protection_scheme.is_none()
}

fn authenticates_v031_origin_ledgers(
    connection: &Connection,
    source: &PrivacyMaterialSource,
    require_unchanged_origin: bool,
) -> Result<bool, PrivacyWorkflowError> {
    let Some((base, effective)) = load_ledger_evidence(
        connection,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_PRIVACY,
        "privacy_materials",
        &source.material_id,
    )?
    else {
        return Ok(false);
    };
    if !ledger_evidence_has_valid_fingerprint(&base)
        || !ledger_evidence_has_valid_fingerprint(&effective)
        || base.target_material_id.as_deref() != Some(source.material_id.as_str())
        || base.target_redaction_id.is_some()
        || base.assigned_generation_number.is_some()
        || base.result_state != "migrated"
        || base.error_code.as_deref() != Some("privacy_case_unassigned")
        || effective.target_material_id.as_deref() != Some(source.material_id.as_str())
        || effective.target_redaction_id.is_some()
        || effective.assigned_generation_number.is_some()
        || effective.result_state != "migrated"
        || !matches!(
            effective.error_code.as_deref(),
            None | Some("privacy_case_unassigned")
        )
        || (require_unchanged_origin
            && (effective.source_fingerprint != base.source_fingerprint
                || effective.error_code != base.error_code))
    {
        return Ok(false);
    }
    let current_material_fingerprint = privacy_material_fingerprint(source);
    if !require_unchanged_origin
        && !((effective.source_fingerprint == base.source_fingerprint
            && effective.error_code.as_deref() == Some("privacy_case_unassigned"))
            || (effective.source_fingerprint == current_material_fingerprint
                && effective.error_code.is_none()))
    {
        return Ok(false);
    }

    let ledger_count = connection
        .query_row(
            "SELECT COUNT(*) FROM case_material_migration_ledger
             WHERE migration_id=?1 AND source_store=?2
               AND source_table='privacy_redactions' AND target_material_id=?3",
            params![
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_PRIVACY,
                source.material_id
            ],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if usize::try_from(ledger_count).ok() != Some(source.redactions.len()) {
        return Ok(false);
    }
    for redaction in &source.redactions {
        let Some((base, effective)) = load_ledger_evidence(
            connection,
            CASE_MATERIAL_MIGRATION_ID,
            SOURCE_STORE_PRIVACY,
            "privacy_redactions",
            &redaction.redaction_id,
        )?
        else {
            return Ok(false);
        };
        let verified_risk_revision =
            match validate_risk_revision_chain(connection, &redaction.redaction_id) {
                Ok(value) => Some(value),
                Err(_) => return Ok(false),
            };
        let current_redaction_fingerprint = privacy_redaction_fingerprint(&ValidatedRedaction {
            source: redaction.clone(),
            verified_risk_revision,
            generation_status: "ready",
            error_code: None,
        });
        if !ledger_evidence_has_valid_fingerprint(&base)
            || !ledger_evidence_has_valid_fingerprint(&effective)
            || base.target_material_id.as_deref() != Some(source.material_id.as_str())
            || base.target_redaction_id.as_deref() != Some(redaction.redaction_id.as_str())
            || base.assigned_generation_number != Some(redaction.generation_number)
            || base.result_state != "migrated"
            || base.error_code.is_some()
            || effective.target_material_id.as_deref() != Some(source.material_id.as_str())
            || effective.target_redaction_id.as_deref() != Some(redaction.redaction_id.as_str())
            || effective.assigned_generation_number != Some(redaction.generation_number)
            || effective.result_state != "migrated"
            || effective.error_code.is_some()
            || (require_unchanged_origin && effective.source_fingerprint != base.source_fingerprint)
            || (!require_unchanged_origin
                && effective.source_fingerprint != base.source_fingerprint
                && effective.source_fingerprint != current_redaction_fingerprint)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn ledger_evidence_has_valid_fingerprint(evidence: &EffectiveLedgerEvidence) -> bool {
    valid_hash(&evidence.source_fingerprint)
}

fn decode_existing_display_name(
    source: &PrivacyMaterialSource,
) -> Result<Option<String>, PrivacyWorkflowError> {
    match (
        source.protected_display_name.as_deref(),
        source.display_name_sha256.as_deref(),
        source.display_name_protection_scheme.as_deref(),
    ) {
        (None, None, None) => Ok(None),
        (Some(protected), Some(expected), Some(LOCAL_PROTECTION_SCHEME)) => {
            let plaintext = unprotect_local(protected).map_err(|_| {
                migration_error(
                    "privacy_display_name_invalid",
                    "A protected material display name failed authentication.",
                )
            })?;
            if sha256_hex(&plaintext) != expected {
                return Err(migration_error(
                    "privacy_display_name_invalid",
                    "A protected material display-name hash did not match.",
                ));
            }
            String::from_utf8(plaintext).map(Some).map_err(|_| {
                migration_error(
                    "privacy_display_name_invalid",
                    "A protected material display name was not valid UTF-8.",
                )
            })
        }
        _ => Err(migration_error(
            "privacy_display_name_invalid",
            "A material display-name protection tuple was incomplete.",
        )),
    }
}

fn validate_vault_binding_content(
    manager: &PrivacyWorkflowManager,
    binding: &vault_broker::VaultImportBinding,
) -> Result<(), PrivacyWorkflowError> {
    let lease = manager
        .shared
        .vault_broker
        .read_source(binding)
        .map_err(PrivacyWorkflowError::vault)?;
    let valid = sha256_hex(lease.content()) == binding.source_sha256.as_str()
        && u64::try_from(lease.content().len()).ok() == Some(binding.content_bytes);
    drop(lease);
    if valid {
        Ok(())
    } else {
        Err(migration_error(
            "privacy_vault_source_invalid",
            "The exact Vault object failed source identity validation.",
        ))
    }
}

fn validate_risk_revision_chain(
    connection: &Connection,
    redaction_id: &str,
) -> Result<i64, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(
            "SELECT revision,state_sha256,risk_sha256,hard_gate_sha256,action_code,
                    reason_codes_json,protected_state_blob,protection_scheme,
                    previous_revision_hash,revision_hash
             FROM privacy_risk_review_revisions
             WHERE redaction_id=?1
             ORDER BY revision",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let rows = statement
        .query_map([redaction_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
            ))
        })
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    let mut previous_hash = String::new();
    let mut expected_revision = 1_i64;
    for (
        revision,
        state_sha256,
        risk_sha256,
        hard_gate_sha256,
        action_code,
        reason_codes_json,
        protected,
        protection_scheme,
        stored_previous_hash,
        revision_hash,
    ) in rows
    {
        let reasons = serde_json::from_str::<Vec<String>>(&reason_codes_json)
            .map_err(|_| risk_chain_error())?;
        if revision != expected_revision
            || stored_previous_hash != previous_hash
            || protection_scheme != LOCAL_PROTECTION_SCHEME
            || !valid_hash(&state_sha256)
            || !valid_hash(&risk_sha256)
            || !valid_hash(&hard_gate_sha256)
            || reasons.iter().any(|value| value.is_empty())
        {
            return Err(risk_chain_error());
        }
        let plaintext = unprotect_local(&protected).map_err(|_| risk_chain_error())?;
        if sha256_hex(&plaintext) != state_sha256 {
            return Err(risk_chain_error());
        }
        let protected_sha256 = sha256_hex(&protected);
        let expected_hash = sha256_hex(
            format!(
                "{RISK_REVISION_PROFILE}\0{redaction_id}\0{revision}\0{state_sha256}\0{risk_sha256}\0{hard_gate_sha256}\0{action_code}\0{reason_codes_json}\0{protected_sha256}\0{stored_previous_hash}"
            )
            .as_bytes(),
        );
        if expected_hash != revision_hash {
            return Err(risk_chain_error());
        }
        previous_hash = revision_hash;
        expected_revision += 1;
    }
    Ok(expected_revision - 1)
}

fn validate_approved_generation(
    connection: &Connection,
    source: &PrivacyRedactionSource,
    payload: &StoredReviewPayload,
    verified_risk_revision: Option<i64>,
) -> Result<(), PrivacyWorkflowError> {
    let approved_hash = source
        .approved_payload_sha256
        .as_deref()
        .filter(|value| valid_hash(value))
        .ok_or_else(approved_generation_error)?;
    let risk_revision = verified_risk_revision
        .filter(|revision| *revision > 0)
        .ok_or_else(approved_generation_error)?;
    if source.unresolved_high_risk_count != 0
        || source.risk_revision != risk_revision
        || source
            .reviewed_at
            .as_deref()
            .is_none_or(|value| !sqlite_datetime_is_valid(connection, value))
        || source.approved_at.as_deref() != source.reviewed_at.as_deref()
    {
        return Err(approved_generation_error());
    }
    let canonical = serde_json::to_vec(&CanonicalApprovedPayload {
        schema_version: APPROVED_PAYLOAD_SCHEMA_VERSION,
        source_sha256: &payload.source_sha256,
        extraction_sha256: &payload.extraction_sha256,
        media_type: &payload.media_type,
        pages: payload
            .pages
            .iter()
            .map(|page| CanonicalApprovedPage {
                page_number: page.page_number,
                text: &page.suggested_redacted_text,
            })
            .collect(),
    })
    .map_err(|_| approved_generation_error())?;
    if sha256_hex(&canonical) != approved_hash {
        return Err(approved_generation_error());
    }
    Ok(())
}

fn sqlite_datetime_is_valid(connection: &Connection, value: &str) -> bool {
    connection
        .query_row("SELECT datetime(?1) IS NOT NULL", [value], |row| {
            row.get::<_, bool>(0)
        })
        .unwrap_or(false)
}

fn valid_redaction_id(value: &str) -> bool {
    value.len() == 36
        && value.starts_with("red_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn approved_generation_error() -> PrivacyWorkflowError {
    migration_error(
        "privacy_approved_generation_invalid",
        "An approved historical generation failed payload, timestamp, or risk-chain validation.",
    )
}

fn risk_chain_error() -> PrivacyWorkflowError {
    migration_error(
        "privacy_risk_chain_invalid",
        "A historical risk-review hash chain failed validation.",
    )
}

fn privacy_migration_store_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_migration_store_failed",
        "The case-material migration could not read or update the Privacy store.",
    )
}

fn binding_candidate_graph(
    user: &UserSnapshot,
    plans: &[PrivacyMaterialPlan],
) -> BindingCandidateGraph {
    let mut projects_by_case = BTreeMap::<String, BTreeSet<String>>::new();
    let mut cases_by_project = BTreeMap::<String, BTreeSet<String>>::new();
    for plan in plans {
        let Some(case_id) = plan.privacy_case_id.as_ref() else {
            continue;
        };
        if plan.validation_error.is_some() {
            continue;
        }
        for project_id in &plan.provenance_projects {
            if user.projects.contains_key(project_id) {
                projects_by_case
                    .entry(case_id.as_str().to_owned())
                    .or_default()
                    .insert(project_id.clone());
                cases_by_project
                    .entry(project_id.clone())
                    .or_default()
                    .insert(case_id.as_str().to_owned());
            }
        }
    }

    let mut blocked_projects = BTreeSet::new();
    for (case_id, projects) in &projects_by_case {
        if projects.len() > 1 {
            blocked_projects.extend(projects.iter().cloned());
        }
        if PrivacyCaseId::parse(case_id.clone()).is_err() {
            blocked_projects.extend(projects.iter().cloned());
        }
    }
    for (project_id, cases) in &cases_by_project {
        if cases.len() > 1 {
            blocked_projects.insert(project_id.clone());
        }
    }
    BindingCandidateGraph {
        projects_by_case,
        cases_by_project,
        blocked_projects,
    }
}

fn backfill_recovered_bindings(
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    plans: &[PrivacyMaterialPlan],
    report: &mut CaseMaterialMigrationReport,
) -> Result<BTreeSet<String>, PrivacyWorkflowError> {
    let BindingCandidateGraph {
        projects_by_case,
        cases_by_project,
        mut blocked_projects,
    } = binding_candidate_graph(user, plans);
    for projects in projects_by_case
        .values()
        .filter(|projects| projects.len() > 1)
    {
        for project_id in projects {
            record_binding_result(
                transaction,
                user.projects
                    .get(project_id)
                    .expect("candidate project came from the user snapshot"),
                &project_binding_fingerprint(
                    user.projects
                        .get(project_id)
                        .expect("candidate project came from the user snapshot"),
                    cases_by_project.get(project_id),
                ),
                None,
                "blocked",
                Some("ambiguous_legacy_binding"),
                report,
            )?;
        }
    }
    for (project_id, cases) in &cases_by_project {
        if cases.len() > 1 {
            record_binding_result(
                transaction,
                user.projects
                    .get(project_id)
                    .expect("candidate project came from the user snapshot"),
                &project_binding_fingerprint(
                    user.projects
                        .get(project_id)
                        .expect("candidate project came from the user snapshot"),
                    Some(cases),
                ),
                None,
                "blocked",
                Some("ambiguous_legacy_binding"),
                report,
            )?;
        }
    }

    let proposals = projects_by_case
        .iter()
        .filter_map(|(case_id, projects)| {
            let project_id = projects.first()?;
            if projects.len() == 1
                && cases_by_project
                    .get(project_id)
                    .is_some_and(|cases| cases.len() == 1)
                && !blocked_projects.contains(project_id)
            {
                Some((project_id.clone(), case_id.clone()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for (project_value, case_value) in proposals {
        let project = ProjectId::parse(project_value.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id =
            PrivacyCaseId::parse(case_value).map_err(PrivacyWorkflowError::project_case_binding)?;
        let context = BindingLifecycleContext::new(
            BindingCreationSource::LegacyMigration,
            deterministic_binding_audit_id(&project, Some(&case_id)),
            Some(PROJECT_CASE_BINDING_MIGRATION_ID.to_owned()),
        )
        .map_err(PrivacyWorkflowError::project_case_binding)?;
        match ProjectPrivacyCaseBindingStore::bind_existing_for_migration_in_transaction(
            transaction,
            &project,
            &case_id,
            &context,
        ) {
            Ok(bound) => {
                let source = user
                    .projects
                    .get(project.as_str())
                    .expect("binding proposal came from a user project");
                let fingerprint =
                    project_binding_fingerprint(source, cases_by_project.get(project.as_str()));
                record_binding_result(
                    transaction,
                    source,
                    &fingerprint,
                    Some(&bound),
                    "migrated",
                    None,
                    report,
                )?;
            }
            Err(
                ProjectPrivacyCaseBindingError::ProjectPrivacyCaseConflict
                | ProjectPrivacyCaseBindingError::AmbiguousLegacyBinding,
            ) => {
                blocked_projects.insert(project_value.clone());
                let source = user
                    .projects
                    .get(&project_value)
                    .expect("binding proposal came from a user project");
                let fingerprint =
                    project_binding_fingerprint(source, cases_by_project.get(&project_value));
                record_binding_result(
                    transaction,
                    source,
                    &fingerprint,
                    None,
                    "blocked",
                    Some("project_privacy_case_conflict"),
                    report,
                )?;
            }
            Err(error) => return Err(PrivacyWorkflowError::project_case_binding(error)),
        }
    }

    // Existing bindings remain authoritative. Record the source-to-binding
    // verification even when this migration did not create the pair.
    for source in user.projects.values() {
        let project = ProjectId::parse(source.project_id.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        if let Some(case_id) = ProjectPrivacyCaseBindingStore::resolve(transaction, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
        {
            if ProjectPrivacyCaseBindingStore::reverse_resolve(transaction, &case_id)
                .map_err(PrivacyWorkflowError::project_case_binding)?
                .as_ref()
                != Some(&project)
            {
                return Err(migration_error(
                    "project_privacy_case_binding_conflict",
                    "A persisted project/privacy case binding failed reverse uniqueness validation.",
                ));
            }
            let fingerprint = project_binding_fingerprint(
                source,
                cases_by_project.get(source.project_id.as_str()),
            );
            record_binding_result(
                transaction,
                source,
                &fingerprint,
                Some(&case_id),
                "migrated",
                None,
                report,
            )?;
        }
    }
    Ok(blocked_projects)
}

fn create_bindings_for_projects_without_privacy_state(
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    plans: &[PrivacyMaterialPlan],
    blocked_projects: &BTreeSet<String>,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let mut privacy_state_projects = blocked_projects.clone();
    for plan in plans {
        privacy_state_projects.extend(plan.provenance_projects.iter().cloned());
        if let Some(project_id) = plan.source.project_id.as_ref() {
            privacy_state_projects.insert(project_id.clone());
        }
    }
    for source in user.projects.values() {
        let project = ProjectId::parse(source.project_id.clone())
            .map_err(PrivacyWorkflowError::project_case_binding)?;
        if ProjectPrivacyCaseBindingStore::resolve(transaction, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .is_some()
        {
            continue;
        }
        if privacy_state_projects.contains(project.as_str()) {
            let fingerprint = project_binding_fingerprint(source, None);
            record_binding_result(
                transaction,
                source,
                &fingerprint,
                None,
                "blocked",
                Some("project_privacy_case_unbound"),
                report,
            )?;
            continue;
        }
        let context = BindingLifecycleContext::new(
            BindingCreationSource::LegacyMigration,
            deterministic_binding_audit_id(&project, None),
            Some(PROJECT_CASE_BINDING_MIGRATION_ID.to_owned()),
        )
        .map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id = ProjectPrivacyCaseBindingStore::resolve_or_create_in_transaction(
            transaction,
            &project,
            &context,
        )
        .map_err(PrivacyWorkflowError::project_case_binding)?;
        let fingerprint = project_binding_fingerprint(source, None);
        record_binding_result(
            transaction,
            source,
            &fingerprint,
            Some(&case_id),
            "migrated",
            None,
            report,
        )?;
    }
    Ok(())
}

fn record_binding_result(
    transaction: &Transaction<'_>,
    source: &ProjectSource,
    source_fingerprint: &str,
    case_id: Option<&PrivacyCaseId>,
    result_state: &'static str,
    error_code: Option<&'static str>,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let target = binding_target_id(&source.project_id);
    let invariant_valid = match case_id {
        Some(case_id) => {
            let project = ProjectId::parse(source.project_id.clone())
                .map_err(PrivacyWorkflowError::project_case_binding)?;
            ProjectPrivacyCaseBindingStore::validate_pair(transaction, &project, case_id).is_ok()
        }
        None => result_state == "blocked",
    };
    if !invariant_valid {
        return Err(migration_target_mismatch());
    }
    let write = record_ledger(
        transaction,
        PROJECT_CASE_BINDING_MIGRATION_ID,
        SOURCE_STORE_USER,
        "projects",
        &source.project_id,
        source_fingerprint,
        &target,
        None,
        None,
        result_state,
        error_code,
    )?;
    match write {
        LedgerWrite::Noop => report.idempotent_noops += 1,
        LedgerWrite::Inserted | LedgerWrite::EventAppended => {
            if result_state == "blocked" {
                report.blocked += 1;
            } else {
                report.bindings_created_or_verified += 1;
            }
        }
    }
    Ok(())
}

fn record_source_manifest(
    transaction: &Transaction<'_>,
    proof: &SourceProof,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let fingerprint = proof.persistent_fingerprint();
    let write = record_ledger(
        transaction,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "source_manifest",
        SOURCE_STORE_USER,
        &fingerprint,
        "source_manifest_v1",
        None,
        None,
        "migrated",
        None,
    )?;
    if write == LedgerWrite::Noop {
        report.idempotent_noops += 1;
    }
    Ok(())
}

fn project_binding_fingerprint(
    source: &ProjectSource,
    candidates: Option<&BTreeSet<String>>,
) -> String {
    let mut fingerprint = Fingerprint::new(b"user-project-binding");
    fingerprint.text(&source.project_id);
    fingerprint.text(&source.title);
    fingerprint.text(&source.case_type);
    fingerprint.text(&source.status);
    fingerprint.optional_text(source.opened_on.as_deref());
    fingerprint.text(&source.summary);
    fingerprint.text(&source.created_at);
    fingerprint.text(&source.updated_at);
    for candidate in candidates.into_iter().flatten() {
        fingerprint.text(candidate);
    }
    fingerprint.finish()
}

fn source_manifest_terminal_matches(
    connection: &Connection,
    source_fingerprint: &str,
) -> Result<bool, PrivacyWorkflowError> {
    let Some((ledger, result_state)) = effective_ledger_entry(
        connection,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "source_manifest",
        SOURCE_STORE_USER,
        source_fingerprint,
    )?
    else {
        return Ok(false);
    };
    if ledger.target_material_id != "source_manifest_v1"
        || ledger.target_redaction_id.is_some()
        || ledger.assigned_generation_number.is_some()
        || result_state != "migrated"
    {
        return Err(migration_target_mismatch());
    }
    Ok(true)
}

fn privacy_plan_terminal_matches(
    connection: &Connection,
    user: &UserSnapshot,
    plan: &PrivacyMaterialPlan,
    blocked_binding_projects: &BTreeSet<String>,
) -> Result<bool, PrivacyWorkflowError> {
    let projection = privacy_material_projection(connection, user, plan, blocked_binding_projects)?;
    let material_result = if projection.migration_status == "blocked" {
        "blocked"
    } else {
        "migrated"
    };
    let Some((material_ledger, effective_result)) = effective_ledger_entry(
        connection,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_PRIVACY,
        "privacy_materials",
        &plan.source.material_id,
        &privacy_material_fingerprint(&plan.source),
    )?
    else {
        return Ok(false);
    };
    if material_ledger.target_material_id != plan.source.material_id
        || material_ledger.target_redaction_id.is_some()
        || material_ledger.assigned_generation_number.is_some()
        || effective_result != material_result
    {
        return Err(migration_target_mismatch());
    }
    validate_material_projection_target(connection, &plan.source.material_id, &projection)?;

    for redaction in &plan.redactions {
        let final_status = if projection.migration_status == "blocked" {
            "blocked"
        } else {
            redaction.generation_status
        };
        let result_state = if final_status == "blocked" {
            "blocked"
        } else {
            "migrated"
        };
        let Some((ledger, effective_result)) = effective_ledger_entry(
            connection,
            CASE_MATERIAL_MIGRATION_ID,
            SOURCE_STORE_PRIVACY,
            "privacy_redactions",
            &redaction.source.redaction_id,
            &privacy_redaction_fingerprint(redaction),
        )?
        else {
            return Ok(false);
        };
        if ledger.target_material_id != plan.source.material_id
            || ledger.target_redaction_id.as_deref() != Some(redaction.source.redaction_id.as_str())
            || ledger.assigned_generation_number != Some(redaction.source.generation_number)
            || effective_result != result_state
        {
            return Err(migration_target_mismatch());
        }
        validate_redaction_projection_target(connection, redaction, final_status)?;
    }
    Ok(true)
}

fn project_binding_terminal_matches(
    connection: &Connection,
    source: &ProjectSource,
    candidates: Option<&BTreeSet<String>>,
) -> Result<bool, PrivacyWorkflowError> {
    let fingerprint = project_binding_fingerprint(source, candidates);
    let Some((ledger, effective_result)) = effective_ledger_entry(
        connection,
        PROJECT_CASE_BINDING_MIGRATION_ID,
        SOURCE_STORE_USER,
        "projects",
        &source.project_id,
        &fingerprint,
    )?
    else {
        return Ok(false);
    };
    if ledger.target_material_id != binding_target_id(&source.project_id)
        || ledger.target_redaction_id.is_some()
        || ledger.assigned_generation_number.is_some()
    {
        return Err(migration_target_mismatch());
    }
    let project = ProjectId::parse(source.project_id.clone())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    match ProjectPrivacyCaseBindingStore::resolve(connection, &project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
    {
        Some(case_id) => {
            if effective_result != "migrated"
                || ProjectPrivacyCaseBindingStore::reverse_resolve(connection, &case_id)
                    .map_err(PrivacyWorkflowError::project_case_binding)?
                    .as_ref()
                    != Some(&project)
                || ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, &case_id)
                    .is_err()
            {
                return Err(migration_target_mismatch());
            }
        }
        None if effective_result == "blocked" => {}
        None => return Ok(false),
    }
    Ok(true)
}

fn deterministic_binding_audit_id(project: &ProjectId, case_id: Option<&PrivacyCaseId>) -> String {
    let mut fingerprint = Fingerprint::new(b"project-case-binding-audit");
    fingerprint.text(PROJECT_CASE_BINDING_MIGRATION_ID);
    fingerprint.text(project.as_str());
    fingerprint.optional_text(case_id.map(PrivacyCaseId::as_str));
    format!("bindmig_{}", &fingerprint.finish()[..32])
}

fn binding_target_id(project_id: &str) -> String {
    let mut fingerprint = Fingerprint::new(b"project-case-binding-target");
    fingerprint.text(project_id);
    format!("binding_{}", &fingerprint.finish()[..32])
}

#[allow(clippy::too_many_arguments)]
fn record_ledger(
    transaction: &Transaction<'_>,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
    source_fingerprint: &str,
    target_material_id: &str,
    target_redaction_id: Option<&str>,
    assigned_generation_number: Option<i64>,
    result_state: &str,
    error_code: Option<&str>,
) -> Result<LedgerWrite, PrivacyWorkflowError> {
    if source_key.is_empty()
        || source_key.len() > MAX_SOURCE_ID_BYTES
        || !valid_hash(source_fingerprint)
    {
        return Err(privacy_migration_store_error());
    }
    let existing = load_ledger(
        transaction,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?;
    if let Some(existing) = existing {
        if existing.target_material_id != target_material_id
            || existing.target_redaction_id.as_deref() != target_redaction_id
            || existing.assigned_generation_number != assigned_generation_number
        {
            return Err(migration_target_mismatch());
        }
        let (effective_fingerprint, effective_result) = effective_ledger_state(
            transaction,
            migration_id,
            source_store,
            source_table,
            source_key,
        )?
        .unwrap_or((existing.source_fingerprint, existing.result_state));
        if effective_fingerprint == source_fingerprint && effective_result == result_state {
            return Ok(LedgerWrite::Noop);
        }
        insert_migration_event(
            transaction,
            migration_id,
            source_store,
            source_table,
            source_key,
            if effective_fingerprint == source_fingerprint {
                "blocked_resolution"
            } else {
                "source_changed"
            },
            Some(source_fingerprint),
            Some(target_material_id),
            target_redaction_id,
            assigned_generation_number,
            Some(result_state),
            error_code,
        )?;
        return Ok(LedgerWrite::EventAppended);
    }

    transaction
        .execute(
            "INSERT INTO case_material_migration_ledger(
                migration_id,source_store,source_table,source_key,source_fingerprint,
                target_material_id,target_redaction_id,assigned_generation_number,
                result_state,error_code,started_at,completed_at
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
            params![
                migration_id,
                source_store,
                source_table,
                source_key,
                source_fingerprint,
                target_material_id,
                target_redaction_id,
                assigned_generation_number,
                result_state,
                error_code,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    insert_migration_event(
        transaction,
        migration_id,
        source_store,
        source_table,
        source_key,
        "completed",
        Some(source_fingerprint),
        Some(target_material_id),
        target_redaction_id,
        assigned_generation_number,
        Some(result_state),
        error_code,
    )?;
    Ok(LedgerWrite::Inserted)
}

fn effective_ledger_state(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
) -> Result<Option<(String, String)>, PrivacyWorkflowError> {
    let Some(ledger) = load_ledger(
        connection,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?
    else {
        return Ok(None);
    };
    let event = connection
        .query_row(
            "SELECT source_fingerprint,result_state
             FROM case_material_migration_events
             WHERE migration_id=?1 AND source_store=?2 AND source_table=?3
               AND source_key=?4 AND source_fingerprint IS NOT NULL
               AND result_state IS NOT NULL
             ORDER BY rowid DESC LIMIT 1",
            params![migration_id, source_store, source_table, source_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    Ok(Some(event.unwrap_or((
        ledger.source_fingerprint,
        ledger.result_state,
    ))))
}

fn load_ledger_evidence(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
) -> Result<Option<(EffectiveLedgerEvidence, EffectiveLedgerEvidence)>, PrivacyWorkflowError> {
    let Some(base) = load_ledger(
        connection,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?
    else {
        return Ok(None);
    };
    let base_evidence = EffectiveLedgerEvidence {
        source_fingerprint: base.source_fingerprint,
        target_material_id: Some(base.target_material_id),
        target_redaction_id: base.target_redaction_id,
        assigned_generation_number: base.assigned_generation_number,
        result_state: base.result_state,
        error_code: base.error_code,
    };
    let event = connection
        .query_row(
            "SELECT source_fingerprint,target_material_id,target_redaction_id,
                    assigned_generation_number,result_state,error_code
             FROM case_material_migration_events
             WHERE migration_id=?1 AND source_store=?2 AND source_table=?3
               AND source_key=?4 AND source_fingerprint IS NOT NULL
               AND result_state IS NOT NULL
             ORDER BY rowid DESC LIMIT 1",
            params![migration_id, source_store, source_table, source_key],
            |row| {
                Ok(EffectiveLedgerEvidence {
                    source_fingerprint: row.get(0)?,
                    target_material_id: row.get(1)?,
                    target_redaction_id: row.get(2)?,
                    assigned_generation_number: row.get(3)?,
                    result_state: row.get(4)?,
                    error_code: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    let effective = event.unwrap_or_else(|| base_evidence.clone());
    Ok(Some((base_evidence, effective)))
}

fn effective_ledger_entry(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
    expected_fingerprint: &str,
) -> Result<Option<(LedgerEntry, String)>, PrivacyWorkflowError> {
    let Some(ledger) = load_ledger(
        connection,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?
    else {
        return Ok(None);
    };
    let Some((effective_fingerprint, effective_result)) = effective_ledger_state(
        connection,
        migration_id,
        source_store,
        source_table,
        source_key,
    )?
    else {
        return Ok(None);
    };
    if effective_fingerprint != expected_fingerprint {
        return Ok(None);
    }
    Ok(Some((ledger, effective_result)))
}

fn load_ledger(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
) -> Result<Option<LedgerEntry>, PrivacyWorkflowError> {
    connection
        .query_row(
            "SELECT source_fingerprint,target_material_id,target_redaction_id,
                    assigned_generation_number,result_state,error_code
             FROM case_material_migration_ledger
             WHERE migration_id=?1 AND source_store=?2 AND source_table=?3 AND source_key=?4",
            params![migration_id, source_store, source_table, source_key],
            |row| {
                Ok(LedgerEntry {
                    source_fingerprint: row.get(0)?,
                    target_material_id: row.get(1)?,
                    target_redaction_id: row.get(2)?,
                    assigned_generation_number: row.get(3)?,
                    result_state: row.get(4)?,
                    error_code: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())
}

#[allow(clippy::too_many_arguments)]
fn insert_migration_event(
    connection: &Connection,
    migration_id: &str,
    source_store: &str,
    source_table: &str,
    source_key: &str,
    event_type: &str,
    source_fingerprint: Option<&str>,
    target_material_id: Option<&str>,
    target_redaction_id: Option<&str>,
    assigned_generation_number: Option<i64>,
    result_state: Option<&str>,
    error_code: Option<&str>,
) -> Result<(), PrivacyWorkflowError> {
    connection
        .execute(
            "INSERT INTO case_material_migration_events(
                migration_event_id,migration_id,source_store,source_table,source_key,
                event_type,source_fingerprint,target_material_id,target_redaction_id,
                assigned_generation_number,result_state,error_code,occurred_at
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,CURRENT_TIMESTAMP)",
            params![
                format!("migev_{}", Uuid::new_v4().simple()),
                migration_id,
                source_store,
                source_table,
                source_key,
                event_type,
                source_fingerprint,
                target_material_id,
                target_redaction_id,
                assigned_generation_number,
                result_state,
                error_code,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    Ok(())
}

fn migration_target_mismatch() -> PrivacyWorkflowError {
    migration_error(
        "case_material_migration_target_mismatch",
        "An idempotent migration ledger no longer matches its exact target identity.",
    )
}

fn migrate_privacy_material(
    _manager: &PrivacyWorkflowManager,
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    plan: &PrivacyMaterialPlan,
    blocked_binding_projects: &BTreeSet<String>,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let projection =
        privacy_material_projection(transaction, user, plan, blocked_binding_projects)?;
    let material_fingerprint = privacy_material_fingerprint(&plan.source);
    let current_fingerprint =
        privacy_material_fingerprint_from_connection(transaction, &plan.source.material_id)?;
    if current_fingerprint != material_fingerprint {
        return Err(migration_error(
            "privacy_material_source_changed",
            "A Privacy material changed during its optimistic migration batch.",
        ));
    }

    apply_privacy_material_projection(transaction, &plan.source, &projection)?;
    let material_result = if projection.migration_status == "blocked" {
        "blocked"
    } else {
        "migrated"
    };
    validate_material_projection_target(transaction, &plan.source.material_id, &projection)?;
    let material_write = record_ledger(
        transaction,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_PRIVACY,
        "privacy_materials",
        &plan.source.material_id,
        &material_fingerprint,
        &plan.source.material_id,
        None,
        None,
        material_result,
        projection.error_code,
    )?;

    let mut redaction_writes = Vec::with_capacity(plan.redactions.len());
    for redaction in &plan.redactions {
        let final_status = if projection.migration_status == "blocked" {
            "blocked"
        } else {
            redaction.generation_status
        };
        apply_redaction_projection(transaction, redaction, final_status)?;
        validate_redaction_projection_target(transaction, redaction, final_status)?;
        let fingerprint = privacy_redaction_fingerprint(redaction);
        let result_state = if final_status == "blocked" {
            "blocked"
        } else {
            "migrated"
        };
        let error_code = if projection.migration_status == "blocked" {
            projection.error_code
        } else if final_status == "legacy_id" {
            Some("legacy_redaction_id")
        } else {
            redaction.error_code
        };
        redaction_writes.push((
            record_ledger(
                transaction,
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_PRIVACY,
                "privacy_redactions",
                &redaction.source.redaction_id,
                &fingerprint,
                &plan.source.material_id,
                Some(&redaction.source.redaction_id),
                Some(redaction.source.generation_number),
                result_state,
                error_code,
            )?,
            result_state,
        ));
    }
    match material_write {
        LedgerWrite::Noop => report.idempotent_noops += 1,
        LedgerWrite::Inserted | LedgerWrite::EventAppended => {
            report.privacy_materials_migrated += 1;
            if material_result == "blocked" {
                report.blocked += 1;
            }
        }
    }
    for (write, result_state) in redaction_writes {
        match write {
            LedgerWrite::Noop => report.idempotent_noops += 1,
            LedgerWrite::Inserted | LedgerWrite::EventAppended => {
                report.redaction_generations_migrated += 1;
                if result_state == "blocked" {
                    report.blocked += 1;
                }
            }
        }
    }
    Ok(())
}

fn privacy_material_projection(
    connection: &Connection,
    user: &UserSnapshot,
    plan: &PrivacyMaterialPlan,
    blocked_binding_projects: &BTreeSet<String>,
) -> Result<MaterialProjection, PrivacyWorkflowError> {
    let source_kind = if plan.source.vault_binding.is_some() {
        "vault"
    } else {
        "local_review"
    };
    let existing_legacy_case_id = plan.source.legacy_case_id.clone();
    let unassigned_legacy_case_id = existing_legacy_case_id.clone().or_else(|| {
        plan.privacy_case_id
            .as_ref()
            .map(|case_id| case_id.as_str().to_owned())
    });
    if let Some(error_code) = plan.validation_error {
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: unassigned_legacy_case_id.clone(),
            source_kind,
            migration_status: "blocked",
            state: "blocked".to_owned(),
            display_name: plan.display_name.clone(),
            error_code: Some(error_code),
        });
    }

    if let Some(project_value) = plan.source.project_id.as_ref() {
        let project = match ProjectId::parse(project_value.clone()) {
            Ok(project) if user.projects.contains_key(project.as_str()) => project,
            _ => {
                return Ok(MaterialProjection {
                    project_id: None,
                    legacy_case_id: unassigned_legacy_case_id.clone(),
                    source_kind,
                    migration_status: "blocked",
                    state: "blocked".to_owned(),
                    display_name: plan.display_name.clone(),
                    error_code: Some("privacy_project_id_invalid"),
                });
            }
        };
        if blocked_binding_projects.contains(project.as_str()) {
            return Ok(MaterialProjection {
                project_id: None,
                legacy_case_id: unassigned_legacy_case_id.clone(),
                source_kind,
                migration_status: "blocked",
                state: "blocked".to_owned(),
                display_name: plan.display_name.clone(),
                error_code: Some("ambiguous_legacy_binding"),
            });
        }
        let binding_valid = match plan.privacy_case_id.as_ref() {
            Some(case_id) => {
                ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, case_id).is_ok()
            }
            None if plan.source.vault_binding.is_none() => {
                ProjectPrivacyCaseBindingStore::resolve(connection, &project)
                    .map_err(PrivacyWorkflowError::project_case_binding)?
                    .is_some()
            }
            None => false,
        };
        if !binding_valid {
            return Ok(MaterialProjection {
                project_id: None,
                legacy_case_id: unassigned_legacy_case_id.clone(),
                source_kind,
                migration_status: "blocked",
                state: "blocked".to_owned(),
                display_name: plan.display_name.clone(),
                error_code: Some("project_privacy_case_binding_conflict"),
            });
        }
        return Ok(MaterialProjection {
            project_id: Some(project.as_str().to_owned()),
            legacy_case_id: existing_legacy_case_id.clone(),
            source_kind,
            migration_status: "ready",
            state: plan.source.state.clone(),
            display_name: plan.display_name.clone(),
            error_code: None,
        });
    }

    let Some(case_id) = plan.privacy_case_id.as_ref() else {
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: existing_legacy_case_id.clone(),
            source_kind,
            migration_status: "unassigned",
            state: plan.source.state.clone(),
            display_name: plan.display_name.clone(),
            error_code: Some("privacy_case_unassigned"),
        });
    };
    let project = ProjectPrivacyCaseBindingStore::reverse_resolve(connection, case_id)
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    let Some(project) = project else {
        let ambiguous = plan.provenance_projects.len() > 1
            || plan
                .provenance_projects
                .iter()
                .any(|value| blocked_binding_projects.contains(value));
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: unassigned_legacy_case_id.clone(),
            source_kind,
            migration_status: if ambiguous { "blocked" } else { "unassigned" },
            state: if ambiguous {
                "blocked".to_owned()
            } else {
                plan.source.state.clone()
            },
            display_name: plan.display_name.clone(),
            error_code: Some(if ambiguous {
                "ambiguous_legacy_binding"
            } else {
                "privacy_case_unassigned"
            }),
        });
    };
    if !user.projects.contains_key(project.as_str())
        || blocked_binding_projects.contains(project.as_str())
        || (!plan.provenance_projects.is_empty()
            && !plan.provenance_projects.contains(project.as_str()))
    {
        return Ok(MaterialProjection {
            project_id: None,
            legacy_case_id: unassigned_legacy_case_id,
            source_kind,
            migration_status: "blocked",
            state: "blocked".to_owned(),
            display_name: plan.display_name.clone(),
            error_code: Some("project_privacy_case_binding_conflict"),
        });
    }
    ProjectPrivacyCaseBindingStore::validate_pair(connection, &project, case_id)
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    Ok(MaterialProjection {
        project_id: Some(project.as_str().to_owned()),
        legacy_case_id: existing_legacy_case_id,
        source_kind,
        migration_status: "ready",
        state: plan.source.state.clone(),
        display_name: plan.display_name.clone(),
        error_code: None,
    })
}

fn apply_privacy_material_projection(
    transaction: &Transaction<'_>,
    source: &PrivacyMaterialSource,
    projection: &MaterialProjection,
) -> Result<(), PrivacyWorkflowError> {
    let (protected_display_name, display_name_sha256, display_name_scheme) =
        match projection.display_name.as_deref() {
            Some(display_name)
                if source.display_name_sha256.as_deref()
                    == Some(sha256_hex(display_name.as_bytes()).as_str())
                    && source.protected_display_name.is_some()
                    && source.display_name_protection_scheme.as_deref()
                        == Some(LOCAL_PROTECTION_SCHEME) =>
            {
                (
                    source.protected_display_name.clone(),
                    source.display_name_sha256.clone(),
                    source.display_name_protection_scheme.clone(),
                )
            }
            Some(display_name) => (
                Some(protect_local(display_name.as_bytes()).map_err(|_| {
                    migration_error(
                        "privacy_display_name_protection_failed",
                        "A migrated material display name could not be protected.",
                    )
                })?),
                Some(sha256_hex(display_name.as_bytes())),
                Some(LOCAL_PROTECTION_SCHEME.to_owned()),
            ),
            None => (
                source.protected_display_name.clone(),
                source.display_name_sha256.clone(),
                source.display_name_protection_scheme.clone(),
            ),
        };
    let changed = source.project_id.as_deref() != projection.project_id.as_deref()
        || source.legacy_case_id.as_deref() != projection.legacy_case_id.as_deref()
        || source.source_kind != projection.source_kind
        || source.migration_status != projection.migration_status
        || source.state != projection.state
        || source.protected_display_name != protected_display_name
        || source.display_name_sha256 != display_name_sha256
        || source.display_name_protection_scheme != display_name_scheme;
    if !changed {
        return Ok(());
    }

    let bypass_approved_source_trigger = source.source_kind != projection.source_kind
        && transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM privacy_redactions
                    WHERE material_id=?1 AND review_state='approved'
                 )",
                [&source.material_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| privacy_migration_store_error())?;
    if bypass_approved_source_trigger {
        transaction
            .execute_batch("DROP TRIGGER trg_privacy_material_approved_source_immutable;")
            .map_err(|_| privacy_migration_store_error())?;
    }
    let update_result = transaction
        .execute(
            "UPDATE privacy_materials
             SET project_id=?2,legacy_case_id=?3,protected_display_name=?4,
                 display_name_sha256=?5,display_name_protection_scheme=?6,
                 source_kind=?7,migration_status=?8,state=?9,
                 updated_at=updated_at,row_version=row_version+1
             WHERE material_id=?1 AND row_version=?10",
            params![
                source.material_id,
                projection.project_id,
                projection.legacy_case_id,
                protected_display_name,
                display_name_sha256,
                display_name_scheme,
                projection.source_kind,
                projection.migration_status,
                projection.state,
                source.row_version,
            ],
        )
        .map_err(|_| privacy_migration_store_error());
    if bypass_approved_source_trigger {
        recreate_approved_source_trigger(transaction)?;
    }
    if update_result? != 1 {
        return Err(migration_error(
            "privacy_material_source_changed",
            "A Privacy material changed during its optimistic migration update.",
        ));
    }
    Ok(())
}

fn recreate_approved_source_trigger(connection: &Connection) -> Result<(), PrivacyWorkflowError> {
    connection
        .execute_batch(
            "CREATE TRIGGER trg_privacy_material_approved_source_immutable
             BEFORE UPDATE ON privacy_materials
             WHEN EXISTS(
                 SELECT 1 FROM privacy_redactions
                 WHERE material_id=OLD.material_id AND review_state='approved'
             )
             AND (
                 NEW.source_sha256 IS NOT OLD.source_sha256
                 OR NEW.source_kind IS NOT OLD.source_kind
             )
             BEGIN
                 SELECT RAISE(ABORT, 'approved generation source identity is immutable');
             END;",
        )
        .map_err(|_| privacy_migration_store_error())
}

fn apply_redaction_projection(
    transaction: &Transaction<'_>,
    redaction: &ValidatedRedaction,
    final_status: &str,
) -> Result<(), PrivacyWorkflowError> {
    let source = &redaction.source;
    let target_risk_revision = redaction
        .verified_risk_revision
        .unwrap_or(source.risk_revision);
    let update_risk =
        source.review_state != "approved" && source.risk_revision != target_risk_revision;
    if source.generation_status == final_status && !update_risk {
        return Ok(());
    }
    let changed = transaction
        .execute(
            "UPDATE privacy_redactions
             SET generation_status=?2,
                 risk_revision=CASE WHEN review_state='approved' THEN risk_revision ELSE ?3 END,
                 row_version=row_version+1
             WHERE redaction_id=?1 AND row_version=?4",
            params![
                source.redaction_id,
                final_status,
                target_risk_revision,
                source.row_version,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    if changed != 1 {
        return Err(migration_error(
            "privacy_redaction_source_changed",
            "A Privacy redaction changed during its optimistic migration update.",
        ));
    }
    Ok(())
}

fn validate_material_projection_target(
    connection: &Connection,
    material_id: &str,
    projection: &MaterialProjection,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT project_id,legacy_case_id,source_kind,migration_status,state,
                    display_name_sha256
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .map_err(|_| privacy_migration_store_error())?;
    let expected_display_hash = projection
        .display_name
        .as_deref()
        .map(|value| sha256_hex(value.as_bytes()));
    if target.0.as_deref() != projection.project_id.as_deref()
        || target.1.as_deref() != projection.legacy_case_id.as_deref()
        || target.2 != projection.source_kind
        || target.3 != projection.migration_status
        || target.4 != projection.state
        || (expected_display_hash.is_some() && target.5 != expected_display_hash)
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn validate_redaction_projection_target(
    connection: &Connection,
    redaction: &ValidatedRedaction,
    final_status: &str,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT material_id,generation_number,generation_status,risk_revision,
                    review_state,revocation_state,revoked_at
             FROM privacy_redactions WHERE redaction_id=?1",
            [&redaction.source.redaction_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .map_err(|_| privacy_migration_store_error())?;
    let expected_risk = if redaction.source.review_state == "approved" {
        redaction.source.risk_revision
    } else {
        redaction
            .verified_risk_revision
            .unwrap_or(redaction.source.risk_revision)
    };
    if target.0 != redaction.source.material_id
        || target.1 != redaction.source.generation_number
        || target.2 != final_status
        || target.3 != expected_risk
        || target.4 != redaction.source.review_state
        || target.5 != redaction.source.revocation_state
        || target.6 != redaction.source.revoked_at
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn privacy_material_fingerprint(source: &PrivacyMaterialSource) -> String {
    let mut fingerprint = Fingerprint::new(b"privacy-material");
    fingerprint.text(&source.material_id);
    fingerprint.optional_text(source.attachment_id.as_deref());
    fingerprint.optional_text(source.source_sha256.as_deref());
    fingerprint.optional_text(source.source_name_sha256.as_deref());
    fingerprint.optional_text(source.media_type.as_deref());
    if let Some(value) = source.page_count {
        fingerprint.integer(value);
    } else {
        fingerprint.optional(None);
    }
    fingerprint.text(&source.extraction_status);
    fingerprint.text(&source.created_at);
    fingerprint.text(&source.updated_at);
    fingerprint.optional_text(source.deleted_at.as_deref());
    if let Some(vault) = source.vault_binding.as_ref() {
        fingerprint.text(vault.case_id.as_str());
        fingerprint.text(vault.object_id.as_str());
        fingerprint.integer(i64::try_from(vault.object_version).unwrap_or(i64::MAX));
        fingerprint.text(vault.source_sha256.as_str());
        fingerprint.text(vault.envelope_sha256.as_str());
        fingerprint.integer(i64::try_from(vault.content_bytes).unwrap_or(i64::MAX));
    }
    fingerprint.finish()
}

fn privacy_material_fingerprint_from_connection(
    connection: &Connection,
    material_id: &str,
) -> Result<String, PrivacyWorkflowError> {
    let mut sources = load_privacy_sources_for_one(connection, material_id)?;
    if sources.len() != 1 {
        return Err(migration_target_mismatch());
    }
    let source = sources.pop().expect("one source was checked");
    Ok(privacy_material_fingerprint(&source))
}

fn load_privacy_sources_for_one(
    connection: &Connection,
    material_id: &str,
) -> Result<Vec<PrivacyMaterialSource>, PrivacyWorkflowError> {
    // Reuse the canonical loader and retain a single exact source. The app
    // operation gate keeps this bounded scan stable while the row is checked.
    Ok(load_privacy_sources(connection)?
        .into_iter()
        .filter(|source| source.material_id == material_id)
        .collect())
}

fn privacy_redaction_fingerprint(redaction: &ValidatedRedaction) -> String {
    let source = &redaction.source;
    let mut fingerprint = Fingerprint::new(b"privacy-redaction");
    fingerprint.text(&source.redaction_id);
    fingerprint.text(&source.material_id);
    fingerprint.integer(source.generation_number);
    fingerprint.text(&source.extraction_sha256);
    fingerprint.text(&source.redacted_content_sha256);
    fingerprint.optional_text(source.approved_payload_sha256.as_deref());
    fingerprint.text(&source.policy_id);
    fingerprint.integer(source.policy_version);
    fingerprint.text(&source.detector_version);
    fingerprint.integer(source.unresolved_high_risk_count);
    fingerprint.text(&source.review_state);
    fingerprint.text(&sha256_hex(&source.protected_review_blob));
    fingerprint.text(&source.protection_scheme);
    fingerprint.optional_text(source.reviewed_by_sha256.as_deref());
    fingerprint.optional_text(source.approved_at.as_deref());
    fingerprint.text(&source.revocation_state);
    fingerprint.optional_text(source.revoked_at.as_deref());
    fingerprint.integer(redaction.verified_risk_revision.unwrap_or(-1));
    fingerprint.text(&source.created_at);
    fingerprint.optional_text(source.reviewed_at.as_deref());
    fingerprint.finish()
}

fn migrate_case_file(
    manager: &PrivacyWorkflowManager,
    transaction: &Transaction<'_>,
    user: &UserSnapshot,
    workspace_instance_id: &str,
    case_file: &CaseFileSource,
    report: &mut CaseMaterialMigrationReport,
) -> Result<(), PrivacyWorkflowError> {
    let project = ProjectId::parse(case_file.project_id.clone())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    if !user.projects.contains_key(project.as_str())
        || ProjectPrivacyCaseBindingStore::resolve(transaction, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .is_none()
    {
        return Err(migration_error(
            "case_file_project_binding_missing",
            "A CaseFile source project has no valid persistent Privacy case binding.",
        ));
    }
    let resolution = user.resolve_attachment(case_file);
    let source_fingerprint = case_file_fingerprint(case_file, user, &resolution);
    let deterministic_target =
        deterministic_case_file_material_id(workspace_instance_id, &case_file.file_id);
    let (target_material_id, result_state, error_code, is_legacy) = match resolution {
        AttachmentResolution::Exact(attachment) => {
            match reusable_privacy_material(manager, transaction, &project, case_file, attachment)?
            {
                Some(material_id) => (material_id, "migrated", None, false),
                None => (deterministic_target.clone(), "migrated", None, false),
            }
        }
        AttachmentResolution::Legacy(error) => (
            deterministic_target.clone(),
            "legacy_reference",
            Some(error),
            true,
        ),
        AttachmentResolution::Blocked(error) => {
            (deterministic_target.clone(), "blocked", Some(error), true)
        }
    };

    match resolution {
        AttachmentResolution::Exact(attachment) => {
            if target_material_id == deterministic_target {
                ensure_user_attachment_target(
                    transaction,
                    case_file,
                    attachment,
                    &target_material_id,
                )?;
            } else {
                validate_reused_material_target(
                    transaction,
                    project.as_str(),
                    attachment,
                    &target_material_id,
                )?;
            }
        }
        AttachmentResolution::Legacy(_) | AttachmentResolution::Blocked(_) => {
            ensure_legacy_reference_target(
                transaction,
                case_file,
                &target_material_id,
                result_state,
                error_code.expect("legacy and blocked resolutions have an error code"),
            )?;
        }
    }
    let ledger_write = record_ledger(
        transaction,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "case_files",
        &case_file.file_id,
        &source_fingerprint,
        &target_material_id,
        None,
        None,
        result_state,
        error_code,
    )?;
    match ledger_write {
        LedgerWrite::Noop => report.idempotent_noops += 1,
        LedgerWrite::Inserted | LedgerWrite::EventAppended => {
            report.case_files_migrated += 1;
            if is_legacy {
                report.legacy_references += 1;
            }
            if result_state == "blocked" {
                report.blocked += 1;
            }
        }
    }
    Ok(())
}

fn reusable_privacy_material(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    project: &ProjectId,
    case_file: &CaseFileSource,
    attachment: &AttachmentSource,
) -> Result<Option<String>, PrivacyWorkflowError> {
    if !optional_v5_auxiliary_table_present(connection, "privacy_vault_material_refs")? {
        return Ok(None);
    }
    let mut statement = connection
        .prepare(
            "SELECT material.material_id
             FROM privacy_materials AS material
             JOIN privacy_vault_material_refs AS vault
               ON vault.material_id=material.material_id
             WHERE material.project_id=?1
               AND material.source_sha256=?2
               AND material.source_kind='vault'
               AND material.migration_status='ready'
               AND material.deleted_at IS NULL
               AND vault.import_state IN('vault_committed','review_ready','processing_failed')
               AND EXISTS(
                   SELECT 1 FROM case_material_migration_ledger AS ledger
                   WHERE ledger.migration_id=?3
                     AND ledger.source_store=?4
                     AND ledger.source_table='privacy_materials'
                     AND ledger.source_key=material.material_id
                     AND ledger.result_state='migrated'
               )
             ORDER BY material.material_id",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let candidates = statement
        .query_map(
            params![
                project.as_str(),
                attachment.sha256,
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_PRIVACY
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    if candidates.len() != 1 {
        return Ok(None);
    }
    let material_id = candidates[0].clone();
    let conflicting_source: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM case_material_migration_ledger
                WHERE migration_id=?1 AND source_store=?2 AND source_table='case_files'
                  AND target_material_id=?3 AND source_key<>?4
             )",
            params![
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                material_id,
                case_file.file_id,
            ],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if conflicting_source {
        return Ok(None);
    }
    let case_id = ProjectPrivacyCaseBindingStore::resolve(connection, project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
        .ok_or_else(migration_target_mismatch)?;
    let binding = vault_broker::load_vault_binding_for_material(connection, &material_id)
        .map_err(PrivacyWorkflowError::vault)?
        .ok_or_else(migration_target_mismatch)?;
    if binding.case_id.as_str() != case_id.as_str()
        || binding.source_sha256.as_str() != attachment.sha256
    {
        return Ok(None);
    }
    validate_vault_binding_content(manager, &binding)?;
    Ok(Some(material_id))
}

fn ensure_user_attachment_target(
    transaction: &Transaction<'_>,
    case_file: &CaseFileSource,
    attachment: &AttachmentSource,
    material_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    let existing = transaction
        .query_row(
            "SELECT project_id,attachment_id,source_sha256,source_name_sha256,media_type,
                    source_kind,extraction_status,migration_status,state,display_name_sha256,
                    row_version
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    let source_name_sha256 = sha256_hex(attachment.original_name.as_bytes());
    let display_name_sha256 = sha256_hex(case_file.title.as_bytes());
    if let Some(existing) = existing {
        if existing.0.as_deref() != Some(case_file.project_id.as_str())
            || existing.1.as_deref() != Some(attachment.attachment_id.as_str())
            || existing.5 != "user_attachment"
            || existing.7 != "ready"
            || existing.8 != "registered"
        {
            return Err(migration_target_mismatch());
        }
        let projection_changed = existing.2.as_deref() != Some(attachment.sha256.as_str())
            || existing.3.as_deref() != Some(source_name_sha256.as_str())
            || existing.4.as_deref() != Some(attachment.detected_mime.as_str())
            || existing.6 != attachment.extraction_status
            || existing.9.as_deref() != Some(display_name_sha256.as_str());
        if projection_changed {
            let has_generation: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM privacy_redactions WHERE material_id=?1
                     )",
                    [material_id],
                    |row| row.get(0),
                )
                .map_err(|_| privacy_migration_store_error())?;
            if has_generation {
                return Err(migration_target_mismatch());
            }
            let protected_display_name =
                protect_local(case_file.title.as_bytes()).map_err(|_| {
                    migration_error(
                        "case_file_display_name_protection_failed",
                        "A changed CaseFile title could not be protected for the unified material index.",
                    )
                })?;
            let changed = transaction
                .execute(
                    "UPDATE privacy_materials
                     SET protected_display_name=?2,display_name_sha256=?3,
                         display_name_protection_scheme=?4,source_sha256=?5,
                         source_name_sha256=?6,media_type=?7,extraction_status=?8,
                         row_version=row_version+1
                     WHERE material_id=?1 AND row_version=?9
                       AND source_kind='user_attachment'
                       AND migration_status='ready' AND state='registered'",
                    params![
                        material_id,
                        protected_display_name,
                        display_name_sha256,
                        LOCAL_PROTECTION_SCHEME,
                        attachment.sha256,
                        source_name_sha256,
                        attachment.detected_mime,
                        attachment.extraction_status,
                        existing.10,
                    ],
                )
                .map_err(|_| privacy_migration_store_error())?;
            if changed != 1 {
                return Err(migration_target_mismatch());
            }
        }
        return Ok(());
    }
    let protected_display_name = protect_local(case_file.title.as_bytes()).map_err(|_| {
        migration_error(
            "case_file_display_name_protection_failed",
            "A CaseFile title could not be protected for the unified material index.",
        )
    })?;
    transaction
        .execute(
            "INSERT INTO privacy_materials(
                material_id,project_id,attachment_id,protected_display_name,
                display_name_sha256,display_name_protection_scheme,source_sha256,
                source_name_sha256,media_type,page_count,source_kind,extraction_status,
                migration_status,state,row_version,created_at,updated_at,deleted_at
             ) VALUES(
                ?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,'user_attachment',?10,
                'ready','registered',1,?11,?11,NULL
             )",
            params![
                material_id,
                case_file.project_id,
                attachment.attachment_id,
                protected_display_name,
                display_name_sha256,
                LOCAL_PROTECTION_SCHEME,
                attachment.sha256,
                source_name_sha256,
                attachment.detected_mime,
                attachment.extraction_status,
                case_file.created_at,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    Ok(())
}

fn validate_reused_material_target(
    connection: &Connection,
    project_id: &str,
    attachment: &AttachmentSource,
    material_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    let valid: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM privacy_materials
                WHERE material_id=?1 AND project_id=?2 AND source_sha256=?3
                  AND source_kind='vault' AND migration_status='ready'
                  AND deleted_at IS NULL
             )",
            params![material_id, project_id, attachment.sha256],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if valid {
        Ok(())
    } else {
        Err(migration_target_mismatch())
    }
}

fn case_file_terminal_matches(
    manager: &PrivacyWorkflowManager,
    connection: &Connection,
    user: &UserSnapshot,
    workspace_instance_id: &str,
    case_file: &CaseFileSource,
) -> Result<bool, PrivacyWorkflowError> {
    let project = ProjectId::parse(case_file.project_id.clone())
        .map_err(PrivacyWorkflowError::project_case_binding)?;
    let Some(_) = ProjectPrivacyCaseBindingStore::resolve(connection, &project)
        .map_err(PrivacyWorkflowError::project_case_binding)?
    else {
        return Ok(false);
    };
    let resolution = user.resolve_attachment(case_file);
    let fingerprint = case_file_fingerprint(case_file, user, &resolution);
    let Some((ledger, effective_result)) = effective_ledger_entry(
        connection,
        CASE_MATERIAL_MIGRATION_ID,
        SOURCE_STORE_USER,
        "case_files",
        &case_file.file_id,
        &fingerprint,
    )?
    else {
        return Ok(false);
    };
    if ledger.target_redaction_id.is_some() || ledger.assigned_generation_number.is_some() {
        return Err(migration_target_mismatch());
    }
    let deterministic_target =
        deterministic_case_file_material_id(workspace_instance_id, &case_file.file_id);
    match resolution {
        AttachmentResolution::Exact(attachment) => {
            if effective_result != "migrated" {
                return Err(migration_target_mismatch());
            }
            let expected_target =
                reusable_privacy_material(manager, connection, &project, case_file, attachment)?
                    .unwrap_or_else(|| deterministic_target.clone());
            if ledger.target_material_id != expected_target {
                return Err(migration_target_mismatch());
            }
            if expected_target == deterministic_target {
                validate_user_attachment_terminal_target(
                    connection,
                    case_file,
                    attachment,
                    &expected_target,
                )?;
            } else {
                validate_reused_material_target(
                    connection,
                    project.as_str(),
                    attachment,
                    &expected_target,
                )?;
            }
        }
        AttachmentResolution::Legacy(error) => {
            if effective_result != "legacy_reference"
                || ledger.target_material_id != deterministic_target
            {
                return Err(migration_target_mismatch());
            }
            validate_legacy_reference_terminal_target(
                connection,
                case_file,
                &deterministic_target,
                "legacy_reference",
                error,
            )?;
        }
        AttachmentResolution::Blocked(error) => {
            if effective_result != "blocked" || ledger.target_material_id != deterministic_target {
                return Err(migration_target_mismatch());
            }
            validate_legacy_reference_terminal_target(
                connection,
                case_file,
                &deterministic_target,
                "blocked",
                error,
            )?;
        }
    }
    Ok(true)
}

fn validate_user_attachment_terminal_target(
    connection: &Connection,
    case_file: &CaseFileSource,
    attachment: &AttachmentSource,
    material_id: &str,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT project_id,attachment_id,protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,media_type,
                    page_count,source_kind,extraction_status,migration_status,state,deleted_at
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            },
        )
        .map_err(|_| migration_target_mismatch())?;
    let display = target
        .2
        .as_deref()
        .ok_or_else(migration_target_mismatch)
        .and_then(|protected| {
            unprotect_local(protected).map_err(|_| migration_target_mismatch())
        })?;
    if target.0.as_deref() != Some(case_file.project_id.as_str())
        || target.1.as_deref() != Some(attachment.attachment_id.as_str())
        || display != case_file.title.as_bytes()
        || target.3.as_deref() != Some(sha256_hex(case_file.title.as_bytes()).as_str())
        || target.4.as_deref() != Some(LOCAL_PROTECTION_SCHEME)
        || target.5.as_deref() != Some(attachment.sha256.as_str())
        || target.6.as_deref() != Some(sha256_hex(attachment.original_name.as_bytes()).as_str())
        || target.7.as_deref() != Some(attachment.detected_mime.as_str())
        || target.8.is_some()
        || target.9 != "user_attachment"
        || target.10 != attachment.extraction_status
        || target.11 != "ready"
        || target.12 != "registered"
        || target.13.is_some()
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn validate_legacy_reference_terminal_target(
    connection: &Connection,
    case_file: &CaseFileSource,
    material_id: &str,
    migration_status: &str,
    error_code: &str,
) -> Result<(), PrivacyWorkflowError> {
    let target = connection
        .query_row(
            "SELECT project_id,attachment_id,protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,media_type,
                    page_count,source_kind,extraction_status,migration_status,state,deleted_at
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, Option<String>>(13)?,
                ))
            },
        )
        .map_err(|_| migration_target_mismatch())?;
    let display = target
        .2
        .as_deref()
        .ok_or_else(migration_target_mismatch)
        .and_then(|protected| {
            unprotect_local(protected).map_err(|_| migration_target_mismatch())
        })?;
    if target.0.as_deref() != Some(case_file.project_id.as_str())
        || target.1.is_some()
        || display != case_file.title.as_bytes()
        || target.3.as_deref() != Some(sha256_hex(case_file.title.as_bytes()).as_str())
        || target.4.as_deref() != Some(LOCAL_PROTECTION_SCHEME)
        || target.5.is_some()
        || target.6.is_some()
        || target.7.is_some()
        || target.8.is_some()
        || target.9 != "legacy_reference"
        || target.10 != error_code
        || target.11 != migration_status
        || target.12 != "blocked"
        || target.13.is_some()
    {
        return Err(migration_target_mismatch());
    }
    let reference = connection
        .query_row(
            "SELECT legacy_reference_id,material_id,protected_storage_reference_blob,
                    storage_reference_sha256,protection_scheme
             FROM case_material_legacy_references
             WHERE migration_id=?1 AND source_store=?2 AND source_table='case_files'
               AND source_key=?3",
            params![
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                case_file.file_id,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            },
        )
        .map_err(|_| migration_target_mismatch())?;
    let storage_reference =
        unprotect_local(&reference.2).map_err(|_| migration_target_mismatch())?;
    if reference.0 != legacy_reference_id(&case_file.file_id)
        || reference.1 != material_id
        || storage_reference != case_file.storage_reference.as_bytes()
        || reference.3 != sha256_hex(case_file.storage_reference.as_bytes())
        || reference.4 != LOCAL_PROTECTION_SCHEME
    {
        return Err(migration_target_mismatch());
    }
    Ok(())
}

fn ensure_legacy_reference_target(
    transaction: &Transaction<'_>,
    case_file: &CaseFileSource,
    material_id: &str,
    result_state: &str,
    error_code: &str,
) -> Result<(), PrivacyWorkflowError> {
    let migration_status = if result_state == "blocked" {
        "blocked"
    } else {
        "legacy_reference"
    };
    let display_name_sha256 = sha256_hex(case_file.title.as_bytes());
    let existing = transaction
        .query_row(
            "SELECT project_id,source_kind,extraction_status,migration_status,state,
                    display_name_sha256
             FROM privacy_materials WHERE material_id=?1",
            [material_id],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    if let Some(existing) = existing {
        if existing.0.as_deref() != Some(case_file.project_id.as_str())
            || existing.1 != "legacy_reference"
            || existing.2 != error_code
            || existing.3 != migration_status
            || existing.4 != "blocked"
            || existing.5.as_deref() != Some(display_name_sha256.as_str())
        {
            return Err(migration_target_mismatch());
        }
    } else {
        let protected_display_name = protect_local(case_file.title.as_bytes()).map_err(|_| {
            migration_error(
                "case_file_display_name_protection_failed",
                "A CaseFile title could not be protected for the unified material index.",
            )
        })?;
        transaction
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,protected_display_name,display_name_sha256,
                    display_name_protection_scheme,source_sha256,source_name_sha256,
                    media_type,page_count,source_kind,extraction_status,migration_status,
                    state,row_version,created_at,updated_at,deleted_at
                 ) VALUES(
                    ?1,?2,?3,?4,?5,NULL,NULL,NULL,NULL,'legacy_reference',?6,?7,
                    'blocked',1,?8,?8,NULL
                 )",
                params![
                    material_id,
                    case_file.project_id,
                    protected_display_name,
                    display_name_sha256,
                    LOCAL_PROTECTION_SCHEME,
                    error_code,
                    migration_status,
                    case_file.created_at,
                ],
            )
            .map_err(|_| privacy_migration_store_error())?;
    }

    let reference_hash = sha256_hex(case_file.storage_reference.as_bytes());
    let existing_reference = transaction
        .query_row(
            "SELECT storage_reference_sha256,protection_scheme
             FROM case_material_legacy_references
             WHERE migration_id=?1 AND source_store=?2 AND source_table='case_files'
               AND source_key=?3",
            params![
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                case_file.file_id,
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|_| privacy_migration_store_error())?;
    if let Some((stored_hash, scheme)) = existing_reference {
        if stored_hash != reference_hash || scheme != LOCAL_PROTECTION_SCHEME {
            return Err(migration_target_mismatch());
        }
        return Ok(());
    }
    let protected_reference =
        protect_local(case_file.storage_reference.as_bytes()).map_err(|_| {
            migration_error(
                "legacy_reference_protection_failed",
                "A legacy CaseFile storage reference could not be protected.",
            )
        })?;
    transaction
        .execute(
            "INSERT INTO case_material_legacy_references(
                legacy_reference_id,material_id,migration_id,source_store,source_table,
                source_key,protected_storage_reference_blob,storage_reference_sha256,
                protection_scheme
             ) VALUES(?1,?2,?3,?4,'case_files',?5,?6,?7,?8)",
            params![
                legacy_reference_id(&case_file.file_id),
                material_id,
                CASE_MATERIAL_MIGRATION_ID,
                SOURCE_STORE_USER,
                case_file.file_id,
                protected_reference,
                reference_hash,
                LOCAL_PROTECTION_SCHEME,
            ],
        )
        .map_err(|_| privacy_migration_store_error())?;
    Ok(())
}

fn case_file_fingerprint(
    case_file: &CaseFileSource,
    user: &UserSnapshot,
    resolution: &AttachmentResolution<'_>,
) -> String {
    let mut fingerprint = Fingerprint::new(b"user-case-file");
    fingerprint.text(&case_file.file_id);
    fingerprint.text(&case_file.project_id);
    fingerprint.text(&case_file.title);
    fingerprint.text(&case_file.file_type);
    fingerprint.text(&case_file.storage_reference);
    fingerprint.text(&case_file.summary);
    fingerprint.text(&case_file.created_at);
    match resolution {
        AttachmentResolution::Exact(attachment) => {
            append_attachment_fingerprint(&mut fingerprint, attachment);
        }
        AttachmentResolution::Legacy(error) | AttachmentResolution::Blocked(error) => {
            fingerprint.text(error);
            for attachment in matching_attachment_candidates(user, case_file) {
                append_attachment_fingerprint(&mut fingerprint, attachment);
            }
        }
    }
    fingerprint.finish()
}

fn matching_attachment_candidates<'a>(
    user: &'a UserSnapshot,
    case_file: &CaseFileSource,
) -> Vec<&'a AttachmentSource> {
    attachment_reference_candidate_ids(&case_file.storage_reference)
        .into_iter()
        .filter_map(|identifier| user.attachments.get(identifier))
        .collect()
}

fn attachment_reference_candidate_ids(raw: &str) -> BTreeSet<&str> {
    let mut identifiers = BTreeSet::from([raw]);
    let mut remainder = raw;
    let mut prefix_count = 0_u8;
    while let Some(stripped) = remainder.strip_prefix("attachment:") {
        prefix_count = prefix_count.saturating_add(1);
        remainder = stripped;
        if prefix_count > 2 {
            return identifiers;
        }
    }
    if prefix_count >= 1 {
        identifiers.insert(
            raw.strip_prefix("attachment:")
                .expect("a counted prefix must strip"),
        );
    }
    if prefix_count == 2 {
        identifiers.insert(remainder);
    }
    identifiers
}

fn append_attachment_fingerprint(fingerprint: &mut Fingerprint, attachment: &AttachmentSource) {
    fingerprint.text(&attachment.attachment_id);
    fingerprint.optional_text(attachment.project_id.as_deref());
    fingerprint.text(&attachment.original_name);
    fingerprint.text(&attachment.extension);
    fingerprint.text(&attachment.detected_mime);
    fingerprint.text(&attachment.sha256);
    fingerprint.integer(attachment.size_bytes);
    fingerprint.text(&attachment.extraction_status);
    fingerprint.optional_text(attachment.extracted_text_sha256.as_deref());
    fingerprint.text(&attachment.segments_json_sha256);
    fingerprint.optional_text(attachment.error_code.as_deref());
    fingerprint.text(&attachment.created_at);
}

fn deterministic_case_file_material_id(workspace_instance_id: &str, file_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MATERIAL_ID_DOMAIN);
    hasher.update(workspace_instance_id.as_bytes());
    hasher.update(b"\0user.sqlite\0case_files\0");
    hasher.update(file_id.as_bytes());
    format!("mat_{}", &format!("{:x}", hasher.finalize())[..32])
}

fn legacy_reference_id(file_id: &str) -> String {
    let mut fingerprint = Fingerprint::new(b"legacy-reference");
    fingerprint.text(CASE_MATERIAL_MIGRATION_ID);
    fingerprint.text(file_id);
    format!("legacyref_{}", &fingerprint.finish()[..32])
}

fn validate_target_invariants(
    connection: &Connection,
    user: &UserSnapshot,
    cleanup: &CleanupAuthorizationSnapshot,
) -> Result<(), PrivacyWorkflowError> {
    for case_file in &user.case_files {
        let covered: bool = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM case_material_migration_ledger
                    WHERE migration_id=?1 AND source_store=?2
                      AND source_table='case_files' AND source_key=?3
                      AND result_state IN('migrated','legacy_reference','blocked')
                 )",
                params![
                    CASE_MATERIAL_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    case_file.file_id
                ],
                |row| row.get(0),
            )
            .map_err(|_| privacy_migration_store_error())?;
        if !covered {
            return Err(migration_target_mismatch());
        }
    }
    let bad_generations: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM privacy_redactions
                WHERE generation_number<=0
             )",
            [],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if bad_generations {
        return Err(migration_target_mismatch());
    }
    let missing_material_target: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM case_material_migration_ledger AS ledger
                LEFT JOIN privacy_materials AS material
                  ON material.material_id=ledger.target_material_id
                WHERE ledger.migration_id=?1
                  AND ledger.source_table<>'source_manifest'
                  AND material.material_id IS NULL
             )",
            [CASE_MATERIAL_MIGRATION_ID],
            |row| row.get(0),
        )
        .map_err(|_| privacy_migration_store_error())?;
    if missing_material_target {
        return Err(migration_target_mismatch());
    }
    let missing_redaction_targets = {
        let mut statement = connection
            .prepare(
                "SELECT ledger.target_redaction_id,ledger.target_material_id,
                        ledger.assigned_generation_number
                 FROM case_material_migration_ledger AS ledger
                 LEFT JOIN privacy_redactions AS redaction
                   ON redaction.redaction_id=ledger.target_redaction_id
                  AND redaction.material_id=ledger.target_material_id
                  AND redaction.generation_number=ledger.assigned_generation_number
                 WHERE ledger.migration_id=?1
                   AND ledger.target_redaction_id IS NOT NULL
                   AND redaction.redaction_id IS NULL
                 ORDER BY ledger.target_redaction_id",
            )
            .map_err(|_| privacy_migration_store_error())?;
        let targets = statement
            .query_map([CASE_MATERIAL_MIGRATION_ID], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| privacy_migration_store_error())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| privacy_migration_store_error())?;
        targets
    };
    if !missing_redaction_targets.is_empty() {
        for (redaction_id, material_id, generation_number) in missing_redaction_targets {
            if cleanup.redactions.get(&redaction_id) != Some(&(material_id, generation_number)) {
                return Err(migration_target_mismatch());
            }
        }
    }
    let privacy_sources = load_privacy_sources(connection)?;
    let mut project_statement = connection
        .prepare(
            "SELECT DISTINCT project_id
             FROM privacy_materials
             WHERE migration_status='ready' AND project_id IS NOT NULL",
        )
        .map_err(|_| privacy_migration_store_error())?;
    let ready_projects = project_statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| privacy_migration_store_error())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| privacy_migration_store_error())?;
    for project_value in ready_projects {
        if !user.projects.contains_key(&project_value) {
            let project_sources = privacy_sources
                .iter()
                .filter(|source| {
                    source.project_id.as_deref() == Some(project_value.as_str())
                        && source.migration_status == "ready"
                })
                .collect::<Vec<_>>();
            if project_sources.is_empty() {
                return Err(migration_target_mismatch());
            }
            for source in project_sources {
                if !completed_project_deletion_tombstone(connection, user, source, cleanup)? {
                    return Err(migration_target_mismatch());
                }
            }
            continue;
        }
        let project =
            ProjectId::parse(project_value).map_err(PrivacyWorkflowError::project_case_binding)?;
        let case_id = ProjectPrivacyCaseBindingStore::resolve(connection, &project)
            .map_err(PrivacyWorkflowError::project_case_binding)?
            .ok_or_else(migration_target_mismatch)?;
        let conflict =
            if optional_v5_auxiliary_table_present(connection, "privacy_vault_material_refs")? {
                connection
                    .query_row(
                        "SELECT EXISTS(
                        SELECT 1
                        FROM privacy_materials AS material
                        JOIN privacy_vault_material_refs AS vault
                          ON vault.material_id=material.material_id
                        WHERE material.project_id=?1 AND material.migration_status='ready'
                          AND material.source_kind='vault' AND vault.case_id<>?2
                     )",
                        params![project.as_str(), case_id.as_str()],
                        |row| row.get(0),
                    )
                    .map_err(|_| privacy_migration_store_error())?
            } else {
                false
            };
        if conflict {
            return Err(migration_target_mismatch());
        }
    }
    Ok(())
}

fn optional_v5_auxiliary_table_present(
    connection: &Connection,
    table_name: &'static str,
) -> Result<bool, PrivacyWorkflowError> {
    let present = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1
             )",
            [table_name],
            |row| row.get::<_, bool>(0),
        )
        .map_err(|_| privacy_preflight_error())?;
    if present {
        return Ok(true);
    }
    let version = connection
        .query_row(
            "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| privacy_preflight_error())?;
    if version.as_deref() == Some("5") {
        Ok(false)
    } else {
        Err(privacy_preflight_error())
    }
}

fn query_manifest(
    connection: &Connection,
    sql: &str,
    columns: usize,
) -> Result<String, PrivacyWorkflowError> {
    let mut statement = connection
        .prepare(sql)
        .map_err(|_| source_snapshot_error())?;
    let mut rows = statement.query([]).map_err(|_| source_snapshot_error())?;
    let mut fingerprint = Fingerprint::new(b"sqlite-manifest");
    while let Some(row) = rows.next().map_err(|_| source_snapshot_error())? {
        for index in 0..columns {
            match row.get_ref(index).map_err(|_| source_snapshot_error())? {
                ValueRef::Null => fingerprint.optional(None),
                ValueRef::Integer(value) => fingerprint.value(&value.to_be_bytes()),
                ValueRef::Real(value) => fingerprint.value(&value.to_bits().to_be_bytes()),
                ValueRef::Text(value) | ValueRef::Blob(value) => fingerprint.value(value),
            }
        }
    }
    Ok(fingerprint.finish())
}

fn case_material_source_schema_manifest(
    connection: &Connection,
) -> Result<String, PrivacyWorkflowError> {
    let exact_schema = database::validate_open_user_database_migration_source_read_only(connection)
        .map_err(|_| source_snapshot_error())?;
    case_material_source_schema_contract(exact_schema)
}

fn case_material_source_schema_contract(
    exact_schema: ValidatedUserSourceSchema,
) -> Result<String, PrivacyWorkflowError> {
    match exact_schema {
        ValidatedUserSourceSchema::V031V10 | ValidatedUserSourceSchema::CurrentV11 => {
            Ok(sha256_hex(CASE_MATERIAL_SOURCE_SCHEMA_CONTRACT.as_bytes()))
        }
    }
}

fn primary_key_manifest(
    connection: &Connection,
    sql: &str,
) -> Result<String, PrivacyWorkflowError> {
    query_manifest(connection, sql, 1)
}

fn source_rows_manifest(connection: &Connection) -> Result<String, PrivacyWorkflowError> {
    let projects = query_manifest(
        connection,
        "SELECT project_id,title,case_type,status,opened_on,summary,created_at,updated_at
         FROM projects ORDER BY project_id",
        8,
    )?;
    let case_files = query_manifest(
        connection,
        "SELECT file_id,project_id,title,file_type,storage_reference,summary,created_at
         FROM case_files ORDER BY file_id",
        7,
    )?;
    let attachments = query_manifest(
        connection,
        "SELECT attachment_id,project_id,original_name,extension,detected_mime,sha256,
                size_bytes,extraction_status,extracted_text,segments_json,error_code,created_at
         FROM attachments ORDER BY attachment_id",
        12,
    )?;
    let mut fingerprint = Fingerprint::new(b"user-source-rows");
    fingerprint.text(&projects);
    fingerprint.text(&case_files);
    fingerprint.text(&attachments);
    Ok(fingerprint.finish())
}

fn file_sha256(path: &Path) -> Result<String, PrivacyWorkflowError> {
    let file = File::open(path).map_err(|_| source_snapshot_error())?;
    hash_open_file(file)
}

fn sqlite_sidecar_sha256(
    database_path: &Path,
    suffix: &str,
) -> Result<Option<String>, PrivacyWorkflowError> {
    let mut sidecar = database_path.as_os_str().to_os_string();
    sidecar.push(suffix);
    match File::open(Path::new(&sidecar)) {
        Ok(file) => hash_open_file(file).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(source_snapshot_error()),
    }
}

fn hash_open_file(mut file: File) -> Result<String, PrivacyWorkflowError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| source_snapshot_error())?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

struct Fingerprint {
    hasher: Sha256,
}

impl Fingerprint {
    fn new(profile: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update((profile.len() as u64).to_be_bytes());
        hasher.update(profile);
        Self { hasher }
    }

    fn value(&mut self, value: &[u8]) {
        self.hasher.update([1]);
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
    }

    fn text(&mut self, value: &str) {
        self.value(value.as_bytes());
    }

    fn integer(&mut self, value: i64) {
        self.value(&value.to_be_bytes());
    }

    fn optional(&mut self, value: Option<&[u8]>) {
        match value {
            Some(value) => self.value(value),
            None => self.hasher.update([0]),
        }
    }

    fn optional_text(&mut self, value: Option<&str>) {
        self.optional(value.map(str::as_bytes));
    }

    fn finish(self) -> String {
        format!("{:x}", self.hasher.finalize())
    }
}

fn migration_error(code: &'static str, message: &'static str) -> PrivacyWorkflowError {
    PrivacyWorkflowError::new(code, message)
}

fn source_snapshot_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_source_snapshot_failed",
        "The immutable user-database migration snapshot could not be verified.",
    )
}

fn v031_user_source_gate_error() -> PrivacyWorkflowError {
    migration_error(
        "v031_case_material_user_source_invalid",
        "Step 5 requires the exact user schema-10 source authenticated by the original rollback gate.",
    )
}

fn v031_privacy_v5_proof_error() -> PrivacyWorkflowError {
    migration_error(
        "v031_case_material_privacy_v5_invalid",
        "The Privacy schema-5 checkpoint failed its exact read-only manifest proof.",
    )
}

fn v031_checkpoint_source_proof_error() -> PrivacyWorkflowError {
    migration_error(
        "v031_case_material_checkpoint_source_invalid",
        "The authenticated pre-v5 source or Binding/Materials checkpoint commitments no longer match Step 5.",
    )
}

fn v031_terminal_proof_error() -> PrivacyWorkflowError {
    migration_error(
        "v031_binding_material_terminal_proof_invalid",
        "Committed Privacy schema-5 state is not an exact terminal binding/material migration.",
    )
}

fn inject_backfill_failure(
    requested: Option<BackfillFailurePoint>,
    current: BackfillFailurePoint,
) -> Result<(), PrivacyWorkflowError> {
    if requested == Some(current) {
        return Err(injected_backfill_failure());
    }
    Ok(())
}

fn injected_backfill_failure() -> PrivacyWorkflowError {
    migration_error(
        "v031_case_material_injected_failure",
        "The test-only Step-5 failure was injected at a durable migration boundary.",
    )
}

fn privacy_preflight_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_privacy_preflight_failed",
        "The Privacy database failed migration integrity or referential checks.",
    )
}

fn cleanup_preflight_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_cleanup_preflight_failed",
        "Pending cleanup state could not be verified without modifying the Privacy or Vault stores.",
    )
}

fn cleanup_pending_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_cleanup_pending",
        "The case-material migration is blocked until prepared or committed cleanup work reaches a terminal state.",
    )
}

fn missing_vault_history_error() -> PrivacyWorkflowError {
    migration_error(
        "case_material_vault_missing_with_history",
        "The Vault is missing while the Privacy store still contains Vault-bound historical identity.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commands::v031_migration_checkpoint::V031MigrationCheckpointProof,
        privacy_manager::{LocalOcrStatus, LocalOcrStatusCode, PrivacyConfig},
        privacy_workflow::{
            approved_case_projection::ProjectionFailurePoint, test_workspace_instance_id,
            ApprovedPublicationInvalidator, LocalOcrExecutionContext, PrivacyReviewView,
        },
    };
    use privacy::{
        vault_store::{VaultPrivateMetadataInputV1, VaultStore},
        vnext::{CaseId, MaterialId},
        ReceiptSigner, RetentionPolicyV1,
    };
    use rusqlite::Connection;
    use serde_json::json;
    use std::{collections::BTreeSet, fs, path::PathBuf, sync::Arc};

    const PROJECT_A: &str = "case-migration-project-a";
    const PROJECT_B: &str = "case-migration-project-b";
    const V031_UNASSIGNED_MATERIAL_ID: &str = "mat_31313131313131313131313131313131";
    const V031_UNASSIGNED_REDACTION_ID: &str = "red_31313131313131313131313131313131";

    struct NoopPublicationInvalidator;

    impl ApprovedPublicationInvalidator for NoopPublicationInvalidator {
        fn invalidate_case(
            &self,
            _case_id: &CaseId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_material(
            &self,
            _case_id: &CaseId,
            _material_id: &MaterialId,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_all(&self, _reason_code: &'static str) -> Result<u64, &'static str> {
            Ok(0)
        }

        fn invalidate_lifecycle_bindings(
            &self,
            _lifecycle_binding_ids: &BTreeSet<String>,
            _reason_code: &'static str,
        ) -> Result<u64, &'static str> {
            Ok(0)
        }
    }

    struct Fixture {
        _directory: tempfile::TempDir,
        user_database_path: PathBuf,
        manager: PrivacyWorkflowManager,
    }

    struct V031Fixture {
        _directory: tempfile::TempDir,
        user_database_path: PathBuf,
        manager: PrivacyWorkflowManager,
        gate: OriginalRollbackVerifiedGate,
    }

    impl V031Fixture {
        fn new(projects: &[&str]) -> Self {
            Self::new_with_privacy_seed(projects, |_| {})
        }

        fn new_with_privacy_seed(
            projects: &[&str],
            seed_privacy: impl FnOnce(&Connection),
        ) -> Self {
            let directory = tempfile::tempdir().expect("v0.3.1 migration fixture directory");
            let user_database_path = database::user_database_path(directory.path());
            create_exact_v031_user_database(&user_database_path, projects);
            let original_user_source =
                database::with_validated_user_database_migration_source_read_only(
                    &user_database_path,
                    |_| (),
                )
                .expect("exact v0.3.1 user source")
                .0;
            let mut gate =
                OriginalRollbackVerifiedGate::from_user_source_for_test(original_user_source);

            let privacy_directory = directory
                .path()
                .join(crate::privacy_workflow::PRIVACY_DIRECTORY_NAME);
            fs::create_dir_all(&privacy_directory).expect("privacy fixture directory");
            let privacy_database =
                privacy_directory.join(crate::privacy_workflow::PRIVACY_DATABASE_NAME);
            let privacy = Connection::open(&privacy_database).expect("privacy v1 database");
            privacy
                .execute_batch(privacy::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
                .expect("privacy v1 schema");
            privacy
                .execute(
                    "INSERT INTO privacy_schema_metadata(key,value,updated_at)
                     VALUES('schema_version','1','2026-07-19 15:41:29')",
                    [],
                )
                .expect("privacy v1 marker");
            seed_privacy(&privacy);
            drop(privacy);
            let original_privacy_source =
                privacy::validate_privacy_v1_migration_source_read_only(&privacy_database)
                    .expect("exact v0.3.1 Privacy source");
            gate = gate.with_privacy_source_for_checkpoint_test(original_privacy_source);

            let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(NoopPublicationInvalidator),
            )
            .expect("deferred v0.3.1 privacy manager");
            manager.set_test_runtime(
                ReceiptSigner::new([31_u8; 32]).expect("v0.3.1 migration test signer"),
                1_800_000_000,
            );
            Self {
                _directory: directory,
                user_database_path,
                manager,
                gate,
            }
        }

        #[cfg(windows)]
        fn with_exact_unassigned_review(projects: &[&str]) -> Self {
            Self::with_unassigned_review_payload(projects, false)
        }

        #[cfg(windows)]
        fn with_nonlegacy_empty_display_review(projects: &[&str]) -> Self {
            Self::with_unassigned_review_payload(projects, true)
        }

        #[cfg(windows)]
        fn with_unassigned_review_payload(
            projects: &[&str],
            include_current_empty_display: bool,
        ) -> Self {
            Self::new_with_privacy_seed(projects, |privacy| {
                let source_sha256 = sha256_hex(b"exact v0.3.1 unassigned review source");
                let extraction_sha256 = sha256_hex(b"exact v0.3.1 extraction");
                let redacted_sha256 = sha256_hex(b"exact v0.3.1 redacted content");
                let mut payload = json!({
                    "schemaVersion": 1,
                    "materialId": V031_UNASSIGNED_MATERIAL_ID,
                    "redactionId": V031_UNASSIGNED_REDACTION_ID,
                    "sourceSha256": source_sha256,
                    "extractionSha256": extraction_sha256,
                    "suggestedRedactedContentSha256": redacted_sha256,
                    "processingVersion": "v0.3.1-exact-test",
                    "mediaType": "text/plain",
                    "pageCount": 0,
                    "backendTrace": [],
                    "summary": {
                        "total": 0,
                        "counts": {},
                        "changed": false,
                        "manualReviewRequired": false,
                        "redactionVersion": "v0.3.1-exact-test"
                    },
                    "forbiddenCanaries": [],
                    "pages": []
                });
                if include_current_empty_display {
                    payload["sourceDisplayName"] = serde_json::Value::String(String::new());
                }
                let payload = serde_json::to_vec(&payload).expect("review payload serializes");
                assert_eq!(
                    is_exact_v031_stored_review_payload(&payload),
                    !include_current_empty_display
                );
                let protected = protect_local(&payload).expect("exact v0.3.1 review protects");
                privacy
                    .execute(
                        "INSERT INTO privacy_materials(
                            material_id,project_id,attachment_id,source_sha256,
                            source_name_sha256,media_type,page_count,state,created_at,updated_at
                         ) VALUES(?1,NULL,NULL,?2,?3,'text/plain',0,'review_required',?4,?4)",
                        params![
                            V031_UNASSIGNED_MATERIAL_ID,
                            source_sha256,
                            sha256_hex(b"exact-v031-local-material.txt"),
                            "2026-07-19 15:41:30"
                        ],
                    )
                    .expect("exact v0.3.1 material inserts");
                privacy
                    .execute(
                        "INSERT INTO privacy_redactions(
                            redaction_id,material_id,extraction_sha256,
                            redacted_content_sha256,approved_payload_sha256,policy_id,
                            policy_version,detector_version,unresolved_high_risk_count,
                            review_state,protected_review_blob,protection_scheme,
                            reviewed_by_sha256,created_at,reviewed_at
                         ) VALUES(
                            ?1,?2,?3,?4,NULL,'v031-policy',1,'v031-detector',0,
                            'review_required',?5,?6,NULL,?7,NULL
                         )",
                        params![
                            V031_UNASSIGNED_REDACTION_ID,
                            V031_UNASSIGNED_MATERIAL_ID,
                            extraction_sha256,
                            redacted_sha256,
                            protected,
                            LOCAL_PROTECTION_SCHEME,
                            "2026-07-19 15:41:31"
                        ],
                    )
                    .expect("exact v0.3.1 redaction inserts");
            })
        }

        fn upgrade_to_v5(&self) -> PrivacyV5ManifestProof {
            self.manager
                .upgrade_v031_privacy_store_to_v5_after_original_rollback(&self.gate)
                .expect("exact Privacy v1 to v5 upgrade")
        }

        fn target_gate(&self) -> V031TargetComponentsPreparedGate {
            V031TargetComponentsPreparedGate::for_case_material_checkpoint_test(
                self.gate.clone(),
                self.manager.shared.workspace_instance_id.clone(),
            )
        }
    }

    #[test]
    fn exact_v031_review_shape_is_narrow_and_does_not_accept_current_empty_display_name() {
        let exact = json!({
            "schemaVersion": 1,
            "materialId": "mat_exact",
            "redactionId": "red_exact",
            "sourceSha256": "1".repeat(64),
            "extractionSha256": "2".repeat(64),
            "suggestedRedactedContentSha256": "3".repeat(64),
            "processingVersion": "v0.3.1",
            "mediaType": "text/plain",
            "pageCount": 0,
            "backendTrace": [],
            "summary": {},
            "forbiddenCanaries": [],
            "pages": []
        });
        let bytes = serde_json::to_vec(&exact).expect("exact shape serializes");
        assert!(is_exact_v031_stored_review_payload(&bytes));

        let mut current = exact.clone();
        current["sourceDisplayName"] = serde_json::Value::String(String::new());
        assert!(!is_exact_v031_stored_review_payload(
            &serde_json::to_vec(&current).expect("current shape serializes")
        ));

        let mut missing = exact;
        missing
            .as_object_mut()
            .expect("shape is an object")
            .remove("pages");
        assert!(!is_exact_v031_stored_review_payload(
            &serde_json::to_vec(&missing).expect("incomplete shape serializes")
        ));
        assert!(!is_exact_v031_stored_review_payload(b"not-json"));
    }

    #[cfg(windows)]
    #[test]
    fn exact_v031_unassigned_review_migrates_readably_without_fabricating_identity() {
        let fixture = V031Fixture::with_exact_unassigned_review(&[PROJECT_A]);
        let user_before = fs::read(&fixture.user_database_path).expect("v0.3.1 user before");
        fixture.upgrade_to_v5();
        let source = fixture
            .manager
            .v031_case_material_migration_source_fingerprint(&fixture.gate)
            .expect("exact v0.3.1 source fingerprint");
        let first = fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("exact v0.3.1 review migrates");
        assert!(first.source_unchanged_verified);
        assert_eq!(first.bindings_created_or_verified, 1);
        assert_eq!(first.privacy_materials_migrated, 1);
        assert_eq!(first.redaction_generations_migrated, 1);
        assert_eq!(first.blocked, 0);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("v0.3.1 user after"),
            user_before
        );
        let connection = fixture
            .manager
            .open_raw_connection()
            .expect("Privacy v5 reader");
        let project = ProjectId::parse(PROJECT_A).expect("project identifier");
        let case_id = ProjectPrivacyCaseBindingStore::resolve(&connection, &project)
            .expect("resolve project binding")
            .expect("independent project receives a binding");
        assert!(case_id.as_str().starts_with("case_"));
        assert_eq!(case_id.as_str().len(), 37);
        assert!(case_id.as_str()[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            ProjectPrivacyCaseBindingStore::reverse_resolve(&connection, &case_id)
                .expect("reverse-resolve project binding")
                .as_ref(),
            Some(&project)
        );
        ProjectPrivacyCaseBindingStore::validate_pair(&connection, &project, &case_id)
            .expect("binding and audit are valid");

        let source_name_sha256 = sha256_hex(b"exact-v031-local-material.txt");
        let material = connection
            .query_row(
                "SELECT project_id,legacy_case_id,attachment_id,source_name_sha256,
                        protected_display_name,display_name_sha256,
                        display_name_protection_scheme,migration_status,state,source_kind
                 FROM privacy_materials WHERE material_id=?1",
                [V031_UNASSIGNED_MATERIAL_ID],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .expect("migrated material");
        assert_eq!(material.0, None);
        assert_eq!(material.1, None);
        assert_eq!(material.2, None);
        assert_eq!(material.3, source_name_sha256);
        assert_eq!(material.4, None);
        assert_eq!(material.5, None);
        assert_eq!(material.6, None);
        assert_eq!(material.7, "unassigned");
        assert_eq!(material.8, "review_required");
        assert_eq!(material.9, "local_review");
        let redaction = connection
            .query_row(
                "SELECT generation_status,review_state
                 FROM privacy_redactions WHERE redaction_id=?1",
                [V031_UNASSIGNED_REDACTION_ID],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .expect("migrated redaction");
        assert_eq!(
            redaction,
            ("ready".to_owned(), "review_required".to_owned())
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT result_state,error_code
                     FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='privacy_materials' AND source_key=?3",
                    params![
                        CASE_MATERIAL_MIGRATION_ID,
                        SOURCE_STORE_PRIVACY,
                        V031_UNASSIGNED_MATERIAL_ID
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .expect("material ledger"),
            (
                "migrated".to_owned(),
                Some("privacy_case_unassigned".to_owned())
            )
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT result_state,error_code
                     FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='privacy_redactions' AND source_key=?3",
                    params![
                        CASE_MATERIAL_MIGRATION_ID,
                        SOURCE_STORE_PRIVACY,
                        V031_UNASSIGNED_REDACTION_ID
                    ],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .expect("redaction ledger"),
            ("migrated".to_owned(), None)
        );
        drop(connection);

        let first_terminal = fixture
            .manager
            .v031_binding_material_terminal_proof(&fixture.gate, &source)
            .expect("first exact v0.3.1 terminal proof");
        assert_eq!(first_terminal.binding_ledger_rows(), 1);
        assert_eq!(first_terminal.material_ledger_rows(), 3);
        assert_eq!(first_terminal.blocked_rows(), 0);
        assert_eq!(first_terminal.bindings_verified(), 1);
        let second = fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("exact v0.3.1 review retry is idempotent");
        assert!(second.source_unchanged_verified);
        assert_eq!(second.bindings_created_or_verified, 0);
        assert_eq!(second.privacy_materials_migrated, 0);
        assert_eq!(second.redaction_generations_migrated, 0);
        assert!(second.idempotent_noops >= 3);
        assert_eq!(
            fixture
                .manager
                .v031_binding_material_terminal_proof(&fixture.gate, &source)
                .expect("second exact v0.3.1 terminal proof"),
            first_terminal
        );
        complete_approved_projection_migration(&fixture.manager);

        let review = fixture
            .manager
            .load_review(V031_UNASSIGNED_REDACTION_ID)
            .expect("exact v0.3.1 review remains readable");
        assert_eq!(review.case_id, None);
        assert_eq!(review.source_display_name, "Local material");
        assert_eq!(
            review.source_sha256,
            sha256_hex(b"exact v0.3.1 unassigned review source")
        );
        assert_eq!(
            review.extraction_sha256,
            sha256_hex(b"exact v0.3.1 extraction")
        );
        assert_eq!(
            review.suggested_redacted_content_sha256,
            sha256_hex(b"exact v0.3.1 redacted content")
        );
        assert!(review.pages.is_empty());
        let user_migration_source = fixture.gate.original_user_source_proof().clone();
        let mut user = database::open_existing_user_database(&fixture.user_database_path)
            .expect("open exact User-v10 post-upgrade target");
        database::migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut user,
            &user_migration_source,
            &database::V031UserUpgradeAuditEvidence {
                lineage_id: "1".repeat(64),
                source_profile_proof_sha256: "2".repeat(64),
                source_privacy_logical_manifest_sha256: "3".repeat(64),
                source_privacy_business_manifest_sha256: "4".repeat(64),
                original_rollback_identity_sha256: "5".repeat(64),
                target_privacy_pre_audit_logical_manifest_sha256: "6".repeat(64),
                target_privacy_pre_audit_business_manifest_sha256: "7".repeat(64),
                previous_receipt_sha256: "8".repeat(64),
                source_privacy_table_count: 5,
                source_privacy_total_rows: 2,
                target_privacy_table_count: privacy::PRIVACY_V6_APPLICATION_TABLES.len() as u64,
                target_privacy_total_rows: 1,
                original_rollback_slot_count: 5,
            },
        )
        .expect("migrate exact User-v10 to canonical User-v11");
        drop(user);

        let unassigned = fixture
            .manager
            .list_unassigned_case_materials(
                crate::privacy_workflow::ListUnassignedCaseMaterialsRequest {
                    project_id: PROJECT_A.to_owned(),
                },
            )
            .expect("exact v0.3.1 review appears as unassigned");
        assert_eq!(unassigned.len(), 1);
        assert_eq!(unassigned[0].material_id, V031_UNASSIGNED_MATERIAL_ID);
        assert_eq!(unassigned[0].display_name, "未归属本地材料");
        assert!(unassigned[0].assignable);
        let assignment = fixture
            .manager
            .assign_unassigned_case_material(
                crate::privacy_workflow::AssignUnassignedCaseMaterialRequest {
                    project_id: PROJECT_A.to_owned(),
                    material_id: V031_UNASSIGNED_MATERIAL_ID.to_owned(),
                    expected_row_version: unassigned[0].row_version,
                    actor: "v0.3.1 upgrade test".to_owned(),
                },
            )
            .expect("user can explicitly assign the historical material");
        assert_eq!(assignment.assignment_mode, "initialize_null_case");
        assert_eq!(assignment.binding_action, "reused");
        let catalog = fixture
            .manager
            .list_case_materials(crate::privacy_workflow::ListCaseMaterialsRequest {
                project_id: PROJECT_A.to_owned(),
            })
            .expect("assigned exact v0.3.1 review appears in the case catalog");
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].material_id, V031_UNASSIGNED_MATERIAL_ID);
        assert_eq!(
            catalog[0].display_name,
            crate::privacy_workflow::case_materials::UNKNOWN_LEGACY_LOCAL_MATERIAL_DISPLAY_NAME
        );
        assert_eq!(catalog[0].migration_status, "ready");
        let assigned_review = fixture
            .manager
            .load_review(V031_UNASSIGNED_REDACTION_ID)
            .expect("assigned exact v0.3.1 review remains readable");
        assert_eq!(assigned_review.case_id.as_deref(), Some(case_id.as_str()));
        assert_eq!(assigned_review.source_display_name, "Local material");
        assert_eq!(assigned_review.source_sha256, review.source_sha256);
        assert_eq!(assigned_review.extraction_sha256, review.extraction_sha256);
        assert_eq!(
            assigned_review.suggested_redacted_content_sha256,
            review.suggested_redacted_content_sha256
        );

        let connection = fixture
            .manager
            .open_connection()
            .expect("assigned exact v0.3.1 reader");
        let (display_blob, display_hash, display_scheme, source_name_hash) = connection
            .query_row(
                "SELECT protected_display_name,display_name_sha256,
                        display_name_protection_scheme,source_name_sha256
                 FROM privacy_materials WHERE material_id=?1",
                [V031_UNASSIGNED_MATERIAL_ID],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .expect("assigned display tuple");
        assert_eq!(
            (display_blob, display_hash, display_scheme),
            (None, None, None)
        );
        assert_eq!(source_name_hash, source_name_sha256);
        let loaded = PrivacyStore::load_review_draft(&connection, V031_UNASSIGNED_REDACTION_ID)
            .expect("assigned review payload");
        assert!(is_exact_v031_assigned_review_payload(
            &loaded.review_payload_plaintext,
            case_id.as_str()
        ));
        let raw = serde_json::from_slice::<serde_json::Value>(&loaded.review_payload_plaintext)
            .expect("assigned review JSON");
        assert!(raw.get("sourceDisplayName").is_none());
        drop(connection);

        assert!(fixture
            .manager
            .case_material_migration_required()
            .expect("assignment changes the canonical source fingerprint"));
        let rerun = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("audited v0.3.1 assignment remains migration-compatible");
        assert_eq!(rerun.blocked, 0);
        assert_eq!(rerun.privacy_materials_migrated, 1);
        assert_eq!(rerun.redaction_generations_migrated, 1);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("post-assignment migration reaches a terminal state"));
        let no_op = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("post-assignment migration replay is idempotent");
        assert_eq!(no_op.blocked, 0);
        assert_eq!(no_op.privacy_materials_migrated, 0);
        assert_eq!(no_op.redaction_generations_migrated, 0);

        let catalog = fixture
            .manager
            .list_case_materials(crate::privacy_workflow::ListCaseMaterialsRequest {
                project_id: PROJECT_A.to_owned(),
            })
            .expect("assigned material remains listable after migration reentry");
        assert_eq!(catalog.len(), 1);
        assert_eq!(
            catalog[0].display_name,
            crate::privacy_workflow::case_materials::UNKNOWN_LEGACY_LOCAL_MATERIAL_DISPLAY_NAME
        );
        let connection = fixture
            .manager
            .open_connection()
            .expect("post-rerun exact v0.3.1 reader");
        let tuple = connection
            .query_row(
                "SELECT protected_display_name,display_name_sha256,
                        display_name_protection_scheme,source_name_sha256
                 FROM privacy_materials WHERE material_id=?1",
                [V031_UNASSIGNED_MATERIAL_ID],
                |row| {
                    Ok((
                        row.get::<_, Option<Vec<u8>>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            )
            .expect("post-rerun display tuple");
        assert_eq!(tuple, (None, None, None, source_name_sha256));
    }

    #[cfg(windows)]
    #[test]
    fn assigned_exact_v031_missing_display_compatibility_rejects_unaudited_ready_material() {
        let (fixture, _) = assigned_exact_v031_fixture();
        let connection = fixture
            .manager
            .open_connection()
            .expect("assigned exact v0.3.1 tamper connection");
        mutate_append_only_row(
            &connection,
            "trg_case_material_assignment_audit_no_delete",
            "DELETE FROM case_material_assignment_audit WHERE material_id=?1",
            V031_UNASSIGNED_MATERIAL_ID,
        );
        drop(connection);
        assert_assigned_exact_v031_listing_rejected(&fixture);
    }

    #[cfg(windows)]
    #[test]
    fn assigned_exact_v031_missing_display_compatibility_rejects_material_event_tampering() {
        for tamper in [
            LatestLedgerTamper::Blocked,
            LatestLedgerTamper::WrongTarget,
            LatestLedgerTamper::WrongError,
        ] {
            let (fixture, _) = assigned_exact_v031_fixture();
            let connection = fixture
                .manager
                .open_connection()
                .expect("assigned exact v0.3.1 material-event connection");
            append_invalid_latest_ledger_event(
                &connection,
                "privacy_materials",
                V031_UNASSIGNED_MATERIAL_ID,
                tamper,
            );
            drop(connection);
            assert_assigned_exact_v031_listing_rejected(&fixture);
        }
    }

    #[cfg(windows)]
    #[test]
    fn assigned_exact_v031_missing_display_compatibility_rejects_redaction_ledger_tampering() {
        for tamper in [
            RedactionLedgerTamper::MissingBase,
            RedactionLedgerTamper::LatestBlocked,
            RedactionLedgerTamper::LatestWrongTarget,
            RedactionLedgerTamper::LatestWrongGeneration,
            RedactionLedgerTamper::ExtraLedger,
        ] {
            let (fixture, _) = assigned_exact_v031_fixture();
            let connection = fixture
                .manager
                .open_connection()
                .expect("assigned exact v0.3.1 redaction-ledger connection");
            match tamper {
                RedactionLedgerTamper::MissingBase => {
                    delete_redaction_ledger_evidence(&connection, V031_UNASSIGNED_REDACTION_ID)
                }
                RedactionLedgerTamper::LatestBlocked => append_invalid_latest_ledger_event(
                    &connection,
                    "privacy_redactions",
                    V031_UNASSIGNED_REDACTION_ID,
                    LatestLedgerTamper::Blocked,
                ),
                RedactionLedgerTamper::LatestWrongTarget => append_invalid_latest_ledger_event(
                    &connection,
                    "privacy_redactions",
                    V031_UNASSIGNED_REDACTION_ID,
                    LatestLedgerTamper::WrongTarget,
                ),
                RedactionLedgerTamper::LatestWrongGeneration => append_invalid_latest_ledger_event(
                    &connection,
                    "privacy_redactions",
                    V031_UNASSIGNED_REDACTION_ID,
                    LatestLedgerTamper::WrongGeneration,
                ),
                RedactionLedgerTamper::ExtraLedger => {
                    connection
                        .execute(
                            "INSERT INTO case_material_migration_ledger(
                                migration_id,source_store,source_table,source_key,
                                source_fingerprint,target_material_id,target_redaction_id,
                                assigned_generation_number,result_state,error_code,
                                started_at,completed_at
                             ) VALUES(?1,?2,'privacy_redactions',?3,?4,?5,?3,2,
                                      'migrated',NULL,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
                            params![
                                CASE_MATERIAL_MIGRATION_ID,
                                SOURCE_STORE_PRIVACY,
                                "red_32323232323232323232323232323232",
                                sha256_hex(b"extra redaction ledger evidence"),
                                V031_UNASSIGNED_MATERIAL_ID,
                            ],
                        )
                        .expect("extra redaction ledger row inserts");
                }
            }
            drop(connection);
            assert_assigned_exact_v031_listing_rejected(&fixture);
        }
    }

    #[cfg(windows)]
    #[test]
    fn assigned_exact_v031_missing_display_compatibility_rejects_assignment_audit_tampering() {
        for tamper in [
            AssignmentAuditTamper::BrokenChain,
            AssignmentAuditTamper::WrongProject,
            AssignmentAuditTamper::WrongCase,
            AssignmentAuditTamper::WrongMode,
            AssignmentAuditTamper::WrongBindingAction,
            AssignmentAuditTamper::WrongRowVersion,
        ] {
            let (fixture, _) = assigned_exact_v031_fixture();
            let connection = fixture
                .manager
                .open_connection()
                .expect("assigned exact v0.3.1 audit connection");
            let update = match tamper {
                AssignmentAuditTamper::BrokenChain => {
                    "UPDATE case_material_assignment_audit
                     SET previous_event_hash='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                     WHERE material_id=?1"
                }
                AssignmentAuditTamper::WrongProject => {
                    "UPDATE case_material_assignment_audit
                     SET project_id='case-assignment-project-b' WHERE material_id=?1"
                }
                AssignmentAuditTamper::WrongCase => {
                    "UPDATE case_material_assignment_audit
                     SET privacy_case_id='case_99999999999999999999999999999999'
                     WHERE material_id=?1"
                }
                AssignmentAuditTamper::WrongMode => {
                    "UPDATE case_material_assignment_audit
                     SET assignment_mode='preserve_historical_case' WHERE material_id=?1"
                }
                AssignmentAuditTamper::WrongBindingAction => {
                    "UPDATE case_material_assignment_audit
                     SET binding_action='created' WHERE material_id=?1"
                }
                AssignmentAuditTamper::WrongRowVersion => {
                    "UPDATE case_material_assignment_audit
                     SET expected_material_row_version=expected_material_row_version+1,
                         assigned_material_row_version=assigned_material_row_version+1
                     WHERE material_id=?1"
                }
            };
            mutate_append_only_row(
                &connection,
                "trg_case_material_assignment_audit_no_update",
                update,
                V031_UNASSIGNED_MATERIAL_ID,
            );
            drop(connection);
            assert_assigned_exact_v031_listing_rejected(&fixture);
        }
    }

    #[cfg(windows)]
    #[test]
    fn assigned_exact_v031_missing_display_compatibility_rejects_broken_binding() {
        let (fixture, _) = assigned_exact_v031_fixture();
        let connection = fixture
            .manager
            .open_connection()
            .expect("assigned exact v0.3.1 binding connection");
        mutate_append_only_row(
            &connection,
            "trg_project_privacy_case_binding_no_delete",
            "DELETE FROM project_privacy_case_bindings WHERE project_id=?1",
            PROJECT_A,
        );
        drop(connection);
        assert_assigned_exact_v031_listing_rejected(&fixture);
    }

    #[cfg(windows)]
    #[test]
    fn assigned_exact_v031_missing_display_compatibility_rejects_noncanonical_payloads() {
        for tamper in [
            AssignedPayloadTamper::WrongCase,
            AssignedPayloadTamper::SourceDisplayName,
            AssignedPayloadTamper::VaultField,
        ] {
            let (fixture, _) = assigned_exact_v031_fixture();
            let connection = fixture
                .manager
                .open_connection()
                .expect("assigned exact v0.3.1 payload connection");
            let loaded = PrivacyStore::load_review_draft(&connection, V031_UNASSIGNED_REDACTION_ID)
                .expect("assigned exact v0.3.1 payload loads");
            let mut payload =
                serde_json::from_slice::<serde_json::Value>(&loaded.review_payload_plaintext)
                    .expect("assigned exact v0.3.1 payload parses");
            match tamper {
                AssignedPayloadTamper::WrongCase => {
                    payload["caseId"] = serde_json::Value::String(
                        "case_99999999999999999999999999999999".to_owned(),
                    );
                }
                AssignedPayloadTamper::SourceDisplayName => {
                    payload["sourceDisplayName"] = serde_json::Value::String(String::new());
                }
                AssignedPayloadTamper::VaultField => {
                    payload["vaultObjectId"] =
                        serde_json::Value::String("obj_not_historical".to_owned());
                }
            }
            let protected =
                protect_local(&serde_json::to_vec(&payload).expect("tampered payload serializes"))
                    .expect("tampered payload protects");
            connection
                .execute(
                    "UPDATE privacy_redactions
                     SET protected_review_blob=?2,row_version=row_version+1
                     WHERE redaction_id=?1",
                    params![V031_UNASSIGNED_REDACTION_ID, protected],
                )
                .expect("tampered review payload writes through canonical row-version trigger");
            drop(connection);
            assert_assigned_exact_v031_listing_rejected(&fixture);
        }
    }

    #[cfg(windows)]
    #[test]
    fn assigned_exact_v031_missing_display_compatibility_rejects_partial_display_tuple() {
        let (fixture, _) = assigned_exact_v031_fixture();
        let connection = fixture
            .manager
            .open_connection()
            .expect("assigned exact v0.3.1 display connection");
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .expect("test explicitly bypasses the all-or-none display tuple CHECK");
        connection
            .execute(
                "UPDATE privacy_materials
                 SET protected_display_name=x'01',row_version=row_version+1
                 WHERE material_id=?1",
                [V031_UNASSIGNED_MATERIAL_ID],
            )
            .expect("partial display tuple writes through canonical row-version trigger");
        connection
            .execute_batch("PRAGMA ignore_check_constraints=OFF")
            .expect("test restores SQLite CHECK enforcement");
        drop(connection);
        assert_assigned_exact_v031_listing_rejected(&fixture);
    }

    #[cfg(windows)]
    #[derive(Clone, Copy)]
    enum LatestLedgerTamper {
        Blocked,
        WrongTarget,
        WrongError,
        WrongGeneration,
    }

    #[cfg(windows)]
    #[derive(Clone, Copy)]
    enum RedactionLedgerTamper {
        MissingBase,
        LatestBlocked,
        LatestWrongTarget,
        LatestWrongGeneration,
        ExtraLedger,
    }

    #[cfg(windows)]
    #[derive(Clone, Copy)]
    enum AssignmentAuditTamper {
        BrokenChain,
        WrongProject,
        WrongCase,
        WrongMode,
        WrongBindingAction,
        WrongRowVersion,
    }

    #[cfg(windows)]
    #[derive(Clone, Copy)]
    enum AssignedPayloadTamper {
        WrongCase,
        SourceDisplayName,
        VaultField,
    }

    #[cfg(windows)]
    fn assigned_exact_v031_fixture() -> (V031Fixture, PrivacyCaseId) {
        let fixture = V031Fixture::with_exact_unassigned_review(&[PROJECT_A]);
        fixture.upgrade_to_v5();
        let source = fixture
            .manager
            .v031_case_material_migration_source_fingerprint(&fixture.gate)
            .expect("exact v0.3.1 assignment fixture source fingerprint");
        let report = fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("exact v0.3.1 assignment fixture migrates");
        assert_eq!(report.blocked, 0);
        complete_approved_projection_migration(&fixture.manager);

        let user_migration_source = fixture.gate.original_user_source_proof().clone();
        let mut user = database::open_existing_user_database(&fixture.user_database_path)
            .expect("open exact assignment fixture User-v10");
        database::migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut user,
            &user_migration_source,
            &database::V031UserUpgradeAuditEvidence {
                lineage_id: "1".repeat(64),
                source_profile_proof_sha256: "2".repeat(64),
                source_privacy_logical_manifest_sha256: "3".repeat(64),
                source_privacy_business_manifest_sha256: "4".repeat(64),
                original_rollback_identity_sha256: "5".repeat(64),
                target_privacy_pre_audit_logical_manifest_sha256: "6".repeat(64),
                target_privacy_pre_audit_business_manifest_sha256: "7".repeat(64),
                previous_receipt_sha256: "8".repeat(64),
                source_privacy_table_count: 5,
                source_privacy_total_rows: 2,
                target_privacy_table_count: privacy::PRIVACY_V6_APPLICATION_TABLES.len() as u64,
                target_privacy_total_rows: 1,
                original_rollback_slot_count: 5,
            },
        )
        .expect("migrate exact assignment fixture User-v10 to User-v11");
        drop(user);

        let unassigned = fixture
            .manager
            .list_unassigned_case_materials(
                crate::privacy_workflow::ListUnassignedCaseMaterialsRequest {
                    project_id: PROJECT_A.to_owned(),
                },
            )
            .expect("exact v0.3.1 assignment fixture is unassigned");
        assert_eq!(unassigned.len(), 1);
        fixture
            .manager
            .assign_unassigned_case_material(
                crate::privacy_workflow::AssignUnassignedCaseMaterialRequest {
                    project_id: PROJECT_A.to_owned(),
                    material_id: V031_UNASSIGNED_MATERIAL_ID.to_owned(),
                    expected_row_version: unassigned[0].row_version,
                    actor: "v0.3.1 assignment compatibility negative test".to_owned(),
                },
            )
            .expect("exact v0.3.1 assignment fixture assigns");
        let project = ProjectId::parse(PROJECT_A).expect("assignment fixture project id");
        let connection = fixture
            .manager
            .open_connection()
            .expect("assigned fixture binding reader");
        let case_id = ProjectPrivacyCaseBindingStore::resolve(&connection, &project)
            .expect("assigned fixture binding resolves")
            .expect("assigned fixture binding exists");
        assert!(authenticates_assigned_exact_v031_missing_display_material(
            &connection,
            V031_UNASSIGNED_MATERIAL_ID,
            &project,
        )
        .expect("clean assignment compatibility authenticates"));
        drop(connection);
        (fixture, case_id)
    }

    #[cfg(windows)]
    fn assert_assigned_exact_v031_listing_rejected(fixture: &V031Fixture) {
        let error = fixture
            .manager
            .list_case_materials(crate::privacy_workflow::ListCaseMaterialsRequest {
                project_id: PROJECT_A.to_owned(),
            })
            .expect_err("tampered v0.3.1 assignment compatibility must fail closed");
        assert!(
            matches!(
                error.code(),
                "case_material_display_name_invalid"
                    | "case_material_assignment_store_failed"
                    | "project_privacy_case_store_failed"
                    | "case_material_store_failed"
                    | "privacy_store_database_error"
                    | "privacy_store_schema_unsupported"
                    | "privacy_store_unavailable"
            ),
            "unexpected fail-closed error code: {}",
            error.code()
        );
    }

    #[cfg(windows)]
    fn append_invalid_latest_ledger_event(
        connection: &Connection,
        source_table: &str,
        source_key: &str,
        tamper: LatestLedgerTamper,
    ) {
        let (_, evidence) = load_ledger_evidence(
            connection,
            CASE_MATERIAL_MIGRATION_ID,
            SOURCE_STORE_PRIVACY,
            source_table,
            source_key,
        )
        .expect("effective migration ledger evidence loads")
        .expect("base migration ledger evidence exists");
        let mut target_material_id = evidence.target_material_id;
        let mut target_redaction_id = evidence.target_redaction_id;
        let mut generation = evidence.assigned_generation_number;
        let mut result_state = evidence.result_state;
        let mut error_code = evidence.error_code;
        match tamper {
            LatestLedgerTamper::Blocked => {
                result_state = "blocked".to_owned();
                error_code = Some("tampered_latest_block".to_owned());
            }
            LatestLedgerTamper::WrongTarget => {
                if source_table == "privacy_redactions" {
                    target_redaction_id = Some("red_32323232323232323232323232323232".to_owned());
                } else {
                    target_material_id = Some("mat_32323232323232323232323232323232".to_owned());
                }
            }
            LatestLedgerTamper::WrongError => {
                error_code = Some("tampered_latest_error".to_owned());
            }
            LatestLedgerTamper::WrongGeneration => generation = Some(2),
        }
        connection
            .execute(
                "INSERT INTO case_material_migration_events(
                    migration_event_id,migration_id,source_store,source_table,source_key,
                    event_type,source_fingerprint,target_material_id,target_redaction_id,
                    assigned_generation_number,result_state,error_code,occurred_at
                 ) VALUES(?1,?2,?3,?4,?5,'tamper_probe',?6,?7,?8,?9,?10,?11,
                          CURRENT_TIMESTAMP)",
                params![
                    format!("migev_{}", Uuid::new_v4().simple()),
                    CASE_MATERIAL_MIGRATION_ID,
                    SOURCE_STORE_PRIVACY,
                    source_table,
                    source_key,
                    evidence.source_fingerprint,
                    target_material_id,
                    target_redaction_id,
                    generation,
                    result_state,
                    error_code,
                ],
            )
            .expect("invalid latest migration event appends");
    }

    #[cfg(windows)]
    fn mutate_append_only_row(
        connection: &Connection,
        trigger_name: &str,
        mutation: &str,
        parameter: &str,
    ) {
        connection
            .execute_batch(&format!("DROP TRIGGER {trigger_name}"))
            .expect("test explicitly removes append-only trigger");
        let changed = connection
            .execute(mutation, [parameter])
            .expect("test-only append-only evidence mutation succeeds");
        assert_eq!(changed, 1, "test-only evidence mutation changes one row");
        connection
            .execute_batch(canonical_tamper_trigger_sql(trigger_name))
            .expect("test restores the canonical append-only trigger");
    }

    #[cfg(windows)]
    fn delete_redaction_ledger_evidence(connection: &Connection, redaction_id: &str) {
        connection
            .execute_batch(
                "DROP TRIGGER trg_case_material_migration_events_no_delete;
                 DROP TRIGGER trg_case_material_migration_ledger_no_delete;",
            )
            .expect("test explicitly removes migration evidence delete triggers");
        connection
            .execute(
                "DELETE FROM case_material_migration_events
                 WHERE migration_id=?1 AND source_store=?2
                   AND source_table='privacy_redactions' AND source_key=?3",
                params![
                    CASE_MATERIAL_MIGRATION_ID,
                    SOURCE_STORE_PRIVACY,
                    redaction_id,
                ],
            )
            .expect("test-only redaction migration events delete");
        connection
            .execute(
                "DELETE FROM case_material_migration_ledger
                 WHERE migration_id=?1 AND source_store=?2
                   AND source_table='privacy_redactions' AND source_key=?3",
                params![
                    CASE_MATERIAL_MIGRATION_ID,
                    SOURCE_STORE_PRIVACY,
                    redaction_id,
                ],
            )
            .expect("test-only redaction migration ledger deletes");
        connection
            .execute_batch(canonical_tamper_trigger_sql(
                "trg_case_material_migration_events_no_delete",
            ))
            .expect("canonical migration event delete trigger restores");
        connection
            .execute_batch(canonical_tamper_trigger_sql(
                "trg_case_material_migration_ledger_no_delete",
            ))
            .expect("canonical migration ledger delete trigger restores");
    }

    #[cfg(windows)]
    fn canonical_tamper_trigger_sql(trigger_name: &str) -> &'static str {
        match trigger_name {
            "trg_case_material_assignment_audit_no_update" => {
                privacy::ASSIGNMENT_AUDIT_NO_UPDATE_TRIGGER_SQL
            }
            "trg_case_material_assignment_audit_no_delete" => {
                privacy::ASSIGNMENT_AUDIT_NO_DELETE_TRIGGER_SQL
            }
            "trg_project_privacy_case_binding_no_delete" => {
                "CREATE TRIGGER IF NOT EXISTS trg_project_privacy_case_binding_no_delete
                 BEFORE DELETE ON project_privacy_case_bindings
                 BEGIN
                     SELECT RAISE(ABORT, 'project/privacy case binding is immutable');
                 END;"
            }
            "trg_case_material_migration_ledger_no_delete" => {
                "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_ledger_no_delete
                 BEFORE DELETE ON case_material_migration_ledger
                 BEGIN
                     SELECT RAISE(ABORT, 'case material migration ledger is append only');
                 END;"
            }
            "trg_case_material_migration_events_no_delete" => {
                "CREATE TRIGGER IF NOT EXISTS trg_case_material_migration_events_no_delete
                 BEFORE DELETE ON case_material_migration_events
                 BEGIN
                     SELECT RAISE(ABORT, 'case material migration events are append only');
                 END;"
            }
            _ => panic!("unsupported test-only append-only trigger: {trigger_name}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn nonlegacy_empty_display_review_is_blocked_instead_of_using_v031_compatibility() {
        let fixture = V031Fixture::with_nonlegacy_empty_display_review(&[PROJECT_A]);
        fixture.upgrade_to_v5();
        let source = fixture
            .manager
            .v031_case_material_migration_source_fingerprint(&fixture.gate)
            .expect("nonlegacy source fingerprint");
        let report = fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("invalid display is ledgered fail-closed");
        assert_eq!(report.blocked, 2);
        complete_approved_projection_migration(&fixture.manager);
        let connection = fixture
            .manager
            .open_connection()
            .expect("Privacy v5 reader");
        assert_eq!(
            connection
                .query_row(
                    "SELECT migration_status,state,project_id,legacy_case_id
                     FROM privacy_materials WHERE material_id=?1",
                    [V031_UNASSIGNED_MATERIAL_ID],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    },
                )
                .expect("blocked material"),
            ("blocked".to_owned(), "blocked".to_owned(), None, None)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT error_code FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='privacy_materials' AND source_key=?3",
                    params![
                        CASE_MATERIAL_MIGRATION_ID,
                        SOURCE_STORE_PRIVACY,
                        V031_UNASSIGNED_MATERIAL_ID
                    ],
                    |row| row.get::<_, Option<String>>(0),
                )
                .expect("blocked material ledger"),
            Some("privacy_display_name_invalid".to_owned())
        );
    }

    #[test]
    fn v031_source_fingerprint_ignores_connection_local_data_version_only() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        let user_source = fixture.gate.original_user_source_proof().clone();
        let case_source = SourceProof {
            file_sha256: "1".repeat(64),
            schema_manifest_sha256: "2".repeat(64),
            project_primary_keys_sha256: "3".repeat(64),
            case_file_primary_keys_sha256: "4".repeat(64),
            attachment_primary_keys_sha256: "5".repeat(64),
            source_rows_sha256: "6".repeat(64),
            wal_file_sha256: Some("7".repeat(64)),
            data_version: 11,
        };
        let expected = v031_source_fingerprint(&fixture.gate, &user_source, &case_source);

        let mut reopened_user_source = user_source.clone();
        reopened_user_source.data_version += 1;
        let mut reopened_case_source = case_source.clone();
        reopened_case_source.data_version += 1;
        assert_eq!(
            v031_source_fingerprint(&fixture.gate, &reopened_user_source, &reopened_case_source,),
            expected,
            "connection-local SQLite data_version values are not durable checkpoint identity",
        );

        let mut user_manifest_drift = user_source.clone();
        user_manifest_drift.business_row_manifest_sha256 = "8".repeat(64);
        assert_ne!(
            v031_source_fingerprint(&fixture.gate, &user_manifest_drift, &case_source),
            expected,
            "durable user-row manifest drift must change checkpoint identity",
        );

        let mut case_manifest_drift = case_source.clone();
        case_manifest_drift.source_rows_sha256 = "9".repeat(64);
        assert_ne!(
            v031_source_fingerprint(&fixture.gate, &user_source, &case_manifest_drift),
            expected,
            "durable case-material row drift must change checkpoint identity",
        );
    }

    #[test]
    fn case_material_source_schema_survives_v10_to_v11_but_detects_source_table_ddl_drift() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        complete_v031_step5(&fixture);

        let full_schema_manifest = |connection: &Connection| {
            query_manifest(
                connection,
                "SELECT type,name,tbl_name,COALESCE(sql,'')
                 FROM sqlite_master
                 ORDER BY type,name,tbl_name,COALESCE(sql,'')",
                4,
            )
            .expect("whole user schema manifest")
        };
        fn source_schema_details(connection: &Connection) -> Vec<String> {
            let mut details = Vec::new();
            for table in ["projects", "case_files", "attachments"] {
                let ddl = connection
                    .query_row(
                        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |row| row.get::<_, String>(0),
                    )
                    .expect("source table DDL");
                details.push(format!("DDL|{table}|{ddl}"));
                for (label, sql) in [
                    (
                        "table_xinfo",
                        format!(
                            "SELECT printf('%d|%s|%s|%d|%s|%d|%d',cid,name,type,\"notnull\",COALESCE(quote(dflt_value),'NULL'),pk,hidden) FROM pragma_table_xinfo('{table}') ORDER BY cid"
                        ),
                    ),
                    (
                        "foreign_key_list",
                        format!(
                            "SELECT printf('%d|%d|%s|%s|%s|%s|%s|%s',id,seq,\"table\",\"from\",\"to\",on_update,on_delete,match) FROM pragma_foreign_key_list('{table}') ORDER BY id,seq"
                        ),
                    ),
                    (
                        "index_list",
                        format!(
                            "SELECT printf('%d|%s|%d|%s|%d',seq,name,\"unique\",origin,partial) FROM pragma_index_list('{table}') ORDER BY seq"
                        ),
                    ),
                ] {
                    let mut statement = connection.prepare(&sql).expect("schema PRAGMA prepares");
                    let rows = statement
                        .query_map([], |row| row.get::<_, String>(0))
                        .expect("schema PRAGMA queries")
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .expect("schema PRAGMA collects");
                    for row in rows {
                        details.push(format!("{label}|{table}|{row}"));
                    }
                }
            }
            details
        }
        let source_proof_before = {
            let connection = database::open_user_database_read_only(&fixture.user_database_path)
                .expect("open exact user v10 source read-only");
            (
                SourceProof::capture(&fixture.user_database_path, &connection)
                    .expect("capture user v10 case-material source"),
                full_schema_manifest(&connection),
                source_schema_details(&connection),
            )
        };

        let mut connection = database::open_existing_user_database(&fixture.user_database_path)
            .expect("open configured exact user v10 upgrade target");
        database::migrate_exact_v031_user_to_v11_with_upgrade_audit(
            &mut connection,
            fixture.gate.original_user_source_proof(),
            &database::V031UserUpgradeAuditEvidence {
                lineage_id: "1".repeat(64),
                source_profile_proof_sha256: "2".repeat(64),
                source_privacy_logical_manifest_sha256: "3".repeat(64),
                source_privacy_business_manifest_sha256: "4".repeat(64),
                original_rollback_identity_sha256: "5".repeat(64),
                target_privacy_pre_audit_logical_manifest_sha256: "6".repeat(64),
                target_privacy_pre_audit_business_manifest_sha256: "7".repeat(64),
                previous_receipt_sha256: "8".repeat(64),
                source_privacy_table_count: 5,
                source_privacy_total_rows: 0,
                target_privacy_table_count: privacy::PRIVACY_V6_APPLICATION_TABLES.len() as u64,
                target_privacy_total_rows: 1,
                original_rollback_slot_count: 5,
            },
        )
        .expect("migrate exact user v10 to canonical v11");
        drop(connection);

        let source_proof_after = {
            let connection = database::open_user_database_read_only(&fixture.user_database_path)
                .expect("open canonical user v11 source read-only");
            (
                SourceProof::capture(&fixture.user_database_path, &connection)
                    .expect("capture user v11 case-material source"),
                full_schema_manifest(&connection),
                source_schema_details(&connection),
            )
        };
        assert_ne!(
            source_proof_before.1, source_proof_after.1,
            "the canonical v10 -> v11 migration must exercise a real whole-schema change",
        );
        let source_table_ddl = |details: &[String]| {
            details
                .iter()
                .filter(|detail| detail.starts_with("DDL|"))
                .cloned()
                .collect::<Vec<_>>()
        };
        let source_table_semantics = |details: &[String]| {
            details
                .iter()
                .filter(|detail| !detail.starts_with("DDL|"))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_ne!(
            source_table_ddl(&source_proof_before.2),
            source_table_ddl(&source_proof_after.2),
            "canonical rebuild records differently formatted sqlite_master DDL",
        );
        assert_eq!(
            source_table_semantics(&source_proof_before.2),
            source_table_semantics(&source_proof_after.2),
            "source table columns, defaults, keys, foreign keys, and indexes remain exact",
        );
        assert_eq!(
            source_proof_before.0.schema_manifest_sha256,
            source_proof_after.0.schema_manifest_sha256,
            "exact v10 and v11 profiles map to one frozen case-material read contract",
        );
        assert_eq!(
            source_proof_before.0.persistent_fingerprint(),
            source_proof_after.0.persistent_fingerprint(),
            "unrelated canonical v11 schema objects must not invalidate committed Step 5",
        );
        assert!(
            !fixture
                .manager
                .case_material_migration_required()
                .expect("canonical user v11 remains a valid no-op probe"),
            "a legal user v10 -> v11 migration must remain a Step-9 no-op",
        );

        let connection = database::open_existing_user_database(&fixture.user_database_path)
            .expect("open configured canonical user v11 for source-table drift");
        connection
            .execute_batch("ALTER TABLE projects ADD COLUMN migration_drift TEXT;")
            .expect("inject source-table DDL drift");
        drop(connection);

        let source = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("open drifted user source read-only");
        source
            .execute_batch("BEGIN DEFERRED TRANSACTION;")
            .expect("pin drifted user source");
        let error = SourceProof::capture(&fixture.user_database_path, &source)
            .expect_err("source-table DDL drift must fail exact-profile capture");
        assert_eq!(error.code(), "case_material_source_snapshot_failed");
        source
            .execute_batch("ROLLBACK")
            .expect("release drifted source");
        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("the public exact-schema gate must fail closed on source DDL drift");
        assert_eq!(error.code(), "case_material_source_snapshot_failed");
    }

    #[test]
    fn checkpoint_image_source_contract_requires_byte_validated_capability() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        let image = serialized_sqlite_checkpoint_image_for_test(&fixture.user_database_path);
        let image_sha256 = sha256_hex(&image);
        let original = fixture.gate.original_user_source_proof();

        let generic_memory = open_verified_checkpoint_image_read_only(&image)
            .expect("generic checkpoint image opens query-only");
        let error = case_material_source_schema_manifest(&generic_memory)
            .expect_err("an arbitrary in-memory connection cannot use the live-file exact gate");
        assert_eq!(error.code(), "case_material_source_snapshot_failed");

        let expected = || V031UserCheckpointImageExpectations {
            database_sha256: &image_sha256,
            schema_manifest_sha256: &original.schema_manifest_sha256,
            logical_manifest_sha256: &original.logical_database_manifest_sha256,
            business_manifest_sha256: &original.business_manifest_sha256,
            total_rows: original.total_rows,
            rollback_semantic_proof: original,
        };
        let verified = open_verified_v031_user_checkpoint_image_read_only(&image, expected())
            .expect("byte-validated v10 image returns the private source capability");
        let detached = verified
            .capture_source_proof()
            .expect("capability captures detached source proof");

        let live = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("live exact v10 source opens read-only");
        live.execute_batch("BEGIN DEFERRED TRANSACTION;")
            .expect("pin live exact v10 source");
        let live_source = SourceProof::capture(&fixture.user_database_path, &live)
            .expect("live exact-v10 source proof");
        live.execute_batch("ROLLBACK")
            .expect("release live exact-v10 source");
        assert_eq!(
            detached.persistent_fingerprint(),
            live_source.persistent_fingerprint(),
            "the capability maps the validated checkpoint to the frozen live read contract",
        );

        let wrong_image_sha256 = "f".repeat(64);
        assert!(open_verified_v031_user_checkpoint_image_read_only(
            &image,
            V031UserCheckpointImageExpectations {
                database_sha256: &wrong_image_sha256,
                ..expected()
            },
        )
        .is_err());
        let wrong_schema_manifest = "e".repeat(64);
        assert!(open_verified_v031_user_checkpoint_image_read_only(
            &image,
            V031UserCheckpointImageExpectations {
                schema_manifest_sha256: &wrong_schema_manifest,
                ..expected()
            },
        )
        .is_err());
        let mut tampered_image = image;
        let last = tampered_image.len() - 1;
        tampered_image[last] ^= 0x01;
        assert!(
            open_verified_v031_user_checkpoint_image_read_only(&tampered_image, expected())
                .is_err()
        );
    }

    fn step4_checkpoint_proofs_for_test(
        fixture: &V031Fixture,
        target: &V031TargetComponentsPreparedGate,
        source: &V031CaseMigrationCheckpointSourceProof,
    ) -> (V031MigrationCheckpointProof, V031MigrationCheckpointProof) {
        let user = fixture.gate.original_user_source_proof();
        let binding = source.binding_checkpoint_candidate_evidence();
        let materials = source.material_checkpoint_candidate_evidence();
        let checkpoint = |kind, candidate: V031CheckpointCandidateEvidence, discriminator| {
            V031MigrationCheckpointProof::binding_material_for_test(
                kind,
                fixture.gate.lineage_id().to_owned(),
                fixture.gate.original_identity_sha256().to_owned(),
                target.workspace_instance_id().as_str().to_owned(),
                "3".repeat(64),
                user.schema_manifest_sha256.clone(),
                user.logical_database_manifest_sha256.clone(),
                user.business_manifest_sha256.clone(),
                user.total_rows,
                "4".repeat(64),
                source.privacy_v1_logical_manifest_sha256.clone(),
                source.privacy_v1_business_manifest_sha256.clone(),
                source.privacy_v1_total_rows,
                candidate.source_fingerprint,
                candidate.candidate_manifest_sha256,
                candidate.candidate_count,
                discriminator,
            )
        };
        (
            checkpoint(V031CheckpointKind::Binding, binding, 11),
            checkpoint(V031CheckpointKind::Materials, materials, 12),
        )
    }

    fn sqlite_file_set_bytes_for_test(path: &Path) -> Vec<(String, Option<Vec<u8>>)> {
        ["", "-wal", "-shm", "-journal"]
            .into_iter()
            .map(|suffix| {
                let mut value = path.as_os_str().to_os_string();
                value.push(suffix);
                let slot = PathBuf::from(value);
                (
                    suffix.to_owned(),
                    match fs::read(slot) {
                        Ok(bytes) => Some(bytes),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => panic!("read SQLite file-set slot {suffix}: {error}"),
                    },
                )
            })
            .collect()
    }

    fn serialized_sqlite_checkpoint_image_for_test(path: &Path) -> Vec<u8> {
        let source = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("checkpoint source opens read-only");
        source
            .execute_batch(
                "PRAGMA query_only=ON;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;
                 BEGIN DEFERRED TRANSACTION;",
            )
            .expect("checkpoint source snapshot pins");
        let mut destination = Connection::open_in_memory().expect("checkpoint image opens");
        rusqlite::backup::Backup::new(&source, &mut destination)
            .expect("checkpoint Backup API starts")
            .run_to_completion(64, std::time::Duration::from_millis(1), None)
            .expect("checkpoint Backup API completes");
        let mut image = destination
            .serialize(rusqlite::MAIN_DB)
            .expect("checkpoint image serializes")
            .to_vec();
        assert!(image.len() >= 100);
        assert!(image.starts_with(b"SQLite format 3\0"));
        match (image[18], image[19]) {
            (1, 1) => {}
            (2, 2) => {
                image[18] = 1;
                image[19] = 1;
            }
            header => panic!("unexpected checkpoint SQLite header mode: {header:?}"),
        }
        image
    }

    fn create_exact_v031_user_database(database_path: &Path, projects: &[&str]) {
        let connection = Connection::open(database_path).expect("v0.3.1 user database");
        let objects =
            include_str!("../../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("schema object"))
                .collect::<Vec<_>>();
        for object_type in ["table", "index", "trigger", "view"] {
            for object in objects
                .iter()
                .filter(|object| object["object_type"] == object_type)
            {
                connection
                    .execute_batch(object["sql"].as_str().expect("schema sql"))
                    .expect("v0.3.1 schema object");
            }
        }
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_SCHEMA_VERSION.to_string()],
            )
            .expect("v0.3.1 schema version");
        connection
            .execute(
                "INSERT INTO user_database_metadata(key,value,updated_at)
                 VALUES('canonical_schema_version',?1,'2026-07-19 15:41:29')",
                [database::V031_USER_CANONICAL_SCHEMA_MARKER],
            )
            .expect("v0.3.1 canonical marker");
        for project_id in projects {
            connection
                .execute(
                    "INSERT INTO projects(
                       project_id,title,case_type,status,opened_on,summary,created_at,updated_at
                     ) VALUES(?1,?2,'civil','active',NULL,'','2026-07-19','2026-07-19')",
                    params![project_id, format!("Project {project_id}")],
                )
                .expect("v0.3.1 project");
        }
    }

    impl Fixture {
        fn new(projects: &[&str]) -> Self {
            let directory = tempfile::tempdir().expect("migration fixture directory");
            let user_database_path =
                database::ensure_user_database(directory.path()).expect("canonical user database");
            let connection =
                database::open_user_database(&user_database_path).expect("open user database");
            for project_id in projects {
                insert_project(&connection, project_id);
            }
            drop(connection);
            let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(NoopPublicationInvalidator),
            )
            .expect("privacy manager");
            manager.set_test_runtime(
                ReceiptSigner::new([29_u8; 32]).expect("migration test signer"),
                1_800_000_000,
            );
            Self {
                _directory: directory,
                user_database_path,
                manager,
            }
        }

        fn user_connection(&self) -> Connection {
            database::open_user_database(&self.user_database_path)
                .expect("writable user database fixture")
        }

        fn add_attachment(
            &self,
            attachment_id: &str,
            project_id: Option<&str>,
            original_name: &str,
            content: &[u8],
        ) {
            let connection = self.user_connection();
            database::insert_attachment(
                &connection,
                &database::NewAttachmentRow {
                    attachment_id: attachment_id.to_owned(),
                    project_id: project_id.map(str::to_owned),
                    original_name: original_name.to_owned(),
                    extension: "txt".to_owned(),
                    detected_mime: "text/plain".to_owned(),
                    sha256: sha256_hex(content),
                    size_bytes: i64::try_from(content.len()).expect("small fixture"),
                    content_blob: content.to_vec(),
                    extraction_status: "succeeded".to_owned(),
                    extracted_text: Some(String::from_utf8_lossy(content).into_owned()),
                    segments_json: "[]".to_owned(),
                    error_code: None,
                },
            )
            .expect("insert attachment");
        }

        fn add_case_file(
            &self,
            file_id: &str,
            project_id: &str,
            title: &str,
            storage_reference: &str,
        ) {
            database::upsert_case_file(
                &self.user_connection(),
                &database::CaseFileRow {
                    file_id: file_id.to_owned(),
                    project_id: project_id.to_owned(),
                    title: title.to_owned(),
                    file_type: "evidence".to_owned(),
                    storage_reference: storage_reference.to_owned(),
                    summary: "fixture summary".to_owned(),
                    created_at: String::new(),
                },
            )
            .expect("insert case file");
        }

        fn prepare_project_material(
            &self,
            project_id: &str,
            source_name: &str,
        ) -> PrivacyReviewView {
            let path = self._directory.path().join(source_name);
            fs::write(
                &path,
                "Synthetic project material: Alice Example, 13800138000.",
            )
            .expect("write project material");
            self.manager
                .prepare_case_selected_material_with_qualification(
                    &path,
                    &PrivacyConfig::default(),
                    &local_ocr_status(),
                    LocalOcrExecutionContext {
                        mineru_config: None,
                        qualification: None,
                    },
                    project_id.to_owned(),
                    Vec::new(),
                )
                .expect("prepare project material")
        }
    }

    fn local_ocr_status() -> LocalOcrStatus {
        LocalOcrStatus {
            code: LocalOcrStatusCode::Disabled,
            message: "disabled for migration lifecycle fixture".to_owned(),
            worker_version: None,
            model_version: None,
            worker_sha256: None,
            model_manifest_sha256: None,
            worker_present: false,
            model_directory_present: false,
            integrity_verified: false,
            network_isolation_verified: false,
            worker_protocol_version: None,
            worker_protocol_identity_sha256: None,
            worker_health_evidence_sha256: None,
            python_version: None,
            mineru_version: None,
            pytorch_version: None,
            cuda_runtime_version: None,
            gpu_driver_version: None,
        }
    }

    fn complete_approved_projection_migration(manager: &PrivacyWorkflowManager) {
        let source_fingerprint = manager
            .approved_projection_migration_source_fingerprint()
            .expect("approved-projection source fingerprint");
        manager
            .run_approved_projection_migration_after_backup_for_source(&source_fingerprint)
            .expect("approved-projection migration");
    }

    fn expire_project_generation(fixture: &Fixture, redaction_id: &str, cleanup_id: &str) {
        let mut connection = fixture.manager.open_connection().expect("privacy store");
        let changed = connection
            .execute(
                "UPDATE privacy_retention_bindings
                 SET expires_at_unix=1799999999
                 WHERE redaction_id=?1",
                [redaction_id],
            )
            .expect("expire project generation");
        assert_eq!(changed, 1);
        let lifecycle =
            PrivacyLifecycle::open(&connection, test_workspace_instance_id()).expect("lifecycle");
        lifecycle
            .run_retention_sweep(&mut connection, cleanup_id, 1_800_000_001)
            .expect("project generation retention cleanup");
    }

    fn project_material_provenance(
        fixture: &Fixture,
        material_id: &str,
    ) -> (
        String,
        String,
        String,
        String,
        String,
        i64,
        String,
        String,
        i64,
    ) {
        fixture
            .manager
            .open_connection()
            .expect("privacy store")
            .query_row(
                "SELECT material.project_id,material.source_kind,material.source_sha256,
                        vault.case_id,vault.object_id,vault.object_version,
                        vault.source_sha256,vault.envelope_sha256,vault.content_bytes
                 FROM privacy_materials AS material
                 JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE material.material_id=?1",
                [material_id],
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
                    ))
                },
            )
            .expect("project material provenance")
    }

    fn exercise_project_deletion_retention_order(
        retention_first: bool,
        tamper_retained_provenance: bool,
    ) {
        let fixture = Fixture::new(&[PROJECT_A]);
        if !retention_first {
            fixture
                .manager
                .run_case_material_migration_after_backup()
                .expect("projects-only migration before new material");
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("projects-only terminal probe"));
        }
        let review = fixture.prepare_project_material(
            PROJECT_A,
            if retention_first {
                "retention-before-project-delete.txt"
            } else {
                "project-delete-before-retention.txt"
            },
        );
        if retention_first {
            fixture
                .manager
                .run_case_material_migration_after_backup()
                .expect("initial project material migration");
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("initial project material terminal probe"));
        }
        let provenance_before = project_material_provenance(&fixture, &review.material_id);
        let evidence_before: (i64, i64) = fixture
            .manager
            .open_connection()
            .expect("privacy store")
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM case_material_migration_ledger
                    WHERE target_material_id=?1),
                   (SELECT COUNT(*) FROM case_material_migration_events
                    WHERE target_material_id=?1)",
                [&review.material_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("material migration evidence");
        if !retention_first {
            assert_eq!(
                evidence_before,
                (0, 0),
                "post-migration material must exercise the project-deletion tombstone branch"
            );
        }

        if retention_first {
            expire_project_generation(
                &fixture,
                &review.redaction_id,
                "cln_dddddddddddddddddddddddddddddddd",
            );
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("retention-before-delete is terminal"));
        }

        assert!(fixture
            .manager
            .delete_case_project_lifecycle(&mut fixture.user_connection(), PROJECT_A)
            .expect("delete project"));
        assert!(fixture
            .manager
            .case_material_migration_required()
            .expect("project source deletion changes the source manifest"));
        let deletion_report = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("project deletion migration restart");
        assert_eq!(deletion_report.privacy_materials_migrated, 0);
        assert_eq!(deletion_report.redaction_generations_migrated, 0);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("project deletion tombstone is terminal"));

        if !retention_first {
            let deletion_state = fixture
                .manager
                .open_connection()
                .expect("privacy after project deletion")
                .query_row(
                    "SELECT material.project_id,material.source_kind,material.state,
                            material.deleted_at IS NOT NULL,vault.import_state,
                            vault.failure_code
                     FROM privacy_materials AS material
                     JOIN privacy_vault_material_refs AS vault
                       ON vault.material_id=material.material_id
                     WHERE material.material_id=?1",
                    [&review.material_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, bool>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, Option<String>>(5)?,
                        ))
                    },
                )
                .expect("project deletion tombstone");
            assert_eq!(
                deletion_state,
                (
                    PROJECT_A.to_owned(),
                    "vault".to_owned(),
                    "revoked".to_owned(),
                    true,
                    "revoked".to_owned(),
                    Some("project_deleted".to_owned()),
                )
            );
            expire_project_generation(
                &fixture,
                &review.redaction_id,
                "cln_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            );
            assert!(!fixture
                .manager
                .case_material_migration_required()
                .expect("delete-before-retention composed tombstone is terminal"));
        }

        let connection = fixture.manager.open_connection().expect("final privacy");
        let final_state = connection
            .query_row(
                "SELECT material.state,material.deleted_at IS NOT NULL,
                        material.protected_display_name,material.display_name_sha256,
                        material.display_name_protection_scheme,
                        vault.import_state,vault.failure_code
                 FROM privacy_materials AS material
                 JOIN privacy_vault_material_refs AS vault
                   ON vault.material_id=material.material_id
                 WHERE material.material_id=?1",
                [&review.material_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .expect("composed tombstone");
        assert_eq!(final_state.0, "revoked");
        assert!(final_state.1);
        assert_eq!(
            (final_state.2, final_state.3, final_state.4),
            (None, None, None)
        );
        assert_eq!(final_state.5, "revoked");
        assert_eq!(final_state.6.as_deref(), Some("retention_expired"));
        drop(connection);
        assert_eq!(
            project_material_provenance(&fixture, &review.material_id),
            provenance_before
        );
        let evidence_after: (i64, i64) = fixture
            .manager
            .open_connection()
            .expect("privacy evidence")
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM case_material_migration_ledger
                    WHERE target_material_id=?1),
                   (SELECT COUNT(*) FROM case_material_migration_events
                    WHERE target_material_id=?1)",
                [&review.material_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("final material migration evidence");
        assert_eq!(evidence_after, evidence_before);
        if tamper_retained_provenance {
            fixture
                .manager
                .open_connection()
                .expect("privacy provenance tamper")
                .execute(
                    "UPDATE privacy_materials
                     SET source_name_sha256=?2,row_version=row_version+1
                     WHERE material_id=?1",
                    params![
                        review.material_id,
                        sha256_hex(b"tampered retained provenance")
                    ],
                )
                .expect("simulate retained provenance drift");
            let error = fixture
                .manager
                .case_material_migration_required()
                .expect_err("retained provenance drift must fail closed");
            assert_eq!(error.code(), "case_material_migration_target_mismatch");
        }
    }

    fn insert_project(connection: &Connection, project_id: &str) {
        database::upsert_case_project(
            connection,
            &database::CaseProjectRow {
                project_id: project_id.to_owned(),
                title: format!("Project {project_id}"),
                case_type: "civil".to_owned(),
                status: "active".to_owned(),
                opened_on: None,
                summary: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            },
        )
        .expect("insert project");
    }

    fn complete_v031_step5(
        fixture: &V031Fixture,
    ) -> (
        V031CaseMaterialSourceFingerprint,
        V031BindingMaterialTerminalProof,
    ) {
        fixture.upgrade_to_v5();
        let source = fixture
            .manager
            .v031_case_material_migration_source_fingerprint(&fixture.gate)
            .expect("Step-5 source fingerprint");
        fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("Step-5 migration");
        let terminal = fixture
            .manager
            .v031_binding_material_terminal_proof(&fixture.gate, &source)
            .expect("Step-5 terminal proof");
        (source, terminal)
    }

    fn projection_checkpoint_for_test(
        fixture: &V031Fixture,
        source: &super::super::approved_case_projection::V031ApprovedProjectionSourceProof,
    ) -> V031MigrationCheckpointProof {
        let user = fixture.gate.original_user_source_proof();
        V031MigrationCheckpointProof::projection_for_test(
            fixture.gate.lineage_id().to_owned(),
            fixture.gate.original_identity_sha256().to_owned(),
            test_workspace_instance_id().as_str().to_owned(),
            "3".repeat(64),
            user.schema_manifest_sha256.clone(),
            user.logical_database_manifest_sha256.clone(),
            user.business_manifest_sha256.clone(),
            user.total_rows,
            source.source_fingerprint().to_owned(),
            source.candidate_manifest_sha256().to_owned(),
            source.candidate_count(),
            source.privacy_v5().logical_manifest.sha256.clone(),
            source.privacy_v5().business_manifest.sha256.clone(),
            source.privacy_v5().total_row_count,
        )
    }

    fn insert_invalid_approved_projection_candidate(fixture: &V031Fixture) {
        let connection = fixture
            .manager
            .open_raw_connection()
            .expect("Privacy v5 writer");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                   material_id,project_id,legacy_case_id,attachment_id,
                   source_sha256,source_name_sha256,media_type,page_count,
                   source_kind,extraction_status,migration_status,state,
                   created_at,updated_at
                 ) VALUES(
                   'projection-material',?1,NULL,NULL,?2,?3,'text/plain',1,
                   'local_review','approved','ready','approved',
                   '2026-07-19 15:41:29','2026-07-19 15:41:29'
                 )",
                params![
                    PROJECT_A,
                    sha256_hex(b"projection source"),
                    sha256_hex(b"projection source name")
                ],
            )
            .expect("projection material");
        connection
            .execute(
                "INSERT INTO privacy_redactions(
                   redaction_id,material_id,generation_number,generation_status,
                   extraction_sha256,redacted_content_sha256,approved_payload_sha256,
                   policy_id,policy_version,detector_version,
                   unresolved_high_risk_count,review_state,risk_revision,
                   protected_review_blob,protection_scheme,reviewed_by_sha256,
                   approved_at,revocation_state,revoked_at,row_version,
                   created_at,reviewed_at
                 ) VALUES(
                   'projection-redaction','projection-material',1,'ready',
                   ?1,?2,?3,'projection-policy',1,'projection-detector',
                   0,'approved',1,x'00',?4,?5,
                   '2026-07-19 15:41:29','active',NULL,1,
                   '2026-07-19 15:41:29','2026-07-19 15:41:29'
                 )",
                params![
                    sha256_hex(b"projection extraction"),
                    sha256_hex(b"projection redacted"),
                    sha256_hex(b"projection approved"),
                    privacy::LOCAL_PROTECTION_SCHEME,
                    sha256_hex(b"projection reviewer"),
                ],
            )
            .expect("invalid historical approved source");
    }

    #[test]
    fn v031_projection_checkpoint_images_rebuild_step5_and_step6_source_without_active_sources() {
        let fixture = V031Fixture::new(&[PROJECT_A, PROJECT_B]);
        let target = fixture.target_gate();
        let step4_source = fixture
            .manager
            .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
            .expect("Step-4 source proof");
        let (binding_checkpoint, material_checkpoint) =
            step4_checkpoint_proofs_for_test(&fixture, &target, &step4_source);
        fixture
            .manager
            .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                &fixture.gate,
                &target,
                &step4_source,
                &binding_checkpoint,
                &material_checkpoint,
            )
            .expect("Privacy v5 initializes after exact checkpoints");
        fixture
            .manager
            .run_v031_case_material_migration_after_checkpoints(
                &fixture.gate,
                &target,
                &binding_checkpoint,
                &material_checkpoint,
            )
            .expect("Step-5 migration completes");
        let expected_terminal = fixture
            .manager
            .v031_binding_material_terminal_proof_after_checkpoints(
                &fixture.gate,
                &target,
                &binding_checkpoint,
                &material_checkpoint,
            )
            .expect("Step-5 terminal proves");
        let expected_projection_source = fixture
            .manager
            .v031_approved_projection_source_proof(&fixture.gate, &expected_terminal)
            .expect("Step-6 source proves");

        let privacy_path = fixture.manager.shared.database_path.clone();
        let user_image = serialized_sqlite_checkpoint_image_for_test(&fixture.user_database_path);
        let privacy_image = serialized_sqlite_checkpoint_image_for_test(&privacy_path);
        let user_image_sha256 = sha256_hex(&user_image);
        let original_user = fixture.gate.original_user_source_proof();
        let verified_user_image = open_verified_v031_user_checkpoint_image_read_only(
            &user_image,
            V031UserCheckpointImageExpectations {
                database_sha256: &user_image_sha256,
                schema_manifest_sha256: &original_user.schema_manifest_sha256,
                logical_manifest_sha256: &original_user.logical_database_manifest_sha256,
                business_manifest_sha256: &original_user.business_manifest_sha256,
                total_rows: original_user.total_rows,
                rollback_semantic_proof: original_user,
            },
        )
        .expect("detached User image validates and opens as one capability");
        let detached_source = verified_user_image
            .capture_source_proof()
            .expect("detached source proof captures");
        let detached_source_fingerprint = v031_source_fingerprint(
            &fixture.gate,
            fixture.gate.original_user_source_proof(),
            &detached_source,
        );
        assert_eq!(
            detached_source_fingerprint.evidence_sha256,
            step4_source.source_fingerprint,
        );
        privacy::validate_privacy_v5_sqlite_image_read_only(&privacy_image)
            .expect("detached Privacy-v5 image validates");
        let projection_checkpoint =
            projection_checkpoint_for_test(&fixture, &expected_projection_source)
                .with_database_image_hashes_for_test(user_image_sha256, sha256_hex(&privacy_image));

        let recovered = fixture
            .manager
            .v031_projection_recovery_proofs_from_verified_checkpoint_images(
                &fixture.gate,
                &target,
                &binding_checkpoint,
                &material_checkpoint,
                &projection_checkpoint,
                &user_image,
                &privacy_image,
            )
            .expect("offline checkpoint images rebuild both capabilities");
        assert_eq!(recovered.0, expected_terminal);
        assert_eq!(recovered.1, expected_projection_source);

        fixture
            .manager
            .run_v031_approved_projection_migration_after_checkpoint(
                &fixture.gate,
                &expected_terminal,
                &expected_projection_source,
                &projection_checkpoint,
            )
            .expect("active Privacy advances to v6");
        let displaced_user = fixture._directory.path().join("displaced-user-v10.sqlite");
        let displaced_privacy = fixture
            ._directory
            .path()
            .join("displaced-privacy-v6.sqlite");
        fs::rename(&fixture.user_database_path, &displaced_user)
            .expect("active User source is displaced");
        fs::rename(&privacy_path, &displaced_privacy).expect("active Privacy source is displaced");

        let recovered_after_advance = fixture
            .manager
            .v031_projection_recovery_proofs_from_verified_checkpoint_images(
                &fixture.gate,
                &target,
                &binding_checkpoint,
                &material_checkpoint,
                &projection_checkpoint,
                &user_image,
                &privacy_image,
            )
            .expect("checkpoint recovery never consults displaced active sources");
        assert_eq!(recovered_after_advance.0, expected_terminal);
        assert_eq!(recovered_after_advance.1, expected_projection_source);

        let mut tampered_privacy = privacy_image.clone();
        let last = tampered_privacy
            .last_mut()
            .expect("non-empty checkpoint image");
        *last ^= 1;
        assert!(fixture
            .manager
            .v031_projection_recovery_proofs_from_verified_checkpoint_images(
                &fixture.gate,
                &target,
                &binding_checkpoint,
                &material_checkpoint,
                &projection_checkpoint,
                &user_image,
                &tampered_privacy,
            )
            .is_err());
    }

    #[test]
    fn v031_step6_projection_is_exact_user_read_only_idempotent_and_proves_v6() {
        let fixture = V031Fixture::new(&[PROJECT_A, PROJECT_B]);
        let user_bytes_before =
            fs::read(&fixture.user_database_path).expect("user v10 bytes before Step 6");
        let user_proof_before = fixture.gate.original_user_source_proof().clone();
        let (_step5_source, step5_terminal) = complete_v031_step5(&fixture);
        let source = fixture
            .manager
            .v031_approved_projection_source_proof(&fixture.gate, &step5_terminal)
            .expect("Step-6 source proof");
        assert_eq!(source.candidate_count(), 0);
        let checkpoint = projection_checkpoint_for_test(&fixture, &source);

        let first = fixture
            .manager
            .run_v031_approved_projection_migration_after_checkpoint(
                &fixture.gate,
                &step5_terminal,
                &source,
                &checkpoint,
            )
            .expect("Step-6 projection migration");
        assert_eq!(first.approved_generation_count(), 0);
        assert_eq!(first.projection_rows(), 0);
        assert_eq!(first.blocked_rows(), 0);
        assert_eq!(first.risk_head_rows(), 0);
        assert_eq!(first.binding_verified_rows(), 0);
        assert_eq!(first.security_trigger_count(), 8);
        assert_eq!(first.privacy_v6().schema_version, 6);
        assert_eq!(
            first.privacy_v6().logical_manifest.tables.len(),
            privacy::PRIVACY_V6_APPLICATION_TABLES.len()
        );
        assert_eq!(first.terminal_manifest_sha256().len(), 64);
        assert_eq!(first.source_evidence_sha256(), source.evidence_sha256());
        assert_eq!(first.v5_source_fingerprint(), source.source_fingerprint());
        assert_eq!(
            first.candidate_manifest_sha256(),
            source.candidate_manifest_sha256()
        );

        let second = fixture
            .manager
            .run_v031_approved_projection_migration_after_checkpoint(
                &fixture.gate,
                &step5_terminal,
                &source,
                &checkpoint,
            )
            .expect("idempotent Step-6 rerun");
        let reconstructed = fixture
            .manager
            .v031_privacy_v6_terminal_proof(&fixture.gate, &step5_terminal, &source, &checkpoint)
            .expect("pure committed-state terminal proof");
        assert_eq!(second, first);
        assert_eq!(reconstructed, first);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("user v10 bytes after Step 6"),
            user_bytes_before
        );
        let user_proof_after = database::with_validated_user_database_migration_source_read_only(
            &fixture.user_database_path,
            |_| (),
        )
        .expect("user v10 semantic proof after Step 6")
        .0;
        assert_eq!(user_proof_after, user_proof_before);
    }

    #[test]
    fn v031_step6_failure_points_resume_prepare_batch_and_finalize() {
        for failure_point in [
            ProjectionFailurePoint::BeforePrepare,
            ProjectionFailurePoint::AfterPrepare,
            ProjectionFailurePoint::BeforeFinalize,
            ProjectionFailurePoint::AfterFinalize,
        ] {
            let fixture = V031Fixture::new(&[PROJECT_A]);
            let user_before =
                fs::read(&fixture.user_database_path).expect("user v10 before failure");
            let (_step5_source, step5_terminal) = complete_v031_step5(&fixture);
            let source = fixture
                .manager
                .v031_approved_projection_source_proof(&fixture.gate, &step5_terminal)
                .expect("empty Step-6 source proof");
            let checkpoint = projection_checkpoint_for_test(&fixture, &source);
            let checkpoint_before = checkpoint.clone();
            let privacy_v5_before = fixture
                .manager
                .open_raw_connection()
                .and_then(|privacy| {
                    compute_privacy_v5_manifests_read_only(&privacy)
                        .map_err(|_| v031_privacy_v5_proof_error())
                })
                .expect("canonical Privacy v5 before projection failure");
            let user_file_set_before = sqlite_file_set_bytes_for_test(&fixture.user_database_path);
            let privacy_file_set_before =
                sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path);
            let error = fixture
                .manager
                .run_v031_approved_projection_migration_with_failure(
                    &fixture.gate,
                    &step5_terminal,
                    &source,
                    &checkpoint,
                    failure_point,
                )
                .expect_err("injected projection failure");
            assert_eq!(error.code(), "v031_projection_injected_failure");
            assert_eq!(
                fs::read(&fixture.user_database_path).expect("user v10 after failure"),
                user_before
            );
            if failure_point == ProjectionFailurePoint::BeforePrepare {
                assert_eq!(checkpoint, checkpoint_before);
                assert_eq!(
                    sqlite_file_set_bytes_for_test(&fixture.user_database_path),
                    user_file_set_before,
                    "BeforePrepare must not mutate any User-v10 SQLite slot",
                );
                assert_eq!(
                    sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path),
                    privacy_file_set_before,
                    "BeforePrepare must precede the first Privacy-v5 file-set write",
                );
                let privacy = fixture
                    .manager
                    .open_raw_connection()
                    .expect("Privacy v5 after BeforePrepare");
                assert_eq!(
                    compute_privacy_v5_manifests_read_only(&privacy)
                        .expect("exact Privacy v5 survives BeforePrepare"),
                    privacy_v5_before,
                );
                assert_eq!(
                    database::validate_user_database_migration_source_read_only(
                        &fixture.user_database_path,
                    )
                    .expect("User remains valid after BeforePrepare"),
                    ValidatedUserSourceSchema::V031V10,
                    "User must remain the exact frozen v0.3.1 schema-10 source",
                );
            }
            let reconstructed_source = fixture
                .manager
                .v031_approved_projection_source_proof(&fixture.gate, &step5_terminal)
                .expect("reconstruct source proof after process-style restart");
            assert_eq!(reconstructed_source, source);
            let terminal = fixture
                .manager
                .run_v031_approved_projection_migration_after_checkpoint(
                    &fixture.gate,
                    &step5_terminal,
                    &reconstructed_source,
                    &checkpoint,
                )
                .expect("projection retry after failure");
            let repeated = fixture
                .manager
                .run_v031_approved_projection_migration_after_checkpoint(
                    &fixture.gate,
                    &step5_terminal,
                    &reconstructed_source,
                    &checkpoint,
                )
                .expect("projection terminal retry is a no-op");
            assert_eq!(repeated, terminal);
            let privacy = fixture
                .manager
                .open_raw_connection()
                .expect("canonical Privacy v6 after projection retry");
            let privacy_v6 = privacy::compute_privacy_v6_manifests_read_only(&privacy)
                .expect("full canonical Privacy v6 manifest");
            assert_eq!(&privacy_v6, terminal.privacy_v6(),);
        }

        for failure_point in [
            ProjectionFailurePoint::BeforeBatch(0),
            ProjectionFailurePoint::AfterBatch(0),
        ] {
            let fixture = V031Fixture::new(&[PROJECT_A]);
            let (_step5_source, authentic_terminal) = complete_v031_step5(&fixture);
            insert_invalid_approved_projection_candidate(&fixture);
            let privacy = fixture
                .manager
                .open_raw_connection()
                .expect("synthetic Privacy v5");
            let v5 = compute_privacy_v5_manifests_read_only(&privacy)
                .expect("synthetic exact Privacy v5 proof");
            drop(privacy);
            let step5_terminal = V031BindingMaterialTerminalProof::for_projection_test(v5.clone());
            let source = fixture
                .manager
                .v031_approved_projection_source_proof(&fixture.gate, &step5_terminal)
                .expect("one blocked projection candidate");
            assert_eq!(source.candidate_count(), 1);
            assert_ne!(step5_terminal, authentic_terminal);
            let checkpoint = projection_checkpoint_for_test(&fixture, &source);
            let error = fixture
                .manager
                .run_v031_approved_projection_migration_with_failure(
                    &fixture.gate,
                    &step5_terminal,
                    &source,
                    &checkpoint,
                    failure_point,
                )
                .expect_err("injected per-batch failure");
            assert_eq!(error.code(), "v031_projection_injected_failure");
            let reconstructed_source = fixture
                .manager
                .v031_approved_projection_source_proof(&fixture.gate, &step5_terminal)
                .expect("reconstruct candidate source after committed batch");
            assert_eq!(reconstructed_source, source);
            let terminal = fixture
                .manager
                .run_v031_approved_projection_migration_after_checkpoint(
                    &fixture.gate,
                    &step5_terminal,
                    &reconstructed_source,
                    &checkpoint,
                )
                .expect("batch retry reaches terminal state");
            let repeated = fixture
                .manager
                .run_v031_approved_projection_migration_after_checkpoint(
                    &fixture.gate,
                    &step5_terminal,
                    &reconstructed_source,
                    &checkpoint,
                )
                .expect("committed projection batch retry is a no-op");
            assert_eq!(repeated, terminal);
            assert_eq!(terminal.approved_generation_count(), 1);
            assert_eq!(terminal.projection_rows(), 0);
            assert_eq!(terminal.blocked_rows(), 1);
            assert_eq!(terminal.risk_head_rows(), 0);
            let ledger = fixture
                .manager
                .open_raw_connection()
                .expect("projection terminal ledger")
                .query_row(
                    "SELECT result_state,error_code,
                            (SELECT COUNT(*) FROM case_material_migration_events
                             WHERE migration_id=?1)
                     FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_key='projection-redaction'",
                    [privacy::APPROVED_CASE_PROJECTION_MIGRATION_ID],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .expect("one append-only blocked ledger row");
            assert_eq!(ledger.0, "blocked");
            assert_eq!(
                ledger.1.as_deref(),
                Some("approved_projection_full_blob_invalid")
            );
            assert_eq!(ledger.2, 1);
        }
    }

    #[test]
    fn v031_step6_rejects_wrong_checkpoint_and_source_or_user_drift_before_write() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        let (_step5_source, step5_terminal) = complete_v031_step5(&fixture);
        let source = fixture
            .manager
            .v031_approved_projection_source_proof(&fixture.gate, &step5_terminal)
            .expect("Step-6 source proof");
        let user = fixture.gate.original_user_source_proof();
        let wrong_checkpoint = V031MigrationCheckpointProof::projection_for_test(
            fixture.gate.lineage_id().to_owned(),
            fixture.gate.original_identity_sha256().to_owned(),
            test_workspace_instance_id().as_str().to_owned(),
            "3".repeat(64),
            user.schema_manifest_sha256.clone(),
            user.logical_database_manifest_sha256.clone(),
            user.business_manifest_sha256.clone(),
            user.total_rows,
            source.source_fingerprint().to_owned(),
            "0".repeat(64),
            source.candidate_count(),
            source.privacy_v5().logical_manifest.sha256.clone(),
            source.privacy_v5().business_manifest.sha256.clone(),
            source.privacy_v5().total_row_count,
        );
        let privacy_before =
            fs::read(&fixture.manager.shared.database_path).expect("Privacy v5 before gate error");
        let error = fixture
            .manager
            .run_v031_approved_projection_migration_after_checkpoint(
                &fixture.gate,
                &step5_terminal,
                &source,
                &wrong_checkpoint,
            )
            .expect_err("wrong projection checkpoint");
        assert_eq!(error.code(), "v031_projection_checkpoint_gate_mismatch");
        assert_eq!(
            fs::read(&fixture.manager.shared.database_path).expect("Privacy after gate error"),
            privacy_before
        );

        fixture
            .manager
            .open_raw_connection()
            .expect("Privacy drift writer")
            .execute(
                "UPDATE privacy_schema_metadata SET updated_at='2030-01-01 00:00:00'
                 WHERE key='schema_version'",
                [],
            )
            .expect("Privacy v5 semantic drift");
        let checkpoint = projection_checkpoint_for_test(&fixture, &source);
        let error = fixture
            .manager
            .run_v031_approved_projection_migration_after_checkpoint(
                &fixture.gate,
                &step5_terminal,
                &source,
                &checkpoint,
            )
            .expect_err("complete v5 manifest drift must close before prepare");
        assert_eq!(error.code(), "v031_projection_v5_source_changed");

        let user_drift = V031Fixture::new(&[PROJECT_A]);
        let (_step5_source, user_step5_terminal) = complete_v031_step5(&user_drift);
        let user_source = user_drift
            .manager
            .v031_approved_projection_source_proof(&user_drift.gate, &user_step5_terminal)
            .expect("user-drift projection source");
        let user_checkpoint = projection_checkpoint_for_test(&user_drift, &user_source);
        Connection::open(&user_drift.user_database_path)
            .expect("user drift writer")
            .execute(
                "UPDATE projects SET title='projection user drift' WHERE project_id=?1",
                [PROJECT_A],
            )
            .expect("mutate active user v10");
        let privacy_before = fs::read(&user_drift.manager.shared.database_path)
            .expect("Privacy before user drift rejection");
        let error = user_drift
            .manager
            .run_v031_approved_projection_migration_after_checkpoint(
                &user_drift.gate,
                &user_step5_terminal,
                &user_source,
                &user_checkpoint,
            )
            .expect_err("user v10 drift must close before Privacy write");
        assert_eq!(error.code(), "v031_case_material_user_source_invalid");
        assert_eq!(
            fs::read(&user_drift.manager.shared.database_path)
                .expect("Privacy after user drift rejection"),
            privacy_before
        );
    }

    #[test]
    fn v031_step6_terminal_proof_rejects_extra_projection_ledger_and_event() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        let (_step5_source, step5_terminal) = complete_v031_step5(&fixture);
        let source = fixture
            .manager
            .v031_approved_projection_source_proof(&fixture.gate, &step5_terminal)
            .expect("Step-6 source proof");
        let checkpoint = projection_checkpoint_for_test(&fixture, &source);
        fixture
            .manager
            .run_v031_approved_projection_migration_after_checkpoint(
                &fixture.gate,
                &step5_terminal,
                &source,
                &checkpoint,
            )
            .expect("Step-6 terminal state");
        let privacy = fixture
            .manager
            .open_raw_connection()
            .expect("extra projection evidence writer");
        privacy
            .execute(
                "INSERT INTO case_material_migration_ledger(
                   migration_id,source_store,source_table,source_key,source_fingerprint,
                   target_material_id,target_redaction_id,assigned_generation_number,
                   result_state,error_code,started_at,completed_at
                 ) VALUES(?1,'privacy-workflow.sqlite','privacy_redactions',
                          'extra-projection-redaction',?2,'extra-projection-material',
                          'extra-projection-redaction',1,'blocked','extra_projection_row',
                          CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
                params![
                    privacy::APPROVED_CASE_PROJECTION_MIGRATION_ID,
                    sha256_hex(b"extra projection source")
                ],
            )
            .expect("extra projection ledger");
        privacy
            .execute(
                "INSERT INTO case_material_migration_events(
                   migration_event_id,migration_id,source_store,source_table,source_key,
                   event_type,source_fingerprint,target_material_id,target_redaction_id,
                   assigned_generation_number,result_state,error_code,occurred_at
                 ) VALUES('extra-projection-event',?1,'privacy-workflow.sqlite',
                          'privacy_redactions','extra-projection-redaction',
                          'approved_projection_backfill',?2,'extra-projection-material',
                          'extra-projection-redaction',1,'blocked','extra_projection_row',
                          CURRENT_TIMESTAMP)",
                params![
                    privacy::APPROVED_CASE_PROJECTION_MIGRATION_ID,
                    sha256_hex(b"extra projection source")
                ],
            )
            .expect("extra projection event");
        drop(privacy);
        fixture
            .manager
            .v031_privacy_v6_terminal_proof(&fixture.gate, &step5_terminal, &source, &checkpoint)
            .expect_err("extra/orphan projection evidence must fail terminal proof");
    }

    #[test]
    fn v031_step4_pre_v5_proof_pins_both_live_sources_and_leaves_bytes_and_sidecars_unchanged() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        let target = fixture.target_gate();
        let user_before = sqlite_file_set_bytes_for_test(&fixture.user_database_path);
        let privacy_before = sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path);

        let proof = fixture
            .manager
            .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
            .expect("simultaneous pre-v5 source proof");

        assert_eq!(proof.evidence_sha256().len(), 64);
        assert_eq!(proof.source_fingerprint().len(), 64);
        assert_eq!(proof.binding_candidate_count, 1);
        // The source-manifest ledger row is a real material candidate even
        // when the legacy Privacy source contains no materials.
        assert_eq!(proof.material_candidate_count, 1);
        assert_ne!(
            proof.binding_candidate_manifest_sha256,
            proof.material_candidate_manifest_sha256
        );
        let diagnostic = format!("{proof:?}");
        assert!(!diagnostic.contains(PROJECT_A));
        assert!(!diagnostic.contains("case_"));
        assert_eq!(
            sqlite_file_set_bytes_for_test(&fixture.user_database_path),
            user_before
        );
        assert_eq!(
            sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path),
            privacy_before
        );
        privacy::validate_privacy_v1_migration_source_read_only(
            &fixture.manager.shared.database_path,
        )
        .expect("live Privacy remains exact v1");
        database::validate_user_database_migration_source_read_only(&fixture.user_database_path)
            .expect("live User remains exact v10");
    }

    #[cfg(windows)]
    #[test]
    fn v031_partial_v5_schema_and_lifecycle_crash_prefixes_reopen_and_resume_to_full_v5() {
        for (index, after_lifecycle) in [false, true].into_iter().enumerate() {
            let fixture = V031Fixture::new(&[PROJECT_A]);
            let root = fixture._directory.path().to_path_buf();
            let workspace = fixture.manager.shared.workspace_instance_id.clone();
            let target = fixture.target_gate();
            let source = fixture
                .manager
                .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
                .expect("pre-v5 checkpoint proof");
            let (binding, materials) = step4_checkpoint_proofs_for_test(&fixture, &target, &source);
            let failure = if after_lifecycle {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_lifecycle_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            } else {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_schema_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            };
            assert!(failure.is_err(), "partial boundary {index} must interrupt");
            let partial_connection = open_privacy_read_only(&fixture.manager.shared.database_path)
                .expect("partial v5 opens read-only");
            let partial = classify_privacy_v5_partial_read_only(&partial_connection, &workspace)
                .expect("partial v5 classifies exactly");
            assert_eq!(
                partial.stage(),
                if after_lifecycle {
                    PrivacyV5PartialStage::LifecycleCommittedBeforeBinding
                } else {
                    PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle
                }
            );
            assert_eq!(
                partial.source_business_manifest_sha256(),
                source.privacy_v1_business_manifest_sha256
            );
            drop(partial_connection);

            let V031Fixture {
                _directory,
                user_database_path,
                manager,
                gate,
            } = fixture;
            drop(manager);
            let reopened = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
                root,
                workspace,
                Arc::new(NoopPublicationInvalidator),
            )
            .expect("fresh manager reopens partial v5");
            reopened.set_test_runtime(
                ReceiptSigner::new([31_u8; 32]).expect("restart signer"),
                1_800_000_000,
            );
            let completed = reopened
                .resume_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                    &gate, &target, &source, &binding, &materials,
                )
                .expect("fresh manager consumes opaque partial capability");
            assert_eq!(completed.schema_version, 5);
            assert_eq!(
                completed.schema_object_count,
                privacy::PRIVACY_V5_SCHEMA_OBJECT_COUNT
            );
            let readback = reopened
                .v031_privacy_v5_manifest_proof_after_checkpoints_read_only(
                    &gate, &target, &binding, &materials,
                )
                .expect("full canonical v5 readback");
            assert_eq!(readback, completed);
            database::validate_user_database_migration_source_read_only(&user_database_path)
                .expect("restart leaves exact User-v10 source unchanged");
            drop(_directory);
        }
    }

    #[cfg(windows)]
    #[test]
    fn v031_partial_v5_tamper_profiles_fail_closed_before_resume_write() {
        #[derive(Clone, Copy)]
        enum Tamper {
            ExtraObject,
            ExtraRow,
            WrongWorkspace,
            HalfBinding,
        }
        for tamper in [
            Tamper::ExtraObject,
            Tamper::ExtraRow,
            Tamper::WrongWorkspace,
            Tamper::HalfBinding,
        ] {
            let fixture = V031Fixture::new(&[PROJECT_A]);
            let target = fixture.target_gate();
            let source = fixture
                .manager
                .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
                .expect("pre-v5 checkpoint proof");
            let (binding, materials) = step4_checkpoint_proofs_for_test(&fixture, &target, &source);
            let after_lifecycle = matches!(tamper, Tamper::ExtraRow | Tamper::WrongWorkspace);
            let failure = if after_lifecycle {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_lifecycle_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            } else {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_schema_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            };
            assert!(failure.is_err());
            let privacy = fixture
                .manager
                .open_raw_connection()
                .expect("partial tamper writer");
            match tamper {
                Tamper::ExtraObject => privacy
                    .execute_batch("CREATE TABLE unexpected_partial_v5(id TEXT PRIMARY KEY);")
                    .expect("extra object tamper"),
                Tamper::ExtraRow => {
                    privacy
                        .execute(
                            "INSERT INTO privacy_mapping_keys(
                           key_version,protected_key,protected_key_sha256,state,
                           created_at_unix,retired_at_unix,revoked_at_unix,destroyed_at_unix
                         )
                         SELECT 2,protected_key,protected_key_sha256,'retired',
                                created_at_unix,created_at_unix,NULL,NULL
                         FROM privacy_mapping_keys WHERE key_version=1",
                            [],
                        )
                        .expect("extra lifecycle row tamper");
                }
                Tamper::WrongWorkspace => {
                    privacy
                        .execute(
                            "UPDATE privacy_lifecycle_meta
                             SET workspace_instance_id=?1 WHERE singleton=1",
                            ["ws_ffffffffffffffffffffffffffffffff"],
                        )
                        .expect("workspace tamper");
                }
                Tamper::HalfBinding => privacy
                    .execute_batch(
                        "CREATE TABLE project_privacy_case_binding_audit(
                           creation_audit_id TEXT PRIMARY KEY
                         );",
                    )
                    .expect("half-binding tamper"),
            }
            drop(privacy);
            let before_rejected_resume =
                sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path);
            fixture
                .manager
                .resume_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                    &fixture.gate,
                    &target,
                    &source,
                    &binding,
                    &materials,
                )
                .expect_err("tampered partial state must fail before resume write");
            assert_eq!(
                sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path),
                before_rejected_resume
            );
            let binding_objects: i64 = Connection::open_with_flags(
                &fixture.manager.shared.database_path,
                OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .expect("post-rejection reader")
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE name IN(
                   'project_privacy_case_binding_audit',
                   'project_privacy_case_bindings'
                 )",
                [],
                |row| row.get(0),
            )
            .expect("binding object count");
            assert!(binding_objects <= 1, "resume must not complete binding DDL");
        }
    }

    #[cfg(windows)]
    #[test]
    fn v031_partial_v5_resume_reauthenticates_each_write_under_immediate_lock() {
        fn is_busy(error: &rusqlite::Error) -> bool {
            matches!(
                error,
                rusqlite::Error::SqliteFailure(inner, _)
                    if matches!(
                        inner.code,
                        rusqlite::ErrorCode::DatabaseBusy
                            | rusqlite::ErrorCode::DatabaseLocked
                    )
            )
        }

        for after_lifecycle in [false, true] {
            let fixture = V031Fixture::new(&[PROJECT_A]);
            let target = fixture.target_gate();
            let source = fixture
                .manager
                .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
                .expect("pre-v5 checkpoint proof");
            let (binding, materials) = step4_checkpoint_proofs_for_test(&fixture, &target, &source);
            let failed = if after_lifecycle {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_lifecycle_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            } else {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_schema_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            };
            assert!(
                failed.is_err(),
                "the requested partial boundary must persist"
            );
            let capability = authorize_v031_privacy_v5_partial_resume(
                &fixture.manager,
                &fixture.gate,
                &target,
                &source,
                &binding,
                &materials,
            )
            .expect("authenticated partial capability");
            let privacy_path = fixture.manager.shared.database_path.clone();
            let mut locked_stages = Vec::new();
            let completed =
                resume_and_initialize_v031_privacy_v5(&fixture.manager, &capability, |stage| {
                    let competing =
                        Connection::open(&privacy_path).expect("competing SQLite writer opens");
                    competing
                        .busy_timeout(std::time::Duration::ZERO)
                        .expect("zero busy timeout configures");
                    let write = match stage {
                        PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle => competing.execute(
                            "UPDATE privacy_schema_metadata
                             SET updated_at='2030-01-01 00:00:00'
                             WHERE key='schema_version'",
                            [],
                        ),
                        PrivacyV5PartialStage::LifecycleCommittedBeforeBinding => competing
                            .execute(
                                "UPDATE privacy_lifecycle_meta
                             SET workspace_instance_id='ws_ffffffffffffffffffffffffffffffff'
                             WHERE singleton=1",
                                [],
                            ),
                    };
                    let error = write.expect_err(
                        "an external writer cannot cross strict reauthentication and first write",
                    );
                    assert!(
                        is_busy(&error),
                        "competing writer must fail specifically as busy"
                    );
                    locked_stages.push(stage);
                    Ok(())
                })
                .expect("locked partial transitions complete");
            assert_eq!(completed.schema_version, 5);
            assert_eq!(
                locked_stages,
                if after_lifecycle {
                    vec![PrivacyV5PartialStage::LifecycleCommittedBeforeBinding]
                } else {
                    vec![
                        PrivacyV5PartialStage::SchemaCommittedBeforeLifecycle,
                        PrivacyV5PartialStage::LifecycleCommittedBeforeBinding,
                    ]
                }
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn v031_partial_v5_stale_capability_is_rejected_inside_immediate_transaction() {
        for after_lifecycle in [false, true] {
            let fixture = V031Fixture::new(&[PROJECT_A]);
            let target = fixture.target_gate();
            let source = fixture
                .manager
                .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
                .expect("pre-v5 checkpoint proof");
            let (binding, materials) = step4_checkpoint_proofs_for_test(&fixture, &target, &source);
            let failed = if after_lifecycle {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_lifecycle_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            } else {
                fixture
                    .manager
                    .upgrade_v031_privacy_store_to_v5_after_checkpoints_fail_after_schema_for_test(
                        &fixture.gate,
                        &target,
                        &source,
                        &binding,
                        &materials,
                    )
            };
            assert!(
                failed.is_err(),
                "the requested partial boundary must persist"
            );
            let capability = authorize_v031_privacy_v5_partial_resume(
                &fixture.manager,
                &fixture.gate,
                &target,
                &source,
                &binding,
                &materials,
            )
            .expect("authenticated partial capability");

            let tamper = Connection::open(&fixture.manager.shared.database_path)
                .expect("stale-capability writer opens");
            if after_lifecycle {
                tamper
                    .execute(
                        "UPDATE privacy_lifecycle_meta
                         SET workspace_instance_id='ws_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
                         WHERE singleton=1",
                        [],
                    )
                    .expect("lifecycle prefix changes after authorization");
            } else {
                tamper
                    .execute(
                        "UPDATE privacy_schema_metadata
                         SET updated_at='2031-01-01 00:00:00'
                         WHERE key='schema_version'",
                        [],
                    )
                    .expect("schema prefix changes after authorization");
            }
            drop(tamper);
            let before_rejected_write =
                sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path);
            resume_and_initialize_v031_privacy_v5(&fixture.manager, &capability, |_| Ok(()))
                .expect_err("stale capability must fail its in-transaction reclassification");
            assert_eq!(
                sqlite_file_set_bytes_for_test(&fixture.manager.shared.database_path),
                before_rejected_write,
                "stale rejection must not add lifecycle rows or binding DDL",
            );
        }
    }

    #[test]
    fn v031_step4_zero_history_commits_new_random_required_and_never_preallocates_case_id() {
        fn migrate_one() -> String {
            let fixture = V031Fixture::new(&[PROJECT_A]);
            let target = fixture.target_gate();
            let proof = fixture
                .manager
                .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
                .expect("zero-history pre-v5 proof");

            with_v031_pinned_user_snapshot(
                &fixture.manager,
                &fixture.gate,
                |user_connection, _path, source| {
                    let user = UserSnapshot::load(user_connection)?;
                    let candidates = compute_v031_candidate_manifests(
                        &user,
                        source,
                        &[],
                        fixture.manager.shared.workspace_instance_id.as_str(),
                    )?;
                    let project = user.projects.get(PROJECT_A).expect("project candidate");
                    let source_fingerprint = source.persistent_fingerprint();
                    let mut expected = Fingerprint::new(b"v031-binding-candidate-manifest-v1");
                    expected.text("project");
                    expected.text(&opaque_candidate_key_commitment(
                        b"v031-binding-project-key-v1",
                        &source_fingerprint,
                        &project.project_id,
                    ));
                    expected.text(&project_binding_fingerprint(project, None));
                    expected.text("new_random_required");
                    expected.optional_text(None);
                    expected.text(&opaque_candidate_key_commitment(
                        b"v031-binding-ledger-target-v1",
                        &source_fingerprint,
                        &binding_target_id(&project.project_id),
                    ));
                    assert_eq!(
                        candidates.binding_manifest_sha256,
                        expected.finish(),
                        "the checkpoint commits the explicit random-allocation outcome"
                    );
                    assert_eq!(
                        candidates.binding_manifest_sha256,
                        proof.binding_candidate_manifest_sha256
                    );
                    Ok(())
                },
            )
            .expect("inspect opaque zero-history commitment");

            let (binding, materials) = step4_checkpoint_proofs_for_test(&fixture, &target, &proof);
            fixture
                .manager
                .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                    &fixture.gate,
                    &target,
                    &proof,
                    &binding,
                    &materials,
                )
                .expect("checkpoint-gated Privacy v5 upgrade");
            let before_writer = fixture
                .manager
                .open_raw_connection()
                .expect("pre-writer Privacy v5");
            let preallocated: i64 = before_writer
                .query_row(
                    "SELECT COUNT(*) FROM project_privacy_case_bindings",
                    [],
                    |row| row.get(0),
                )
                .expect("preallocated binding count");
            assert_eq!(preallocated, 0);
            drop(before_writer);

            fixture
                .manager
                .run_v031_case_material_migration_after_checkpoints(
                    &fixture.gate,
                    &target,
                    &binding,
                    &materials,
                )
                .expect("strict Step-5 writer");
            fixture
                .manager
                .open_raw_connection()
                .expect("terminal binding reader")
                .query_row(
                    "SELECT privacy_case_id FROM project_privacy_case_bindings
                     WHERE project_id=?1",
                    [PROJECT_A],
                    |row| row.get(0),
                )
                .expect("transactionally generated Privacy CaseId")
        }

        let first = migrate_one();
        let second = migrate_one();
        assert!(PrivacyCaseId::parse(first.clone()).is_ok());
        assert!(PrivacyCaseId::parse(second.clone()).is_ok());
        assert_ne!(
            first, second,
            "separate CSPRNG allocations must not derive identity"
        );
    }

    #[test]
    fn v031_step5_recomputes_pre_v5_manifests_and_rejects_tamper_before_first_write() {
        let fixture = V031Fixture::new(&[PROJECT_A, PROJECT_B]);
        let target = fixture.target_gate();
        let source = fixture
            .manager
            .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
            .expect("pre-v5 source proof");
        let (binding, materials) = step4_checkpoint_proofs_for_test(&fixture, &target, &source);
        let reconstructed = fixture
            .manager
            .v031_case_migration_checkpoint_source_proof_from_verified_checkpoints(
                &fixture.gate,
                &target,
                &binding,
                &materials,
            )
            .expect("restart source-proof reconstruction");
        assert_eq!(reconstructed, source);
        fixture
            .manager
            .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                &fixture.gate,
                &target,
                &source,
                &binding,
                &materials,
            )
            .expect("Privacy v1 to v5 after both checkpoints");

        let before = fixture
            .manager
            .open_raw_connection()
            .expect("pre-tamper Privacy");
        let before_manifest =
            compute_privacy_v5_manifests_read_only(&before).expect("pre-tamper v5 manifest");
        drop(before);
        let tampered_materials = materials
            .clone()
            .with_candidate_manifest_for_test("f".repeat(64));
        fixture
            .manager
            .run_v031_case_material_migration_after_checkpoints(
                &fixture.gate,
                &target,
                &binding,
                &tampered_materials,
            )
            .expect_err("tampered material candidate must fail before first target row write");
        let after_failure = fixture
            .manager
            .open_raw_connection()
            .expect("post-failure Privacy");
        assert_eq!(
            compute_privacy_v5_manifests_read_only(&after_failure)
                .expect("post-failure v5 manifest"),
            before_manifest
        );
        let target_rows: i64 = after_failure
            .query_row(
                "SELECT
                   (SELECT COUNT(*) FROM project_privacy_case_bindings) +
                   (SELECT COUNT(*) FROM case_material_migration_ledger) +
                   (SELECT COUNT(*) FROM case_material_migration_events)",
                [],
                |row| row.get(0),
            )
            .expect("zero Step-5 rows after rejected proof");
        assert_eq!(target_rows, 0);
        drop(after_failure);

        fixture
            .manager
            .run_v031_case_material_migration_after_checkpoints(
                &fixture.gate,
                &target,
                &binding,
                &materials,
            )
            .expect("untampered post-v5 candidate recomputation");
        let terminal = fixture
            .manager
            .v031_binding_material_terminal_proof_after_checkpoints(
                &fixture.gate,
                &target,
                &binding,
                &materials,
            )
            .expect("checkpoint-bound terminal proof");
        assert_eq!(terminal.binding_ledger_rows(), 2);
        assert_eq!(terminal.material_ledger_rows(), 1);
        assert_eq!(terminal.bindings_verified(), 2);
    }

    #[test]
    fn v031_step4_user_or_privacy_drift_after_checkpoints_rejects_before_v5_write() {
        let user_drift = V031Fixture::new(&[PROJECT_A]);
        let user_target = user_drift.target_gate();
        let user_source = user_drift
            .manager
            .v031_case_migration_checkpoint_source_proof(&user_drift.gate, &user_target)
            .expect("user-drift pre-v5 proof");
        let (user_binding, user_materials) =
            step4_checkpoint_proofs_for_test(&user_drift, &user_target, &user_source);
        Connection::open(&user_drift.user_database_path)
            .expect("user drift writer")
            .execute(
                "UPDATE projects SET summary='drifted after checkpoint' WHERE project_id=?1",
                [PROJECT_A],
            )
            .expect("mutate authenticated User source");
        let privacy_before_user_rejection =
            sqlite_file_set_bytes_for_test(&user_drift.manager.shared.database_path);
        user_drift
            .manager
            .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                &user_drift.gate,
                &user_target,
                &user_source,
                &user_binding,
                &user_materials,
            )
            .expect_err("User physical/semantic drift must reject the v1 to v5 write");
        assert_eq!(
            sqlite_file_set_bytes_for_test(&user_drift.manager.shared.database_path),
            privacy_before_user_rejection
        );
        privacy::validate_privacy_v1_migration_source_read_only(
            &user_drift.manager.shared.database_path,
        )
        .expect("Privacy remains v1 after User rejection");

        let privacy_drift = V031Fixture::new(&[PROJECT_A]);
        let privacy_target = privacy_drift.target_gate();
        let privacy_source = privacy_drift
            .manager
            .v031_case_migration_checkpoint_source_proof(&privacy_drift.gate, &privacy_target)
            .expect("Privacy-drift pre-v5 proof");
        let (privacy_binding, privacy_materials) =
            step4_checkpoint_proofs_for_test(&privacy_drift, &privacy_target, &privacy_source);
        Connection::open(&privacy_drift.manager.shared.database_path)
            .expect("Privacy physical drift writer")
            .pragma_update(None, "user_version", 7_i64)
            .expect("mutate Privacy physical file set without adding source rows");
        let privacy_after_drift =
            sqlite_file_set_bytes_for_test(&privacy_drift.manager.shared.database_path);
        privacy_drift
            .manager
            .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                &privacy_drift.gate,
                &privacy_target,
                &privacy_source,
                &privacy_binding,
                &privacy_materials,
            )
            .expect_err("Privacy physical drift must reject the v1 to v5 write");
        assert_eq!(
            sqlite_file_set_bytes_for_test(&privacy_drift.manager.shared.database_path),
            privacy_after_drift
        );
        let drifted = Connection::open_with_flags(
            &privacy_drift.manager.shared.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("drifted Privacy reader");
        assert_eq!(
            PrivacyStore::preflight_schema(&drifted).expect("drifted schema preflight"),
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 1 }
        );
    }

    #[test]
    fn v031_step5_is_exact_read_only_idempotent_and_reconstructs_terminal_counts() {
        let fixture = V031Fixture::new(&[PROJECT_A, PROJECT_B]);
        let user_before = fs::read(&fixture.user_database_path).expect("v0.3.1 user before");
        let v5 = fixture.upgrade_to_v5();
        assert_eq!(v5.schema_version, 5);
        assert!(fixture
            .manager
            .v031_case_material_migration_required(&fixture.gate)
            .expect("initial v0.3.1 probe"));
        let source = fixture
            .manager
            .v031_case_material_migration_source_fingerprint(&fixture.gate)
            .expect("v0.3.1 source fingerprint");
        assert_eq!(source.evidence_sha256().len(), 64);
        let report = fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("v0.3.1 binding/material migration");
        assert!(report.source_unchanged_verified);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("v0.3.1 user after"),
            user_before
        );
        assert!(!fixture
            .manager
            .v031_case_material_migration_required(&fixture.gate)
            .expect("terminal v0.3.1 probe"));

        let first_terminal = fixture
            .manager
            .v031_binding_material_terminal_proof(&fixture.gate, &source)
            .expect("first terminal proof");
        assert_eq!(first_terminal.binding_ledger_rows, 2);
        assert_eq!(first_terminal.material_ledger_rows, 1);
        assert_eq!(first_terminal.terminal_rows, 1);
        assert_eq!(first_terminal.blocked_rows, 0);
        assert_eq!(first_terminal.privacy_migration_batches, 1);
        assert_eq!(first_terminal.bindings_verified, 2);

        let rerun = fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("idempotent v0.3.1 rerun");
        assert!(rerun.idempotent_noops >= 3);
        let second_terminal = fixture
            .manager
            .v031_binding_material_terminal_proof(&fixture.gate, &source)
            .expect("second terminal proof");
        assert_eq!(second_terminal, first_terminal);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("v0.3.1 user after rerun"),
            user_before
        );
    }

    #[test]
    fn v031_gate_rejects_source_drift_before_privacy_schema_write() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        Connection::open(&fixture.user_database_path)
            .expect("writable drift fixture")
            .execute(
                "UPDATE projects SET title='drifted source' WHERE project_id=?1",
                [PROJECT_A],
            )
            .expect("source drift");
        let error = fixture
            .manager
            .upgrade_v031_privacy_store_to_v5_after_original_rollback(&fixture.gate)
            .expect_err("source drift must close the v5 writer gate");
        assert_eq!(error.code(), "v031_case_material_user_source_invalid");
        let privacy =
            Connection::open(&fixture.manager.shared.database_path).expect("unchanged privacy v1");
        assert_eq!(
            PrivacyStore::preflight_schema(&privacy).expect("privacy v1 preflight"),
            PrivacyStoreSchemaStatus::UpgradeRequired { found_version: 1 }
        );
    }

    #[test]
    fn v031_terminal_proof_rejects_extra_ledger_and_orphan_binding_audit() {
        let fixture = V031Fixture::new(&[PROJECT_A]);
        fixture.upgrade_to_v5();
        let source = fixture
            .manager
            .v031_case_material_migration_source_fingerprint(&fixture.gate)
            .expect("source fingerprint");
        fixture
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&fixture.gate, &source)
            .expect("terminal migration");
        let privacy = fixture
            .manager
            .open_raw_connection()
            .expect("privacy writer");
        privacy
            .execute(
                "INSERT INTO case_material_migration_ledger(
                   migration_id,source_store,source_table,source_key,source_fingerprint,
                   target_material_id,result_state,started_at,completed_at
                 ) VALUES(?1,?2,'source_manifest','unexpected-source',?3,
                          'source_manifest_v1','migrated',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)",
                params![
                    CASE_MATERIAL_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    sha256_hex(b"unexpected terminal source")
                ],
            )
            .expect("extra ledger");
        drop(privacy);
        let error = fixture
            .manager
            .v031_binding_material_terminal_proof(&fixture.gate, &source)
            .expect_err("extra ledger must fail closed");
        assert_eq!(error.code(), "v031_binding_material_terminal_proof_invalid");

        let clean = V031Fixture::new(&[PROJECT_A]);
        clean.upgrade_to_v5();
        let clean_source = clean
            .manager
            .v031_case_material_migration_source_fingerprint(&clean.gate)
            .expect("clean source fingerprint");
        clean
            .manager
            .run_v031_case_material_migration_after_backup_for_source(&clean.gate, &clean_source)
            .expect("clean terminal migration");
        let privacy = clean.manager.open_raw_connection().expect("audit writer");
        privacy
            .execute(
                "INSERT INTO project_privacy_case_binding_audit(
                   creation_audit_id,project_id,privacy_case_id,binding_version,
                   creation_source,migration_id,result,created_at
                 ) VALUES(
                   'orphan-audit','case-orphan-audit',
                   'case_11111111111111111111111111111111',1,
                   'legacy_migration',?1,'created',CURRENT_TIMESTAMP
                 )",
                [PROJECT_CASE_BINDING_MIGRATION_ID],
            )
            .expect("orphan binding audit");
        drop(privacy);
        let error = clean
            .manager
            .v031_binding_material_terminal_proof(&clean.gate, &clean_source)
            .expect_err("orphan audit must fail closed");
        assert_eq!(error.code(), "v031_binding_material_terminal_proof_invalid");
    }

    #[test]
    fn v031_step5_checkpoint_gated_failure_windows_resume_without_duplicate_identity_or_evidence() {
        fn prepare_checkpoint_gated_writer(
            fixture: &V031Fixture,
        ) -> (
            V031TargetComponentsPreparedGate,
            V031MigrationCheckpointProof,
            V031MigrationCheckpointProof,
        ) {
            let target = fixture.target_gate();
            let source = fixture
                .manager
                .v031_case_migration_checkpoint_source_proof(&fixture.gate, &target)
                .expect("checkpoint-gated Step-5 source");
            let (binding, materials) = step4_checkpoint_proofs_for_test(fixture, &target, &source);
            fixture
                .manager
                .upgrade_v031_privacy_store_to_v5_after_binding_material_checkpoints(
                    &fixture.gate,
                    &target,
                    &source,
                    &binding,
                    &materials,
                )
                .expect("checkpoint-gated Privacy v5 upgrade");
            (target, binding, materials)
        }

        fn target_inventory(fixture: &V031Fixture) -> (i64, i64, i64, i64, i64, i64, i64, i64) {
            fixture
                .manager
                .open_raw_connection()
                .expect("Step-5 target inventory reader")
                .query_row(
                    "SELECT
                       (SELECT COUNT(*) FROM project_privacy_case_bindings),
                       (SELECT COUNT(DISTINCT project_id)
                          FROM project_privacy_case_bindings),
                       (SELECT COUNT(DISTINCT privacy_case_id)
                          FROM project_privacy_case_bindings),
                       (SELECT COUNT(*) FROM project_privacy_case_binding_audit),
                       (SELECT COUNT(*) FROM case_material_migration_ledger),
                       (SELECT COUNT(*) FROM case_material_migration_events),
                       (SELECT COUNT(*) FROM case_material_selections),
                       (SELECT COUNT(*) FROM case_material_legacy_references)",
                    [],
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
                        ))
                    },
                )
                .expect("Step-5 target inventory")
        }

        #[allow(clippy::type_complexity)]
        fn sqlite_file_set_state(
            path: &std::path::Path,
        ) -> Vec<(String, Option<(u64, u128, String)>)> {
            ["", "-wal", "-shm", "-journal"]
                .into_iter()
                .map(|suffix| {
                    let mut value = path.as_os_str().to_os_string();
                    value.push(suffix);
                    let slot = PathBuf::from(value);
                    let state = match fs::metadata(&slot) {
                        Ok(metadata) => {
                            let modified = metadata
                                .modified()
                                .expect("SQLite slot mtime")
                                .duration_since(std::time::UNIX_EPOCH)
                                .expect("SQLite slot mtime after Unix epoch")
                                .as_nanos();
                            let bytes = fs::read(&slot).expect("SQLite slot bytes");
                            Some((metadata.len(), modified, sha256_hex(&bytes)))
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => panic!("inspect SQLite file-set slot {suffix}: {error}"),
                    };
                    (suffix.to_owned(), state)
                })
                .collect()
        }

        fn assert_production_retry_is_idempotent(
            fixture: &V031Fixture,
            target: &V031TargetComponentsPreparedGate,
            binding: &V031MigrationCheckpointProof,
            materials: &V031MigrationCheckpointProof,
        ) -> V031BindingMaterialTerminalProof {
            fixture
                .manager
                .run_v031_case_material_migration_after_checkpoints(
                    &fixture.gate,
                    target,
                    binding,
                    materials,
                )
                .expect("production checkpoint-gated retry");
            let first = fixture
                .manager
                .v031_binding_material_terminal_proof_after_checkpoints(
                    &fixture.gate,
                    target,
                    binding,
                    materials,
                )
                .expect("first committed Step-5 terminal proof");
            let inventory = target_inventory(fixture);
            let repeated = fixture
                .manager
                .run_v031_case_material_migration_after_checkpoints(
                    &fixture.gate,
                    target,
                    binding,
                    materials,
                )
                .expect("second production checkpoint-gated retry");
            assert!(repeated.source_unchanged_verified);
            let second = fixture
                .manager
                .v031_binding_material_terminal_proof_after_checkpoints(
                    &fixture.gate,
                    target,
                    binding,
                    materials,
                )
                .expect("second committed Step-5 terminal proof");
            assert_eq!(second, first);
            assert_eq!(
                target_inventory(fixture),
                inventory,
                "a normal retry must not create a second binding, material, ledger, or event",
            );
            first
        }

        let before_transaction = V031Fixture::new(&[PROJECT_A, PROJECT_B]);
        let (target, binding, materials) = prepare_checkpoint_gated_writer(&before_transaction);
        let binding_before = binding.clone();
        let materials_before = materials.clone();
        let privacy = before_transaction
            .manager
            .open_raw_connection()
            .expect("Privacy v5 before transaction boundary");
        let privacy_v5_before = compute_privacy_v5_manifests_read_only(&privacy)
            .expect("exact Privacy v5 before transaction boundary");
        drop(privacy);
        let user_file_set_before =
            sqlite_file_set_bytes_for_test(&before_transaction.user_database_path);
        let privacy_file_set_before =
            sqlite_file_set_bytes_for_test(&before_transaction.manager.shared.database_path);
        let error = before_transaction
            .manager
            .run_v031_case_material_migration_after_checkpoints_with_failure(
                &before_transaction.gate,
                &target,
                &binding,
                &materials,
                BackfillFailurePoint::BeforeTransaction,
            )
            .expect_err("BeforeTransaction must stop before the first Privacy write");
        assert_eq!(error.code(), "v031_case_material_injected_failure");
        assert_eq!(binding, binding_before);
        assert_eq!(materials, materials_before);
        assert_eq!(
            sqlite_file_set_bytes_for_test(&before_transaction.user_database_path),
            user_file_set_before,
            "BeforeTransaction must preserve the complete User-v10 file set",
        );
        assert_eq!(
            sqlite_file_set_bytes_for_test(&before_transaction.manager.shared.database_path),
            privacy_file_set_before,
            "BeforeTransaction must preserve the complete Privacy-v5 file set",
        );
        let privacy = before_transaction
            .manager
            .open_raw_connection()
            .expect("Privacy v5 after BeforeTransaction");
        assert_eq!(
            compute_privacy_v5_manifests_read_only(&privacy)
                .expect("exact Privacy v5 after BeforeTransaction"),
            privacy_v5_before,
        );
        drop(privacy);
        assert_eq!(
            target_inventory(&before_transaction),
            (0, 0, 0, 0, 0, 0, 0, 0)
        );
        assert_eq!(
            database::validate_user_database_migration_source_read_only(
                &before_transaction.user_database_path,
            )
            .expect("User remains valid after BeforeTransaction"),
            ValidatedUserSourceSchema::V031V10,
            "User must remain the exact frozen v0.3.1 schema-10 source",
        );
        assert_production_retry_is_idempotent(&before_transaction, &target, &binding, &materials);

        for failure_point in [
            BackfillFailurePoint::AfterProjectBindings,
            BackfillFailurePoint::BeforeCommit,
        ] {
            let fixture = V031Fixture::new(&[PROJECT_A, PROJECT_B]);
            let (target, binding, materials) = prepare_checkpoint_gated_writer(&fixture);
            let user_before = sqlite_file_set_bytes_for_test(&fixture.user_database_path);
            let privacy = fixture
                .manager
                .open_raw_connection()
                .expect("Privacy v5 before rollback boundary");
            let privacy_v5_before = compute_privacy_v5_manifests_read_only(&privacy)
                .expect("exact Privacy v5 before rollback boundary");
            drop(privacy);

            let error = fixture
                .manager
                .run_v031_case_material_migration_after_checkpoints_with_failure(
                    &fixture.gate,
                    &target,
                    &binding,
                    &materials,
                    failure_point,
                )
                .expect_err("in-transaction Step-5 failure must roll back");
            assert_eq!(error.code(), "v031_case_material_injected_failure");
            assert_eq!(
                sqlite_file_set_bytes_for_test(&fixture.user_database_path),
                user_before,
                "the pinned User-v10 source must remain byte-for-byte read-only",
            );
            let privacy = fixture
                .manager
                .open_raw_connection()
                .expect("Privacy v5 rollback inspection");
            assert_eq!(
                compute_privacy_v5_manifests_read_only(&privacy)
                    .expect("rolled-back Privacy remains exact v5"),
                privacy_v5_before,
                "the complete Privacy transaction must roll back",
            );
            drop(privacy);
            assert_eq!(target_inventory(&fixture), (0, 0, 0, 0, 0, 0, 0, 0));
            assert_production_retry_is_idempotent(&fixture, &target, &binding, &materials);
        }

        let after_commit = V031Fixture::new(&[PROJECT_A, PROJECT_B]);
        let (target, binding, materials) = prepare_checkpoint_gated_writer(&after_commit);
        let user_before = sqlite_file_set_bytes_for_test(&after_commit.user_database_path);
        let error = after_commit
            .manager
            .run_v031_case_material_migration_after_checkpoints_with_failure(
                &after_commit.gate,
                &target,
                &binding,
                &materials,
                BackfillFailurePoint::AfterCommit,
            )
            .expect_err("AfterCommit must expose the committed-before-receipt window");
        assert_eq!(error.code(), "v031_case_material_injected_failure");
        assert_eq!(
            sqlite_file_set_bytes_for_test(&after_commit.user_database_path),
            user_before,
            "AfterCommit still leaves the User-v10 source byte-for-byte read-only",
        );
        let committed = after_commit
            .manager
            .v031_binding_material_terminal_proof_after_checkpoints(
                &after_commit.gate,
                &target,
                &binding,
                &materials,
            )
            .expect("committed rows expose a restart-safe proof for the receipt layer");
        assert_eq!(committed.binding_ledger_rows(), 2);
        assert_eq!(committed.material_ledger_rows(), 1);
        assert_eq!(committed.bindings_verified(), 2);
        let inventory_before_retry = target_inventory(&after_commit);
        assert_eq!(inventory_before_retry.0, 2);
        assert_eq!(inventory_before_retry.1, 2);
        assert_eq!(inventory_before_retry.2, 2);
        assert_eq!(inventory_before_retry.3, 2);
        let user_before_read_only_resume = sqlite_file_set_state(&after_commit.user_database_path);
        let privacy_before_read_only_resume =
            sqlite_file_set_state(&after_commit.manager.shared.database_path);
        let boundary_probe = after_commit
            .manager
            .run_v031_case_material_migration_after_checkpoints_with_failure(
                &after_commit.gate,
                &target,
                &binding,
                &materials,
                BackfillFailurePoint::BeforeTransaction,
            )
            .expect("terminal restart returns before the transaction boundary");
        assert!(boundary_probe.source_unchanged_verified);
        assert!(boundary_probe.idempotent_noops >= 3);
        let resume = after_commit
            .manager
            .run_v031_case_material_migration_after_checkpoints(
                &after_commit.gate,
                &target,
                &binding,
                &materials,
            )
            .expect("AfterCommit restart takes the read-only terminal branch");
        assert!(resume.source_unchanged_verified);
        assert!(resume.idempotent_noops >= 3);
        let retried = after_commit
            .manager
            .v031_binding_material_terminal_proof_after_checkpoints(
                &after_commit.gate,
                &target,
                &binding,
                &materials,
            )
            .expect("receipt layer can rebuild proof without reopening the writer");
        assert_eq!(retried, committed);
        assert_eq!(
            sqlite_file_set_state(&after_commit.user_database_path),
            user_before_read_only_resume,
            "the committed-before-Receipt5 resume must not touch User or its sidecars",
        );
        assert_eq!(
            sqlite_file_set_state(&after_commit.manager.shared.database_path),
            privacy_before_read_only_resume,
            "the committed-before-Receipt5 resume must not touch Privacy or its sidecars",
        );
        assert_eq!(target_inventory(&after_commit), inventory_before_retry);
    }

    #[test]
    fn empty_databases_finish_with_persistent_read_only_terminal_probe() {
        let fixture = Fixture::new(&[]);
        assert!(fixture
            .manager
            .case_material_migration_required()
            .expect("initial probe"));
        let user_before = fs::read(&fixture.user_database_path).expect("user bytes before");
        let report = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("empty migration");
        assert!(report.source_unchanged_verified);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("user bytes after"),
            user_before
        );

        let privacy_before =
            fs::read(&fixture.manager.shared.database_path).expect("privacy bytes before probe");
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("terminal probe"));
        assert_eq!(
            fs::read(&fixture.manager.shared.database_path).expect("privacy bytes after probe"),
            privacy_before,
            "the startup probe must be strictly read-only"
        );
    }

    #[test]
    fn unrelated_user_rows_do_not_change_semantic_source_or_repeat_migration() {
        let fixture = Fixture::new(&[PROJECT_A]);
        let fingerprint = fixture
            .manager
            .case_material_migration_source_fingerprint()
            .expect("initial semantic fingerprint");
        fixture
            .manager
            .run_case_material_migration_after_backup_for_source(&fingerprint)
            .expect("initial fingerprint-bound migration");
        fixture
            .user_connection()
            .execute(
                "INSERT INTO conversations(conversation_id,project_id,title,status)
                 VALUES('conversation-unrelated',NULL,'Unrelated assistant chat','open')",
                [],
            )
            .expect("insert unrelated assistant row");

        assert_eq!(
            fixture
                .manager
                .case_material_migration_source_fingerprint()
                .expect("fingerprint after unrelated write"),
            fingerprint
        );
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("unrelated write must not require migration"));
    }

    #[test]
    fn source_table_change_updates_semantic_fingerprint_and_rejects_stale_backup_token() {
        let fixture = Fixture::new(&[PROJECT_A]);
        let fingerprint = fixture
            .manager
            .case_material_migration_source_fingerprint()
            .expect("initial semantic fingerprint");
        fixture
            .user_connection()
            .execute(
                "UPDATE projects SET title='Changed migration source'
                 WHERE project_id=?1",
                [PROJECT_A],
            )
            .expect("change source table");
        let changed = fixture
            .manager
            .case_material_migration_source_fingerprint()
            .expect("changed semantic fingerprint");
        assert_ne!(changed, fingerprint);

        let error = fixture
            .manager
            .run_case_material_migration_after_backup_for_source(&fingerprint)
            .expect_err("stale backup source token must fail");
        assert_eq!(error.code(), "case_material_backup_source_mismatch");
        let privacy = fixture.manager.open_connection().expect("privacy store");
        assert_eq!(
            privacy
                .query_row(
                    "SELECT COUNT(*) FROM project_privacy_case_bindings",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("binding count"),
            0
        );
        assert_eq!(
            privacy
                .query_row(
                    "SELECT COUNT(*) FROM case_material_migration_ledger",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("ledger count"),
            0
        );
    }

    #[test]
    fn empty_privacy_rejects_existing_nonempty_vault_inventory_without_writes() {
        let directory = tempfile::tempdir().expect("empty Privacy inventory fixture");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("canonical user database");
        let user = database::open_user_database(&user_database_path).expect("open user database");
        insert_project(&user, PROJECT_A);
        drop(user);
        let vault_root = directory.path().join(vault_broker::VAULT_ROOT_DIRECTORY);
        let vault = VaultStore::initialize(&vault_root, test_workspace_instance_id())
            .expect("initialize existing Vault");
        let case_id =
            CaseId::parse("case_44444444444444444444444444444444").expect("synthetic Vault case");
        vault
            .create_source_object(
                &case_id,
                VaultPrivateMetadataInputV1 {
                    original_file_name: "unbound-existing.pdf".to_owned(),
                    original_source_path: None,
                    original_media_type: "application/pdf".to_owned(),
                    imported_at_unix: 100,
                },
                b"unbound existing Vault content",
                100,
            )
            .expect("create existing Vault inventory");
        vault
            .prepare_encrypted_backup_snapshot()
            .expect("checkpoint Vault inventory");
        drop(vault);
        let vault_database = vault_root.join("vault-state.sqlite");
        let before_database = fs::read(&vault_database).expect("Vault before startup probe");

        let manager =
            PrivacyWorkflowManager::new_for_application_startup_with_approved_publication_invalidator(
                directory.path().to_path_buf(),
                test_workspace_instance_id(),
                Arc::new(NoopPublicationInvalidator),
            )
            .expect("deferred manager");
        let error = manager
            .case_material_migration_required()
            .expect_err("unbound Vault inventory must fail closed");

        assert_eq!(error.code(), "case_material_unbound_vault_inventory");
        assert_eq!(
            fs::read(&vault_database).expect("Vault after startup probe"),
            before_database
        );
        assert!(!manager.shared.database_path.exists());
    }

    #[test]
    fn privacy_prepared_cleanup_blocks_migration_without_mutating_the_store() {
        let fixture = Fixture::new(&[]);
        let connection = fixture.manager.open_connection().expect("privacy store");
        connection
            .execute(
                "INSERT INTO privacy_cleanup_journal(
                    cleanup_id,state,policy_revision,started_at_unix,completed_at_unix,
                    candidate_count,removed_count,keys_destroyed,error_code,
                    previous_event_hash,event_hash,erasure_disclosure
                 ) VALUES(
                    'cln_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                    'prepared',1,100,NULL,0,0,0,NULL,'','',?1
                 )",
                [privacy::LOGICAL_ERASURE_DISCLOSURE],
            )
            .expect("insert pending privacy cleanup");
        drop(connection);
        let database = &fixture.manager.shared.database_path;
        let before = fs::read(database).expect("privacy bytes before blocked probe");
        let modified = fs::metadata(database)
            .expect("privacy metadata before blocked probe")
            .modified()
            .expect("privacy mtime before blocked probe");

        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("prepared privacy cleanup blocks migration");
        assert_eq!(error.code(), "case_material_cleanup_pending");
        assert_eq!(
            fs::read(database).expect("privacy bytes after blocked probe"),
            before
        );
        assert_eq!(
            fs::metadata(database)
                .expect("privacy metadata after blocked probe")
                .modified()
                .expect("privacy mtime after blocked probe"),
            modified
        );
    }

    #[test]
    fn vault_prepared_and_committed_cleanup_block_without_mutating_vault_database() {
        let fixture = Fixture::new(&[]);
        let vault_database = fixture
            .user_database_path
            .parent()
            .expect("application root")
            .join(vault_broker::VAULT_ROOT_DIRECTORY)
            .join("vault-state.sqlite");
        let connection = Connection::open(&vault_database).expect("vault fixture database");
        connection
            .execute(
                "INSERT INTO vault_cleanup_journal(
                    cleanup_id,state,started_at_unix,completed_at_unix,candidate_count,
                    removed_count,key_records_destroyed,previous_event_hash,event_hash,
                    erasure_disclosure
                 ) VALUES(
                    'cln_cccccccccccccccccccccccccccccccc',
                    'prepared',100,NULL,0,0,0,'','',?1
                 )",
                [privacy::VAULT_LOGICAL_ERASURE_DISCLOSURE],
            )
            .expect("insert prepared Vault cleanup");
        drop(connection);
        let prepared_bytes = fs::read(&vault_database).expect("prepared Vault bytes");
        let prepared_modified = fs::metadata(&vault_database)
            .expect("prepared Vault metadata")
            .modified()
            .expect("prepared Vault mtime");
        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("prepared Vault cleanup blocks migration");
        assert_eq!(error.code(), "case_material_cleanup_pending");
        assert_eq!(
            fs::read(&vault_database).expect("Vault bytes after prepared probe"),
            prepared_bytes
        );
        assert_eq!(
            fs::metadata(&vault_database)
                .expect("Vault metadata after prepared probe")
                .modified()
                .expect("Vault mtime after prepared probe"),
            prepared_modified
        );

        let connection = Connection::open(&vault_database).expect("Vault committed fixture");
        connection
            .execute(
                "UPDATE vault_cleanup_journal
                 SET state='committed',completed_at_unix=101
                 WHERE cleanup_id='cln_cccccccccccccccccccccccccccccccc'
                   AND state='prepared'",
                [],
            )
            .expect("mark Vault cleanup committed");
        drop(connection);
        let committed_bytes = fs::read(&vault_database).expect("committed Vault bytes");
        let committed_modified = fs::metadata(&vault_database)
            .expect("committed Vault metadata")
            .modified()
            .expect("committed Vault mtime");
        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("committed Vault cleanup blocks migration");
        assert_eq!(error.code(), "case_material_cleanup_pending");
        assert_eq!(
            fs::read(&vault_database).expect("Vault bytes after committed probe"),
            committed_bytes
        );
        assert_eq!(
            fs::metadata(&vault_database)
                .expect("Vault metadata after committed probe")
                .modified()
                .expect("Vault mtime after committed probe"),
            committed_modified
        );
    }

    #[test]
    fn projects_only_receive_distinct_random_persistent_bindings_and_rerun_is_noop() {
        let fixture = Fixture::new(&[PROJECT_A, PROJECT_B]);
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("projects-only migration");
        let connection = fixture.manager.open_connection().expect("privacy store");
        let project_a = ProjectId::parse(PROJECT_A).expect("project A");
        let project_b = ProjectId::parse(PROJECT_B).expect("project B");
        let case_a = ProjectPrivacyCaseBindingStore::resolve(&connection, &project_a)
            .expect("resolve A")
            .expect("binding A");
        let case_b = ProjectPrivacyCaseBindingStore::resolve(&connection, &project_b)
            .expect("resolve B")
            .expect("binding B");
        assert_ne!(case_a, case_b);
        assert!(case_a.as_str().starts_with("case_"));
        assert!(case_b.as_str().starts_with("case_"));
        drop(connection);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("completed probe"));

        let second = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("idempotent rerun");
        assert_eq!(second.bindings_created_or_verified, 0);
        assert!(second.idempotent_noops >= 3);
        let connection = fixture.manager.open_connection().expect("privacy store");
        assert_eq!(
            ProjectPrivacyCaseBindingStore::resolve(&connection, &project_a)
                .expect("resolve A again"),
            Some(case_a)
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM project_privacy_case_bindings",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("binding count"),
            2
        );
    }

    #[test]
    fn exact_attachment_and_legacy_case_files_migrate_without_copying_source_blob() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-exact",
            Some(PROJECT_A),
            "original-private-name.txt",
            b"exact attachment bytes",
        );
        fixture.add_case_file(
            "file-exact",
            PROJECT_A,
            "用户材料标题",
            "attachment:attachment:attachment-exact",
        );
        fixture.add_case_file(
            "file-legacy",
            PROJECT_A,
            "旧引用",
            r"C:\historical\never-read.txt",
        );
        let source_before = fs::read(&fixture.user_database_path).expect("source before");
        let report = fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("case-file migration");
        assert_eq!(report.case_files_migrated, 2);
        assert_eq!(report.legacy_references, 1);
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("source after"),
            source_before
        );

        let connection = fixture.manager.open_connection().expect("privacy store");
        let exact_id = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-exact",
        );
        let exact = connection
            .query_row(
                "SELECT project_id,attachment_id,source_kind,migration_status,state,source_sha256
                 FROM privacy_materials WHERE material_id=?1",
                [&exact_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .expect("exact target");
        assert_eq!(exact.0, PROJECT_A);
        assert_eq!(exact.1, "attachment-exact");
        assert_eq!(exact.2, "user_attachment");
        assert_eq!(exact.3, "ready");
        assert_eq!(exact.4, "registered");
        assert_eq!(exact.5, sha256_hex(b"exact attachment bytes"));

        let legacy_id = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-legacy",
        );
        let protected = connection
            .query_row(
                "SELECT reference.protected_storage_reference_blob
                 FROM case_material_legacy_references AS reference
                 JOIN privacy_materials AS material
                   ON material.material_id=reference.material_id
                 WHERE reference.material_id=?1
                   AND material.source_kind='legacy_reference'
                   AND material.migration_status='legacy_reference'",
                [&legacy_id],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("protected legacy provenance");
        assert_eq!(
            unprotect_local(&protected).expect("unprotect legacy provenance"),
            br"C:\historical\never-read.txt"
        );
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("case-file terminal probe"));
    }

    #[test]
    fn changed_case_file_appends_source_changed_event_and_updates_exact_projection() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-source-change",
            Some(PROJECT_A),
            "source-change.txt",
            b"stable source bytes",
        );
        fixture.add_case_file(
            "file-source-change",
            PROJECT_A,
            "初始标题",
            "attachment:attachment-source-change",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("initial migration");

        fixture.add_case_file(
            "file-source-change",
            PROJECT_A,
            "更新后的标题",
            "attachment:attachment-source-change",
        );
        assert!(fixture
            .manager
            .case_material_migration_required()
            .expect("changed source requires migration"));
        let source_before = fs::read(&fixture.user_database_path).expect("changed source before");
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("source-changed migration");
        assert_eq!(
            fs::read(&fixture.user_database_path).expect("changed source after"),
            source_before
        );

        let connection = fixture.manager.open_connection().expect("privacy store");
        let target = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-source-change",
        );
        let (event_type, material_id, protected_display_name, display_hash): (
            String,
            String,
            Vec<u8>,
            String,
        ) = connection
            .query_row(
                "SELECT event.event_type,material.material_id,material.protected_display_name,
                            material.display_name_sha256
                     FROM case_material_migration_events AS event
                     JOIN privacy_materials AS material
                       ON material.material_id=event.target_material_id
                     WHERE event.migration_id=?1 AND event.source_store=?2
                       AND event.source_table='case_files'
                       AND event.source_key='file-source-change'
                     ORDER BY event.rowid DESC LIMIT 1",
                params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("source-changed event");
        assert_eq!(event_type, "source_changed");
        assert_eq!(material_id, target);
        assert_eq!(
            unprotect_local(&protected_display_name).expect("updated protected display"),
            "更新后的标题".as_bytes()
        );
        assert_eq!(display_hash, sha256_hex("更新后的标题".as_bytes()));
        drop(connection);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("updated terminal probe"));
    }

    #[test]
    fn repeat_probe_fails_closed_when_exact_target_projection_drifts() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-target-drift",
            Some(PROJECT_A),
            "target-drift.txt",
            b"target drift bytes",
        );
        fixture.add_case_file(
            "file-target-drift",
            PROJECT_A,
            "目标漂移",
            "attachment:attachment-target-drift",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("initial migration");
        let target = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-target-drift",
        );
        fixture
            .manager
            .open_connection()
            .expect("privacy store")
            .execute(
                "UPDATE privacy_materials
                 SET display_name_sha256=?2,row_version=row_version+1
                 WHERE material_id=?1",
                params![target, sha256_hex(b"tampered display")],
            )
            .expect("tamper target projection");

        let error = fixture
            .manager
            .case_material_migration_required()
            .expect_err("target drift must fail closed");
        assert_eq!(error.code(), "case_material_migration_target_mismatch");
    }

    #[test]
    fn ambiguous_attachment_reference_is_blocked_without_guessing() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment:ambiguous",
            Some(PROJECT_A),
            "first.txt",
            b"first",
        );
        fixture.add_attachment("ambiguous", Some(PROJECT_A), "second.txt", b"second");
        fixture.add_case_file(
            "file-ambiguous",
            PROJECT_A,
            "歧义引用",
            "attachment:ambiguous",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("ambiguous migration is terminal, not fatal");
        let connection = fixture.manager.open_connection().expect("privacy store");
        let result = connection
            .query_row(
                "SELECT ledger.result_state,ledger.error_code,material.migration_status
                 FROM case_material_migration_ledger AS ledger
                 JOIN privacy_materials AS material
                   ON material.material_id=ledger.target_material_id
                 WHERE ledger.migration_id=?1 AND ledger.source_store=?2
                   AND ledger.source_table='case_files' AND ledger.source_key='file-ambiguous'",
                params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("blocked ledger");
        assert_eq!(
            result,
            (
                "blocked".to_owned(),
                "attachment_reference_ambiguous".to_owned(),
                "blocked".to_owned()
            )
        );
    }

    #[test]
    fn cross_project_and_ownerless_exact_attachments_are_blocked_with_stable_codes() {
        let fixture = Fixture::new(&[PROJECT_A, PROJECT_B]);
        fixture.add_attachment(
            "attachment-cross-project",
            Some(PROJECT_B),
            "cross-project.txt",
            b"cross project",
        );
        fixture.add_attachment("attachment-ownerless", None, "ownerless.txt", b"ownerless");
        fixture.add_case_file(
            "file-cross-project",
            PROJECT_A,
            "跨项目附件",
            "attachment:attachment-cross-project",
        );
        fixture.add_case_file(
            "file-ownerless",
            PROJECT_A,
            "无归属附件",
            "attachment:attachment-ownerless",
        );
        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("ownership conflicts are terminal blocked rows");
        let connection = fixture.manager.open_connection().expect("privacy store");
        let mut statement = connection
            .prepare(
                "SELECT source_key,error_code,result_state
                 FROM case_material_migration_ledger
                 WHERE migration_id=?1 AND source_store=?2
                   AND source_table='case_files'
                 ORDER BY source_key",
            )
            .expect("ownership ledgers");
        let rows = statement
            .query_map(
                params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("query ownership ledgers")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect ownership ledgers");
        assert_eq!(
            rows,
            vec![
                (
                    "file-cross-project".to_owned(),
                    "attachment_project_conflict".to_owned(),
                    "blocked".to_owned()
                ),
                (
                    "file-ownerless".to_owned(),
                    "attachment_owner_unknown".to_owned(),
                    "blocked".to_owned()
                ),
            ]
        );
        drop(statement);
        drop(connection);
        assert!(!fixture
            .manager
            .case_material_migration_required()
            .expect("blocked ownership terminal probe"));
    }

    #[test]
    fn valid_v4_history_is_upgraded_only_explicitly_then_backfilled_with_stable_generation() {
        let directory = tempfile::tempdir().expect("legacy fixture");
        let user_database_path =
            database::ensure_user_database(directory.path()).expect("user database");
        let privacy_directory = directory.path().join("privacy");
        fs::create_dir_all(&privacy_directory).expect("privacy directory");
        let privacy_path = privacy_directory.join("privacy-workflow.sqlite");
        create_valid_v4_history(&privacy_path);

        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("legacy-compatible manager");
        assert!(manager.privacy_store_schema_upgrade_required());
        assert!(manager
            .case_material_migration_required()
            .expect("v4 requires migration"));
        let unchanged_version: String = Connection::open(&privacy_path)
            .expect("legacy database")
            .query_row(
                "SELECT value FROM privacy_schema_metadata WHERE key='schema_version'",
                [],
                |row| row.get(0),
            )
            .expect("legacy version");
        assert_eq!(unchanged_version, "4");

        manager
            .upgrade_privacy_store_schema_after_backup()
            .expect("explicit post-backup upgrade");
        let user_before = fs::read(&user_database_path).expect("user source before");
        manager
            .run_case_material_migration_after_backup()
            .expect("valid history backfill");
        complete_approved_projection_migration(&manager);
        assert_eq!(
            fs::read(&user_database_path).expect("user source after"),
            user_before
        );
        let connection = manager.open_connection().expect("upgraded privacy store");
        let material = connection
            .query_row(
                "SELECT project_id,legacy_case_id,migration_status,display_name_sha256
                 FROM privacy_materials WHERE material_id='mat_legacyvalid00000000000000000000'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .expect("legacy material");
        assert_eq!(material.0, None);
        assert_eq!(
            material.1.as_deref(),
            Some("case_99999999999999999999999999999999")
        );
        assert_eq!(material.2, "unassigned");
        assert_eq!(
            material.3.as_deref(),
            Some(sha256_hex("历史材料.pdf".as_bytes()).as_str())
        );
        let generation = connection
            .query_row(
                "SELECT generation_number,generation_status,risk_revision
                 FROM privacy_redactions
                 WHERE redaction_id='red_11111111111111111111111111111111'",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("legacy generation");
        assert_eq!(generation, (1, "ready".to_owned(), 0));
        drop(connection);
        assert!(!manager
            .case_material_migration_required()
            .expect("legacy orphan identity is a terminal no-op"));
        let connection = manager.open_connection().expect("privacy store");
        assert!(connection
            .execute(
                "UPDATE privacy_materials
                 SET legacy_case_id=?2,row_version=row_version+1
                 WHERE material_id=?1",
                params![
                    "mat_legacyvalid00000000000000000000",
                    format!("case_{}", "8".repeat(32))
                ],
            )
            .is_err());
        drop(connection);
        assert!(!manager
            .case_material_migration_required()
            .expect("blocked tamper preserves terminal state"));
    }

    #[test]
    fn committed_retention_cleanup_is_a_read_only_noop_and_tamper_fails_closed() {
        let directory = tempfile::tempdir().expect("retention migration fixture");
        let _user_database_path =
            database::ensure_user_database(directory.path()).expect("user database");
        let privacy_directory = directory.path().join("privacy");
        fs::create_dir_all(&privacy_directory).expect("privacy directory");
        let privacy_path = privacy_directory.join("privacy-workflow.sqlite");
        create_valid_v4_history(&privacy_path);
        let manager = PrivacyWorkflowManager::new(
            directory.path().to_path_buf(),
            test_workspace_instance_id(),
        )
        .expect("legacy-compatible manager");
        manager
            .upgrade_privacy_store_schema_after_backup()
            .expect("upgrade retention fixture");
        manager
            .run_case_material_migration_after_backup()
            .expect("migrate retention fixture");
        complete_approved_projection_migration(&manager);

        let mut connection = manager.open_connection().expect("privacy store");
        let lifecycle =
            PrivacyLifecycle::open(&connection, test_workspace_instance_id()).expect("lifecycle");
        let current = lifecycle.retention_policy(&connection).expect("policy");
        lifecycle
            .set_retention_policy(
                &mut connection,
                &RetentionPolicyV1 {
                    policy_id: "migration-retention-test".to_owned(),
                    review_retention_seconds: 10,
                    mapping_retention_seconds: 10,
                    receipt_grace_seconds: 0,
                    backup_retention_seconds: 20,
                    revision: current.revision + 1,
                    updated_at_unix: 1_900_000_000,
                },
            )
            .expect("short retention policy");
        lifecycle
            .bind_redaction_retention(
                &connection,
                "red_11111111111111111111111111111111",
                1_900_000_001,
            )
            .expect("bind migrated generation");
        let ledger_before: (i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM case_material_migration_ledger),
                    (SELECT COUNT(*) FROM case_material_migration_events)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("migration evidence before retention");
        let cleanup_id = "cln_cccccccccccccccccccccccccccccccc";
        lifecycle
            .run_retention_sweep(&mut connection, cleanup_id, 1_900_000_020)
            .expect("commit migrated retention cleanup");
        let tombstone = connection
            .query_row(
                "SELECT legacy_case_id,source_kind,state,deleted_at IS NOT NULL,
                        protected_display_name,display_name_sha256,
                        display_name_protection_scheme
                 FROM privacy_materials
                 WHERE material_id='mat_legacyvalid00000000000000000000'",
                [],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, bool>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .expect("retention tombstone");
        assert_eq!(
            tombstone.0.as_deref(),
            Some("case_99999999999999999999999999999999")
        );
        assert_eq!(tombstone.1, "local_review");
        assert_eq!(tombstone.2, "revoked");
        assert!(tombstone.3);
        assert_eq!((tombstone.4, tombstone.5, tombstone.6), (None, None, None));
        assert!(connection
            .execute(
                "UPDATE privacy_cleanup_candidates SET expected_sha256=?2
                 WHERE cleanup_id=?1 AND target_kind='redaction'",
                params![cleanup_id, sha256_hex(b"blocked candidate tamper")],
            )
            .is_err());
        drop(connection);

        assert!(!manager
            .case_material_migration_required()
            .expect("authorized retention is a terminal read-only no-op"));
        let connection = manager.open_connection().expect("privacy after probe");
        assert_eq!(
            connection
                .query_row(
                    "SELECT
                        (SELECT COUNT(*) FROM case_material_migration_ledger),
                        (SELECT COUNT(*) FROM case_material_migration_events)",
                    [],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
                )
                .expect("migration evidence after retention probe"),
            ledger_before
        );
        connection
            .execute_batch(
                "DROP TRIGGER trg_privacy_cleanup_candidate_one_way;
                 UPDATE privacy_cleanup_candidates
                 SET expected_sha256='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                 WHERE cleanup_id='cln_cccccccccccccccccccccccccccccccc'
                   AND target_kind='redaction';",
            )
            .expect("simulate storage-level cleanup evidence tamper");
        drop(connection);
        let error = manager
            .case_material_migration_required()
            .expect_err("tampered cleanup evidence must fail closed");
        assert_eq!(error.code(), "case_material_migration_target_mismatch");
    }

    #[test]
    fn retention_then_project_deletion_preserves_historical_provenance_and_restarts_noop() {
        exercise_project_deletion_retention_order(true, false);
    }

    #[test]
    fn project_deletion_then_retention_preserves_scope_and_rejects_provenance_drift() {
        exercise_project_deletion_retention_order(false, true);
    }

    #[test]
    fn project_with_unbound_privacy_state_records_stable_terminal_blocked_binding() {
        let fixture = Fixture::new(&[PROJECT_A]);
        let user_connection = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("read user database");
        let user = UserSnapshot::load(&user_connection).expect("load user snapshot");
        let source = user.projects.get(PROJECT_A).expect("project source");
        let blocked_projects = BTreeSet::from([PROJECT_A.to_owned()]);
        let mut connection = fixture.manager.open_connection().expect("privacy database");
        let mut first_report = CaseMaterialMigrationReport::default();
        let transaction = connection.transaction().expect("privacy transaction");
        create_bindings_for_projects_without_privacy_state(
            &transaction,
            &user,
            &[],
            &blocked_projects,
            &mut first_report,
        )
        .expect("record terminal blocked binding");
        transaction.commit().expect("commit terminal binding");
        assert_eq!(first_report.blocked, 1);
        assert!(project_binding_terminal_matches(&connection, source, None)
            .expect("terminal blocked binding satisfies the project probe"));

        let terminal = connection
            .query_row(
                "SELECT result_state,error_code
                 FROM case_material_migration_ledger
                 WHERE migration_id=?1 AND source_store=?2
                   AND source_table='projects' AND source_key=?3",
                params![
                    PROJECT_CASE_BINDING_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    PROJECT_A
                ],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .expect("project binding terminal ledger");
        assert_eq!(
            terminal,
            (
                "blocked".to_owned(),
                Some("project_privacy_case_unbound".to_owned())
            )
        );
        let before_counts = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3),
                    (SELECT COUNT(*) FROM case_material_migration_events
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3)",
                params![
                    PROJECT_CASE_BINDING_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    PROJECT_A
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("project binding evidence counts");

        let mut second_report = CaseMaterialMigrationReport::default();
        let transaction = connection
            .transaction()
            .expect("repeat privacy transaction");
        create_bindings_for_projects_without_privacy_state(
            &transaction,
            &user,
            &[],
            &blocked_projects,
            &mut second_report,
        )
        .expect("repeat terminal blocked binding");
        transaction.commit().expect("commit idempotent repeat");
        assert_eq!(second_report.idempotent_noops, 1);
        let after_counts = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3),
                    (SELECT COUNT(*) FROM case_material_migration_events
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='projects' AND source_key=?3)",
                params![
                    PROJECT_CASE_BINDING_MIGRATION_ID,
                    SOURCE_STORE_USER,
                    PROJECT_A
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("stable project binding evidence counts");
        assert_eq!(after_counts, before_counts);
    }

    #[test]
    fn target_without_ledger_is_adopted_as_interrupted_recovery() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-recovery",
            Some(PROJECT_A),
            "recovery.txt",
            b"recovery",
        );
        fixture.add_case_file(
            "file-recovery",
            PROJECT_A,
            "恢复材料",
            "attachment:attachment-recovery",
        );
        let user = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("read user snapshot");
        let snapshot = UserSnapshot::load(&user).expect("load source snapshot");
        let case_file = snapshot
            .case_files
            .iter()
            .find(|source| source.file_id == "file-recovery")
            .expect("recovery case file");
        let attachment = match snapshot.resolve_attachment(case_file) {
            AttachmentResolution::Exact(attachment) => attachment,
            _ => panic!("fixture must resolve exactly"),
        };
        let target = deterministic_case_file_material_id(
            test_workspace_instance_id().as_str(),
            "file-recovery",
        );
        let mut privacy = fixture.manager.open_connection().expect("privacy store");
        let transaction = privacy
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .expect("target transaction");
        ensure_user_attachment_target(&transaction, case_file, attachment, &target)
            .expect("simulate committed target");
        transaction.commit().expect("commit target without ledger");
        drop(privacy);

        fixture
            .manager
            .run_case_material_migration_after_backup()
            .expect("recover interrupted target");
        let connection = fixture.manager.open_connection().expect("privacy store");
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM privacy_materials WHERE material_id=?1",
                    [&target],
                    |row| row.get::<_, i64>(0),
                )
                .expect("target count"),
            1
        );
        assert_eq!(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM case_material_migration_ledger
                     WHERE migration_id=?1 AND source_store=?2
                       AND source_table='case_files' AND source_key='file-recovery'",
                    params![CASE_MATERIAL_MIGRATION_ID, SOURCE_STORE_USER],
                    |row| row.get::<_, i64>(0),
                )
                .expect("recovered ledger"),
            1
        );
    }

    #[test]
    fn changed_source_proof_rolls_back_the_complete_target_transaction() {
        let fixture = Fixture::new(&[PROJECT_A]);
        fixture.add_attachment(
            "attachment-proof-rollback",
            Some(PROJECT_A),
            "proof-rollback.txt",
            b"proof rollback",
        );
        fixture.add_case_file(
            "file-proof-rollback",
            PROJECT_A,
            "旧快照标题",
            "attachment:attachment-proof-rollback",
        );

        let stale_user = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("stale read-only source");
        stale_user
            .execute_batch("BEGIN DEFERRED TRANSACTION")
            .expect("stale source transaction");
        let stale_proof = SourceProof::capture(&fixture.user_database_path, &stale_user)
            .expect("stale source proof");
        let stale_snapshot = UserSnapshot::load(&stale_user).expect("stale source snapshot");
        stale_user
            .execute_batch("ROLLBACK")
            .expect("close stale source transaction");
        drop(stale_user);

        fixture.add_case_file(
            "file-proof-rollback",
            PROJECT_A,
            "并发更新标题",
            "attachment:attachment-proof-rollback",
        );
        let current_user = database::open_user_database_read_only(&fixture.user_database_path)
            .expect("current read-only source");
        current_user
            .execute_batch("BEGIN DEFERRED TRANSACTION")
            .expect("current source transaction");
        let mut privacy = fixture.manager.open_connection().expect("privacy store");
        let error = run_backfill(
            &fixture.manager,
            &mut privacy,
            &current_user,
            &fixture.user_database_path,
            &stale_proof,
            &stale_snapshot,
            &test_workspace_instance_id(),
        )
        .expect_err("stale source proof must roll back the target transaction");
        assert_eq!(error.code(), "case_material_source_changed");
        current_user
            .execute_batch("ROLLBACK")
            .expect("close current source transaction");
        drop(privacy);

        let connection = fixture.manager.open_connection().expect("privacy store");
        let counts: (i64, i64, i64, i64) = connection
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM project_privacy_case_bindings),
                    (SELECT COUNT(*) FROM project_privacy_case_binding_audit),
                    (SELECT COUNT(*) FROM case_material_migration_ledger),
                    (SELECT COUNT(*) FROM privacy_materials)",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("rolled-back target counts");
        assert_eq!(counts, (0, 0, 0, 0));
    }

    fn create_valid_v4_history(path: &Path) {
        let source_sha256 = sha256_hex(b"legacy source");
        let extraction_sha256 = sha256_hex(b"legacy extraction");
        let redacted_sha256 = sha256_hex(b"legacy redacted");
        let payload = serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "materialId": "mat_legacyvalid00000000000000000000",
            "redactionId": "red_11111111111111111111111111111111",
            "caseId": "case_99999999999999999999999999999999",
            "sourceDisplayName": "历史材料.pdf",
            "sourceSha256": source_sha256,
            "extractionSha256": extraction_sha256,
            "suggestedRedactedContentSha256": redacted_sha256,
            "processingVersion": "legacy-v1",
            "mediaType": "application/pdf",
            "pageCount": 0,
            "inputTransform": null,
            "backendTrace": [],
            "summary": {
                "total": 0,
                "counts": {},
                "changed": false,
                "manualReviewRequired": false,
                "redactionVersion": "legacy-v1"
            },
            "forbiddenCanaries": [],
            "pages": []
        }))
        .expect("serialize legacy payload");
        let protected = protect_local(&payload).expect("protect legacy payload");
        let connection = Connection::open(path).expect("legacy privacy database");
        connection
            .execute_batch(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE privacy_schema_metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );
                 INSERT INTO privacy_schema_metadata(key,value) VALUES('schema_version','4');
                 CREATE TABLE privacy_materials(
                    material_id TEXT PRIMARY KEY,project_id TEXT,attachment_id TEXT,
                    source_sha256 TEXT NOT NULL,source_name_sha256 TEXT NOT NULL,
                    media_type TEXT NOT NULL,page_count INTEGER,state TEXT NOT NULL,
                    created_at TEXT NOT NULL,updated_at TEXT NOT NULL
                 );
                 CREATE TABLE privacy_redactions(
                    redaction_id TEXT PRIMARY KEY,material_id TEXT NOT NULL,
                    extraction_sha256 TEXT NOT NULL,redacted_content_sha256 TEXT NOT NULL,
                    approved_payload_sha256 TEXT,policy_id TEXT NOT NULL,
                    policy_version INTEGER NOT NULL,detector_version TEXT NOT NULL,
                    unresolved_high_risk_count INTEGER NOT NULL,review_state TEXT NOT NULL,
                    protected_review_blob BLOB NOT NULL,protection_scheme TEXT NOT NULL,
                    reviewed_by_sha256 TEXT,created_at TEXT NOT NULL,reviewed_at TEXT,
                    FOREIGN KEY(material_id) REFERENCES privacy_materials(material_id)
                 );",
            )
            .expect("legacy schema");
        connection
            .execute(
                "INSERT INTO privacy_materials(
                    material_id,project_id,attachment_id,source_sha256,source_name_sha256,
                    media_type,page_count,state,created_at,updated_at
                 ) VALUES(?1,NULL,NULL,?2,?3,'application/pdf',0,'review_required',
                          '2025-01-01 00:00:00','2025-01-01 00:00:00')",
                params![
                    "mat_legacyvalid00000000000000000000",
                    source_sha256,
                    sha256_hex("历史材料.pdf".as_bytes())
                ],
            )
            .expect("legacy material");
        connection
            .execute(
                "INSERT INTO privacy_redactions(
                    redaction_id,material_id,extraction_sha256,redacted_content_sha256,
                    approved_payload_sha256,policy_id,policy_version,detector_version,
                    unresolved_high_risk_count,review_state,protected_review_blob,
                    protection_scheme,reviewed_by_sha256,created_at,reviewed_at
                 ) VALUES(?1,?2,?3,?4,NULL,'policy',1,'detector',0,'review_required',
                          ?5,?6,NULL,'2025-01-01 00:00:00',NULL)",
                params![
                    "red_11111111111111111111111111111111",
                    "mat_legacyvalid00000000000000000000",
                    extraction_sha256,
                    redacted_sha256,
                    protected,
                    LOCAL_PROTECTION_SCHEME,
                ],
            )
            .expect("legacy redaction");
    }
}
