//! R3 authenticated v0.3.1 migration recovery.
//!
//! Staging is the only ordinary-application entry. Applying is startup-only,
//! manager-free, owns the fixed application-restore slots, and exits without
//! allowing ordinary initialization.

use super::{
    application_backup::{
        acquire_v031_recovery_user_database_write_barrier,
        build_and_install_v031_recovery_safety_backup, capture_v031_recovery_active_fingerprints,
        capture_v031_recovery_slot_fingerprint, reject_unknown_v031_recovery_restore_siblings,
        remove_v031_recovery_approved_parent_if_empty, remove_v031_recovery_auxiliary_directory,
        remove_v031_recovery_component, rename_v031_recovery_component_no_replace,
        v031_recovery_path_is_present, v031_recovery_swap_paths,
        verify_v031_recovery_safety_backup_read_only, write_v031_recovery_database_incoming,
        V031RecoveryComponent, V031RecoverySafetyBackupProof, V031RecoverySlotFingerprint,
        V031RecoverySwapPaths,
    },
    original_migration_backup::{
        open_authenticated_original_v2_images_for_recovery, AuthenticatedOriginalV2Images,
    },
    privacy_workflow::IpcError,
};
use crate::{
    approved_mcp::{
        advance_v031_recovery_approved_mcp_credential_delete_prefix,
        authenticate_v031_recovery_approved_mcp_credentials_read_only,
        capture_v031_recovery_approved_mcp_credentials_read_only,
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only,
        restore_v031_recovery_approved_mcp_credentials_exact, ApprovedMcpWorkspace,
        V031ApprovedMcpCredentialSnapshot,
    },
    privacy_manager,
    privacy_workflow::PrivacyWorkflowManager,
    state::AppState,
    v031_startup,
    v031_upgrade_r2::{self, DirectorySync, PlatformDirectorySync, V031_MIGRATION_ID},
};
use privacy::{
    protect_local, sha256_hex, unprotect_local,
    vnext::{canonical_json_v1, strict_json_v1_from_slice},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tauri::{Manager, State};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) const V031_MIGRATION_RECOVERY_MARKER: &str = "v031-migration-recovery-pending.dpapi";
const V031_MIGRATION_RECOVERY_MARKER_INCOMING: &str =
    "v031-migration-recovery-pending.dpapi.incoming";
const V031_MIGRATION_RECOVERY_MARKER_STAGING: &str =
    "v031-migration-recovery-pending.dpapi.incoming.staging";
const RECOVERY_AUDIT_DIRECTORY: &str = "v031-migration-recovery-audit";
const SAFETY_BACKUP_BASENAME: &str = "current-v040-safety-v3.lavbackup";
const CREDENTIAL_ARCHIVE_BASENAME: &str = "current-v040-credentials.dpapi";
const COMMIT_EVIDENCE_BASENAME: &str = "five-slot-commit.evidence.dpapi";
const ABORT_INTENT_BASENAME: &str = "abort-to-current.evidence.dpapi";
const APPLIED_REPORT_BASENAME: &str = "applied-downgrade.report.dpapi";
const ABORTED_REPORT_BASENAME: &str = "aborted-current-restored.report.dpapi";
const MARKER_SCHEMA: &str = "lawyer-assistance-v031-migration-recovery-pending-v1";
const AUDIT_EVIDENCE_SCHEMA: &str = "lawyer-assistance-v031-migration-recovery-audit-v1";
const MARKER_FORMAT_VERSION: u64 = 1;
const MAX_MARKER_BYTES: usize = 64 * 1024;
const MAX_CREDENTIAL_ARCHIVE_BYTES: usize = 64 * 1024;
const MAX_AUDIT_EVIDENCE_BYTES: usize = 64 * 1024;
const CREATOR_APP_VERSION: &str = "0.4.0";
pub(crate) const TARGET_APP_VERSION: &str = "0.3.1";
pub const V031_MIGRATION_RECOVERY_CONFIRMATION: &str = "恢复到 v0.3.1 并退出当前应用";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageV031MigrationRecoveryRequest {
    confirmation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryPhase {
    Requested,
    UserV10Staged,
    SourcesStaged,
    CommitReady,
    UserMovedToRollback,
    UserInstalled,
    PrivacyMovedToRollback,
    PrivacyInstalled,
    VaultMovedToRollback,
    ApprovedMovedToRollback,
    WorkProductsMovedToRollback,
    FiveSlotCommitted,
    WorkProductsRollbackCleaned,
    ApprovedRollbackCleaned,
    VaultRollbackCleaned,
    PrivacyRollbackCleaned,
    UserRollbackCleaned,
    TicketSessionsCleaned,
    QualificationCleaned,
    CredentialQualificationDeleted,
    CredentialTicketDeleted,
    CredentialWorkProductDeleted,
    CredentialApprovedDeleted,
    TargetVerified,
    ReportInstalled,
}

impl RecoveryPhase {
    const fn ordinal(self) -> u8 {
        self as u8
    }

    const fn is_precommit(self) -> bool {
        self.ordinal() < Self::FiveSlotCommitted.ordinal()
    }

    const fn successor(self) -> Option<Self> {
        Some(match self {
            Self::Requested => Self::UserV10Staged,
            Self::UserV10Staged => Self::SourcesStaged,
            Self::SourcesStaged => Self::CommitReady,
            Self::CommitReady => Self::UserMovedToRollback,
            Self::UserMovedToRollback => Self::UserInstalled,
            Self::UserInstalled => Self::PrivacyMovedToRollback,
            Self::PrivacyMovedToRollback => Self::PrivacyInstalled,
            Self::PrivacyInstalled => Self::VaultMovedToRollback,
            Self::VaultMovedToRollback => Self::ApprovedMovedToRollback,
            Self::ApprovedMovedToRollback => Self::WorkProductsMovedToRollback,
            Self::WorkProductsMovedToRollback => Self::FiveSlotCommitted,
            Self::FiveSlotCommitted => Self::WorkProductsRollbackCleaned,
            Self::WorkProductsRollbackCleaned => Self::ApprovedRollbackCleaned,
            Self::ApprovedRollbackCleaned => Self::VaultRollbackCleaned,
            Self::VaultRollbackCleaned => Self::PrivacyRollbackCleaned,
            Self::PrivacyRollbackCleaned => Self::UserRollbackCleaned,
            Self::UserRollbackCleaned => Self::TicketSessionsCleaned,
            Self::TicketSessionsCleaned => Self::QualificationCleaned,
            Self::QualificationCleaned => Self::CredentialQualificationDeleted,
            Self::CredentialQualificationDeleted => Self::CredentialTicketDeleted,
            Self::CredentialTicketDeleted => Self::CredentialWorkProductDeleted,
            Self::CredentialWorkProductDeleted => Self::CredentialApprovedDeleted,
            Self::CredentialApprovedDeleted => Self::TargetVerified,
            Self::TargetVerified => Self::ReportInstalled,
            Self::ReportInstalled => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CredentialArchiveProof {
    basename: String,
    protected_sha256: String,
    protected_bytes: u64,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct V031MigrationRecoveryPendingV1 {
    schema: String,
    format_version: u64,
    migration_id: String,
    recovery_id: String,
    lineage_id: String,
    envelope_binding_id: String,
    source_profile_proof_sha256: String,
    creator_app_version: String,
    target_app_version: String,
    created_at_unix: u64,
    receipt_nine_protected_sha256: String,
    receipt_nine_evidence_sha256: String,
    step8_predecessor_protected_sha256: String,
    upgrade_complete_sidecar_protected_sha256: String,
    original_identity_protected_sha256: String,
    original_identity_protected_bytes: u64,
    original_bundle_sha256: String,
    original_bundle_bytes: u64,
    original_user_sha256: String,
    original_user_bytes: u64,
    original_privacy_sha256: String,
    original_privacy_bytes: u64,
    workspace_instance_id: String,
    current_five_slot_manifest_sha256: String,
    current_slots: [V031RecoverySlotFingerprint; 5],
    safety_backup: V031RecoverySafetyBackupProof,
    credential_archive: CredentialArchiveProof,
    slot_count: u64,
    phase: RecoveryPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    commit_evidence_protected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    report_protected_sha256: Option<String>,
}

impl std::fmt::Debug for V031MigrationRecoveryPendingV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("V031MigrationRecoveryPendingV1")
            .field("schema", &self.schema)
            .field("format_version", &self.format_version)
            .field("creator_app_version", &self.creator_app_version)
            .field("target_app_version", &self.target_app_version)
            .field("phase", &self.phase)
            .field("slot_count", &self.slot_count)
            .field("identifiers", &"<redacted>")
            .field("paths", &"<fixed-basenames>")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AuditEvidenceKind {
    FiveSlotCommit,
    AbortToCurrent,
    AppliedDowngrade,
    AbortedCurrentRestored,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryAuditSlotV1 {
    component: V031RecoveryComponent,
    active: Option<V031RecoverySlotFingerprint>,
    incoming: Option<V031RecoverySlotFingerprint>,
    rollback: Option<V031RecoverySlotFingerprint>,
    cleanup: Option<V031RecoverySlotFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryAuditEvidenceV1 {
    schema: String,
    format_version: u64,
    kind: AuditEvidenceKind,
    recovery_id: String,
    migration_id: String,
    lineage_id: String,
    source_profile_proof_sha256: String,
    safety_backup_sha256: String,
    credential_archive_sha256: String,
    current_five_slot_manifest_sha256: String,
    target_app_version: String,
    marker_phase: RecoveryPhase,
    stage_slot_inventory_sha256: String,
    physical_slots: [RecoveryAuditSlotV1; 5],
    credential_delete_prefix: u64,
    commit_evidence_authenticated_absent: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MarkerInstallState {
    Final,
    ReplaceFinalWithIncoming,
    DiscardIncomingForAbort,
}

#[derive(Debug, Clone, Copy)]
struct ObservedMarkerInstallProof<'a> {
    marker: &'a V031MigrationRecoveryPendingV1,
    marker_protected_sha256: &'a str,
    predecessor_marker_protected_sha256: Option<&'a str>,
    successor_marker_protected_sha256: Option<&'a str>,
    marker_install_state: MarkerInstallState,
}

#[derive(Debug, Clone, Copy)]
enum AbortMarkerExpectation<'a> {
    Observed(ObservedMarkerInstallProof<'a>),
    ForwardError(&'a V031MigrationRecoveryPendingV1),
}

#[derive(Debug)]
struct AuthenticatedAbortMarkerSuccessor {
    marker: V031MigrationRecoveryPendingV1,
    protected_sha256: String,
}

#[derive(Debug)]
struct AuthenticatedAbortMarkerAuthority {
    formal_marker: V031MigrationRecoveryPendingV1,
    formal_protected_sha256: String,
    successor: Option<AuthenticatedAbortMarkerSuccessor>,
}

pub(crate) struct V031MigrationRecoveryGate {
    marker: V031MigrationRecoveryPendingV1,
    marker_protected_sha256: String,
    predecessor_marker_protected_sha256: Option<String>,
    successor_marker_protected_sha256: Option<String>,
    marker_install_state: MarkerInstallState,
    physical_phase: RecoveryPhase,
    abort_requested: bool,
    original: AuthenticatedOriginalV2Images,
    credentials: V031ApprovedMcpCredentialSnapshot,
}

impl V031MigrationRecoveryGate {
    fn marker_install_proof(&self) -> ObservedMarkerInstallProof<'_> {
        ObservedMarkerInstallProof {
            marker: &self.marker,
            marker_protected_sha256: &self.marker_protected_sha256,
            predecessor_marker_protected_sha256: self
                .predecessor_marker_protected_sha256
                .as_deref(),
            successor_marker_protected_sha256: self.successor_marker_protected_sha256.as_deref(),
            marker_install_state: self.marker_install_state,
        }
    }
}

impl std::fmt::Debug for V031MigrationRecoveryGate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("V031MigrationRecoveryGate")
            .field("phase", &self.marker.phase)
            .field("marker_proof", &"<authenticated>")
            .field("physical_phase", &self.physical_phase)
            .field("marker_install_state", &self.marker_install_state)
            .field("abort_requested", &self.abort_requested)
            .field("authority", &"<authenticated>")
            .finish()
    }
}

pub(crate) enum V031MigrationRecoveryObservation {
    Absent,
    Authenticated(Box<V031MigrationRecoveryGate>),
}

#[derive(Debug)]
pub(crate) struct AppliedDowngrade {
    target_app_version: &'static str,
}

impl AppliedDowngrade {
    pub(crate) const fn target_app_version(&self) -> &'static str {
        self.target_app_version
    }
}

fn recovery_error(error_type: &str, message: &str) -> IpcError {
    IpcError {
        error_type: error_type.to_owned(),
        message: message.to_owned(),
    }
}

fn invalid_recovery() -> IpcError {
    recovery_error(
        "v031_migration_recovery_invalid",
        "The authenticated v0.3.1 migration recovery state is invalid.",
    )
}

fn io_recovery() -> IpcError {
    recovery_error(
        "v031_migration_recovery_io",
        "The authenticated v0.3.1 migration recovery evidence could not be persisted.",
    )
}

fn unix_now() -> Result<u64, IpcError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| invalid_recovery())
}

fn marker_paths(app_local_data_dir: &Path) -> (PathBuf, PathBuf) {
    (
        app_local_data_dir.join(V031_MIGRATION_RECOVERY_MARKER),
        app_local_data_dir.join(V031_MIGRATION_RECOVERY_MARKER_INCOMING),
    )
}

fn marker_staging_path(app_local_data_dir: &Path) -> PathBuf {
    app_local_data_dir.join(V031_MIGRATION_RECOVERY_MARKER_STAGING)
}

fn audit_directory(app_local_data_dir: &Path, recovery_id: &str) -> Result<PathBuf, IpcError> {
    if !valid_recovery_id(recovery_id) {
        return Err(invalid_recovery());
    }
    Ok(app_local_data_dir
        .join(RECOVERY_AUDIT_DIRECTORY)
        .join(recovery_id))
}

fn valid_recovery_id(value: &str) -> bool {
    value.strip_prefix("rcv_").is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sync_directory(path: &Path) -> Result<(), IpcError> {
    PlatformDirectorySync
        .sync_directory(path)
        .map_err(|_| io_recovery())
}

fn create_audit_directory(
    app_local_data_dir: &Path,
    recovery_id: &str,
) -> Result<PathBuf, IpcError> {
    if !privacy_manager::is_normal_local_absolute(app_local_data_dir)
        || !privacy_manager::local_path_chain_is_ordinary(app_local_data_dir)
    {
        return Err(invalid_recovery());
    }
    let root = app_local_data_dir.join(RECOVERY_AUDIT_DIRECTORY);
    match fs::create_dir(&root) {
        Ok(()) => sync_directory(app_local_data_dir)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(io_recovery()),
    }
    if !root.is_dir() || !privacy_manager::local_path_chain_is_ordinary(&root) {
        return Err(invalid_recovery());
    }
    let directory = audit_directory(app_local_data_dir, recovery_id)?;
    fs::create_dir(&directory).map_err(|_| io_recovery())?;
    sync_directory(&root)?;
    if !directory.is_dir() || !privacy_manager::local_path_chain_is_ordinary(&directory) {
        return Err(invalid_recovery());
    }
    Ok(directory)
}

fn install_credential_archive(
    directory: &Path,
    snapshot: &V031ApprovedMcpCredentialSnapshot,
) -> Result<CredentialArchiveProof, IpcError> {
    let plaintext = snapshot
        .to_canonical_archive_plaintext()
        .map_err(|_| invalid_recovery())?;
    let protected = protect_local(plaintext.as_bytes()).map_err(|_| invalid_recovery())?;
    let path = directory.join(CREDENTIAL_ARCHIVE_BASENAME);
    v031_upgrade_r2::write_create_new_sync(&path, &protected, MAX_CREDENTIAL_ARCHIVE_BYTES)
        .map_err(|_| io_recovery())?;
    sync_directory(directory)?;
    let proof = CredentialArchiveProof {
        basename: CREDENTIAL_ARCHIVE_BASENAME.to_owned(),
        protected_sha256: sha256_hex(&protected),
        protected_bytes: u64::try_from(protected.len()).map_err(|_| invalid_recovery())?,
    };
    let decoded = open_credential_archive(&path, &proof)?;
    authenticate_v031_recovery_approved_mcp_credentials_read_only(&decoded)
        .map_err(|_| invalid_recovery())?;
    Ok(proof)
}

fn open_credential_archive(
    path: &Path,
    expected: &CredentialArchiveProof,
) -> Result<V031ApprovedMcpCredentialSnapshot, IpcError> {
    if expected.basename != CREDENTIAL_ARCHIVE_BASENAME || !valid_hash(&expected.protected_sha256) {
        return Err(invalid_recovery());
    }
    let protected = v031_upgrade_r2::read_bounded_file(path, MAX_CREDENTIAL_ARCHIVE_BYTES)
        .map_err(|_| invalid_recovery())?;
    if u64::try_from(protected.len()).ok() != Some(expected.protected_bytes)
        || sha256_hex(&protected) != expected.protected_sha256
    {
        return Err(invalid_recovery());
    }
    let plaintext = Zeroizing::new(unprotect_local(&protected).map_err(|_| invalid_recovery())?);
    V031ApprovedMcpCredentialSnapshot::from_canonical_archive_plaintext(plaintext.as_slice())
        .map_err(|_| invalid_recovery())
}

fn canonical_protected_marker(
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<Vec<u8>, IpcError> {
    validate_marker_static(marker)?;
    let plaintext = canonical_json_v1(marker).map_err(|_| invalid_recovery())?;
    protect_local(&plaintext).map_err(|_| invalid_recovery())
}

fn read_marker(path: &Path) -> Result<(V031MigrationRecoveryPendingV1, String), IpcError> {
    let protected = v031_upgrade_r2::read_bounded_file(path, MAX_MARKER_BYTES)
        .map_err(|_| invalid_recovery())?;
    let plaintext = Zeroizing::new(unprotect_local(&protected).map_err(|_| invalid_recovery())?);
    let marker: V031MigrationRecoveryPendingV1 =
        strict_json_v1_from_slice(plaintext.as_slice()).map_err(|_| invalid_recovery())?;
    if canonical_json_v1(&marker).map_err(|_| invalid_recovery())? != plaintext.as_slice() {
        return Err(invalid_recovery());
    }
    validate_marker_static(&marker)?;
    Ok((marker, sha256_hex(&protected)))
}

fn validate_marker_static(marker: &V031MigrationRecoveryPendingV1) -> Result<(), IpcError> {
    if marker.schema != MARKER_SCHEMA
        || marker.format_version != MARKER_FORMAT_VERSION
        || marker.migration_id != V031_MIGRATION_ID
        || !valid_recovery_id(&marker.recovery_id)
        || v031_upgrade_r2::validate_lineage_id(&marker.lineage_id).is_err()
        || marker.creator_app_version != CREATOR_APP_VERSION
        || marker.target_app_version != TARGET_APP_VERSION
        || marker.created_at_unix == 0
        || marker.slot_count != 5
        || marker.original_identity_protected_bytes == 0
        || marker.original_bundle_bytes == 0
        || marker.original_user_bytes == 0
        || marker.original_privacy_bytes == 0
        || marker.safety_backup.bundle_bytes() == 0
        || marker.safety_backup.workspace_instance_id() != marker.workspace_instance_id
        || !valid_hash(marker.safety_backup.component_identity_sha256())
        || marker.safety_backup.stage_slot_inventory_sha256()
            != stage_slot_inventory_sha256(marker)?
        || marker.credential_archive.basename != CREDENTIAL_ARCHIVE_BASENAME
        || marker.current_slots.len() != 5
        || marker
            .current_slots
            .iter()
            .zip(RECOVERY_COMPONENTS)
            .any(|(fingerprint, component)| !fingerprint.is_well_formed_for(component))
        || [
            &marker.source_profile_proof_sha256,
            &marker.receipt_nine_protected_sha256,
            &marker.receipt_nine_evidence_sha256,
            &marker.step8_predecessor_protected_sha256,
            &marker.upgrade_complete_sidecar_protected_sha256,
            &marker.original_identity_protected_sha256,
            &marker.original_bundle_sha256,
            &marker.original_user_sha256,
            &marker.original_privacy_sha256,
            &marker.current_five_slot_manifest_sha256,
            marker.safety_backup.bundle_sha256(),
            &marker.credential_archive.protected_sha256,
        ]
        .into_iter()
        .any(|hash| !valid_hash(hash))
        || marker
            .commit_evidence_protected_sha256
            .as_deref()
            .is_some_and(|hash| !valid_hash(hash))
        || marker
            .report_protected_sha256
            .as_deref()
            .is_some_and(|hash| !valid_hash(hash))
        || (marker.phase.ordinal() >= RecoveryPhase::FiveSlotCommitted.ordinal())
            != marker.commit_evidence_protected_sha256.is_some()
        || (marker.phase == RecoveryPhase::ReportInstalled)
            != marker.report_protected_sha256.is_some()
    {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn direct_marker_successor(
    current: &V031MigrationRecoveryPendingV1,
    candidate: &V031MigrationRecoveryPendingV1,
) -> bool {
    if current.phase.successor() != Some(candidate.phase) {
        return false;
    }
    let evidence_transition_is_valid = match candidate.phase {
        RecoveryPhase::FiveSlotCommitted => {
            current.commit_evidence_protected_sha256.is_none()
                && candidate.commit_evidence_protected_sha256.is_some()
                && candidate.report_protected_sha256 == current.report_protected_sha256
        }
        RecoveryPhase::ReportInstalled => {
            current.report_protected_sha256.is_none()
                && candidate.report_protected_sha256.is_some()
                && candidate.commit_evidence_protected_sha256
                    == current.commit_evidence_protected_sha256
        }
        _ => {
            candidate.commit_evidence_protected_sha256 == current.commit_evidence_protected_sha256
                && candidate.report_protected_sha256 == current.report_protected_sha256
        }
    };
    if !evidence_transition_is_valid {
        return false;
    }
    let mut expected = current.clone();
    expected.phase = candidate.phase;
    expected.commit_evidence_protected_sha256 = candidate.commit_evidence_protected_sha256.clone();
    expected.report_protected_sha256 = candidate.report_protected_sha256.clone();
    &expected == candidate
}

fn install_initial_marker_incoming(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<(), IpcError> {
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let staging_path = marker_staging_path(app_local_data_dir);
    if v031_recovery_path_is_present(&final_path)? || v031_recovery_path_is_present(&incoming_path)?
    {
        return Err(invalid_recovery());
    }
    if v031_recovery_path_is_present(&staging_path)? {
        remove_fixed_file(&staging_path)?;
    }
    let protected = canonical_protected_marker(marker)?;
    v031_upgrade_r2::write_create_new_sync(&staging_path, &protected, MAX_MARKER_BYTES)
        .map_err(|_| io_recovery())?;
    sync_directory(app_local_data_dir)?;
    let (readback, _) = read_marker(&staging_path)?;
    if &readback != marker {
        return Err(invalid_recovery());
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&staging_path, &incoming_path)
        .map_err(|_| io_recovery())?;
    sync_directory(app_local_data_dir)?;
    let (readback, _) = read_marker(&incoming_path)?;
    if &readback != marker || v031_recovery_path_is_present(&staging_path)? {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn finalize_initial_marker(app_local_data_dir: &Path) -> Result<(), IpcError> {
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    if v031_recovery_path_is_present(&final_path)?
        || v031_recovery_path_is_present(&marker_staging_path(app_local_data_dir))?
    {
        return Err(invalid_recovery());
    }
    read_marker(&incoming_path)?;
    v031_upgrade_r2::rename_new_no_replace_write_through(&incoming_path, &final_path)
        .map_err(|_| io_recovery())?;
    sync_directory(app_local_data_dir)?;
    read_marker(&final_path)?;
    Ok(())
}

fn cleanup_unauthorized_initial_marker_residue(app_local_data_dir: &Path) -> Result<(), IpcError> {
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let staging_path = marker_staging_path(app_local_data_dir);
    if v031_recovery_path_is_present(&final_path)? {
        return Err(invalid_recovery());
    }
    if v031_recovery_path_is_present(&incoming_path)? {
        remove_fixed_file(&incoming_path)?;
    }
    if v031_recovery_path_is_present(&staging_path)? {
        remove_fixed_file(&staging_path)?;
    }
    sync_directory(app_local_data_dir)?;
    if v031_recovery_path_is_present(&final_path)?
        || v031_recovery_path_is_present(&incoming_path)?
        || v031_recovery_path_is_present(&staging_path)?
    {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn install_marker_successor(
    app_local_data_dir: &Path,
    current: &V031MigrationRecoveryPendingV1,
    next: V031MigrationRecoveryPendingV1,
) -> Result<V031MigrationRecoveryPendingV1, IpcError> {
    if !direct_marker_successor(current, &next) {
        return Err(invalid_recovery());
    }
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let staging_path = marker_staging_path(app_local_data_dir);
    let (installed, _) = read_marker(&final_path)?;
    if &installed != current || v031_recovery_path_is_present(&incoming_path)? {
        return Err(invalid_recovery());
    }
    if v031_recovery_path_is_present(&staging_path)? {
        remove_fixed_file(&staging_path)?;
    }
    let protected = canonical_protected_marker(&next)?;
    v031_upgrade_r2::write_create_new_sync(&staging_path, &protected, MAX_MARKER_BYTES)
        .map_err(|_| io_recovery())?;
    sync_directory(app_local_data_dir)?;
    let (staged, _) = read_marker(&staging_path)?;
    if staged != next {
        return Err(invalid_recovery());
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&staging_path, &incoming_path)
        .map_err(|_| io_recovery())?;
    sync_directory(app_local_data_dir)?;
    let (staged, _) = read_marker(&incoming_path)?;
    if staged != next || v031_recovery_path_is_present(&staging_path)? {
        return Err(invalid_recovery());
    }
    v031_upgrade_r2::replace_existing_sibling_write_through(&incoming_path, &final_path)
        .map_err(|_| io_recovery())?;
    sync_directory(app_local_data_dir)?;
    let (readback, _) = read_marker(&final_path)?;
    if readback != next {
        return Err(invalid_recovery());
    }
    Ok(next)
}

fn advance_marker(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    phase: RecoveryPhase,
    evidence_sha256: Option<String>,
) -> Result<V031MigrationRecoveryPendingV1, IpcError> {
    let mut next = marker.clone();
    next.phase = phase;
    match phase {
        RecoveryPhase::FiveSlotCommitted => {
            next.commit_evidence_protected_sha256 = evidence_sha256;
        }
        RecoveryPhase::ReportInstalled => {
            next.report_protected_sha256 = evidence_sha256;
        }
        _ if evidence_sha256.is_some() => return Err(invalid_recovery()),
        _ => {}
    }
    install_marker_successor(app_local_data_dir, marker, next)
}

fn stage_slot_inventory_sha256(
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<String, IpcError> {
    canonical_json_v1(&marker.current_slots)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| invalid_recovery())
}

fn audit_inventory_shape_matches_kind(
    current_slots: &[V031RecoverySlotFingerprint; 5],
    kind: AuditEvidenceKind,
    physical_slots: &[RecoveryAuditSlotV1; 5],
) -> bool {
    physical_slots
        .iter()
        .zip(RECOVERY_COMPONENTS)
        .enumerate()
        .all(|(index, (slot, component))| {
            if slot.component != component {
                return false;
            }
            let current = &current_slots[index];
            match kind {
                AuditEvidenceKind::FiveSlotCommit => match component {
                    V031RecoveryComponent::UserDatabase
                    | V031RecoveryComponent::PrivacyDatabase => {
                        slot.active.is_some()
                            && slot.incoming.is_none()
                            && slot.rollback.as_ref() == Some(current)
                            && slot.cleanup.is_none()
                    }
                    V031RecoveryComponent::VaultStore
                    | V031RecoveryComponent::ApprovedWorkspace
                    | V031RecoveryComponent::WorkProducts => {
                        slot.active.is_none()
                            && slot.incoming.is_none()
                            && slot.rollback.as_ref() == Some(current)
                            && slot.cleanup.is_none()
                    }
                },
                AuditEvidenceKind::AppliedDowngrade => match component {
                    V031RecoveryComponent::UserDatabase
                    | V031RecoveryComponent::PrivacyDatabase => {
                        slot.active.is_some()
                            && slot.incoming.is_none()
                            && slot.rollback.is_none()
                            && slot.cleanup.is_none()
                    }
                    V031RecoveryComponent::VaultStore
                    | V031RecoveryComponent::ApprovedWorkspace
                    | V031RecoveryComponent::WorkProducts => {
                        slot.active.is_none()
                            && slot.incoming.is_none()
                            && slot.rollback.is_none()
                            && slot.cleanup.is_none()
                    }
                },
                AuditEvidenceKind::AbortedCurrentRestored => {
                    slot.active.as_ref() == Some(current)
                        && slot.incoming.is_none()
                        && slot.rollback.is_none()
                        && slot.cleanup.is_none()
                }
                AuditEvidenceKind::AbortToCurrent => true,
            }
        })
}

fn database_target_fingerprints_match(
    physical_slots: &[RecoveryAuditSlotV1; 5],
    user_target: &V031RecoverySlotFingerprint,
    privacy_target: &V031RecoverySlotFingerprint,
) -> bool {
    physical_slots[component_index(V031RecoveryComponent::UserDatabase)]
        .active
        .as_ref()
        == Some(user_target)
        && physical_slots[component_index(V031RecoveryComponent::PrivacyDatabase)]
            .active
            .as_ref()
            == Some(privacy_target)
}

fn applied_target_fingerprints_match_commit(
    commit_slots: &[RecoveryAuditSlotV1; 5],
    applied_slots: &[RecoveryAuditSlotV1; 5],
) -> bool {
    [
        V031RecoveryComponent::UserDatabase,
        V031RecoveryComponent::PrivacyDatabase,
    ]
    .into_iter()
    .all(|component| {
        let index = component_index(component);
        commit_slots[index].active.is_some()
            && applied_slots[index].active == commit_slots[index].active
    })
}

fn validate_applied_report_commit_binding(
    marker: &V031MigrationRecoveryPendingV1,
    commit: &RecoveryAuditEvidenceV1,
    applied: &RecoveryAuditEvidenceV1,
) -> Result<(), IpcError> {
    validate_audit_evidence(marker, AuditEvidenceKind::FiveSlotCommit, commit)?;
    validate_audit_evidence(marker, AuditEvidenceKind::AppliedDowngrade, applied)?;
    if !applied_target_fingerprints_match_commit(&commit.physical_slots, &applied.physical_slots) {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn validate_audit_evidence(
    marker: &V031MigrationRecoveryPendingV1,
    kind: AuditEvidenceKind,
    evidence: &RecoveryAuditEvidenceV1,
) -> Result<(), IpcError> {
    let fixed_fields_match = evidence.schema == AUDIT_EVIDENCE_SCHEMA
        && evidence.format_version == 1
        && evidence.kind == kind
        && evidence.recovery_id == marker.recovery_id
        && evidence.migration_id == marker.migration_id
        && evidence.lineage_id == marker.lineage_id
        && evidence.source_profile_proof_sha256 == marker.source_profile_proof_sha256
        && evidence.safety_backup_sha256 == marker.safety_backup.bundle_sha256()
        && evidence.credential_archive_sha256 == marker.credential_archive.protected_sha256
        && evidence.current_five_slot_manifest_sha256 == marker.current_five_slot_manifest_sha256
        && evidence.target_app_version == marker.target_app_version
        && evidence.stage_slot_inventory_sha256 == stage_slot_inventory_sha256(marker)?
        && valid_hash(&evidence.stage_slot_inventory_sha256)
        && evidence.credential_delete_prefix <= 4;
    if !fixed_fields_match {
        return Err(invalid_recovery());
    }
    for (slot, component) in evidence.physical_slots.iter().zip(RECOVERY_COMPONENTS) {
        if slot.component != component
            || [&slot.active, &slot.incoming, &slot.rollback, &slot.cleanup]
                .into_iter()
                .flatten()
                .any(|fingerprint| !fingerprint.is_well_formed_for(component))
        {
            return Err(invalid_recovery());
        }
    }
    let semantic_fields_match =
        audit_inventory_shape_matches_kind(&marker.current_slots, kind, &evidence.physical_slots)
            && match kind {
                AuditEvidenceKind::FiveSlotCommit => {
                    evidence.marker_phase == RecoveryPhase::WorkProductsMovedToRollback
                        && evidence.credential_delete_prefix == 0
                        && !evidence.commit_evidence_authenticated_absent
                }
                AuditEvidenceKind::AbortToCurrent => {
                    evidence.marker_phase.is_precommit()
                        && evidence.marker_phase == marker.phase
                        && evidence.credential_delete_prefix == 0
                        && evidence.commit_evidence_authenticated_absent
                }
                AuditEvidenceKind::AppliedDowngrade => {
                    evidence.marker_phase == RecoveryPhase::TargetVerified
                        && evidence.credential_delete_prefix == 4
                        && !evidence.commit_evidence_authenticated_absent
                }
                AuditEvidenceKind::AbortedCurrentRestored => {
                    evidence.marker_phase.is_precommit()
                        && evidence.marker_phase == marker.phase
                        && evidence.credential_delete_prefix == 0
                        && evidence.commit_evidence_authenticated_absent
                }
            };
    if !semantic_fields_match {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn audit_evidence_path(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    basename: &str,
) -> Result<PathBuf, IpcError> {
    if !matches!(
        basename,
        COMMIT_EVIDENCE_BASENAME
            | ABORT_INTENT_BASENAME
            | APPLIED_REPORT_BASENAME
            | ABORTED_REPORT_BASENAME
    ) {
        return Err(invalid_recovery());
    }
    Ok(audit_directory(app_local_data_dir, &marker.recovery_id)?.join(basename))
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn audit_evidence_transaction_paths(final_path: &Path) -> (PathBuf, PathBuf) {
    let incoming = append_path_suffix(final_path, ".incoming");
    let staging = append_path_suffix(&incoming, ".staging");
    (incoming, staging)
}

fn read_audit_evidence_file(
    path: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    kind: AuditEvidenceKind,
) -> Result<(RecoveryAuditEvidenceV1, String), IpcError> {
    let protected = v031_upgrade_r2::read_bounded_file(path, MAX_AUDIT_EVIDENCE_BYTES)
        .map_err(|_| invalid_recovery())?;
    let plaintext = Zeroizing::new(unprotect_local(&protected).map_err(|_| invalid_recovery())?);
    let decoded: RecoveryAuditEvidenceV1 =
        strict_json_v1_from_slice(plaintext.as_slice()).map_err(|_| invalid_recovery())?;
    if canonical_json_v1(&decoded).map_err(|_| invalid_recovery())? != plaintext.as_slice() {
        return Err(invalid_recovery());
    }
    validate_audit_evidence(marker, kind, &decoded)?;
    Ok((decoded, sha256_hex(&protected)))
}

fn authenticated_target_active_fingerprint(
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
    component: V031RecoveryComponent,
) -> Result<V031RecoverySlotFingerprint, IpcError> {
    let (bytes, sha256) = match component {
        V031RecoveryComponent::UserDatabase => (
            original.user_database(),
            marker.original_user_sha256.as_str(),
        ),
        V031RecoveryComponent::PrivacyDatabase => (
            original.privacy_database(),
            marker.original_privacy_sha256.as_str(),
        ),
        _ => return Err(invalid_recovery()),
    };
    if !target_database_matches(paths.active(component), component, bytes, sha256)? {
        return Err(invalid_recovery());
    }
    capture_v031_recovery_slot_fingerprint(paths.active(component), component)?
        .ok_or_else(invalid_recovery)
}

fn validate_audit_evidence_cross_binding(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    kind: AuditEvidenceKind,
    evidence: &RecoveryAuditEvidenceV1,
) -> Result<(), IpcError> {
    if matches!(
        kind,
        AuditEvidenceKind::FiveSlotCommit | AuditEvidenceKind::AppliedDowngrade
    ) {
        let original = open_authenticated_original_v2_images_for_recovery(
            app_local_data_dir,
            &marker.lineage_id,
        )
        .map_err(|_| invalid_recovery())?;
        if !marker_matches_original(marker, &original) {
            return Err(invalid_recovery());
        }
        let paths = v031_recovery_swap_paths(app_local_data_dir);
        let user_target = authenticated_target_active_fingerprint(
            &paths,
            marker,
            &original,
            V031RecoveryComponent::UserDatabase,
        )?;
        let privacy_target = authenticated_target_active_fingerprint(
            &paths,
            marker,
            &original,
            V031RecoveryComponent::PrivacyDatabase,
        )?;
        if !database_target_fingerprints_match(
            &evidence.physical_slots,
            &user_target,
            &privacy_target,
        ) {
            return Err(invalid_recovery());
        }
    }
    if kind != AuditEvidenceKind::AppliedDowngrade {
        return Ok(());
    }
    let commit_path = audit_evidence_path(app_local_data_dir, marker, COMMIT_EVIDENCE_BASENAME)?;
    if !v031_recovery_path_is_present(&commit_path)? {
        return Err(invalid_recovery());
    }
    let (commit, protected_sha256) =
        read_audit_evidence_file(&commit_path, marker, AuditEvidenceKind::FiveSlotCommit)?;
    if marker.commit_evidence_protected_sha256.as_deref() != Some(protected_sha256.as_str()) {
        return Err(invalid_recovery());
    }
    validate_applied_report_commit_binding(marker, &commit, evidence)
}

fn cleanup_audit_evidence_install_residue(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    basename: &str,
) -> Result<(), IpcError> {
    let final_path = audit_evidence_path(app_local_data_dir, marker, basename)?;
    let (incoming, staging) = audit_evidence_transaction_paths(&final_path);
    remove_fixed_file(&staging)?;
    remove_fixed_file(&incoming)?;
    Ok(())
}

fn audit_evidence_install_residue_present(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    basename: &str,
) -> Result<bool, IpcError> {
    let final_path = audit_evidence_path(app_local_data_dir, marker, basename)?;
    let (incoming, staging) = audit_evidence_transaction_paths(&final_path);
    Ok(v031_recovery_path_is_present(&incoming)? || v031_recovery_path_is_present(&staging)?)
}

fn ensure_all_audit_evidence_install_residue_absent(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<(), IpcError> {
    for basename in [
        COMMIT_EVIDENCE_BASENAME,
        ABORT_INTENT_BASENAME,
        APPLIED_REPORT_BASENAME,
        ABORTED_REPORT_BASENAME,
    ] {
        if audit_evidence_install_residue_present(app_local_data_dir, marker, basename)? {
            return Err(invalid_recovery());
        }
    }
    Ok(())
}

fn any_audit_evidence_install_residue_present(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<bool, IpcError> {
    for basename in [
        COMMIT_EVIDENCE_BASENAME,
        ABORT_INTENT_BASENAME,
        APPLIED_REPORT_BASENAME,
        ABORTED_REPORT_BASENAME,
    ] {
        if audit_evidence_install_residue_present(app_local_data_dir, marker, basename)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn install_or_verify_audit_evidence(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    basename: &str,
    kind: AuditEvidenceKind,
    candidate: &RecoveryAuditEvidenceV1,
) -> Result<String, IpcError> {
    let path = audit_evidence_path(app_local_data_dir, marker, basename)?;
    let (incoming, staging) = audit_evidence_transaction_paths(&path);
    validate_audit_evidence(marker, kind, candidate)?;
    validate_audit_evidence_cross_binding(app_local_data_dir, marker, kind, candidate)?;
    if v031_recovery_path_is_present(&path)? {
        let (installed, installed_hash) = read_audit_evidence_file(&path, marker, kind)?;
        if kind != AuditEvidenceKind::AbortToCurrent && installed != *candidate {
            return Err(invalid_recovery());
        }
        cleanup_audit_evidence_install_residue(app_local_data_dir, marker, basename)?;
        if kind == AuditEvidenceKind::AbortToCurrent {
            let (reread, reread_hash) = read_audit_evidence_file(&path, marker, kind)?;
            if reread != installed || reread_hash != installed_hash {
                return Err(invalid_recovery());
            }
        }
        return Ok(installed_hash);
    }
    // An interrupted abort install may itself be the only durable indication
    // that forward recovery must never resume.  Preserve and authenticate that
    // transaction state until the abort final has been installed and reread.
    if kind == AuditEvidenceKind::AbortToCurrent {
        let incoming_present = v031_recovery_path_is_present(&incoming)?;
        let staging_present = v031_recovery_path_is_present(&staging)?;
        match (incoming_present, staging_present) {
            // With no authoritative final, two independently durable candidate
            // residues are ambiguous.  Neither may be selected or discarded.
            (true, true) => return Err(invalid_recovery()),
            (true, false) => {
                let (staged, _) = read_audit_evidence_file(&incoming, marker, kind)?;
                if staged != *candidate {
                    return Err(invalid_recovery());
                }
            }
            (false, true) => {
                let (staged, _) = read_audit_evidence_file(&staging, marker, kind)?;
                if staged != *candidate {
                    return Err(invalid_recovery());
                }
                v031_upgrade_r2::rename_new_no_replace_write_through(&staging, &incoming)
                    .map_err(|_| io_recovery())?;
                sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
            }
            (false, false) => {
                let plaintext = canonical_json_v1(candidate).map_err(|_| invalid_recovery())?;
                let protected = protect_local(&plaintext).map_err(|_| invalid_recovery())?;
                v031_upgrade_r2::write_create_new_sync(
                    &staging,
                    &protected,
                    MAX_AUDIT_EVIDENCE_BYTES,
                )
                .map_err(|_| io_recovery())?;
                sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
                let (staged, _) = read_audit_evidence_file(&staging, marker, kind)?;
                if staged != *candidate {
                    return Err(invalid_recovery());
                }
                v031_upgrade_r2::rename_new_no_replace_write_through(&staging, &incoming)
                    .map_err(|_| io_recovery())?;
                sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
            }
        }
        let (staged, _) = read_audit_evidence_file(&incoming, marker, kind)?;
        if staged != *candidate || v031_recovery_path_is_present(&staging)? {
            return Err(invalid_recovery());
        }
        v031_upgrade_r2::rename_new_no_replace_write_through(&incoming, &path)
            .map_err(|_| io_recovery())?;
        sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
        let (installed, installed_hash) = read_audit_evidence_file(&path, marker, kind)?;
        if installed != *candidate {
            return Err(invalid_recovery());
        }
        cleanup_audit_evidence_install_residue(app_local_data_dir, marker, basename)?;
        let (reread, reread_hash) = read_audit_evidence_file(&path, marker, kind)?;
        if reread != installed || reread_hash != installed_hash {
            return Err(invalid_recovery());
        }
        return Ok(installed_hash);
    }
    remove_fixed_file(&staging)?;
    if !v031_recovery_path_is_present(&incoming)? {
        let plaintext = canonical_json_v1(candidate).map_err(|_| invalid_recovery())?;
        let protected = protect_local(&plaintext).map_err(|_| invalid_recovery())?;
        v031_upgrade_r2::write_create_new_sync(&staging, &protected, MAX_AUDIT_EVIDENCE_BYTES)
            .map_err(|_| io_recovery())?;
        sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
        let (staged, _) = read_audit_evidence_file(&staging, marker, kind)?;
        if staged != *candidate {
            return Err(invalid_recovery());
        }
        v031_upgrade_r2::rename_new_no_replace_write_through(&staging, &incoming)
            .map_err(|_| io_recovery())?;
        sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
    }
    let (staged, _) = read_audit_evidence_file(&incoming, marker, kind)?;
    if staged != *candidate || v031_recovery_path_is_present(&staging)? {
        return Err(invalid_recovery());
    }
    v031_upgrade_r2::rename_new_no_replace_write_through(&incoming, &path)
        .map_err(|_| io_recovery())?;
    sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
    let (installed, installed_hash) = read_audit_evidence_file(&path, marker, kind)?;
    if installed != *candidate
        || v031_recovery_path_is_present(&incoming)?
        || v031_recovery_path_is_present(&staging)?
    {
        return Err(invalid_recovery());
    }
    Ok(installed_hash)
}

fn audit_evidence_final_if_present(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    basename: &str,
    kind: AuditEvidenceKind,
) -> Result<Option<(RecoveryAuditEvidenceV1, String)>, IpcError> {
    let path = audit_evidence_path(app_local_data_dir, marker, basename)?;
    if !v031_recovery_path_is_present(&path)? {
        return Ok(None);
    }
    read_audit_evidence_file(&path, marker, kind).map(Some)
}

type RecoveryAuditEvidenceWithHash = (RecoveryAuditEvidenceV1, String);
type CommitAbortFinals = (
    Option<RecoveryAuditEvidenceWithHash>,
    Option<RecoveryAuditEvidenceWithHash>,
);

fn commit_abort_finals_exclusive(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<CommitAbortFinals, IpcError> {
    let commit = audit_evidence_final_if_present(
        app_local_data_dir,
        marker,
        COMMIT_EVIDENCE_BASENAME,
        AuditEvidenceKind::FiveSlotCommit,
    )?;
    let abort = audit_evidence_final_if_present(
        app_local_data_dir,
        marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
    )?;
    if commit.is_some() && abort.is_some() {
        return Err(invalid_recovery());
    }
    Ok((commit, abort))
}

fn audit_evidence_present_and_valid(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    basename: &str,
    kind: AuditEvidenceKind,
) -> Result<Option<String>, IpcError> {
    let Some((evidence, hash)) =
        audit_evidence_final_if_present(app_local_data_dir, marker, basename, kind)?
    else {
        return Ok(None);
    };
    validate_audit_evidence_cross_binding(app_local_data_dir, marker, kind, &evidence)?;
    Ok(Some(hash))
}

fn remove_fixed_file(path: &Path) -> Result<(), IpcError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(io_recovery()),
        Ok(metadata)
            if metadata.is_file()
                && privacy_manager::is_normal_local_absolute(path)
                && privacy_manager::local_path_chain_is_ordinary(path) => {}
        Ok(_) => return Err(invalid_recovery()),
    }
    v031_upgrade_r2::verify_plain_single_link_file(path).map_err(|_| invalid_recovery())?;
    fs::remove_file(path).map_err(|_| io_recovery())?;
    sync_directory(path.parent().ok_or_else(invalid_recovery)?)?;
    if v031_recovery_path_is_present(path)? {
        return Err(io_recovery());
    }
    Ok(())
}

fn ensure_ordinary_restore_markers_absent(app_local_data_dir: &Path) -> Result<(), IpcError> {
    for path in [
        app_local_data_dir.join("application-restore-pending.dpapi"),
        app_local_data_dir.join("application-restore-pending.dpapi.incoming"),
        app_local_data_dir.join("user.sqlite.restore-pending.json"),
        app_local_data_dir.join("privacy/privacy-workflow.sqlite.restore-pending.dpapi"),
    ] {
        if v031_recovery_path_is_present(&path)? {
            return Err(invalid_recovery());
        }
    }
    Ok(())
}

fn ensure_recovery_stage_slots_clean(paths: &V031RecoverySwapPaths) -> Result<(), IpcError> {
    for component in RECOVERY_COMPONENTS {
        let incoming_present = paths
            .incoming(component)
            .map(|path| capture_v031_recovery_slot_fingerprint(path, component))
            .transpose()?
            .flatten()
            .is_some();
        let staging_present = paths
            .staging(component)
            .map(|path| capture_v031_recovery_slot_fingerprint(path, component))
            .transpose()?
            .flatten()
            .is_some();
        let cleanup_present = paths
            .cleanup(component)
            .map(|path| capture_v031_recovery_slot_fingerprint(path, component))
            .transpose()?
            .flatten()
            .is_some();
        if capture_v031_recovery_slot_fingerprint(paths.rollback(component), component)?.is_some()
            || incoming_present
            || staging_present
            || cleanup_present
        {
            return Err(invalid_recovery());
        }
    }
    Ok(())
}

fn database_staging_present(paths: &V031RecoverySwapPaths) -> Result<bool, IpcError> {
    for component in [
        V031RecoveryComponent::UserDatabase,
        V031RecoveryComponent::PrivacyDatabase,
    ] {
        let path = paths.staging(component).ok_or_else(invalid_recovery)?;
        if v031_recovery_path_is_present(path)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn remove_database_staging_residue(paths: &V031RecoverySwapPaths) -> Result<(), IpcError> {
    for component in [
        V031RecoveryComponent::PrivacyDatabase,
        V031RecoveryComponent::UserDatabase,
    ] {
        let path = paths.staging(component).ok_or_else(invalid_recovery)?;
        if v031_recovery_path_is_present(path)? {
            remove_v031_recovery_component(path, component)?;
        }
        if v031_recovery_path_is_present(path)? {
            return Err(invalid_recovery());
        }
    }
    Ok(())
}

fn prepare_recovery_stage(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(), IpcError> {
    ensure_ordinary_restore_markers_absent(app_local_data_dir)?;
    reject_unknown_v031_recovery_restore_siblings(app_local_data_dir)?;
    let (marker_path, marker_incoming) = marker_paths(app_local_data_dir);
    let marker_staging = marker_staging_path(app_local_data_dir);
    if v031_recovery_path_is_present(&marker_path)? {
        return Err(invalid_recovery());
    }
    if v031_recovery_path_is_present(&marker_incoming)? {
        remove_fixed_file(&marker_incoming)?;
    }
    if v031_recovery_path_is_present(&marker_staging)? {
        remove_fixed_file(&marker_staging)?;
    }
    let initial_complete = v031_startup::authenticate_completed_v031_for_recovery_stage(
        app_local_data_dir,
        workflow,
        approved_workspace,
    )
    .map_err(|_| invalid_recovery())?;
    let paths = v031_recovery_swap_paths(app_local_data_dir);
    remove_database_staging_residue(&paths)?;
    ensure_recovery_stage_slots_clean(&paths)?;
    let recovery_id = format!("rcv_{}", Uuid::new_v4().simple());
    let directory = create_audit_directory(app_local_data_dir, &recovery_id)?;
    let (safety_backup, current_slots) = build_and_install_v031_recovery_safety_backup(
        app_local_data_dir,
        state,
        workflow,
        approved_workspace,
        &directory.join(SAFETY_BACKUP_BASENAME),
    )?;
    let credentials = capture_v031_recovery_approved_mcp_credentials_read_only()
        .map_err(|_| invalid_recovery())?;
    let credential_archive = install_credential_archive(&directory, &credentials)?;
    let complete = v031_startup::authenticate_completed_v031_for_recovery_stage(
        app_local_data_dir,
        workflow,
        approved_workspace,
    )
    .map_err(|_| invalid_recovery())?;
    if initial_complete.lineage_id() != complete.lineage_id()
        || initial_complete.receipt_nine_sha256() != complete.receipt_nine_sha256()
        || initial_complete.evidence_sha256() != complete.evidence_sha256()
    {
        return Err(invalid_recovery());
    }
    let original = open_authenticated_original_v2_images_for_recovery(
        app_local_data_dir,
        complete.lineage_id(),
    )
    .map_err(|_| invalid_recovery())?;
    if original.receipt_nine_protected_sha256() != complete.receipt_nine_sha256()
        || original.receipt_nine_evidence_sha256() != complete.evidence_sha256()
        || safety_backup.workspace_instance_id() != workflow.workspace_instance_id().as_str()
    {
        return Err(invalid_recovery());
    }
    ensure_recovery_stage_slots_clean(&paths)?;
    let current_slots_after_safety = capture_v031_recovery_active_fingerprints(&paths)?;
    let slot_inventory = canonical_json_v1(&current_slots).map_err(|_| invalid_recovery())?;
    if current_slots_after_safety != current_slots
        || sha256_hex(&slot_inventory) != safety_backup.stage_slot_inventory_sha256()
        || !valid_hash(safety_backup.component_identity_sha256())
    {
        return Err(invalid_recovery());
    }
    authenticate_v031_recovery_approved_mcp_credentials_read_only(&credentials)
        .map_err(|_| invalid_recovery())?;
    verify_v031_recovery_safety_backup_read_only(
        &directory.join(SAFETY_BACKUP_BASENAME),
        &safety_backup,
    )?;
    let marker = V031MigrationRecoveryPendingV1 {
        schema: MARKER_SCHEMA.to_owned(),
        format_version: MARKER_FORMAT_VERSION,
        migration_id: V031_MIGRATION_ID.to_owned(),
        recovery_id,
        lineage_id: original.lineage_id().to_owned(),
        envelope_binding_id: original.envelope_binding_id().to_owned(),
        source_profile_proof_sha256: original.source_profile_proof_sha256().to_owned(),
        creator_app_version: CREATOR_APP_VERSION.to_owned(),
        target_app_version: TARGET_APP_VERSION.to_owned(),
        created_at_unix: unix_now()?,
        receipt_nine_protected_sha256: original.receipt_nine_protected_sha256().to_owned(),
        receipt_nine_evidence_sha256: original.receipt_nine_evidence_sha256().to_owned(),
        step8_predecessor_protected_sha256: original
            .step8_predecessor_protected_sha256()
            .to_owned(),
        upgrade_complete_sidecar_protected_sha256: original
            .upgrade_complete_sidecar_protected_sha256()
            .to_owned(),
        original_identity_protected_sha256: original.identity_protected_sha256().to_owned(),
        original_identity_protected_bytes: original.identity_protected_bytes(),
        original_bundle_sha256: original.bundle_sha256().to_owned(),
        original_bundle_bytes: original.bundle_bytes(),
        original_user_sha256: sha256_hex(original.user_database()),
        original_user_bytes: u64::try_from(original.user_database().len())
            .map_err(|_| invalid_recovery())?,
        original_privacy_sha256: sha256_hex(original.privacy_database()),
        original_privacy_bytes: u64::try_from(original.privacy_database().len())
            .map_err(|_| invalid_recovery())?,
        workspace_instance_id: workflow.workspace_instance_id().as_str().to_owned(),
        current_five_slot_manifest_sha256: complete.final_component_manifest_sha256().to_owned(),
        current_slots,
        safety_backup,
        credential_archive,
        slot_count: 5,
        phase: RecoveryPhase::Requested,
        commit_evidence_protected_sha256: None,
        report_protected_sha256: None,
    };
    install_initial_marker_incoming(app_local_data_dir, &marker)
}

fn validate_initial_audit_directory_shape(directory: &Path) -> Result<(), IpcError> {
    validate_audit_directory_shape(directory)?;
    let present = fs::read_dir(directory)
        .map_err(|_| invalid_recovery())?
        .map(|entry| {
            entry
                .map_err(|_| invalid_recovery())?
                .file_name()
                .into_string()
                .map_err(|_| invalid_recovery())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if present
        != BTreeSet::from([
            SAFETY_BACKUP_BASENAME.to_owned(),
            CREDENTIAL_ARCHIVE_BASENAME.to_owned(),
        ])
    {
        return Err(invalid_recovery());
    }
    Ok(())
}

/// Re-proves the complete staged authority only after MCP admission has been
/// permanently closed. The three component barriers are intentionally leaked
/// after the formal marker is installed: their OS handles/mutexes then freeze
/// User, Privacy/Vault and Approved/Work-Products until controlled restart.
fn finalize_initial_marker_after_quiescence(
    app_local_data_dir: &Path,
    state: &AppState,
    workflow: &PrivacyWorkflowManager,
    approved_workspace: &ApprovedMcpWorkspace,
) -> Result<(), IpcError> {
    ensure_ordinary_restore_markers_absent(app_local_data_dir)?;
    reject_unknown_v031_recovery_restore_siblings(app_local_data_dir)?;
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let staging_path = marker_staging_path(app_local_data_dir);
    if v031_recovery_path_is_present(&final_path)?
        || v031_recovery_path_is_present(&staging_path)?
        || !v031_recovery_path_is_present(&incoming_path)?
    {
        return Err(invalid_recovery());
    }

    // Re-authenticate the current terminal lineage immediately before taking
    // the permanent component barriers. Any concurrent business write that
    // wins before a barrier is acquired is detected by the locked slot reproof
    // below and therefore cannot authorize the formal marker.
    let complete = v031_startup::authenticate_completed_v031_for_recovery_stage(
        app_local_data_dir,
        workflow,
        approved_workspace,
    )
    .map_err(|_| invalid_recovery())?;

    let privacy_barrier = workflow.begin_application_backup_pair();
    let user_barrier = acquire_v031_recovery_user_database_write_barrier(
        app_local_data_dir,
        state.user_database_path(),
    )?;
    let approved_barrier = approved_workspace
        .begin_v031_recovery_quiescence()
        .map_err(|_| invalid_recovery())?;

    let (marker, _) = read_marker(&incoming_path)?;
    if marker.phase != RecoveryPhase::Requested
        || marker.commit_evidence_protected_sha256.is_some()
        || marker.report_protected_sha256.is_some()
        || marker.lineage_id != complete.lineage_id()
        || marker.receipt_nine_protected_sha256 != complete.receipt_nine_sha256()
        || marker.receipt_nine_evidence_sha256 != complete.evidence_sha256()
        || marker.current_five_slot_manifest_sha256 != complete.final_component_manifest_sha256()
    {
        return Err(invalid_recovery());
    }

    let directory = audit_directory(app_local_data_dir, &marker.recovery_id)?;
    validate_initial_audit_directory_shape(&directory)?;
    verify_v031_recovery_safety_backup_read_only(
        &directory.join(SAFETY_BACKUP_BASENAME),
        &marker.safety_backup,
    )?;
    let archived = open_credential_archive(
        &directory.join(CREDENTIAL_ARCHIVE_BASENAME),
        &marker.credential_archive,
    )?;
    let current_credentials = capture_v031_recovery_approved_mcp_credentials_read_only()
        .map_err(|_| invalid_recovery())?;
    let archived_plaintext = archived
        .to_canonical_archive_plaintext()
        .map_err(|_| invalid_recovery())?;
    let current_plaintext = current_credentials
        .to_canonical_archive_plaintext()
        .map_err(|_| invalid_recovery())?;
    if archived_plaintext.as_bytes() != current_plaintext.as_bytes() {
        return Err(invalid_recovery());
    }
    authenticate_v031_recovery_approved_mcp_credentials_read_only(&current_credentials)
        .map_err(|_| invalid_recovery())?;

    let original =
        open_authenticated_original_v2_images_for_recovery(app_local_data_dir, &marker.lineage_id)
            .map_err(|_| invalid_recovery())?;
    if !marker_matches_original(&marker, &original)
        || marker.safety_backup.workspace_instance_id() != workflow.workspace_instance_id().as_str()
    {
        return Err(invalid_recovery());
    }
    let paths = v031_recovery_swap_paths(app_local_data_dir);
    ensure_recovery_stage_slots_clean(&paths)?;
    if database_staging_present(&paths)?
        || any_audit_evidence_install_residue_present(app_local_data_dir, &marker)?
    {
        return Err(invalid_recovery());
    }
    let current_slots = capture_v031_recovery_active_fingerprints(&paths)?;
    let current_slot_inventory =
        canonical_json_v1(&current_slots).map_err(|_| invalid_recovery())?;
    if current_slots != marker.current_slots
        || sha256_hex(&current_slot_inventory) != marker.safety_backup.stage_slot_inventory_sha256()
    {
        return Err(invalid_recovery());
    }
    ensure_ordinary_restore_markers_absent(app_local_data_dir)?;
    reject_unknown_v031_recovery_restore_siblings(app_local_data_dir)?;
    if v031_recovery_path_is_present(&final_path)? || v031_recovery_path_is_present(&staging_path)?
    {
        return Err(invalid_recovery());
    }
    let (readback, _) = read_marker(&incoming_path)?;
    if readback != marker {
        return Err(invalid_recovery());
    }
    let install = finalize_initial_marker(app_local_data_dir);
    let formal_present = v031_recovery_path_is_present(&final_path).unwrap_or(true);
    if install.is_ok() || formal_present {
        std::mem::forget(approved_barrier);
        std::mem::forget(user_barrier);
        std::mem::forget(privacy_barrier);
    }
    install
}

fn marker_matches_original(
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
) -> bool {
    marker.lineage_id == original.lineage_id()
        && marker.envelope_binding_id == original.envelope_binding_id()
        && marker.source_profile_proof_sha256 == original.source_profile_proof_sha256()
        && marker.receipt_nine_protected_sha256 == original.receipt_nine_protected_sha256()
        && marker.receipt_nine_evidence_sha256 == original.receipt_nine_evidence_sha256()
        && marker.step8_predecessor_protected_sha256
            == original.step8_predecessor_protected_sha256()
        && marker.upgrade_complete_sidecar_protected_sha256
            == original.upgrade_complete_sidecar_protected_sha256()
        && marker.original_identity_protected_sha256 == original.identity_protected_sha256()
        && marker.original_identity_protected_bytes == original.identity_protected_bytes()
        && marker.original_bundle_sha256 == original.bundle_sha256()
        && marker.original_bundle_bytes == original.bundle_bytes()
        && marker.original_user_sha256 == sha256_hex(original.user_database())
        && u64::try_from(original.user_database().len()).ok() == Some(marker.original_user_bytes)
        && marker.original_privacy_sha256 == sha256_hex(original.privacy_database())
        && u64::try_from(original.privacy_database().len()).ok()
            == Some(marker.original_privacy_bytes)
        && marker.current_five_slot_manifest_sha256 == original.final_component_manifest_sha256()
}

fn validate_audit_directory_shape(directory: &Path) -> Result<(), IpcError> {
    if !directory.is_dir()
        || !privacy_manager::is_normal_local_absolute(directory)
        || !privacy_manager::local_path_chain_is_ordinary(directory)
    {
        return Err(invalid_recovery());
    }
    let mut allowed = BTreeSet::from([
        SAFETY_BACKUP_BASENAME.to_owned(),
        CREDENTIAL_ARCHIVE_BASENAME.to_owned(),
    ]);
    for basename in [
        COMMIT_EVIDENCE_BASENAME,
        ABORT_INTENT_BASENAME,
        APPLIED_REPORT_BASENAME,
        ABORTED_REPORT_BASENAME,
    ] {
        allowed.insert(basename.to_owned());
        allowed.insert(format!("{basename}.incoming"));
        allowed.insert(format!("{basename}.incoming.staging"));
    }
    let mut present = BTreeSet::new();
    for entry in fs::read_dir(directory).map_err(|_| invalid_recovery())? {
        let entry = entry.map_err(|_| invalid_recovery())?;
        let basename = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_recovery())?;
        if !allowed.contains(&basename) || !present.insert(basename) {
            return Err(invalid_recovery());
        }
        let metadata = entry.metadata().map_err(|_| invalid_recovery())?;
        if !metadata.is_file() || !privacy_manager::local_path_chain_is_ordinary(&entry.path()) {
            return Err(invalid_recovery());
        }
        v031_upgrade_r2::verify_plain_single_link_file(&entry.path())
            .map_err(|_| invalid_recovery())?;
    }
    if !present.contains(SAFETY_BACKUP_BASENAME) || !present.contains(CREDENTIAL_ARCHIVE_BASENAME) {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn validate_approved_auxiliary_namespace(
    app_local_data_dir: &Path,
    paths: &V031RecoverySwapPaths,
) -> Result<(), IpcError> {
    let parent = app_local_data_dir.join("privacy/approved-mcp");
    if !v031_recovery_path_is_present(&parent)? {
        return Ok(());
    }
    if !parent.is_dir() || !privacy_manager::local_path_chain_is_ordinary(&parent) {
        return Err(invalid_recovery());
    }
    let basename = |path: &Path| -> Result<String, IpcError> {
        path.file_name()
            .and_then(|value| value.to_str())
            .map(str::to_owned)
            .ok_or_else(invalid_recovery)
    };
    let allowed = BTreeSet::from([
        basename(paths.active(V031RecoveryComponent::ApprovedWorkspace))?,
        basename(
            paths
                .incoming(V031RecoveryComponent::ApprovedWorkspace)
                .ok_or_else(invalid_recovery)?,
        )?,
        basename(paths.rollback(V031RecoveryComponent::ApprovedWorkspace))?,
        basename(
            paths
                .cleanup(V031RecoveryComponent::ApprovedWorkspace)
                .ok_or_else(invalid_recovery)?,
        )?,
        basename(paths.active(V031RecoveryComponent::WorkProducts))?,
        basename(
            paths
                .incoming(V031RecoveryComponent::WorkProducts)
                .ok_or_else(invalid_recovery)?,
        )?,
        basename(paths.rollback(V031RecoveryComponent::WorkProducts))?,
        basename(
            paths
                .cleanup(V031RecoveryComponent::WorkProducts)
                .ok_or_else(invalid_recovery)?,
        )?,
        "ticket-sessions".to_owned(),
        "qualification".to_owned(),
    ]);
    let mut present = BTreeSet::new();
    for entry in fs::read_dir(&parent).map_err(|_| invalid_recovery())? {
        let entry = entry.map_err(|_| invalid_recovery())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| invalid_recovery())?;
        if !allowed.contains(&name) || !present.insert(name) {
            return Err(invalid_recovery());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedRecoverySlot {
    active: Option<V031RecoverySlotFingerprint>,
    incoming: Option<V031RecoverySlotFingerprint>,
    rollback: Option<V031RecoverySlotFingerprint>,
    cleanup: Option<V031RecoverySlotFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedRecoveryLayout {
    slots: [ObservedRecoverySlot; 5],
    credential_delete_prefix: usize,
}

const RECOVERY_COMPONENTS: [V031RecoveryComponent; 5] = [
    V031RecoveryComponent::UserDatabase,
    V031RecoveryComponent::PrivacyDatabase,
    V031RecoveryComponent::VaultStore,
    V031RecoveryComponent::ApprovedWorkspace,
    V031RecoveryComponent::WorkProducts,
];

const fn component_index(component: V031RecoveryComponent) -> usize {
    match component {
        V031RecoveryComponent::UserDatabase => 0,
        V031RecoveryComponent::PrivacyDatabase => 1,
        V031RecoveryComponent::VaultStore => 2,
        V031RecoveryComponent::ApprovedWorkspace => 3,
        V031RecoveryComponent::WorkProducts => 4,
    }
}

fn capture_recovery_layout(
    paths: &V031RecoverySwapPaths,
    credential_delete_prefix: usize,
) -> Result<ObservedRecoveryLayout, IpcError> {
    let mut captured = Vec::with_capacity(RECOVERY_COMPONENTS.len());
    for component in RECOVERY_COMPONENTS {
        captured.push(ObservedRecoverySlot {
            active: capture_v031_recovery_slot_fingerprint(paths.active(component), component)?,
            incoming: match paths.incoming(component) {
                Some(path) => capture_v031_recovery_slot_fingerprint(path, component)?,
                None => None,
            },
            rollback: capture_v031_recovery_slot_fingerprint(paths.rollback(component), component)?,
            cleanup: match paths.cleanup(component) {
                Some(path) => capture_v031_recovery_slot_fingerprint(path, component)?,
                None => None,
            },
        });
    }
    let slots: [ObservedRecoverySlot; 5] = captured.try_into().map_err(|_| invalid_recovery())?;
    Ok(ObservedRecoveryLayout {
        slots,
        credential_delete_prefix,
    })
}

fn layout_from_audit_evidence(
    evidence: &RecoveryAuditEvidenceV1,
) -> Result<ObservedRecoveryLayout, IpcError> {
    let slots = evidence
        .physical_slots
        .iter()
        .map(|slot| ObservedRecoverySlot {
            active: slot.active.clone(),
            incoming: slot.incoming.clone(),
            rollback: slot.rollback.clone(),
            cleanup: slot.cleanup.clone(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| invalid_recovery())?;
    Ok(ObservedRecoveryLayout {
        slots,
        credential_delete_prefix: usize::try_from(evidence.credential_delete_prefix)
            .map_err(|_| invalid_recovery())?,
    })
}

fn abort_layout_is_legal_reverse_prefix(
    current: &ObservedRecoveryLayout,
    evidence: &RecoveryAuditEvidenceV1,
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<bool, IpcError> {
    validate_audit_evidence(marker, AuditEvidenceKind::AbortToCurrent, evidence)?;
    let expected = layout_from_audit_evidence(evidence)?;
    // Historical evidence is self-contained.  Re-validating it against the
    // current filesystem would reject legitimate reverse prefixes after a
    // target active or incoming database has already been removed.
    validate_abort_layout_structure(&expected, marker)?;
    abort_layout_is_legal_reverse_prefix_after_validation(current, expected, &marker.current_slots)
}

fn abort_layout_is_legal_reverse_prefix_after_validation(
    current: &ObservedRecoveryLayout,
    mut expected: ObservedRecoveryLayout,
    current_slots: &[V031RecoverySlotFingerprint; 5],
) -> Result<bool, IpcError> {
    if current == &expected {
        return Ok(true);
    }
    for component in [
        V031RecoveryComponent::WorkProducts,
        V031RecoveryComponent::ApprovedWorkspace,
        V031RecoveryComponent::VaultStore,
        V031RecoveryComponent::PrivacyDatabase,
        V031RecoveryComponent::UserDatabase,
    ] {
        let index = component_index(component);
        let stage_current = current_slots[index].clone();
        if expected.slots[index].rollback.as_ref() == Some(&stage_current) {
            match component {
                V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase => {
                    if expected.slots[index].active.as_ref() == Some(&stage_current) {
                        return Err(invalid_recovery());
                    }
                    if expected.slots[index].active.is_some() {
                        expected.slots[index].active = None;
                        if current == &expected {
                            return Ok(true);
                        }
                    }
                }
                V031RecoveryComponent::VaultStore
                | V031RecoveryComponent::ApprovedWorkspace
                | V031RecoveryComponent::WorkProducts => {
                    if expected.slots[index].active.is_some() {
                        return Err(invalid_recovery());
                    }
                }
            }
            expected.slots[index].active = Some(stage_current.clone());
            expected.slots[index].rollback = None;
            if current == &expected {
                return Ok(true);
            }
        } else if expected.slots[index].active.as_ref() != Some(&stage_current) {
            return Err(invalid_recovery());
        }
        if matches!(
            component,
            V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase
        ) && expected.slots[index].incoming.is_some()
        {
            if current == &expected {
                return Ok(true);
            }
            expected.slots[index].incoming = None;
        }
        if current == &expected {
            return Ok(true);
        }
    }
    Ok(false)
}

fn capture_recovery_audit_evidence(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    credentials: &V031ApprovedMcpCredentialSnapshot,
    kind: AuditEvidenceKind,
) -> Result<RecoveryAuditEvidenceV1, IpcError> {
    let credential_gate =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(credentials)
            .map_err(|_| invalid_recovery())?;
    let layout = capture_recovery_layout(
        &v031_recovery_swap_paths(app_local_data_dir),
        credential_gate.prefix_len(),
    )?;
    let physical_slots = layout
        .slots
        .into_iter()
        .zip(RECOVERY_COMPONENTS)
        .map(|(slot, component)| RecoveryAuditSlotV1 {
            component,
            active: slot.active,
            incoming: slot.incoming,
            rollback: slot.rollback,
            cleanup: slot.cleanup,
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| invalid_recovery())?;
    let commit_evidence_authenticated_absent = matches!(
        kind,
        AuditEvidenceKind::AbortToCurrent | AuditEvidenceKind::AbortedCurrentRestored
    );
    if commit_evidence_authenticated_absent
        && audit_evidence_present_and_valid(
            app_local_data_dir,
            marker,
            COMMIT_EVIDENCE_BASENAME,
            AuditEvidenceKind::FiveSlotCommit,
        )?
        .is_some()
    {
        return Err(invalid_recovery());
    }
    // Abort intent authenticates the absence of a commit *final*.  An
    // unauthoritative interrupted commit install is retained until that abort
    // final is durable, then removed by the post-intent cleanup.  A terminal
    // aborted report, by contrast, proves that all install residue is gone.
    if kind == AuditEvidenceKind::AbortedCurrentRestored
        && audit_evidence_install_residue_present(
            app_local_data_dir,
            marker,
            COMMIT_EVIDENCE_BASENAME,
        )?
    {
        return Err(invalid_recovery());
    }
    let evidence = RecoveryAuditEvidenceV1 {
        schema: AUDIT_EVIDENCE_SCHEMA.to_owned(),
        format_version: 1,
        kind,
        recovery_id: marker.recovery_id.clone(),
        migration_id: marker.migration_id.clone(),
        lineage_id: marker.lineage_id.clone(),
        source_profile_proof_sha256: marker.source_profile_proof_sha256.clone(),
        safety_backup_sha256: marker.safety_backup.bundle_sha256().to_owned(),
        credential_archive_sha256: marker.credential_archive.protected_sha256.clone(),
        current_five_slot_manifest_sha256: marker.current_five_slot_manifest_sha256.clone(),
        target_app_version: marker.target_app_version.clone(),
        marker_phase: marker.phase,
        stage_slot_inventory_sha256: stage_slot_inventory_sha256(marker)?,
        physical_slots,
        credential_delete_prefix: u64::try_from(layout.credential_delete_prefix)
            .map_err(|_| invalid_recovery())?,
        commit_evidence_authenticated_absent,
    };
    validate_audit_evidence(marker, kind, &evidence)?;
    Ok(evidence)
}

fn target_database_matches(
    path: &Path,
    component: V031RecoveryComponent,
    expected: &[u8],
    expected_sha256: &str,
) -> Result<bool, IpcError> {
    if !matches!(
        component,
        V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase
    ) || expected.is_empty()
        || sha256_hex(expected) != expected_sha256
    {
        return Err(invalid_recovery());
    }
    if capture_v031_recovery_slot_fingerprint(path, component)?.is_none() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid_recovery())?;
    if !metadata.is_file() {
        return Err(invalid_recovery());
    }
    if usize::try_from(metadata.len()).ok() != Some(expected.len()) {
        return Ok(false);
    }
    let bytes =
        v031_upgrade_r2::read_bounded_file(path, expected.len()).map_err(|_| invalid_recovery())?;
    if bytes.as_slice() != expected || sha256_hex(&bytes) != expected_sha256 {
        return Ok(false);
    }
    match component {
        V031RecoveryComponent::UserDatabase => {
            database::validate_v031_user_sqlite_image_read_only(&bytes)
                .map_err(|_| invalid_recovery())?;
        }
        V031RecoveryComponent::PrivacyDatabase => {
            privacy::validate_privacy_v1_sqlite_image_read_only(&bytes)
                .map_err(|_| invalid_recovery())?;
        }
        _ => return Err(invalid_recovery()),
    }
    Ok(true)
}

fn slot_is_current(
    observed: &Option<V031RecoverySlotFingerprint>,
    marker: &V031MigrationRecoveryPendingV1,
    component: V031RecoveryComponent,
) -> bool {
    observed.as_ref() == Some(&marker.current_slots[component_index(component)])
}

fn expected_credential_delete_prefix(phase: RecoveryPhase) -> usize {
    if phase.ordinal() >= RecoveryPhase::CredentialApprovedDeleted.ordinal() {
        4
    } else if phase.ordinal() >= RecoveryPhase::CredentialWorkProductDeleted.ordinal() {
        3
    } else if phase.ordinal() >= RecoveryPhase::CredentialTicketDeleted.ordinal() {
        2
    } else if phase.ordinal() >= RecoveryPhase::CredentialQualificationDeleted.ordinal() {
        1
    } else {
        0
    }
}

fn database_slot_matches_phase(
    layout: &ObservedRecoveryLayout,
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
    component: V031RecoveryComponent,
    phase: RecoveryPhase,
) -> Result<bool, IpcError> {
    let slot = &layout.slots[component_index(component)];
    if slot.cleanup.is_some() {
        return Err(invalid_recovery());
    }
    let (stage_phase, moved_phase, installed_phase, cleaned_phase, bytes, sha256) = match component
    {
        V031RecoveryComponent::UserDatabase => (
            RecoveryPhase::UserV10Staged,
            RecoveryPhase::UserMovedToRollback,
            RecoveryPhase::UserInstalled,
            RecoveryPhase::UserRollbackCleaned,
            original.user_database(),
            marker.original_user_sha256.as_str(),
        ),
        V031RecoveryComponent::PrivacyDatabase => (
            RecoveryPhase::SourcesStaged,
            RecoveryPhase::PrivacyMovedToRollback,
            RecoveryPhase::PrivacyInstalled,
            RecoveryPhase::PrivacyRollbackCleaned,
            original.privacy_database(),
            marker.original_privacy_sha256.as_str(),
        ),
        _ => return Err(invalid_recovery()),
    };
    let active_target = target_database_matches(paths.active(component), component, bytes, sha256)?;
    let incoming_target = match paths.incoming(component) {
        Some(path) => target_database_matches(path, component, bytes, sha256)?,
        None => return Err(invalid_recovery()),
    };
    let ordinal = phase.ordinal();
    let matches = if ordinal < stage_phase.ordinal() {
        slot_is_current(&slot.active, marker, component)
            && slot.incoming.is_none()
            && slot.rollback.is_none()
            && !active_target
            && !incoming_target
    } else if ordinal < moved_phase.ordinal() {
        slot_is_current(&slot.active, marker, component)
            && incoming_target
            && slot.rollback.is_none()
            && !active_target
    } else if ordinal == moved_phase.ordinal() {
        slot.active.is_none()
            && incoming_target
            && slot_is_current(&slot.rollback, marker, component)
    } else if ordinal < cleaned_phase.ordinal() {
        active_target
            && slot.incoming.is_none()
            && slot_is_current(&slot.rollback, marker, component)
    } else {
        active_target && slot.incoming.is_none() && slot.rollback.is_none()
    };
    let _ = installed_phase;
    Ok(matches)
}

fn directory_slot_matches_phase(
    layout: &ObservedRecoveryLayout,
    marker: &V031MigrationRecoveryPendingV1,
    component: V031RecoveryComponent,
    phase: RecoveryPhase,
) -> Result<bool, IpcError> {
    let slot = &layout.slots[component_index(component)];
    if slot.incoming.is_some() {
        return Err(invalid_recovery());
    }
    let (moved, cleaned) = match component {
        V031RecoveryComponent::VaultStore => (
            RecoveryPhase::VaultMovedToRollback,
            RecoveryPhase::VaultRollbackCleaned,
        ),
        V031RecoveryComponent::ApprovedWorkspace => (
            RecoveryPhase::ApprovedMovedToRollback,
            RecoveryPhase::ApprovedRollbackCleaned,
        ),
        V031RecoveryComponent::WorkProducts => (
            RecoveryPhase::WorkProductsMovedToRollback,
            RecoveryPhase::WorkProductsRollbackCleaned,
        ),
        _ => return Err(invalid_recovery()),
    };
    Ok(if phase.ordinal() < moved.ordinal() {
        slot_is_current(&slot.active, marker, component)
            && slot.rollback.is_none()
            && slot.cleanup.is_none()
    } else if phase.ordinal() < cleaned.ordinal() {
        slot.active.is_none()
            && slot_is_current(&slot.rollback, marker, component)
            && slot.cleanup.is_none()
    } else if phase == cleaned {
        slot.active.is_none() && slot.rollback.is_none()
    } else {
        slot.active.is_none() && slot.rollback.is_none() && slot.cleanup.is_none()
    })
}

fn layout_matches_phase(
    layout: &ObservedRecoveryLayout,
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
    phase: RecoveryPhase,
) -> Result<bool, IpcError> {
    Ok(
        layout.credential_delete_prefix == expected_credential_delete_prefix(phase)
            && database_slot_matches_phase(
                layout,
                paths,
                marker,
                original,
                V031RecoveryComponent::UserDatabase,
                phase,
            )?
            && database_slot_matches_phase(
                layout,
                paths,
                marker,
                original,
                V031RecoveryComponent::PrivacyDatabase,
                phase,
            )?
            && directory_slot_matches_phase(
                layout,
                marker,
                V031RecoveryComponent::VaultStore,
                phase,
            )?
            && directory_slot_matches_phase(
                layout,
                marker,
                V031RecoveryComponent::ApprovedWorkspace,
                phase,
            )?
            && directory_slot_matches_phase(
                layout,
                marker,
                V031RecoveryComponent::WorkProducts,
                phase,
            )?,
    )
}

fn validate_abort_layout_structure(
    layout: &ObservedRecoveryLayout,
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<(), IpcError> {
    if layout.credential_delete_prefix != 0 {
        return Err(invalid_recovery());
    }
    for component in RECOVERY_COMPONENTS {
        let slot = &layout.slots[component_index(component)];
        let active_current = slot_is_current(&slot.active, marker, component);
        let rollback_current = slot_is_current(&slot.rollback, marker, component);
        if slot.cleanup.is_some() {
            return Err(invalid_recovery());
        }
        if active_current == rollback_current {
            return Err(invalid_recovery());
        }
        match component {
            V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase => {
                if active_current && slot.rollback.is_some()
                    || rollback_current && slot.active.is_some() && slot.incoming.is_some()
                {
                    return Err(invalid_recovery());
                }
            }
            _ => {
                if slot.incoming.is_some()
                    || active_current && slot.rollback.is_some()
                    || rollback_current && slot.active.is_some()
                {
                    return Err(invalid_recovery());
                }
            }
        }
    }
    Ok(())
}

fn validate_live_abort_layout(
    layout: &ObservedRecoveryLayout,
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
) -> Result<(), IpcError> {
    validate_abort_layout_structure(layout, marker)?;
    for component in [
        V031RecoveryComponent::UserDatabase,
        V031RecoveryComponent::PrivacyDatabase,
    ] {
        let slot = &layout.slots[component_index(component)];
        let (bytes, hash) = if component == V031RecoveryComponent::UserDatabase {
            (
                original.user_database(),
                marker.original_user_sha256.as_str(),
            )
        } else {
            (
                original.privacy_database(),
                marker.original_privacy_sha256.as_str(),
            )
        };
        let active_target =
            target_database_matches(paths.active(component), component, bytes, hash)?;
        let incoming_target = target_database_matches(
            paths.incoming(component).ok_or_else(invalid_recovery)?,
            component,
            bytes,
            hash,
        )?;
        let active_current = slot_is_current(&slot.active, marker, component);
        if active_current && active_target
            || slot.active.is_some() && !active_current && !active_target
            || slot.incoming.is_some() && !incoming_target
        {
            return Err(invalid_recovery());
        }
    }
    Ok(())
}

fn validate_evidence_state(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
) -> Result<(bool, bool), IpcError> {
    // Read and authenticate both physical finals before any target-state cross
    // binding.  Their coexistence is an unconditional protocol contradiction.
    let (commit, abort) = commit_abort_finals_exclusive(app_local_data_dir, marker)?;
    if let Some((evidence, _)) = &commit {
        validate_audit_evidence_cross_binding(
            app_local_data_dir,
            marker,
            AuditEvidenceKind::FiveSlotCommit,
            evidence,
        )?;
    }
    if let Some((evidence, _)) = &abort {
        validate_audit_evidence_cross_binding(
            app_local_data_dir,
            marker,
            AuditEvidenceKind::AbortToCurrent,
            evidence,
        )?;
    }
    let commit = commit.map(|(_, hash)| hash);
    let abort = abort.map(|(_, hash)| hash);
    let applied = audit_evidence_present_and_valid(
        app_local_data_dir,
        marker,
        APPLIED_REPORT_BASENAME,
        AuditEvidenceKind::AppliedDowngrade,
    )?;
    let aborted = audit_evidence_present_and_valid(
        app_local_data_dir,
        marker,
        ABORTED_REPORT_BASENAME,
        AuditEvidenceKind::AbortedCurrentRestored,
    )?;
    if marker.phase.ordinal() >= RecoveryPhase::FiveSlotCommitted.ordinal() {
        if commit.is_none()
            || marker.commit_evidence_protected_sha256.is_none()
            || commit.as_deref() != marker.commit_evidence_protected_sha256.as_deref()
        {
            return Err(invalid_recovery());
        }
    } else if marker.commit_evidence_protected_sha256.is_some()
        || commit.is_some() && marker.phase != RecoveryPhase::WorkProductsMovedToRollback
    {
        return Err(invalid_recovery());
    }
    if marker.phase == RecoveryPhase::ReportInstalled {
        if applied.is_none()
            || marker.report_protected_sha256.is_none()
            || applied.as_deref() != marker.report_protected_sha256.as_deref()
        {
            return Err(invalid_recovery());
        }
    } else if marker.report_protected_sha256.is_some()
        || applied.is_some() && marker.phase != RecoveryPhase::TargetVerified
    {
        return Err(invalid_recovery());
    }
    if aborted.is_some() && abort.is_none() || abort.is_some() && !marker.phase.is_precommit() {
        return Err(invalid_recovery());
    }
    Ok((commit.is_some(), abort.is_some()))
}

pub(crate) fn observe_v031_migration_recovery_read_only(
    app_local_data_dir: &Path,
) -> Result<V031MigrationRecoveryObservation, IpcError> {
    if !privacy_manager::is_normal_local_absolute(app_local_data_dir) {
        return Err(invalid_recovery());
    }
    match fs::symlink_metadata(app_local_data_dir) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(V031MigrationRecoveryObservation::Absent);
        }
        Err(_) => return Err(invalid_recovery()),
        Ok(metadata)
            if !metadata.is_dir()
                || !privacy_manager::local_path_chain_is_ordinary(app_local_data_dir) =>
        {
            return Err(invalid_recovery());
        }
        Ok(_) => {}
    }
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let final_present = v031_recovery_path_is_present(&final_path)?;
    let incoming_present = v031_recovery_path_is_present(&incoming_path)?;
    // A staged initial marker is deliberately non-authoritative.  Startup must
    // not parse, promote, delete, or otherwise let a partial/tampered staging
    // residue block ordinary arbitration while the formal marker is absent.
    if !final_present {
        return Ok(V031MigrationRecoveryObservation::Absent);
    }
    ensure_ordinary_restore_markers_absent(app_local_data_dir)?;
    reject_unknown_v031_recovery_restore_siblings(app_local_data_dir)?;
    let (
        marker,
        marker_protected_sha256,
        predecessor_marker_protected_sha256,
        successor_marker_protected_sha256,
        marker_install_state,
    ) = match incoming_present {
        false => {
            let (marker, protected_sha256) = read_marker(&final_path)?;
            (
                marker,
                protected_sha256,
                None,
                None,
                MarkerInstallState::Final,
            )
        }
        true => {
            let (current, current_protected_sha256) = read_marker(&final_path)?;
            let (candidate, candidate_protected_sha256) = read_marker(&incoming_path)?;
            if !direct_marker_successor(&current, &candidate) {
                return Err(invalid_recovery());
            }
            if audit_evidence_present_and_valid(
                app_local_data_dir,
                &current,
                ABORT_INTENT_BASENAME,
                AuditEvidenceKind::AbortToCurrent,
            )?
            .is_some()
            {
                (
                    current,
                    current_protected_sha256,
                    None,
                    Some(candidate_protected_sha256),
                    MarkerInstallState::DiscardIncomingForAbort,
                )
            } else {
                (
                    candidate,
                    candidate_protected_sha256,
                    Some(current_protected_sha256),
                    None,
                    MarkerInstallState::ReplaceFinalWithIncoming,
                )
            }
        }
    };
    let directory = audit_directory(app_local_data_dir, &marker.recovery_id)?;
    validate_audit_directory_shape(&directory)?;
    verify_v031_recovery_safety_backup_read_only(
        &directory.join(SAFETY_BACKUP_BASENAME),
        &marker.safety_backup,
    )?;
    let credentials = open_credential_archive(
        &directory.join(CREDENTIAL_ARCHIVE_BASENAME),
        &marker.credential_archive,
    )?;
    let original =
        open_authenticated_original_v2_images_for_recovery(app_local_data_dir, &marker.lineage_id)
            .map_err(|_| invalid_recovery())?;
    if !marker_matches_original(&marker, &original) {
        return Err(invalid_recovery());
    }
    let (commit_observed, authenticated_abort_intent) =
        validate_evidence_state(app_local_data_dir, &marker)?;
    let credential_gate =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(&credentials)
            .map_err(|_| invalid_recovery())?;
    let paths = v031_recovery_swap_paths(app_local_data_dir);
    validate_approved_auxiliary_namespace(app_local_data_dir, &paths)?;
    let transient_precommit_staging = database_staging_present(&paths)?
        || v031_recovery_path_is_present(&marker_staging_path(app_local_data_dir))?
        || any_audit_evidence_install_residue_present(app_local_data_dir, &marker)?;
    let layout = capture_recovery_layout(&paths, credential_gate.prefix_len())?;
    let physical_phase = if authenticated_abort_intent {
        validate_live_abort_layout(&layout, &paths, &marker, &original)?;
        marker.phase
    } else {
        let current_matches =
            layout_matches_phase(&layout, &paths, &marker, &original, marker.phase)?;
        let successor_matches = match marker.phase.successor() {
            Some(successor) => {
                layout_matches_phase(&layout, &paths, &marker, &original, successor)?
            }
            None => false,
        };
        match marker_install_state {
            MarkerInstallState::ReplaceFinalWithIncoming if current_matches => marker.phase,
            MarkerInstallState::ReplaceFinalWithIncoming => return Err(invalid_recovery()),
            MarkerInstallState::Final if current_matches => marker.phase,
            MarkerInstallState::Final if successor_matches => {
                marker.phase.successor().ok_or_else(invalid_recovery)?
            }
            MarkerInstallState::Final => return Err(invalid_recovery()),
            MarkerInstallState::DiscardIncomingForAbort => return Err(invalid_recovery()),
        }
    };
    let abort_requested = authenticated_abort_intent
        || marker.phase.is_precommit()
            && !commit_observed
            && (transient_precommit_staging
                || marker.phase != RecoveryPhase::Requested
                || physical_phase != RecoveryPhase::Requested
                || marker_install_state != MarkerInstallState::Final);
    Ok(V031MigrationRecoveryObservation::Authenticated(Box::new(
        V031MigrationRecoveryGate {
            marker,
            marker_protected_sha256,
            predecessor_marker_protected_sha256,
            successor_marker_protected_sha256,
            marker_install_state,
            physical_phase,
            abort_requested,
            original,
            credentials,
        },
    )))
}

fn reconcile_gate_marker(
    app_local_data_dir: &Path,
    gate: &V031MigrationRecoveryGate,
) -> Result<(), IpcError> {
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let staging_path = marker_staging_path(app_local_data_dir);
    match gate.marker_install_state {
        MarkerInstallState::Final => {
            let (marker, protected_sha256) = read_marker(&final_path)?;
            if marker != gate.marker
                || protected_sha256 != gate.marker_protected_sha256
                || v031_recovery_path_is_present(&incoming_path)?
                || v031_recovery_path_is_present(&staging_path)?
            {
                return Err(invalid_recovery());
            }
        }
        MarkerInstallState::ReplaceFinalWithIncoming => {
            let (current, current_protected_sha256) = read_marker(&final_path)?;
            let (incoming, incoming_protected_sha256) = read_marker(&incoming_path)?;
            if incoming != gate.marker
                || incoming_protected_sha256 != gate.marker_protected_sha256
                || Some(current_protected_sha256.as_str())
                    != gate.predecessor_marker_protected_sha256.as_deref()
                || gate.successor_marker_protected_sha256.is_some()
                || !direct_marker_successor(&current, &incoming)
                || v031_recovery_path_is_present(&staging_path)?
            {
                return Err(invalid_recovery());
            }
            v031_upgrade_r2::replace_existing_sibling_write_through(&incoming_path, &final_path)
                .map_err(|_| io_recovery())?;
            sync_directory(app_local_data_dir)?;
            let (installed, protected_sha256) = read_marker(&final_path)?;
            if installed != gate.marker
                || protected_sha256 != gate.marker_protected_sha256
                || v031_recovery_path_is_present(&incoming_path)?
            {
                return Err(invalid_recovery());
            }
        }
        // Abort-owned marker residue is reconciled only after the authenticated
        // abort final has been installed and reread.
        MarkerInstallState::DiscardIncomingForAbort => return Err(invalid_recovery()),
    }
    Ok(())
}

fn ensure_target_database_incoming(
    paths: &V031RecoverySwapPaths,
    component: V031RecoveryComponent,
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<V031RecoverySlotFingerprint, IpcError> {
    let incoming = paths.incoming(component).ok_or_else(invalid_recovery)?;
    let staging = paths.staging(component).ok_or_else(invalid_recovery)?;
    if !v031_recovery_path_is_present(incoming)? {
        return write_v031_recovery_database_incoming(incoming, component, bytes, expected_sha256);
    }
    if v031_recovery_path_is_present(staging)?
        || !target_database_matches(incoming, component, bytes, expected_sha256)?
    {
        return Err(invalid_recovery());
    }
    capture_v031_recovery_slot_fingerprint(incoming, component)?.ok_or_else(invalid_recovery)
}

fn move_current_active_to_rollback(
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    component: V031RecoveryComponent,
) -> Result<(), IpcError> {
    let expected = &marker.current_slots[component_index(component)];
    let active = capture_v031_recovery_slot_fingerprint(paths.active(component), component)?;
    let rollback = capture_v031_recovery_slot_fingerprint(paths.rollback(component), component)?;
    if active.is_none() && rollback.as_ref() == Some(expected) {
        return Ok(());
    }
    if active.as_ref() != Some(expected) || rollback.is_some() {
        return Err(invalid_recovery());
    }
    rename_v031_recovery_component_no_replace(
        paths.active(component),
        paths.rollback(component),
        component,
        expected,
    )
}

fn install_target_database_from_incoming(
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    component: V031RecoveryComponent,
    bytes: &[u8],
    expected_sha256: &str,
) -> Result<(), IpcError> {
    let incoming = paths.incoming(component).ok_or_else(invalid_recovery)?;
    let rollback = capture_v031_recovery_slot_fingerprint(paths.rollback(component), component)?;
    if rollback.as_ref() != Some(&marker.current_slots[component_index(component)]) {
        return Err(invalid_recovery());
    }
    if target_database_matches(paths.active(component), component, bytes, expected_sha256)?
        && !v031_recovery_path_is_present(incoming)?
    {
        return Ok(());
    }
    if v031_recovery_path_is_present(paths.active(component))? {
        return Err(invalid_recovery());
    }
    let expected = ensure_target_database_incoming(paths, component, bytes, expected_sha256)?;
    rename_v031_recovery_component_no_replace(
        incoming,
        paths.active(component),
        component,
        &expected,
    )?;
    if !target_database_matches(paths.active(component), component, bytes, expected_sha256)? {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn stage_current_rollback_cleanup(
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    component: V031RecoveryComponent,
) -> Result<(), IpcError> {
    let expected = &marker.current_slots[component_index(component)];
    let rollback = capture_v031_recovery_slot_fingerprint(paths.rollback(component), component)?;
    if let Some(cleanup) = paths.cleanup(component) {
        let cleanup_fingerprint = capture_v031_recovery_slot_fingerprint(cleanup, component)?;
        if rollback.is_none() && cleanup_fingerprint.as_ref() == Some(expected) {
            return Ok(());
        }
        if rollback.as_ref() != Some(expected) || cleanup_fingerprint.is_some() {
            return Err(invalid_recovery());
        }
        rename_v031_recovery_component_no_replace(
            paths.rollback(component),
            cleanup,
            component,
            expected,
        )?;
        if capture_v031_recovery_slot_fingerprint(cleanup, component)?.as_ref() != Some(expected)
            || v031_recovery_path_is_present(paths.rollback(component))?
        {
            return Err(invalid_recovery());
        }
        return Ok(());
    }
    if rollback.is_none() {
        return Ok(());
    }
    if rollback.as_ref() != Some(expected) {
        return Err(invalid_recovery());
    }
    remove_v031_recovery_component(paths.rollback(component), component)?;
    if v031_recovery_path_is_present(paths.rollback(component))? {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn finish_directory_cleanup_tombstone(
    paths: &V031RecoverySwapPaths,
    component: V031RecoveryComponent,
) -> Result<(), IpcError> {
    let cleanup = paths.cleanup(component).ok_or_else(invalid_recovery)?;
    if v031_recovery_path_is_present(paths.rollback(component))? {
        return Err(invalid_recovery());
    }
    if v031_recovery_path_is_present(cleanup)? {
        remove_v031_recovery_component(cleanup, component)?;
    }
    if v031_recovery_path_is_present(cleanup)? {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn revalidate_precommit_authority(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    credentials: &V031ApprovedMcpCredentialSnapshot,
    allow_commit_boundary_evidence: bool,
) -> Result<(), IpcError> {
    let directory = audit_directory(app_local_data_dir, &marker.recovery_id)?;
    validate_audit_directory_shape(&directory)?;
    verify_v031_recovery_safety_backup_read_only(
        &directory.join(SAFETY_BACKUP_BASENAME),
        &marker.safety_backup,
    )?;
    let archived = open_credential_archive(
        &directory.join(CREDENTIAL_ARCHIVE_BASENAME),
        &marker.credential_archive,
    )?;
    let archived_plaintext = archived
        .to_canonical_archive_plaintext()
        .map_err(|_| invalid_recovery())?;
    let expected_plaintext = credentials
        .to_canonical_archive_plaintext()
        .map_err(|_| invalid_recovery())?;
    if archived_plaintext.as_bytes() != expected_plaintext.as_bytes() {
        return Err(invalid_recovery());
    }
    authenticate_v031_recovery_approved_mcp_credentials_read_only(credentials)
        .map_err(|_| invalid_recovery())?;
    let original =
        open_authenticated_original_v2_images_for_recovery(app_local_data_dir, &marker.lineage_id)
            .map_err(|_| invalid_recovery())?;
    if !marker_matches_original(marker, &original) {
        return Err(invalid_recovery());
    }
    let (commit_present, abort_present) = validate_evidence_state(app_local_data_dir, marker)?;
    if abort_present || commit_present && !allow_commit_boundary_evidence {
        return Err(invalid_recovery());
    }
    if !commit_present && any_audit_evidence_install_residue_present(app_local_data_dir, marker)? {
        return Err(invalid_recovery());
    }
    let paths = v031_recovery_swap_paths(app_local_data_dir);
    validate_approved_auxiliary_namespace(app_local_data_dir, &paths)?;
    let credential_gate =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(credentials)
            .map_err(|_| invalid_recovery())?;
    let layout = capture_recovery_layout(&paths, credential_gate.prefix_len())?;
    let matches_current = layout_matches_phase(&layout, &paths, marker, &original, marker.phase)?;
    let matches_successor = match marker.phase.successor() {
        Some(successor) => layout_matches_phase(&layout, &paths, marker, &original, successor)?,
        None => false,
    };
    if !matches_current && !matches_successor {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn advance_credential_deletion(
    marker: &V031MigrationRecoveryPendingV1,
    credentials: &V031ApprovedMcpCredentialSnapshot,
    next_phase: RecoveryPhase,
) -> Result<(), IpcError> {
    let observed =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(credentials)
            .map_err(|_| invalid_recovery())?;
    let current_prefix = expected_credential_delete_prefix(marker.phase);
    let next_prefix = expected_credential_delete_prefix(next_phase);
    if next_prefix != current_prefix + 1 {
        return Err(invalid_recovery());
    }
    if observed.prefix_len() == next_prefix {
        return Ok(());
    }
    if observed.prefix_len() != current_prefix {
        return Err(invalid_recovery());
    }
    let advanced =
        advance_v031_recovery_approved_mcp_credential_delete_prefix(credentials, &observed)
            .map_err(|_| invalid_recovery())?;
    if advanced.prefix_len() != next_prefix {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn verify_target_state(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
    credentials: &V031ApprovedMcpCredentialSnapshot,
) -> Result<(), IpcError> {
    let paths = v031_recovery_swap_paths(app_local_data_dir);
    ensure_ordinary_restore_markers_absent(app_local_data_dir)?;
    reject_unknown_v031_recovery_restore_siblings(app_local_data_dir)?;
    validate_approved_auxiliary_namespace(app_local_data_dir, &paths)?;
    let credential_gate =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(credentials)
            .map_err(|_| invalid_recovery())?;
    let layout = capture_recovery_layout(&paths, credential_gate.prefix_len())?;
    if database_staging_present(&paths)?
        || !layout_matches_phase(
            &layout,
            &paths,
            marker,
            original,
            RecoveryPhase::TargetVerified,
        )?
        || v031_recovery_path_is_present(
            &app_local_data_dir.join("privacy/approved-mcp/ticket-sessions"),
        )?
        || v031_recovery_path_is_present(
            &app_local_data_dir.join("privacy/approved-mcp/qualification"),
        )?
    {
        return Err(invalid_recovery());
    }
    let audit = audit_directory(app_local_data_dir, &marker.recovery_id)?;
    validate_audit_directory_shape(&audit)?;
    verify_v031_recovery_safety_backup_read_only(
        &audit.join(SAFETY_BACKUP_BASENAME),
        &marker.safety_backup,
    )?;
    let reopened =
        open_authenticated_original_v2_images_for_recovery(app_local_data_dir, &marker.lineage_id)
            .map_err(|_| invalid_recovery())?;
    if !marker_matches_original(marker, &reopened) {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn restore_current_component(
    paths: &V031RecoverySwapPaths,
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
    component: V031RecoveryComponent,
) -> Result<(), IpcError> {
    let expected = &marker.current_slots[component_index(component)];
    let active = capture_v031_recovery_slot_fingerprint(paths.active(component), component)?;
    let rollback = capture_v031_recovery_slot_fingerprint(paths.rollback(component), component)?;
    if active.as_ref() == Some(expected) {
        if rollback.is_some() {
            return Err(invalid_recovery());
        }
    } else if rollback.as_ref() == Some(expected) {
        if matches!(
            component,
            V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase
        ) {
            let (bytes, hash) = if component == V031RecoveryComponent::UserDatabase {
                (
                    original.user_database(),
                    marker.original_user_sha256.as_str(),
                )
            } else {
                (
                    original.privacy_database(),
                    marker.original_privacy_sha256.as_str(),
                )
            };
            if active.is_some() {
                if !target_database_matches(paths.active(component), component, bytes, hash)? {
                    return Err(invalid_recovery());
                }
                remove_v031_recovery_component(paths.active(component), component)?;
            }
        } else if active.is_some() {
            return Err(invalid_recovery());
        }
        rename_v031_recovery_component_no_replace(
            paths.rollback(component),
            paths.active(component),
            component,
            expected,
        )?;
    } else {
        return Err(invalid_recovery());
    }
    if let Some(incoming) = paths.incoming(component) {
        if capture_v031_recovery_slot_fingerprint(incoming, component)?.is_some() {
            if !matches!(
                component,
                V031RecoveryComponent::UserDatabase | V031RecoveryComponent::PrivacyDatabase
            ) {
                return Err(invalid_recovery());
            }
            let (bytes, hash) = if component == V031RecoveryComponent::UserDatabase {
                (
                    original.user_database(),
                    marker.original_user_sha256.as_str(),
                )
            } else {
                (
                    original.privacy_database(),
                    marker.original_privacy_sha256.as_str(),
                )
            };
            if !target_database_matches(incoming, component, bytes, hash)? {
                return Err(invalid_recovery());
            }
            remove_v031_recovery_component(incoming, component)?;
        }
    }
    if capture_v031_recovery_slot_fingerprint(paths.active(component), component)?.as_ref()
        != Some(expected)
        || capture_v031_recovery_slot_fingerprint(paths.rollback(component), component)?.is_some()
        || match paths.incoming(component) {
            Some(incoming) => {
                capture_v031_recovery_slot_fingerprint(incoming, component)?.is_some()
            }
            None => false,
        }
    {
        return Err(invalid_recovery());
    }
    Ok(())
}

fn authenticate_authoritative_marker_for_abort(
    app_local_data_dir: &Path,
    expectation: AbortMarkerExpectation<'_>,
) -> Result<AuthenticatedAbortMarkerAuthority, IpcError> {
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let (formal, formal_protected_sha256) = read_marker(&final_path)?;
    if !formal.phase.is_precommit() {
        return Err(invalid_recovery());
    }

    let successor = match expectation {
        AbortMarkerExpectation::Observed(proof) => match proof.marker_install_state {
            MarkerInstallState::Final => {
                if proof.predecessor_marker_protected_sha256.is_some()
                    || proof.successor_marker_protected_sha256.is_some()
                    || formal != *proof.marker
                    || formal_protected_sha256 != proof.marker_protected_sha256
                    || v031_recovery_path_is_present(&incoming_path)?
                {
                    return Err(invalid_recovery());
                }
                None
            }
            MarkerInstallState::ReplaceFinalWithIncoming => {
                let predecessor_protected_sha256 = proof
                    .predecessor_marker_protected_sha256
                    .ok_or_else(invalid_recovery)?;
                if proof.successor_marker_protected_sha256.is_some()
                    || formal_protected_sha256 != predecessor_protected_sha256
                    || !v031_recovery_path_is_present(&incoming_path)?
                {
                    return Err(invalid_recovery());
                }
                let (incoming, incoming_protected_sha256) = read_marker(&incoming_path)?;
                if incoming != *proof.marker
                    || incoming_protected_sha256 != proof.marker_protected_sha256
                    || !direct_marker_successor(&formal, &incoming)
                {
                    return Err(invalid_recovery());
                }
                Some(AuthenticatedAbortMarkerSuccessor {
                    marker: incoming,
                    protected_sha256: incoming_protected_sha256,
                })
            }
            MarkerInstallState::DiscardIncomingForAbort => {
                let successor_protected_sha256 = proof
                    .successor_marker_protected_sha256
                    .ok_or_else(invalid_recovery)?;
                if proof.predecessor_marker_protected_sha256.is_some()
                    || formal != *proof.marker
                    || formal_protected_sha256 != proof.marker_protected_sha256
                    || !v031_recovery_path_is_present(&incoming_path)?
                {
                    return Err(invalid_recovery());
                }
                let (incoming, incoming_protected_sha256) = read_marker(&incoming_path)?;
                if incoming_protected_sha256 != successor_protected_sha256
                    || !direct_marker_successor(&formal, &incoming)
                {
                    return Err(invalid_recovery());
                }
                Some(AuthenticatedAbortMarkerSuccessor {
                    marker: incoming,
                    protected_sha256: incoming_protected_sha256,
                })
            }
        },
        AbortMarkerExpectation::ForwardError(expected) => {
            let incoming = if v031_recovery_path_is_present(&incoming_path)? {
                let (marker, protected_sha256) = read_marker(&incoming_path)?;
                Some(AuthenticatedAbortMarkerSuccessor {
                    marker,
                    protected_sha256,
                })
            } else {
                None
            };
            match &incoming {
                None if formal == *expected => None,
                Some(successor)
                    if formal == *expected
                        && direct_marker_successor(&formal, &successor.marker) =>
                {
                    Some(AuthenticatedAbortMarkerSuccessor {
                        marker: successor.marker.clone(),
                        protected_sha256: successor.protected_sha256.clone(),
                    })
                }
                None if direct_marker_successor(expected, &formal) => None,
                _ => return Err(invalid_recovery()),
            }
        }
    };
    Ok(AuthenticatedAbortMarkerAuthority {
        formal_marker: formal,
        formal_protected_sha256,
        successor,
    })
}

fn cleanup_precommit_residue_after_authenticated_abort(
    app_local_data_dir: &Path,
    authority: &AuthenticatedAbortMarkerAuthority,
    expected_abort: &RecoveryAuditEvidenceV1,
) -> Result<(), IpcError> {
    let marker = &authority.formal_marker;
    let abort_path = audit_evidence_path(app_local_data_dir, marker, ABORT_INTENT_BASENAME)?;
    let (installed_abort, installed_abort_hash) =
        read_audit_evidence_file(&abort_path, marker, AuditEvidenceKind::AbortToCurrent)?;
    validate_audit_evidence_cross_binding(
        app_local_data_dir,
        marker,
        AuditEvidenceKind::AbortToCurrent,
        &installed_abort,
    )?;
    if installed_abort != *expected_abort
        || audit_evidence_present_and_valid(
            app_local_data_dir,
            marker,
            COMMIT_EVIDENCE_BASENAME,
            AuditEvidenceKind::FiveSlotCommit,
        )?
        .is_some()
    {
        return Err(invalid_recovery());
    }

    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let (formal, formal_protected_sha256) = read_marker(&final_path)?;
    if formal != *marker
        || formal_protected_sha256 != authority.formal_protected_sha256
        || !formal.phase.is_precommit()
    {
        return Err(invalid_recovery());
    }

    // Inner staging is never authority and must be removed and proved absent
    // before the direct-successor incoming is authenticated or discarded.
    let marker_staging_path = marker_staging_path(app_local_data_dir);
    remove_fixed_file(&marker_staging_path)?;
    if v031_recovery_path_is_present(&marker_staging_path)? {
        return Err(invalid_recovery());
    }
    match &authority.successor {
        Some(expected_successor) => {
            if !v031_recovery_path_is_present(&incoming_path)? {
                return Err(invalid_recovery());
            }
            let (incoming, incoming_protected_sha256) = read_marker(&incoming_path)?;
            if incoming != expected_successor.marker
                || incoming_protected_sha256 != expected_successor.protected_sha256
                || !direct_marker_successor(&formal, &incoming)
            {
                return Err(invalid_recovery());
            }
            remove_fixed_file(&incoming_path)?;
            if v031_recovery_path_is_present(&incoming_path)? {
                return Err(invalid_recovery());
            }
        }
        None if v031_recovery_path_is_present(&incoming_path)? => {
            return Err(invalid_recovery());
        }
        None => {}
    }

    let paths = v031_recovery_swap_paths(app_local_data_dir);
    remove_database_staging_residue(&paths)?;
    for basename in [
        COMMIT_EVIDENCE_BASENAME,
        ABORT_INTENT_BASENAME,
        APPLIED_REPORT_BASENAME,
        ABORTED_REPORT_BASENAME,
    ] {
        cleanup_audit_evidence_install_residue(app_local_data_dir, marker, basename)?;
    }

    let (reread_abort, reread_abort_hash) =
        read_audit_evidence_file(&abort_path, marker, AuditEvidenceKind::AbortToCurrent)?;
    if reread_abort != installed_abort
        || reread_abort_hash != installed_abort_hash
        || audit_evidence_present_and_valid(
            app_local_data_dir,
            marker,
            COMMIT_EVIDENCE_BASENAME,
            AuditEvidenceKind::FiveSlotCommit,
        )?
        .is_some()
        || {
            let (reread_marker, reread_marker_hash) = read_marker(&final_path)?;
            reread_marker != *marker || reread_marker_hash != authority.formal_protected_sha256
        }
        || v031_recovery_path_is_present(&incoming_path)?
        || v031_recovery_path_is_present(&marker_staging_path)?
        || database_staging_present(&paths)?
    {
        return Err(invalid_recovery());
    }
    ensure_all_audit_evidence_install_residue_absent(app_local_data_dir, marker)?;
    Ok(())
}

fn abort_to_current(
    app_local_data_dir: &Path,
    expectation: AbortMarkerExpectation<'_>,
    original: &AuthenticatedOriginalV2Images,
    credentials: &V031ApprovedMcpCredentialSnapshot,
) -> Result<(), IpcError> {
    // Authentication is deliberately mutation-free.  All precommit residue is
    // retained until the abort final below has become durable and is reread.
    let authority = authenticate_authoritative_marker_for_abort(app_local_data_dir, expectation)?;
    let marker = &authority.formal_marker;
    if audit_evidence_present_and_valid(
        app_local_data_dir,
        marker,
        COMMIT_EVIDENCE_BASENAME,
        AuditEvidenceKind::FiveSlotCommit,
    )?
    .is_some()
    {
        return Err(invalid_recovery());
    }
    let paths = v031_recovery_swap_paths(app_local_data_dir);
    let credential_gate =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(credentials)
            .map_err(|_| invalid_recovery())?;
    let abort_layout = capture_recovery_layout(&paths, credential_gate.prefix_len())?;
    validate_live_abort_layout(&abort_layout, &paths, marker, original)?;
    let abort_evidence = capture_recovery_audit_evidence(
        app_local_data_dir,
        marker,
        credentials,
        AuditEvidenceKind::AbortToCurrent,
    )?;
    install_or_verify_audit_evidence(
        app_local_data_dir,
        marker,
        ABORT_INTENT_BASENAME,
        AuditEvidenceKind::AbortToCurrent,
        &abort_evidence,
    )?;
    let abort_intent_path = audit_evidence_path(app_local_data_dir, marker, ABORT_INTENT_BASENAME)?;
    let (installed_abort_intent, _) = read_audit_evidence_file(
        &abort_intent_path,
        marker,
        AuditEvidenceKind::AbortToCurrent,
    )?;
    if audit_evidence_present_and_valid(
        app_local_data_dir,
        marker,
        COMMIT_EVIDENCE_BASENAME,
        AuditEvidenceKind::FiveSlotCommit,
    )?
    .is_some()
    {
        return Err(invalid_recovery());
    }
    cleanup_precommit_residue_after_authenticated_abort(
        app_local_data_dir,
        &authority,
        &installed_abort_intent,
    )?;
    let credential_gate =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(credentials)
            .map_err(|_| invalid_recovery())?;
    let before_reverse = capture_recovery_layout(&paths, credential_gate.prefix_len())?;
    if !abort_layout_is_legal_reverse_prefix(&before_reverse, &installed_abort_intent, marker)? {
        return Err(invalid_recovery());
    }
    for component in [
        V031RecoveryComponent::WorkProducts,
        V031RecoveryComponent::ApprovedWorkspace,
        V031RecoveryComponent::VaultStore,
        V031RecoveryComponent::PrivacyDatabase,
        V031RecoveryComponent::UserDatabase,
    ] {
        restore_current_component(&paths, marker, original, component)?;
    }
    restore_v031_recovery_approved_mcp_credentials_exact(credentials)
        .map_err(|_| invalid_recovery())?;
    let credential_gate =
        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(credentials)
            .map_err(|_| invalid_recovery())?;
    let layout = capture_recovery_layout(&paths, credential_gate.prefix_len())?;
    remove_database_staging_residue(&paths)?;
    if database_staging_present(&paths)?
        || !layout_matches_phase(&layout, &paths, marker, original, RecoveryPhase::Requested)?
    {
        return Err(invalid_recovery());
    }
    let aborted_evidence = capture_recovery_audit_evidence(
        app_local_data_dir,
        marker,
        credentials,
        AuditEvidenceKind::AbortedCurrentRestored,
    )?;
    install_or_verify_audit_evidence(
        app_local_data_dir,
        marker,
        ABORTED_REPORT_BASENAME,
        AuditEvidenceKind::AbortedCurrentRestored,
        &aborted_evidence,
    )?;
    ensure_all_audit_evidence_install_residue_absent(app_local_data_dir, marker)?;
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    let staging_path = marker_staging_path(app_local_data_dir);
    if v031_recovery_path_is_present(&incoming_path)?
        || v031_recovery_path_is_present(&staging_path)?
    {
        return Err(invalid_recovery());
    }
    let (formal, formal_protected_sha256) = read_marker(&final_path)?;
    if formal != *marker || formal_protected_sha256 != authority.formal_protected_sha256 {
        return Err(invalid_recovery());
    }
    remove_fixed_file(&final_path)?;
    Ok(())
}

fn finish_success_marker(
    app_local_data_dir: &Path,
    marker: &V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
    credentials: &V031ApprovedMcpCredentialSnapshot,
) -> Result<AppliedDowngrade, IpcError> {
    if marker.phase != RecoveryPhase::ReportInstalled {
        return Err(invalid_recovery());
    }
    verify_target_state(app_local_data_dir, marker, original, credentials)?;
    let (commit_present, abort_present) = validate_evidence_state(app_local_data_dir, marker)?;
    if !commit_present || abort_present {
        return Err(invalid_recovery());
    }
    let report = audit_evidence_present_and_valid(
        app_local_data_dir,
        marker,
        APPLIED_REPORT_BASENAME,
        AuditEvidenceKind::AppliedDowngrade,
    )?;
    if report.is_none()
        || marker.report_protected_sha256.is_none()
        || report.as_deref() != marker.report_protected_sha256.as_deref()
    {
        return Err(invalid_recovery());
    }
    ensure_all_audit_evidence_install_residue_absent(app_local_data_dir, marker)?;
    let (final_path, incoming_path) = marker_paths(app_local_data_dir);
    if v031_recovery_path_is_present(&incoming_path)?
        || v031_recovery_path_is_present(&marker_staging_path(app_local_data_dir))?
        || read_marker(&final_path)?.0 != *marker
    {
        return Err(invalid_recovery());
    }
    remove_fixed_file(&final_path)?;
    if v031_recovery_path_is_present(&final_path)? || v031_recovery_path_is_present(&incoming_path)?
    {
        return Err(invalid_recovery());
    }
    Ok(AppliedDowngrade {
        target_app_version: TARGET_APP_VERSION,
    })
}

fn run_forward_recovery(
    app_local_data_dir: &Path,
    mut marker: V031MigrationRecoveryPendingV1,
    original: &AuthenticatedOriginalV2Images,
    credentials: &V031ApprovedMcpCredentialSnapshot,
) -> Result<AppliedDowngrade, (IpcError, Box<V031MigrationRecoveryPendingV1>)> {
    let paths = v031_recovery_swap_paths(app_local_data_dir);
    loop {
        let step = (|| -> Result<Option<AppliedDowngrade>, IpcError> {
            match marker.phase {
                RecoveryPhase::Requested => {
                    ensure_target_database_incoming(
                        &paths,
                        V031RecoveryComponent::UserDatabase,
                        original.user_database(),
                        &marker.original_user_sha256,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::UserV10Staged,
                        None,
                    )?;
                }
                RecoveryPhase::UserV10Staged => {
                    ensure_target_database_incoming(
                        &paths,
                        V031RecoveryComponent::PrivacyDatabase,
                        original.privacy_database(),
                        &marker.original_privacy_sha256,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::SourcesStaged,
                        None,
                    )?;
                }
                RecoveryPhase::SourcesStaged => {
                    revalidate_precommit_authority(
                        app_local_data_dir,
                        &marker,
                        credentials,
                        false,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::CommitReady,
                        None,
                    )?;
                }
                RecoveryPhase::CommitReady => {
                    revalidate_precommit_authority(
                        app_local_data_dir,
                        &marker,
                        credentials,
                        false,
                    )?;
                    move_current_active_to_rollback(
                        &paths,
                        &marker,
                        V031RecoveryComponent::UserDatabase,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::UserMovedToRollback,
                        None,
                    )?;
                }
                RecoveryPhase::UserMovedToRollback => {
                    install_target_database_from_incoming(
                        &paths,
                        &marker,
                        V031RecoveryComponent::UserDatabase,
                        original.user_database(),
                        &marker.original_user_sha256,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::UserInstalled,
                        None,
                    )?;
                }
                RecoveryPhase::UserInstalled => {
                    move_current_active_to_rollback(
                        &paths,
                        &marker,
                        V031RecoveryComponent::PrivacyDatabase,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::PrivacyMovedToRollback,
                        None,
                    )?;
                }
                RecoveryPhase::PrivacyMovedToRollback => {
                    install_target_database_from_incoming(
                        &paths,
                        &marker,
                        V031RecoveryComponent::PrivacyDatabase,
                        original.privacy_database(),
                        &marker.original_privacy_sha256,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::PrivacyInstalled,
                        None,
                    )?;
                }
                RecoveryPhase::PrivacyInstalled => {
                    move_current_active_to_rollback(
                        &paths,
                        &marker,
                        V031RecoveryComponent::VaultStore,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::VaultMovedToRollback,
                        None,
                    )?;
                }
                RecoveryPhase::VaultMovedToRollback => {
                    move_current_active_to_rollback(
                        &paths,
                        &marker,
                        V031RecoveryComponent::ApprovedWorkspace,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::ApprovedMovedToRollback,
                        None,
                    )?;
                }
                RecoveryPhase::ApprovedMovedToRollback => {
                    move_current_active_to_rollback(
                        &paths,
                        &marker,
                        V031RecoveryComponent::WorkProducts,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::WorkProductsMovedToRollback,
                        None,
                    )?;
                }
                RecoveryPhase::WorkProductsMovedToRollback => {
                    revalidate_precommit_authority(app_local_data_dir, &marker, credentials, true)?;
                    let credential_gate =
                        observe_v031_recovery_approved_mcp_credential_delete_prefix_read_only(
                            credentials,
                        )
                        .map_err(|_| invalid_recovery())?;
                    let layout = capture_recovery_layout(&paths, credential_gate.prefix_len())?;
                    if !layout_matches_phase(
                        &layout,
                        &paths,
                        &marker,
                        original,
                        RecoveryPhase::WorkProductsMovedToRollback,
                    )? {
                        return Err(invalid_recovery());
                    }
                    if audit_evidence_present_and_valid(
                        app_local_data_dir,
                        &marker,
                        ABORT_INTENT_BASENAME,
                        AuditEvidenceKind::AbortToCurrent,
                    )?
                    .is_some()
                    {
                        return Err(invalid_recovery());
                    }
                    cleanup_audit_evidence_install_residue(
                        app_local_data_dir,
                        &marker,
                        ABORT_INTENT_BASENAME,
                    )?;
                    let candidate = capture_recovery_audit_evidence(
                        app_local_data_dir,
                        &marker,
                        credentials,
                        AuditEvidenceKind::FiveSlotCommit,
                    )?;
                    let evidence = install_or_verify_audit_evidence(
                        app_local_data_dir,
                        &marker,
                        COMMIT_EVIDENCE_BASENAME,
                        AuditEvidenceKind::FiveSlotCommit,
                        &candidate,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::FiveSlotCommitted,
                        Some(evidence),
                    )?;
                }
                RecoveryPhase::FiveSlotCommitted => {
                    stage_current_rollback_cleanup(
                        &paths,
                        &marker,
                        V031RecoveryComponent::WorkProducts,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::WorkProductsRollbackCleaned,
                        None,
                    )?;
                }
                RecoveryPhase::WorkProductsRollbackCleaned => {
                    finish_directory_cleanup_tombstone(
                        &paths,
                        V031RecoveryComponent::WorkProducts,
                    )?;
                    stage_current_rollback_cleanup(
                        &paths,
                        &marker,
                        V031RecoveryComponent::ApprovedWorkspace,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::ApprovedRollbackCleaned,
                        None,
                    )?;
                }
                RecoveryPhase::ApprovedRollbackCleaned => {
                    finish_directory_cleanup_tombstone(
                        &paths,
                        V031RecoveryComponent::ApprovedWorkspace,
                    )?;
                    stage_current_rollback_cleanup(
                        &paths,
                        &marker,
                        V031RecoveryComponent::VaultStore,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::VaultRollbackCleaned,
                        None,
                    )?;
                }
                RecoveryPhase::VaultRollbackCleaned => {
                    finish_directory_cleanup_tombstone(&paths, V031RecoveryComponent::VaultStore)?;
                    stage_current_rollback_cleanup(
                        &paths,
                        &marker,
                        V031RecoveryComponent::PrivacyDatabase,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::PrivacyRollbackCleaned,
                        None,
                    )?;
                }
                RecoveryPhase::PrivacyRollbackCleaned => {
                    stage_current_rollback_cleanup(
                        &paths,
                        &marker,
                        V031RecoveryComponent::UserDatabase,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::UserRollbackCleaned,
                        None,
                    )?;
                }
                RecoveryPhase::UserRollbackCleaned => {
                    remove_v031_recovery_auxiliary_directory(
                        app_local_data_dir,
                        "ticket-sessions",
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::TicketSessionsCleaned,
                        None,
                    )?;
                }
                RecoveryPhase::TicketSessionsCleaned => {
                    remove_v031_recovery_auxiliary_directory(app_local_data_dir, "qualification")?;
                    remove_v031_recovery_approved_parent_if_empty(app_local_data_dir)?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::QualificationCleaned,
                        None,
                    )?;
                }
                RecoveryPhase::QualificationCleaned => {
                    advance_credential_deletion(
                        &marker,
                        credentials,
                        RecoveryPhase::CredentialQualificationDeleted,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::CredentialQualificationDeleted,
                        None,
                    )?;
                }
                RecoveryPhase::CredentialQualificationDeleted => {
                    advance_credential_deletion(
                        &marker,
                        credentials,
                        RecoveryPhase::CredentialTicketDeleted,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::CredentialTicketDeleted,
                        None,
                    )?;
                }
                RecoveryPhase::CredentialTicketDeleted => {
                    advance_credential_deletion(
                        &marker,
                        credentials,
                        RecoveryPhase::CredentialWorkProductDeleted,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::CredentialWorkProductDeleted,
                        None,
                    )?;
                }
                RecoveryPhase::CredentialWorkProductDeleted => {
                    advance_credential_deletion(
                        &marker,
                        credentials,
                        RecoveryPhase::CredentialApprovedDeleted,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::CredentialApprovedDeleted,
                        None,
                    )?;
                }
                RecoveryPhase::CredentialApprovedDeleted => {
                    verify_target_state(app_local_data_dir, &marker, original, credentials)?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::TargetVerified,
                        None,
                    )?;
                }
                RecoveryPhase::TargetVerified => {
                    verify_target_state(app_local_data_dir, &marker, original, credentials)?;
                    let (commit_present, abort_present) =
                        validate_evidence_state(app_local_data_dir, &marker)?;
                    if !commit_present || abort_present {
                        return Err(invalid_recovery());
                    }
                    let candidate = capture_recovery_audit_evidence(
                        app_local_data_dir,
                        &marker,
                        credentials,
                        AuditEvidenceKind::AppliedDowngrade,
                    )?;
                    let report = install_or_verify_audit_evidence(
                        app_local_data_dir,
                        &marker,
                        APPLIED_REPORT_BASENAME,
                        AuditEvidenceKind::AppliedDowngrade,
                        &candidate,
                    )?;
                    marker = advance_marker(
                        app_local_data_dir,
                        &marker,
                        RecoveryPhase::ReportInstalled,
                        Some(report),
                    )?;
                }
                RecoveryPhase::ReportInstalled => {
                    return finish_success_marker(
                        app_local_data_dir,
                        &marker,
                        original,
                        credentials,
                    )
                    .map(Some);
                }
            }
            Ok(None)
        })();
        match step {
            Ok(Some(applied)) => return Ok(applied),
            Ok(None) => {}
            Err(error) => return Err((error, Box::new(marker))),
        }
    }
}

pub(crate) fn apply_observed_v031_migration_recovery(
    app_local_data_dir: &Path,
    gate: V031MigrationRecoveryGate,
) -> Result<AppliedDowngrade, IpcError> {
    ensure_ordinary_restore_markers_absent(app_local_data_dir)?;
    reject_unknown_v031_recovery_restore_siblings(app_local_data_dir)?;
    if gate.abort_requested {
        let marker_install_proof = gate.marker_install_proof();
        abort_to_current(
            app_local_data_dir,
            AbortMarkerExpectation::Observed(marker_install_proof),
            &gate.original,
            &gate.credentials,
        )?;
        return Err(recovery_error(
            "v031_migration_recovery_aborted",
            "The interrupted downgrade was reversed to the authenticated v0.4 safety state.",
        ));
    }
    reconcile_gate_marker(app_local_data_dir, &gate)?;
    match run_forward_recovery(
        app_local_data_dir,
        gate.marker,
        &gate.original,
        &gate.credentials,
    ) {
        Ok(applied) => Ok(applied),
        Err((error, marker)) if marker.phase.is_precommit() => {
            if audit_evidence_present_and_valid(
                app_local_data_dir,
                &marker,
                COMMIT_EVIDENCE_BASENAME,
                AuditEvidenceKind::FiveSlotCommit,
            )?
            .is_some()
            {
                return Err(error);
            }
            abort_to_current(
                app_local_data_dir,
                AbortMarkerExpectation::ForwardError(&marker),
                &gate.original,
                &gate.credentials,
            )?;
            Err(recovery_error(
                "v031_migration_recovery_aborted",
                "The downgrade failed before commit and the authenticated v0.4 safety state was restored.",
            ))
        }
        Err((error, _)) => Err(error),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageExitOwnership {
    Owned,
    RestartAlreadyOwned,
}

#[derive(Debug)]
enum StagePreparationOutcome {
    PreparedAndExitOwned,
    Failed {
        error: IpcError,
        exit_ownership: Option<StageExitOwnership>,
    },
}

#[derive(Debug)]
enum StageFinalizeOutcome {
    FormalInstalled,
    FailedFormalAbsent {
        error: IpcError,
        cleanup_error: Option<IpcError>,
    },
    FailedFormalPresent {
        error: IpcError,
    },
    FailedFormalStateUnknown {
        error: IpcError,
    },
}

/// Narrow production/test boundary for the public R3 staging state machine.
///
/// `prepare_reserve_exit_and_close_admission` intentionally keeps preparation,
/// exit reservation and any begin-failure cleanup in one migration-guard
/// critical section. Likewise, `finalize_after_quiescence` owns the final
/// marker observation and any formal-absent cleanup under one guard. The
/// generic sequencer therefore tests the real public control flow without
/// weakening either durable boundary or requiring a Tauri `AppHandle`.
type StageFuture<'a, Output> = Pin<Box<dyn Future<Output = Output> + Send + 'a>>;

trait V031RecoveryStageRuntime: Send {
    fn prepare_reserve_exit_and_close_admission(
        &mut self,
    ) -> StageFuture<'_, StagePreparationOutcome>;
    fn drain_mcp_and_standalone(&mut self) -> StageFuture<'_, Result<(), IpcError>>;
    fn cleanup_unauthorized_residue(&mut self) -> StageFuture<'_, Result<(), IpcError>>;
    fn finalize_after_quiescence(&mut self) -> StageFuture<'_, StageFinalizeOutcome>;
    fn restart_owned_exit_once(&mut self) -> StageFuture<'_, ()>;
}

struct ProductionV031RecoveryStageRuntime {
    #[cfg(not(test))]
    app: Option<tauri::AppHandle>,
    #[cfg(test)]
    restart_request_count: usize,
    app_local_data_dir: PathBuf,
    identifier: String,
    state: AppState,
    workflow: PrivacyWorkflowManager,
    approved_workspace: ApprovedMcpWorkspace,
    mcp_manager: crate::mcp_manager::McpManager,
    exit_drain: Arc<crate::ExitDrainCoordinator>,
    #[cfg(test)]
    recovery_credential_override_factory:
        Option<crate::approved_mcp::V031RecoveryCredentialOverrideFactory>,
}

impl V031RecoveryStageRuntime for ProductionV031RecoveryStageRuntime {
    fn prepare_reserve_exit_and_close_admission(
        &mut self,
    ) -> StageFuture<'_, StagePreparationOutcome> {
        let stage_root = self.app_local_data_dir.clone();
        let stage_identifier = self.identifier.clone();
        let stage_state = self.state.clone();
        let stage_workflow = self.workflow.clone();
        let stage_approved_workspace = self.approved_workspace.clone();
        let stage_mcp_manager = self.mcp_manager.clone();
        let stage_exit_drain = Arc::clone(&self.exit_drain);
        #[cfg(test)]
        let stage_credential_override_factory = self.recovery_credential_override_factory.clone();
        Box::pin(async move {
            tauri::async_runtime::spawn_blocking(move || {
                #[cfg(test)]
                let _credential_override = match stage_credential_override_factory {
                    Some(factory) => match factory.install_on_current_thread() {
                        Ok(guard) => Some(guard),
                        Err(_) => {
                            return StagePreparationOutcome::Failed {
                                error: invalid_recovery(),
                                exit_ownership: None,
                            };
                        }
                    },
                    None => None,
                };
                let _migration_guard =
                    match crate::single_instance::acquire_migration_guard(&stage_identifier) {
                        Ok(guard) => guard,
                        Err(_) => {
                            return StagePreparationOutcome::Failed {
                                error: io_recovery(),
                                exit_ownership: None,
                            };
                        }
                    };

                if let Err(error) = prepare_recovery_stage(
                    &stage_root,
                    &stage_state,
                    &stage_workflow,
                    &stage_approved_workspace,
                ) {
                    return match cleanup_unauthorized_initial_marker_residue(&stage_root) {
                        Ok(()) => StagePreparationOutcome::Failed {
                            error,
                            exit_ownership: None,
                        },
                        Err(cleanup_error) => {
                            let exit_ownership = if stage_exit_drain.begin_programmatic_exit() {
                                StageExitOwnership::Owned
                            } else {
                                StageExitOwnership::RestartAlreadyOwned
                            };
                            stage_mcp_manager.close_v031_recovery_admission();
                            StagePreparationOutcome::Failed {
                                error: cleanup_error,
                                exit_ownership: Some(exit_ownership),
                            }
                        }
                    };
                }

                if !stage_exit_drain.begin_programmatic_exit() {
                    stage_mcp_manager.close_v031_recovery_admission();
                    let error = cleanup_unauthorized_initial_marker_residue(&stage_root)
                        .err()
                        .unwrap_or_else(|| {
                            recovery_error(
                                "application_exiting",
                                "Another application exit, restart, or installer hand-off is already in progress",
                            )
                        });
                    return StagePreparationOutcome::Failed {
                        error,
                        exit_ownership: Some(StageExitOwnership::RestartAlreadyOwned),
                    };
                }

                stage_mcp_manager.close_v031_recovery_admission();
                StagePreparationOutcome::PreparedAndExitOwned
            })
            .await
            .unwrap_or_else(|_| StagePreparationOutcome::Failed {
                error: io_recovery(),
                exit_ownership: None,
            })
        })
    }

    fn drain_mcp_and_standalone(&mut self) -> StageFuture<'_, Result<(), IpcError>> {
        let mcp_manager = self.mcp_manager.clone();
        Box::pin(async move {
            if mcp_manager
                .shutdown_for_v031_recovery_with_timeout(crate::MCP_EXIT_DRAIN_TIMEOUT)
                .await
            {
                Ok(())
            } else {
                Err(recovery_error(
                    "v031_migration_recovery_drain_failed",
                    "MCP and standalone Approved work did not quiesce; no formal recovery marker was installed.",
                ))
            }
        })
    }

    fn cleanup_unauthorized_residue(&mut self) -> StageFuture<'_, Result<(), IpcError>> {
        let cleanup_root = self.app_local_data_dir.clone();
        let cleanup_identifier = self.identifier.clone();
        Box::pin(async move {
            tauri::async_runtime::spawn_blocking(move || {
                let _migration_guard =
                    crate::single_instance::acquire_migration_guard(&cleanup_identifier)
                        .map_err(|_| io_recovery())?;
                cleanup_unauthorized_initial_marker_residue(&cleanup_root)
            })
            .await
            .map_err(|_| io_recovery())?
        })
    }

    fn finalize_after_quiescence(&mut self) -> StageFuture<'_, StageFinalizeOutcome> {
        let finalize_root = self.app_local_data_dir.clone();
        let finalize_identifier = self.identifier.clone();
        let state = self.state.clone();
        let workflow = self.workflow.clone();
        let approved_workspace = self.approved_workspace.clone();
        #[cfg(test)]
        let finalize_credential_override_factory =
            self.recovery_credential_override_factory.clone();
        Box::pin(async move {
            tauri::async_runtime::spawn_blocking(move || {
                #[cfg(test)]
                let _credential_override = match finalize_credential_override_factory {
                    Some(factory) => match factory.install_on_current_thread() {
                        Ok(guard) => Some(guard),
                        Err(_) => {
                            return StageFinalizeOutcome::FailedFormalStateUnknown {
                                error: invalid_recovery(),
                            };
                        }
                    },
                    None => None,
                };
                let migration_guard =
                    match crate::single_instance::acquire_migration_guard(&finalize_identifier) {
                        Ok(guard) => guard,
                        Err(_) => {
                            return StageFinalizeOutcome::FailedFormalStateUnknown {
                                error: io_recovery(),
                            };
                        }
                    };
                match finalize_initial_marker_after_quiescence(
                    &finalize_root,
                    &state,
                    &workflow,
                    &approved_workspace,
                ) {
                    Ok(()) => {
                        std::mem::forget(migration_guard);
                        StageFinalizeOutcome::FormalInstalled
                    }
                    Err(error) => {
                        let (formal_path, _) = marker_paths(&finalize_root);
                        match v031_recovery_path_is_present(&formal_path) {
                            Ok(true) => {
                                std::mem::forget(migration_guard);
                                StageFinalizeOutcome::FailedFormalPresent { error }
                            }
                            Ok(false) => {
                                let cleanup_error =
                                    cleanup_unauthorized_initial_marker_residue(&finalize_root)
                                        .err();
                                StageFinalizeOutcome::FailedFormalAbsent {
                                    error,
                                    cleanup_error,
                                }
                            }
                            Err(_) => {
                                std::mem::forget(migration_guard);
                                StageFinalizeOutcome::FailedFormalStateUnknown { error }
                            }
                        }
                    }
                }
            })
            .await
            .unwrap_or_else(|_| StageFinalizeOutcome::FailedFormalStateUnknown {
                error: io_recovery(),
            })
        })
    }

    fn restart_owned_exit_once(&mut self) -> StageFuture<'_, ()> {
        #[cfg(test)]
        {
            // The real-process test runtime intentionally has no Tauri
            // AppHandle. The shared sequencer's exactly-once restart ordering
            // is covered by its runtime test; this concrete acceptance path
            // exercises every production durable/quiescence boundary through
            // the formal marker and then lets the child process terminate.
            debug_assert_eq!(self.restart_request_count, 0);
            self.restart_request_count += 1;
            Box::pin(async {})
        }
        #[cfg(not(test))]
        {
            let app = self.app.take();
            debug_assert!(
                app.is_some(),
                "R3 staging attempted to restart one owned exit twice"
            );
            let Some(app) = app else {
                return Box::pin(async {});
            };
            let exit_drain = Arc::clone(&self.exit_drain);
            Box::pin(async move {
                crate::drain_mcp_and_finalize(
                    app,
                    None,
                    exit_drain,
                    crate::FinalExitAction::Restart,
                )
                .await;
            })
        }
    }
}

async fn sequence_v031_recovery_stage<Runtime>(runtime: &mut Runtime) -> Result<(), IpcError>
where
    Runtime: V031RecoveryStageRuntime,
{
    match runtime.prepare_reserve_exit_and_close_admission().await {
        StagePreparationOutcome::PreparedAndExitOwned => {}
        StagePreparationOutcome::Failed {
            error,
            exit_ownership,
        } => {
            if exit_ownership == Some(StageExitOwnership::Owned) {
                // Cleanup could not prove that unauthorized staging residue is
                // absent. Admission is already permanently closed; make one
                // best-effort R3 drain before the single owned restart.
                let _ = runtime.drain_mcp_and_standalone().await;
                runtime.restart_owned_exit_once().await;
            }
            // `RestartAlreadyOwned` is deliberately terminal here: another
            // exit owner will finish the process, so issuing a second restart
            // would violate the global single-exit contract.
            return Err(error);
        }
    }

    let result = match runtime.drain_mcp_and_standalone().await {
        Ok(()) => match runtime.finalize_after_quiescence().await {
            StageFinalizeOutcome::FormalInstalled => Ok(()),
            StageFinalizeOutcome::FailedFormalAbsent {
                error,
                cleanup_error,
            } => Err(cleanup_error.unwrap_or(error)),
            StageFinalizeOutcome::FailedFormalPresent { error }
            | StageFinalizeOutcome::FailedFormalStateUnknown { error } => Err(error),
        },
        Err(error) => Err(runtime
            .cleanup_unauthorized_residue()
            .await
            .err()
            .unwrap_or(error)),
    };

    runtime.restart_owned_exit_once().await;
    result
}

#[tauri::command]
pub async fn stage_v031_migration_recovery(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    workflow: State<'_, PrivacyWorkflowManager>,
    approved_workspace: State<'_, ApprovedMcpWorkspace>,
    mcp_manager: State<'_, crate::mcp_manager::McpManager>,
    exit_drain: State<'_, Arc<crate::ExitDrainCoordinator>>,
    request: StageV031MigrationRecoveryRequest,
) -> Result<(), IpcError> {
    if request.confirmation != V031_MIGRATION_RECOVERY_CONFIRMATION {
        return Err(recovery_error(
            "v031_migration_recovery_confirmation_required",
            "恢复到 v0.3.1 需要输入界面显示的完整确认短语。",
        ));
    }
    let app_local_data_dir = app.path().app_local_data_dir().map_err(|_| io_recovery())?;
    let identifier = app.config().identifier.clone();
    let state = state.inner().clone();
    let workflow = workflow.inner().clone();
    let approved_workspace = approved_workspace.inner().clone();
    let mcp_manager = mcp_manager.inner().clone();
    let exit_drain = Arc::clone(exit_drain.inner());
    let mut runtime = ProductionV031RecoveryStageRuntime {
        #[cfg(not(test))]
        app: Some(app),
        #[cfg(test)]
        restart_request_count: 0,
        app_local_data_dir,
        identifier,
        state,
        workflow,
        approved_workspace,
        mcp_manager,
        exit_drain,
        #[cfg(test)]
        recovery_credential_override_factory: None,
    };
    sequence_v031_recovery_stage(&mut runtime).await
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use rusqlite::{params, Connection};
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use std::{
        io::Read,
        os::windows::io::AsRawHandle as _,
        process::{Child, Stdio},
        thread::JoinHandle,
    };
    use zeroize::Zeroize;

    const CHILD_MODE_ENV: &str = "LAWYER_ASSISTANCE_R3_RECOVERY_CHILD_MODE";
    const CHILD_ROOT_ENV: &str = "LAWYER_ASSISTANCE_R3_RECOVERY_CHILD_ROOT";
    const CHILD_CREDENTIAL_PREFIX_ENV: &str =
        "LAWYER_ASSISTANCE_R3_RECOVERY_CHILD_CREDENTIAL_PREFIX";
    const CHILD_WORKSPACE_ENV: &str = "LAWYER_ASSISTANCE_R3_RECOVERY_CHILD_WORKSPACE";
    const CHILD_LINEAGE_ENV: &str = "LAWYER_ASSISTANCE_R3_RECOVERY_CHILD_LINEAGE";
    const CHILD_STARTUP_TRACE_ENV: &str = "LAWYER_ASSISTANCE_R3_RECOVERY_CHILD_STARTUP_TRACE";
    const CHILD_TEST_PATH: &str =
        "commands::v031_migration_recovery::tests::r3_real_binary_recovery_child_process";

    const REAL_EXE_ENV: &str = "LAWYER_ASSISTANCE_R3_V031_EXE";
    const REAL_EXE_SHA256_ENV: &str = "LAWYER_ASSISTANCE_R3_V031_EXE_SHA256";
    const CDP_HELPER_ENV: &str = "LAWYER_ASSISTANCE_R3_V031_CDP_HELPER";
    const NODE_EXE_ENV: &str = "LAWYER_ASSISTANCE_R3_NODE_EXE";
    const APP_IDENTIFIER_ENV: &str = "LAWYER_ASSISTANCE_R3_APP_IDENTIFIER";
    const WINDOW_CLASS_ENV: &str = "LAWYER_ASSISTANCE_R3_WINDOW_CLASS";
    const APP_ROOT_ENV: &str = "LAWYER_ASSISTANCE_R3_APP_ROOT";
    const CDP_PORT_ENV: &str = "LAWYER_ASSISTANCE_R3_CDP_PORT";
    const RUN_ROOT_ENV: &str = "LAWYER_ASSISTANCE_R3_RUN_ROOT";
    const TAG_OBJECT_ENV: &str = "LAWYER_ASSISTANCE_R3_TAG_OBJECT";
    const PEELED_COMMIT_ENV: &str = "LAWYER_ASSISTANCE_R3_PEELED_COMMIT";
    const TAURI_OVERRIDE_SHA256_ENV: &str = "LAWYER_ASSISTANCE_R3_TAURI_OVERRIDE_SHA256";
    const LEGAL_RESOURCE_SHA256_ENV: &str = "LAWYER_ASSISTANCE_R3_LEGAL_RESOURCE_SHA256";
    const KEEP_APP_ROOT_ENV: &str = "LAWYER_ASSISTANCE_R3_KEEP_APP_ROOT";
    const CURRENT_EXE_ENV: &str = "LAWYER_ASSISTANCE_R3_V040_EXE";
    const CURRENT_EXE_SHA256_ENV: &str = "LAWYER_ASSISTANCE_R3_V040_EXE_SHA256";
    const CURRENT_CDP_HELPER_ENV: &str = "LAWYER_ASSISTANCE_R3_V040_CDP_HELPER";
    const CURRENT_APP_VERSION_ENV: &str = "LAWYER_ASSISTANCE_R3_V040_APP_VERSION";
    const CURRENT_RUN_ID_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_RUN_ID";
    const CURRENT_CDP_PORT_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_CDP_PORT";
    const CURRENT_CREDENTIAL_PREFIX_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_CREDENTIAL_PREFIX";
    const CURRENT_WINDOW_CLASS_ENV: &str = "LAWYER_ASSISTANCE_R3_CURRENT_WINDOW_CLASS";
    const REAL_WINDOW_TITLE: &str = "Lawyer Assistance R3 v0.3.1 acceptance";
    const CURRENT_WINDOW_TITLE: &str = "Lawyer Assistance R3 v0.4.0 acceptance";
    const REAL_WINDOW_MESSAGE_TIMEOUT_MS: u32 = 10_000;
    const REAL_PROCESS_EXIT_TIMEOUT_MS: u32 = 30_000;

    const PINNED_TAG_OBJECT: &str = "9a92737f87ef3a5cc33953b874bbc97a8b5e79fc";
    const PINNED_PEELED_COMMIT: &str = "0970f1c614b1bec1856869c68065162339849468";

    #[derive(Debug)]
    struct RealV031Fixture {
        project_id: String,
        project_title_sha256: String,
        conversation_id: String,
        conversation_title_sha256: String,
        message_id: String,
        message_text_sha256: String,
        redaction_id: String,
        material_id: String,
        source_sha256: String,
        extraction_sha256: String,
        suggested_redacted_sha256: String,
        privacy_original_text_sha256: String,
        privacy_redacted_text_sha256: String,
    }

    #[derive(Debug)]
    struct CompletedUpgrade {
        workspace_instance_id: String,
        lineage_id: String,
    }

    #[cfg(windows)]
    struct RealRecoveryStartupActions {
        root: PathBuf,
        trace_path: PathBuf,
        observed: Option<crate::v031_startup::ProductionStartupObservation>,
        migration_guard: Option<crate::single_instance::NamedMutexGuard>,
        exit_drain: crate::ExitDrainCoordinator,
    }

    #[cfg(windows)]
    impl RealRecoveryStartupActions {
        fn new(root: PathBuf, trace_path: PathBuf) -> std::io::Result<Self> {
            let identifier = format!(
                "com.shilittle.lawyer-assistance.r3-real-apply-exit-{}",
                std::process::id()
            );
            Ok(Self {
                root,
                trace_path,
                observed: None,
                migration_guard: Some(crate::single_instance::acquire_migration_guard(
                    &identifier,
                )?),
                exit_drain: crate::ExitDrainCoordinator::default(),
            })
        }

        fn record(&self, event: &str) -> std::io::Result<()> {
            use std::io::Write as _;

            let mut trace = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.trace_path)?;
            writeln!(trace, "{event}")?;
            trace.sync_all()
        }

        fn forbidden(&self, event: &str) -> std::io::Error {
            self.record(event)
                .expect("R3 real recovery child records forbidden startup work");
            std::io::Error::other(format!(
                "real recovery-only startup invoked forbidden action {event}"
            ))
        }
    }

    #[cfg(windows)]
    impl crate::ExplicitRecoveryExitBoundary for RealRecoveryStartupActions {
        type Error = std::io::Error;

        fn apply_authenticated_recovery(&mut self) -> Result<String, Self::Error> {
            let gate = self
                .observed
                .as_mut()
                .and_then(|observed| observed.take_explicit_recovery_gate())
                .ok_or_else(|| {
                    std::io::Error::other(
                        "real recovery-only startup has no authenticated apply capability",
                    )
                })?;
            let applied =
                apply_observed_v031_migration_recovery(&self.root, gate).map_err(|error| {
                    std::io::Error::other(format!(
                        "real authenticated recovery failed: {}",
                        error.message
                    ))
                })?;
            self.record("apply:real-authenticated-five-slot-recovery")?;
            Ok(applied.target_app_version().to_owned())
        }

        fn release_recovery_migration_guard(&mut self) -> Result<(), Self::Error> {
            let guard = self.migration_guard.take().ok_or_else(|| {
                std::io::Error::other("real recovery migration guard was released twice")
            })?;
            drop(guard);
            self.record("release:migration-guard")
        }

        fn mark_recovery_exit_finalizing(&mut self) {
            self.exit_drain.mark_finalizing();
            self.record("exit-drain:finalizing")
                .expect("R3 real recovery child records Finalizing");
        }

        fn exit_recovery_process(&mut self, exit_code: i32) {
            if self.migration_guard.is_some() || !self.exit_drain.is_finalizing() {
                self.record("invalid:exit-order")
                    .expect("R3 real recovery child records invalid exit ordering");
                std::process::exit(93);
            }
            self.record(&format!("exit:{exit_code}"))
                .expect("R3 real recovery child records its process exit");
            std::process::exit(exit_code);
        }
    }

    #[cfg(windows)]
    impl crate::v031_startup::StartupActions for RealRecoveryStartupActions {
        type Error = std::io::Error;

        fn observe_read_only(
            &mut self,
        ) -> Result<crate::v031_startup::StartupObservation, Self::Error> {
            if self.observed.is_some() {
                return Err(std::io::Error::other(
                    "real production startup observer ran twice",
                ));
            }
            let observed = crate::v031_startup::observe_production_startup_read_only(&self.root)
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "real production startup observation failed: {error}"
                    ))
                })?;
            let summary = observed.summary();
            self.observed = Some(observed);
            self.record("observe:production-authenticated-recovery")?;
            Ok(summary)
        }

        fn apply_explicit_recovery_and_exit(&mut self) -> Result<(), Self::Error> {
            crate::apply_authenticated_recovery_and_exit(self)
        }

        fn apply_current_restore(
            &mut self,
            _kind: crate::v031_startup::CurrentRestoreKind,
        ) -> Result<(), Self::Error> {
            Err(self.forbidden("forbidden:ordinary-restore"))
        }

        fn advance_upgrade_through_receipt_eight(
            &mut self,
            _next_ordinal: u8,
        ) -> Result<(), Self::Error> {
            Err(self.forbidden("forbidden:ordinary-migration"))
        }

        fn run_step_eight_and_install_receipt_nine(&mut self) -> Result<(), Self::Error> {
            Err(self.forbidden("forbidden:ordinary-step-eight"))
        }

        fn request_controlled_restart(&mut self) -> Result<(), Self::Error> {
            Err(self.forbidden("forbidden:restart"))
        }

        fn initialize_ordinary_application(&mut self, _fresh: bool) -> Result<(), Self::Error> {
            Err(self.forbidden("forbidden:ordinary-initialization"))
        }
    }

    #[cfg(windows)]
    #[test]
    fn r3_real_binary_recovery_child_process() {
        let Some(mode) = std::env::var_os(CHILD_MODE_ENV) else {
            return;
        };
        let mode = mode
            .into_string()
            .expect("R3 child mode remains canonical ASCII");
        let root = PathBuf::from(
            std::env::var_os(CHILD_ROOT_ENV).expect("R3 child receives the exact application root"),
        );
        let credential_prefix = std::env::var(CHILD_CREDENTIAL_PREFIX_ENV)
            .expect("R3 child receives only the non-secret credential prefix");
        let expected_workspace = std::env::var(CHILD_WORKSPACE_ENV)
            .expect("R3 child receives the public workspace identity");
        let expected_lineage = std::env::var(CHILD_LINEAGE_ENV)
            .expect("R3 child receives the public lineage identity");
        let credentials = crate::approved_mcp::V031CrossProcessCredentialHarness::reopen_child(
            root.clone(),
            &credential_prefix,
        )
        .expect("R3 child reopens the five UUID-scoped test credentials");

        match mode.as_str() {
            "terminal" => complete_receipt_nine_in_child(
                &root,
                &credentials,
                &expected_workspace,
                &expected_lineage,
            ),
            "stage" => {
                stage_recovery_in_child(&root, &credentials, &expected_workspace, &expected_lineage)
            }
            "apply" => {
                let _credential_override = credentials
                    .install_recovery_credential_override_for_test()
                    .expect("R3 child installs only its UUID-scoped credential provider");
                let trace_path = PathBuf::from(
                    std::env::var_os(CHILD_STARTUP_TRACE_ENV)
                        .expect("R3 apply child receives its fixed startup trace path"),
                );
                let mut startup = RealRecoveryStartupActions::new(root, trace_path)
                    .expect("R3 apply child acquires its real migration guard");
                let returned = crate::v031_startup::execute_startup(&mut startup);
                panic!("real recovery-only startup returned instead of exiting: {returned:?}");
            }
            _ => panic!("R3 child mode is not frozen"),
        }
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "run only through scripts/test-v031-real-binary-reopen.ps1"]
    fn r3_real_v031_binary_reopen_and_v040_reupgrade() {
        let environment = read_real_binary_environment();
        assert!(
            !environment.app_root.exists(),
            "reserved R3 app root starts absent"
        );
        fs::create_dir(&environment.app_root).expect("reserved R3 app root creates exactly once");
        let fixture = create_real_v031_source_fixture(&environment.app_root);
        let mut credentials =
            crate::approved_mcp::V031CrossProcessCredentialHarness::create_parent(
                environment.app_root.clone(),
            )
            .expect("R3 fixture allocates one isolated credential namespace");

        let first = advance_exact_v031_to_receipt_eight(&environment.app_root, &credentials);
        run_recovery_child("terminal", &environment.app_root, &credentials, &first);
        let recovery_source_hashes =
            authenticated_recovery_source_hashes(&environment.app_root, &first.lineage_id);
        run_recovery_child("stage", &environment.app_root, &credentials, &first);
        assert!(environment
            .app_root
            .join(V031_MIGRATION_RECOVERY_MARKER)
            .is_file());
        run_recovery_child("apply", &environment.app_root, &credentials, &first);

        assert_restored_v031_profile(&environment.app_root, &fixture, &recovery_source_hashes);
        run_real_v031_binary(&environment, &fixture);

        let second = advance_exact_v031_to_receipt_eight(&environment.app_root, &credentials);
        assert_ne!(second.workspace_instance_id, first.workspace_instance_id);
        assert_ne!(second.lineage_id, first.lineage_id);
        run_recovery_child("terminal", &environment.app_root, &credentials, &second);
        assert_completed_reupgrade_is_idempotent(
            &environment.app_root,
            &credentials,
            &fixture,
            &second,
        );
        run_real_v040_current_binary(&environment, &fixture, &credentials, &second);

        credentials
            .cleanup()
            .expect("R3 fixture removes exactly its five UUID-scoped credentials");
        println!("R3_REAL_V031_REOPEN_AND_V040_REUPGRADE=PASS");
    }

    #[derive(Debug)]
    struct RealBinaryEnvironment {
        executable: PathBuf,
        executable_sha256: String,
        cdp_helper: PathBuf,
        node_executable: PathBuf,
        app_identifier: String,
        window_class: String,
        app_root: PathBuf,
        cdp_port: String,
        current_executable: PathBuf,
        current_executable_sha256: String,
        current_cdp_helper: PathBuf,
        current_app_version: String,
        current_run_id: String,
        current_window_class: String,
        current_cdp_port: String,
    }

    #[cfg(windows)]
    fn complete_receipt_nine_in_child(
        root: &Path,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        expected_workspace: &str,
        expected_lineage: &str,
    ) {
        let process_start = crate::commands::v031_upgrade_complete::
            observe_v031_upgrade_at_process_start_read_only(root)
            .expect("R3 terminal child authenticates receipts zero through eight");
        assert_eq!(process_start.active_final_receipt_count(), Some(9));
        assert_eq!(process_start.active_lineage_id(), Some(expected_lineage));
        let manager = migration_manager(root, credentials, expected_workspace);
        let terminal = crate::v031_startup::run_step_eight_with_existing_managers_for_test(
            root,
            &process_start,
            &manager,
            &credentials.workspace,
        )
        .expect("R3 terminal child installs receipt nine through the production Gate8 path");
        assert_eq!(terminal.lineage_id(), expected_lineage);
    }

    #[cfg(windows)]
    fn stage_recovery_in_child(
        root: &Path,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        expected_workspace: &str,
        expected_lineage: &str,
    ) {
        let process_start = crate::commands::v031_upgrade_complete::
            observe_v031_upgrade_at_process_start_read_only(root)
            .expect("R3 stage child authenticates terminal receipt history");
        assert!(process_start.has_terminal_lineage_only());
        assert_eq!(process_start.terminal_lineage_count(), 1);
        let manager = migration_manager(root, credentials, expected_workspace);
        let exact =
            crate::v031_startup::observe_exact_current_profile_with_approved_workspace_for_test(
                root,
                &credentials.workspace,
            )
            .expect("R3 stage child observes the exact current profile");
        let crate::v031_startup::ExactCurrentProfileObservation::Exact(exact) = exact else {
            panic!("R3 stage requires the exact current profile")
        };
        let terminal = crate::v031_startup::load_completed_v031_with_existing_managers_for_test(
            root,
            &process_start,
            &exact,
            &manager,
            &credentials.workspace,
        )
        .expect("R3 stage child live-authenticates the completed lineage");
        assert_eq!(terminal.lineage_id(), expected_lineage);

        let state = AppState::new(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("resources")
                .join("legal_core.sqlite"),
            database::user_database_path(root),
        );
        let mcp_manager = crate::mcp_manager::McpManager::new_with_approved_workspace(
            root.to_path_buf(),
            state.legal_core_path().to_path_buf(),
            state.user_database_path().to_path_buf(),
            credentials.workspace.clone(),
        )
        .expect("R3 stage child constructs the production Approved MCP manager");
        let exit_drain = Arc::new(crate::ExitDrainCoordinator::default());
        let mut runtime = ProductionV031RecoveryStageRuntime {
            restart_request_count: 0,
            app_local_data_dir: root.to_path_buf(),
            identifier: format!(
                "com.shilittle.lawyer-assistance.r3-real-stage-{}",
                std::process::id()
            ),
            state,
            workflow: manager,
            approved_workspace: credentials.workspace.clone(),
            mcp_manager: mcp_manager.clone(),
            exit_drain: Arc::clone(&exit_drain),
            recovery_credential_override_factory: Some(
                credentials.recovery_credential_override_factory_for_test(),
            ),
        };
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("R3 stage child constructs its current-thread runtime")
            .block_on(sequence_v031_recovery_stage(&mut runtime))
            .expect("R3 stage child executes the production staging sequencer");
        assert_eq!(
            runtime.restart_request_count, 1,
            "R3 production sequencer requests exactly one controlled restart"
        );

        assert!(
            root.join(V031_MIGRATION_RECOVERY_MARKER).is_file(),
            "R3 production sequencer installs the formal recovery marker"
        );
        assert!(
            !exit_drain.begin_programmatic_exit() && !exit_drain.is_finalizing(),
            "R3 exit coordinator remains in Draining until the test child exits"
        );
        assert_eq!(
            mcp_manager
                .provision_standalone_approved_session(
                    "codex".to_owned(),
                    privacy::mcp_ticket::McpTransportBindingV1::Stdio,
                    Vec::new(),
                    60,
                    None,
                    Vec::new(),
                )
                .expect_err("R3 staging permanently closes standalone admission")
                .code(),
            "application_exiting"
        );
        assert!(
            mcp_manager
                .list_standalone_approved_sessions()
                .expect("R3 stage child rechecks authenticated standalone descriptors")
                .into_iter()
                .all(|session| !session.active),
            "R3 staging leaves no active authenticated standalone descriptor"
        );
    }

    #[cfg(windows)]
    fn read_real_binary_environment() -> RealBinaryEnvironment {
        fn path(name: &str) -> PathBuf {
            let value = PathBuf::from(
                std::env::var_os(name).unwrap_or_else(|| panic!("missing R3 environment {name}")),
            );
            assert!(value.is_absolute(), "{name} is absolute");
            value
        }

        fn text(name: &str) -> String {
            std::env::var(name).unwrap_or_else(|_| panic!("missing R3 environment {name}"))
        }

        fn hash(name: &str) -> String {
            let value = text(name);
            assert!(
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{name} is one lowercase SHA-256"
            );
            value
        }

        assert_eq!(text(TAG_OBJECT_ENV), PINNED_TAG_OBJECT);
        assert_eq!(text(PEELED_COMMIT_ENV), PINNED_PEELED_COMMIT);
        assert_eq!(text(KEEP_APP_ROOT_ENV), "1");
        let _override_sha256 = hash(TAURI_OVERRIDE_SHA256_ENV);
        let _legal_resource_sha256 = hash(LEGAL_RESOURCE_SHA256_ENV);
        let run_root = path(RUN_ROOT_ENV);
        assert!(run_root.is_dir(), "R3 retained run root exists");

        let executable = path(REAL_EXE_ENV);
        let cdp_helper = path(CDP_HELPER_ENV);
        let node_executable = path(NODE_EXE_ENV);
        let current_executable = path(CURRENT_EXE_ENV);
        let current_cdp_helper = path(CURRENT_CDP_HELPER_ENV);
        assert!(executable.is_file(), "pinned v0.3.1 executable exists");
        assert!(cdp_helper.is_file(), "audited CDP helper exists");
        assert!(node_executable.is_file(), "pinned Node executable exists");
        assert!(current_executable.is_file(), "current executable exists");
        assert!(current_cdp_helper.is_file(), "current CDP helper exists");

        let app_identifier = text(APP_IDENTIFIER_ENV);
        assert!(app_identifier.starts_with("com.shilittle.lawyer-assistance.r3-"));
        let window_class = text(WINDOW_CLASS_ENV);
        assert!(window_class.starts_with("LawyerAssistanceR3V031"));
        assert!(window_class
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric()));
        let app_root = path(APP_ROOT_ENV);
        let app_parent = app_root.parent().expect("R3 app root has a parent");
        assert!(app_parent.is_dir(), "R3 app parent already exists");
        assert_eq!(app_root, app_parent.join(&app_identifier));

        let cdp_port = text(CDP_PORT_ENV);
        let parsed_port = cdp_port.parse::<u16>().expect("R3 CDP port parses");
        assert!(parsed_port >= 1024, "R3 CDP port is unprivileged");

        let current_cdp_port = text(CURRENT_CDP_PORT_ENV);
        assert!(current_cdp_port
            .parse::<u16>()
            .is_ok_and(|value| value >= 1024));
        assert_ne!(current_cdp_port, cdp_port);

        RealBinaryEnvironment {
            executable,
            executable_sha256: hash(REAL_EXE_SHA256_ENV),
            cdp_helper,
            node_executable,
            app_identifier,
            window_class,
            app_root,
            cdp_port,
            current_executable,
            current_executable_sha256: hash(CURRENT_EXE_SHA256_ENV),
            current_cdp_helper,
            current_app_version: text(CURRENT_APP_VERSION_ENV),
            current_run_id: text(CURRENT_RUN_ID_ENV),
            current_window_class: text(CURRENT_WINDOW_CLASS_ENV),
            current_cdp_port,
        }
    }

    #[derive(Debug, Deserialize)]
    struct FrozenUserSchemaObject {
        object_type: String,
        sql: String,
    }

    #[cfg(windows)]
    fn create_real_v031_source_fixture(root: &Path) -> RealV031Fixture {
        const PROJECT_ID: &str = "case-r3-real-v031";
        const CONVERSATION_ID: &str = "conv_31313131313131313131313131313131";
        const MESSAGE_ID: &str = "msg_31313131313131313131313131313131";
        const MATERIAL_ID: &str = "mat_31313131313131313131313131313131";
        const REDACTION_ID: &str = "red_31313131313131313131313131313131";
        const PROJECT_TITLE: &str = "R3 真实旧版回开合成案件";
        const CONVERSATION_TITLE: &str = "R3 合成会话";
        const MESSAGE_TEXT: &str = "请核验恢复后的 v0.3.1 会话仍可读取。";
        const ORIGINAL_TEXT: &str = "合成当事人张三，联系电话 13800138000。";
        const REDACTED_TEXT: &str = "合成当事人【姓名】，联系电话【手机号】。";

        let user_path = database::user_database_path(root);
        let user = Connection::open(&user_path).expect("exact User-v10 fixture opens");
        let objects =
            include_str!("../../../../../crates/database/schema/v031-user-sqlite-master.jsonl")
                .lines()
                .map(|line| {
                    serde_json::from_str::<FrozenUserSchemaObject>(line)
                        .expect("frozen User-v10 schema object parses")
                })
                .collect::<Vec<_>>();
        for object_type in ["table", "index", "trigger", "view"] {
            for object in objects
                .iter()
                .filter(|object| object.object_type == object_type)
            {
                user.execute_batch(&object.sql)
                    .expect("frozen User-v10 DDL executes");
            }
        }
        user.execute(
            "INSERT INTO user_database_metadata(key,value,updated_at)
             VALUES('schema_version',?1,'2026-08-02 00:00:00')",
            [database::V031_USER_SCHEMA_VERSION.to_string()],
        )
        .expect("User-v10 schema version inserts");
        user.execute(
            "INSERT INTO user_database_metadata(key,value,updated_at)
             VALUES('canonical_schema_version',?1,'2026-08-02 00:00:00')",
            [database::V031_USER_CANONICAL_SCHEMA_MARKER],
        )
        .expect("User-v10 canonical marker inserts");
        user.execute(
            "INSERT INTO projects(
                 project_id,title,case_type,status,opened_on,summary,created_at,updated_at
             ) VALUES(?1,?2,'synthetic','active','2026-08-02','R3 fixture',?3,?3)",
            params![PROJECT_ID, PROJECT_TITLE, "2026-08-02 00:00:01"],
        )
        .expect("one exact v0.3.1 project inserts");
        user.execute(
            "INSERT INTO conversations(
                 conversation_id,project_id,title,status,created_at,updated_at
             ) VALUES(?1,?2,?3,'open',?4,?4)",
            params![
                CONVERSATION_ID,
                PROJECT_ID,
                CONVERSATION_TITLE,
                "2026-08-02 00:00:02"
            ],
        )
        .expect("one exact v0.3.1 conversation inserts");
        user.execute(
            "INSERT INTO messages(
                 message_id,conversation_id,role,kind,text_summary,created_at
             ) VALUES(?1,?2,'user','text',?3,?4)",
            params![
                MESSAGE_ID,
                CONVERSATION_ID,
                MESSAGE_TEXT,
                "2026-08-02 00:00:03"
            ],
        )
        .expect("one exact v0.3.1 message inserts");
        drop(user);

        let source_sha256 = sha256_hex(ORIGINAL_TEXT.as_bytes());
        let extraction_sha256 = sha256_hex(b"r3-real-v031-extraction-v1");
        let canonical_redacted = serde_json::json!({
            "schemaVersion": 1,
            "pages": [{"pageNumber": 1, "text": REDACTED_TEXT}],
        });
        let suggested_redacted_sha256 = sha256_hex(
            &serde_json::to_vec(&canonical_redacted)
                .expect("canonical R3 redacted fixture serializes"),
        );
        let stored_review = serde_json::json!({
            "schemaVersion": 1,
            "materialId": MATERIAL_ID,
            "redactionId": REDACTION_ID,
            "sourceSha256": source_sha256,
            "extractionSha256": extraction_sha256,
            "suggestedRedactedContentSha256": suggested_redacted_sha256,
            "processingVersion": "lawyer-assistance-r3-real-v031-v1",
            "mediaType": "text/plain",
            "pageCount": 1,
            "backendTrace": [{
                "backend": "native_text",
                "workerSha256": null,
                "modelManifestSha256": null,
                "configSha256": null,
                "device": "local-cpu",
                "pageNumbers": [1],
                "isolationVerified": true,
                "isolationMechanism": "in_process_native_text_v1"
            }],
            "summary": {
                "total": 2,
                "counts": {"name": 1, "phone": 1},
                "changed": true,
                "manualReviewRequired": true,
                "redactionVersion": "r3-real-v031-v1"
            },
            "forbiddenCanaries": [],
            "pages": [{
                "pageNumber": 1,
                "locator": "synthetic-page-1",
                "assessment": {
                    "pageNumber": 1,
                    "nonWhitespaceChars": 24,
                    "printableRatio": 1.0,
                    "replacementCharRatio": 0.0,
                    "cjkRatio": 0.75,
                    "readingOrderScore": 1.0,
                    "decision": "native_accepted",
                    "reasonCodes": ["native_text_healthy"]
                },
                "spans": [{
                    "spanId": "r3-real-v031-span-1",
                    "text": ORIGINAL_TEXT,
                    "bbox": null,
                    "confidence": 1.0,
                    "kind": "text",
                    "backend": "native_text"
                }],
                "originalText": ORIGINAL_TEXT,
                "suggestedRedactedText": REDACTED_TEXT
            }]
        });
        let protected_review = protect_local(
            &serde_json::to_vec(&stored_review).expect("R3 stored review serializes"),
        )
        .expect("R3 stored review is protected for this Windows user");

        let privacy_path = root.join("privacy/privacy-workflow.sqlite");
        fs::create_dir(privacy_path.parent().expect("Privacy-v1 path has a parent"))
            .expect("Privacy-v1 directory creates");
        let privacy = Connection::open(&privacy_path).expect("exact Privacy-v1 fixture opens");
        privacy
            .execute_batch(privacy::PRIVACY_V1_SCHEMA_MANIFEST_DDL)
            .expect("frozen Privacy-v1 DDL executes");
        privacy
            .execute(
                "INSERT INTO privacy_schema_metadata(key,value,updated_at)
                 VALUES('schema_version','1','2026-08-02 00:00:00')",
                [],
            )
            .expect("Privacy-v1 schema version inserts");
        privacy
            .execute(
                "INSERT INTO privacy_materials(
                 material_id,project_id,attachment_id,source_sha256,source_name_sha256,
                     media_type,page_count,state,created_at,updated_at
                 ) VALUES(?1,NULL,NULL,?2,?3,'text/plain',1,'review_required',?4,?4)",
                params![
                    MATERIAL_ID,
                    &source_sha256,
                    sha256_hex(b"r3-real-v031-source.txt"),
                    "2026-08-02 00:00:04"
                ],
            )
            .expect("one exact Privacy-v1 material inserts");
        privacy
            .execute(
                "INSERT INTO privacy_redactions(
                     redaction_id,material_id,extraction_sha256,redacted_content_sha256,
                     approved_payload_sha256,policy_id,policy_version,detector_version,
                     unresolved_high_risk_count,review_state,protected_review_blob,
                     protection_scheme,reviewed_by_sha256,created_at,reviewed_at
                 ) VALUES(
                     ?1,?2,?3,?4,NULL,'cn-legal-default',1,'r3-real-v031-v1',0,
                     'review_required',?5,'windows_dpapi_current_user_v1',NULL,?6,NULL
                 )",
                params![
                    REDACTION_ID,
                    MATERIAL_ID,
                    &extraction_sha256,
                    &suggested_redacted_sha256,
                    protected_review,
                    "2026-08-02 00:00:05"
                ],
            )
            .expect("one exact Privacy-v1 review inserts");
        drop(privacy);

        database::with_validated_user_database_migration_source_read_only(&user_path, |_| ())
            .expect("seeded User-v10 remains an exact migration source");
        privacy::with_validated_privacy_v1_migration_source_read_only(&privacy_path, |_| ())
            .expect("seeded Privacy-v1 remains an exact migration source");

        RealV031Fixture {
            project_id: PROJECT_ID.to_owned(),
            project_title_sha256: sha256_hex(PROJECT_TITLE.as_bytes()),
            conversation_id: CONVERSATION_ID.to_owned(),
            conversation_title_sha256: sha256_hex(CONVERSATION_TITLE.as_bytes()),
            message_id: MESSAGE_ID.to_owned(),
            message_text_sha256: sha256_hex(MESSAGE_TEXT.as_bytes()),
            redaction_id: REDACTION_ID.to_owned(),
            material_id: MATERIAL_ID.to_owned(),
            source_sha256,
            extraction_sha256,
            suggested_redacted_sha256,
            privacy_original_text_sha256: sha256_hex(ORIGINAL_TEXT.as_bytes()),
            privacy_redacted_text_sha256: sha256_hex(REDACTED_TEXT.as_bytes()),
        }
    }

    #[cfg(windows)]
    fn receipt_signer(
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        create: bool,
    ) -> privacy::ReceiptSigner {
        let mut key = if create {
            credentials
                .load_or_create_privacy_receipt_signer_key()
                .expect("isolated Privacy receipt-signer credential loads or creates")
        } else {
            credentials
                .load_privacy_receipt_signer_key_read_only()
                .expect("isolated Privacy receipt-signer credential reopens read-only")
        };
        let signer =
            privacy::ReceiptSigner::new(key).expect("isolated Privacy receipt signer constructs");
        key.zeroize();
        signer
    }

    #[cfg(windows)]
    fn receipt_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("R3 test clock follows the Unix epoch")
            .as_secs()
    }

    #[cfg(windows)]
    fn migration_manager(
        root: &Path,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        workspace_instance_id: &str,
    ) -> PrivacyWorkflowManager {
        let workspace_instance_id =
            privacy::vnext::WorkspaceInstanceId::parse(workspace_instance_id)
                .expect("R3 public workspace identity parses");
        let manager = PrivacyWorkflowManager::
            new_for_application_startup_with_approved_publication_invalidator(
                root.to_path_buf(),
                workspace_instance_id,
                Arc::new(credentials.workspace.clone()),
            )
            .expect("R3 child constructs the maintenance-deferred Privacy manager");
        manager.set_test_runtime(receipt_signer(credentials, false), receipt_timestamp());
        manager
    }

    #[cfg(windows)]
    fn advance_exact_v031_to_receipt_eight(
        root: &Path,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
    ) -> CompletedUpgrade {
        let user_path = database::user_database_path(root);
        let privacy_path = root.join("privacy/privacy-workflow.sqlite");
        let credential_probe = credentials.credential_probe();
        let rollback = crate::commands::original_migration_backup::
            establish_original_migration_backup_with_credential_probe_for_test(
                root,
                &user_path,
                &privacy_path,
                &credential_probe,
            )
            .expect("R3 upgrade commits the authenticated original V2 and receipts zero/one");
        let target = crate::commands::v031_target_components::
            prepare_v031_target_components_with_ephemeral_workspace_for_test(
                root,
                &rollback,
                &credentials.workspace,
            )
            .expect("R3 upgrade creates isolated target credentials and receipt two");
        let manager = PrivacyWorkflowManager::new_with_approved_publication_invalidator(
            root.to_path_buf(),
            target.workspace_instance_id().clone(),
            Arc::new(credentials.workspace.clone()),
        )
        .expect("R3 upgrade opens the migration Privacy manager");
        manager.set_test_runtime(receipt_signer(credentials, true), receipt_timestamp());

        let case_backups = crate::commands::v031_checkpoint_receipts::
            ensure_v031_case_migration_backups_verified_gate(
                root,
                &manager,
                &credentials.workspace,
                &target,
            )
            .expect("R3 upgrade commits receipt three");
        let privacy_v5 = crate::commands::v031_privacy_migration::ensure_v031_privacy_v5_verified(
            root,
            &manager,
            &credentials.workspace,
            &case_backups,
        )
        .expect("R3 upgrade commits Privacy-v5 and receipt four");
        let binding =
            crate::commands::v031_privacy_migration::ensure_v031_binding_materials_verified(
                root,
                &manager,
                &credentials.workspace,
                &privacy_v5,
            )
            .expect("R3 upgrade commits the project/privacy-case binding and receipt five");
        let projection =
            crate::commands::v031_checkpoint_receipts::ensure_v031_projection_backup_verified_gate(
                root,
                &manager,
                &credentials.workspace,
                &binding,
            )
            .expect("R3 upgrade commits the projection checkpoint and receipt six");
        let privacy_v6 = crate::commands::v031_privacy_migration::ensure_v031_privacy_v6_verified(
            root,
            &manager,
            &credentials.workspace,
            &projection,
        )
        .expect("R3 upgrade commits Privacy-v6 and receipt seven");
        let before_receipt_eight = crate::commands::v031_upgrade_complete::
            observe_v031_upgrade_at_process_start_read_only(root)
            .expect("R3 upgrade freezes its pre-receipt-eight process observation");
        assert_eq!(before_receipt_eight.active_final_receipt_count(), Some(8));
        let receipt_eight = crate::commands::v031_user_upgrade::ensure_v031_user_v11_verified(
            root,
            &manager,
            &credentials.workspace,
            privacy_v6.receipt_context().lineage_id.as_str(),
        )
        .expect("R3 upgrade commits User-v11 and receipt eight");
        assert_eq!(
            before_receipt_eight.active_final_receipt_count(),
            Some(8),
            "receipt eight cannot mutate the frozen process-start observation"
        );

        CompletedUpgrade {
            workspace_instance_id: target.workspace_instance_id().as_str().to_owned(),
            lineage_id: receipt_eight.receipt_context().lineage_id.clone(),
        }
    }

    #[cfg(windows)]
    fn run_recovery_child(
        mode: &str,
        root: &Path,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        upgrade: &CompletedUpgrade,
    ) {
        let startup_trace = (mode == "apply").then(|| {
            PathBuf::from(
                std::env::var_os(RUN_ROOT_ENV)
                    .expect("R3 real harness passes its retained run root"),
            )
            .join("r3-production-recovery-apply-and-exit.trace")
        });
        if let Some(path) = &startup_trace {
            assert!(!path.exists(), "R3 startup trace path starts absent");
        }
        let mut command = std::process::Command::new(
            std::env::current_exe().expect("R3 current test executable resolves"),
        );
        command
            .arg("--exact")
            .arg(CHILD_TEST_PATH)
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(CHILD_MODE_ENV, mode)
            .env(CHILD_ROOT_ENV, root)
            .env(CHILD_CREDENTIAL_PREFIX_ENV, credentials.service_prefix())
            .env(CHILD_WORKSPACE_ENV, &upgrade.workspace_instance_id)
            .env(CHILD_LINEAGE_ENV, &upgrade.lineage_id);
        if let Some(path) = &startup_trace {
            command.env(CHILD_STARTUP_TRACE_ENV, path);
        }
        let output = command.output().expect("R3 recovery child launches");
        assert!(
            output.status.success(),
            "R3 {mode} child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if let Some(path) = startup_trace {
            assert_eq!(output.status.code(), Some(0));
            let events = std::fs::read_to_string(path)
                .expect("R3 real recovery startup persisted its exit trace");
            assert_eq!(
                events.lines().collect::<Vec<_>>(),
                [
                    "observe:production-authenticated-recovery",
                    "apply:real-authenticated-five-slot-recovery",
                    "release:migration-guard",
                    "exit-drain:finalizing",
                    "exit:0",
                ]
            );
            assert!(!events.contains("forbidden:"));
            println!("R3_REAL_PRODUCTION_STARTUP_APPLY_AND_EXIT=PASS");
        }
    }

    #[cfg(windows)]
    fn authenticated_recovery_source_hashes(root: &Path, lineage_id: &str) -> (String, String) {
        let original = open_authenticated_original_v2_images_for_recovery(root, lineage_id)
            .expect("R3 parent authenticates the exact original V2 images before staging");
        (
            sha256_hex(original.user_database()),
            sha256_hex(original.privacy_database()),
        )
    }

    #[cfg(windows)]
    fn assert_restored_v031_profile(
        root: &Path,
        fixture: &RealV031Fixture,
        expected_database_sha256: &(String, String),
    ) {
        let user_path = database::user_database_path(root);
        let privacy_path = root.join("privacy/privacy-workflow.sqlite");
        assert_eq!(
            sha256_hex(&fs::read(&user_path).expect("restored User-v10 bytes read")),
            expected_database_sha256.0,
            "R3 restores the authenticated original-V2 User-v10 bytes exactly"
        );
        assert_eq!(
            sha256_hex(&fs::read(&privacy_path).expect("restored Privacy-v1 bytes read")),
            expected_database_sha256.1,
            "R3 restores the authenticated original-V2 Privacy-v1 bytes exactly"
        );
        database::with_validated_user_database_migration_source_read_only(&user_path, |_| ())
            .expect("R3 restored User database is the exact v0.3.1 source profile");
        privacy::with_validated_privacy_v1_migration_source_read_only(&privacy_path, |_| ())
            .expect("R3 restored Privacy database is the exact v0.3.1 source profile");

        let user = Connection::open(&user_path).expect("restored User-v10 opens");
        let user_row = user
            .query_row(
                "SELECT p.project_id,p.title,c.conversation_id,c.title,m.message_id,m.text_summary
                 FROM projects p
                 JOIN conversations c ON c.project_id=p.project_id
                 JOIN messages m ON m.conversation_id=c.conversation_id",
                [],
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
            .expect("restored User-v10 synthetic row reads");
        assert_eq!(user_row.0, fixture.project_id);
        assert_eq!(
            sha256_hex(user_row.1.as_bytes()),
            fixture.project_title_sha256
        );
        assert_eq!(user_row.2, fixture.conversation_id);
        assert_eq!(
            sha256_hex(user_row.3.as_bytes()),
            fixture.conversation_title_sha256
        );
        assert_eq!(user_row.4, fixture.message_id);
        assert_eq!(
            sha256_hex(user_row.5.as_bytes()),
            fixture.message_text_sha256
        );
        assert_eq!(
            user.query_row("SELECT COUNT(*) FROM provider_profiles", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("restored provider cardinality reads"),
            0
        );
        drop(user);

        let privacy = Connection::open(&privacy_path).expect("restored Privacy-v1 opens");
        let privacy_row = privacy
            .query_row(
                "SELECT r.redaction_id,m.material_id,m.project_id,m.source_sha256,
                        r.extraction_sha256,r.redacted_content_sha256,r.review_state
                 FROM privacy_materials m
                 JOIN privacy_redactions r ON r.material_id=m.material_id",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .expect("restored Privacy-v1 synthetic row reads");
        assert_eq!(privacy_row.0, fixture.redaction_id);
        assert_eq!(privacy_row.1, fixture.material_id);
        assert_eq!(privacy_row.2, None);
        assert_eq!(privacy_row.3, fixture.source_sha256);
        assert_eq!(privacy_row.4, fixture.extraction_sha256);
        assert_eq!(privacy_row.5, fixture.suggested_redacted_sha256);
        assert_eq!(privacy_row.6, "review_required");
        drop(privacy);

        assert!(!root.join(V031_MIGRATION_RECOVERY_MARKER).exists());
        assert!(!root.join(V031_MIGRATION_RECOVERY_MARKER_INCOMING).exists());
        assert!(!root.join(V031_MIGRATION_RECOVERY_MARKER_STAGING).exists());
        let paths = v031_recovery_swap_paths(root);
        for component in [
            V031RecoveryComponent::VaultStore,
            V031RecoveryComponent::ApprovedWorkspace,
            V031RecoveryComponent::WorkProducts,
        ] {
            assert!(!v031_recovery_path_is_present(paths.active(component))
                .expect("R3 target active slot inspects"));
            assert!(!v031_recovery_path_is_present(
                paths
                    .incoming(component)
                    .expect("directory component has incoming slot")
            )
            .expect("R3 target incoming slot inspects"));
            assert!(!v031_recovery_path_is_present(paths.rollback(component))
                .expect("R3 target rollback slot inspects"));
            assert!(!v031_recovery_path_is_present(
                paths
                    .cleanup(component)
                    .expect("directory component has cleanup slot")
            )
            .expect("R3 target cleanup slot inspects"));
        }
    }

    #[derive(Debug)]
    struct RealBinaryOutputDigest {
        bytes: u64,
        sha256: String,
    }

    fn drain_real_binary_output<R>(
        mut reader: R,
    ) -> JoinHandle<Result<RealBinaryOutputDigest, &'static str>>
    where
        R: Read + Send + 'static,
    {
        std::thread::spawn(move || {
            let mut digest = Sha256::new();
            let mut bytes = 0_u64;
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let read = reader
                    .read(&mut buffer)
                    .map_err(|_| "R3_REAL_BINARY_OUTPUT_READ_FAILED")?;
                if read == 0 {
                    break;
                }
                bytes = bytes
                    .checked_add(read as u64)
                    .ok_or("R3_REAL_BINARY_OUTPUT_SIZE_OVERFLOW")?;
                digest.update(&buffer[..read]);
            }
            Ok(RealBinaryOutputDigest {
                bytes,
                sha256: format!("{:x}", digest.finalize()),
            })
        })
    }

    struct ExactRealBinaryChild {
        child: Child,
        reaped: bool,
    }

    impl ExactRealBinaryChild {
        fn new(child: Child) -> Self {
            Self {
                child,
                reaped: false,
            }
        }

        fn id(&self) -> u32 {
            self.child.id()
        }

        fn process_handle(&self) -> windows_sys::Win32::Foundation::HANDLE {
            self.child.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE
        }

        fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            let status = self.child.wait()?;
            self.reaped = true;
            Ok(status)
        }
    }

    impl Drop for ExactRealBinaryChild {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = true;
                }
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    self.reaped = true;
                }
            }
        }
    }

    #[repr(C)]
    struct ExactRealBinaryWindowSearch {
        process_id: u32,
        title: [u16; 256],
        title_len: usize,
        class_name: [u16; 256],
        class_name_len: usize,
        candidates: [windows_sys::Win32::Foundation::HWND; 2],
        candidate_count: usize,
        ambiguous: bool,
    }

    impl ExactRealBinaryWindowSearch {
        fn new(process_id: u32, title: &str, class_name: &str) -> Result<Self, &'static str> {
            fn freeze(value: &str) -> Result<([u16; 256], usize), &'static str> {
                let encoded = value.encode_utf16().collect::<Vec<_>>();
                if encoded.is_empty() || encoded.len() >= 256 {
                    return Err("R3_REAL_BINARY_WINDOW_IDENTITY_INVALID");
                }
                let mut frozen = [0_u16; 256];
                frozen[..encoded.len()].copy_from_slice(&encoded);
                Ok((frozen, encoded.len()))
            }

            let (title, title_len) = freeze(title)?;
            let (class_name, class_name_len) = freeze(class_name)?;
            Ok(Self {
                process_id,
                title,
                title_len,
                class_name,
                class_name_len,
                candidates: [std::ptr::null_mut(); 2],
                candidate_count: 0,
                ambiguous: false,
            })
        }
    }

    unsafe fn real_binary_window_matches(
        window: windows_sys::Win32::Foundation::HWND,
        search: &ExactRealBinaryWindowSearch,
    ) -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            GetAncestor, GetClassNameW, GetWindow, GetWindowTextW, GetWindowThreadProcessId,
            IsWindow, IsWindowVisible, GA_ROOT, GW_OWNER,
        };

        if unsafe { IsWindow(window) } == 0 || unsafe { IsWindowVisible(window) } == 0 {
            return false;
        }
        let mut process_id = 0_u32;
        if unsafe { GetWindowThreadProcessId(window, &mut process_id) } == 0
            || process_id != search.process_id
            || unsafe { GetAncestor(window, GA_ROOT) } != window
            || !unsafe { GetWindow(window, GW_OWNER) }.is_null()
        {
            return false;
        }

        let mut title = [0_u16; 256];
        let title_len = unsafe { GetWindowTextW(window, title.as_mut_ptr(), title.len() as i32) };
        if title_len < 0
            || title_len as usize != search.title_len
            || title[..search.title_len] != search.title[..search.title_len]
        {
            return false;
        }

        let mut class_name = [0_u16; 256];
        let class_name_len =
            unsafe { GetClassNameW(window, class_name.as_mut_ptr(), class_name.len() as i32) };
        class_name_len >= 0
            && class_name_len as usize == search.class_name_len
            && class_name[..search.class_name_len] == search.class_name[..search.class_name_len]
    }

    unsafe extern "system" fn enumerate_real_binary_window(
        window: windows_sys::Win32::Foundation::HWND,
        context: windows_sys::Win32::Foundation::LPARAM,
    ) -> windows_sys::core::BOOL {
        let search = unsafe { &mut *(context as *mut ExactRealBinaryWindowSearch) };
        if !unsafe { real_binary_window_matches(window, search) } {
            return 1;
        }
        if search.candidate_count < search.candidates.len() {
            search.candidates[search.candidate_count] = window;
            search.candidate_count += 1;
        }
        if search.candidate_count > 1 {
            search.ambiguous = true;
            return 0;
        }
        1
    }

    fn find_exact_real_binary_window(
        process_id: u32,
        title: &str,
        class_name: &str,
    ) -> Result<
        (
            windows_sys::Win32::Foundation::HWND,
            ExactRealBinaryWindowSearch,
        ),
        &'static str,
    > {
        use windows_sys::Win32::UI::WindowsAndMessaging::EnumWindows;

        let mut search = ExactRealBinaryWindowSearch::new(process_id, title, class_name)?;
        let enumerated = unsafe {
            EnumWindows(
                Some(enumerate_real_binary_window),
                (&mut search as *mut ExactRealBinaryWindowSearch) as isize,
            )
        };
        if search.ambiguous {
            return Err("R3_REAL_BINARY_WINDOW_AMBIGUOUS");
        }
        if enumerated == 0 {
            return Err("R3_REAL_BINARY_WINDOW_ENUMERATION_FAILED");
        }
        if search.candidate_count != 1 {
            return Err("R3_REAL_BINARY_WINDOW_NOT_FOUND");
        }
        Ok((search.candidates[0], search))
    }

    fn close_exact_real_binary_normally(
        child: &mut ExactRealBinaryChild,
        window_title: &str,
        window_class: &str,
    ) -> Result<std::process::ExitStatus, &'static str> {
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::WaitForSingleObject,
            UI::WindowsAndMessaging::{
                SendMessageTimeoutW, SMTO_ABORTIFHUNG, SMTO_BLOCK, WM_CLOSE,
            },
        };

        let process_handle = child.process_handle();
        if unsafe { WaitForSingleObject(process_handle, 0) } != WAIT_TIMEOUT {
            return Err("R3_REAL_BINARY_EXITED_BEFORE_NORMAL_CLOSE");
        }
        let (window, search) =
            find_exact_real_binary_window(child.id(), window_title, window_class)?;
        if !unsafe { real_binary_window_matches(window, &search) }
            || unsafe { WaitForSingleObject(process_handle, 0) } != WAIT_TIMEOUT
        {
            return Err("R3_REAL_BINARY_WINDOW_REVALIDATION_FAILED");
        }

        let mut message_result = 0_usize;
        let sent = unsafe {
            SendMessageTimeoutW(
                window,
                WM_CLOSE,
                0,
                0,
                SMTO_ABORTIFHUNG | SMTO_BLOCK,
                REAL_WINDOW_MESSAGE_TIMEOUT_MS,
                &mut message_result,
            )
        };
        if sent == 0 {
            return Err("R3_REAL_BINARY_WM_CLOSE_FAILED");
        }
        match unsafe { WaitForSingleObject(process_handle, REAL_PROCESS_EXIT_TIMEOUT_MS) } {
            WAIT_OBJECT_0 => child
                .wait()
                .map_err(|_| "R3_REAL_BINARY_EXIT_STATUS_FAILED"),
            WAIT_TIMEOUT => Err("R3_REAL_BINARY_NORMAL_CLOSE_TIMEOUT"),
            _ => Err("R3_REAL_BINARY_PROCESS_WAIT_FAILED"),
        }
    }

    #[cfg(windows)]
    fn run_real_v031_binary(environment: &RealBinaryEnvironment, fixture: &RealV031Fixture) {
        let mcp_config_path = environment.app_root.join("mcp/server-config.json");
        let mcp_config_metadata = fs::symlink_metadata(&mcp_config_path)
            .expect("production recovery stage installs the safe MCP default");
        assert!(mcp_config_metadata.is_file());
        assert!(!mcp_config_metadata.file_type().is_symlink());
        assert!(privacy_manager::local_path_chain_is_ordinary(
            &mcp_config_path
        ));
        assert!((1..=128 * 1024).contains(&mcp_config_metadata.len()));
        for directory in [
            environment.app_root.join("mcp/materials"),
            environment.app_root.join("mcp/exports"),
        ] {
            let metadata = fs::symlink_metadata(&directory)
                .expect("production recovery stage installs a safe MCP directory");
            assert!(metadata.is_dir());
            assert!(!metadata.file_type().is_symlink());
            assert!(privacy_manager::local_path_chain_is_ordinary(&directory));
        }
        let mcp_config_bytes =
            fs::read(&mcp_config_path).expect("safe MCP default reads before launch");
        let mcp_config_sha256 = sha256_hex(&mcp_config_bytes);
        let mcp_config: crate::mcp_manager::McpServerConfig =
            serde_json::from_slice(&mcp_config_bytes).expect("safe MCP default parses strictly");
        let expected_mcp_config =
            crate::mcp_manager::McpServerConfig::defaults_for_test(&environment.app_root);
        assert_eq!(mcp_config, expected_mcp_config);
        assert_eq!(
            mcp_config_bytes,
            serde_json::to_vec_pretty(&expected_mcp_config)
                .expect("safe MCP default serializes canonically")
        );
        assert_eq!(
            sha256_hex(&fs::read(&environment.executable).expect("real v0.3.1 executable reads")),
            environment.executable_sha256,
            "real v0.3.1 executable authenticates before launch"
        );

        let mut command = std::process::Command::new(&environment.executable);
        command
            .current_dir(
                environment
                    .executable
                    .parent()
                    .expect("real v0.3.1 executable has a parent"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = ExactRealBinaryChild::new(
            command
                .spawn()
                .expect("Rust launches and retains the exact real v0.3.1 process handle"),
        );
        let stdout = child
            .child
            .stdout
            .take()
            .expect("real v0.3.1 stdout pipe is retained");
        let stderr = child
            .child
            .stderr
            .take()
            .expect("real v0.3.1 stderr pipe is retained");
        let stdout_digest = drain_real_binary_output(stdout);
        let stderr_digest = drain_real_binary_output(stderr);

        let output = std::process::Command::new(&environment.node_executable)
            .arg(&environment.cdp_helper)
            .arg("--exe")
            .arg(&environment.executable)
            .arg("--exe-sha256")
            .arg(&environment.executable_sha256)
            .arg("--app-root")
            .arg(&environment.app_root)
            .arg("--app-identifier")
            .arg(&environment.app_identifier)
            .arg("--pid")
            .arg(child.id().to_string())
            .arg("--port")
            .arg(&environment.cdp_port)
            .arg("--project-id")
            .arg(&fixture.project_id)
            .arg("--project-title-sha256")
            .arg(&fixture.project_title_sha256)
            .arg("--conversation-id")
            .arg(&fixture.conversation_id)
            .arg("--conversation-title-sha256")
            .arg(&fixture.conversation_title_sha256)
            .arg("--message-id")
            .arg(&fixture.message_id)
            .arg("--message-text-sha256")
            .arg(&fixture.message_text_sha256)
            .arg("--redaction-id")
            .arg(&fixture.redaction_id)
            .arg("--material-id")
            .arg(&fixture.material_id)
            .arg("--source-sha256")
            .arg(&fixture.source_sha256)
            .arg("--extraction-sha256")
            .arg(&fixture.extraction_sha256)
            .arg("--suggested-redacted-sha256")
            .arg(&fixture.suggested_redacted_sha256)
            .arg("--privacy-original-text-sha256")
            .arg(&fixture.privacy_original_text_sha256)
            .arg("--privacy-redacted-text-sha256")
            .arg(&fixture.privacy_redacted_text_sha256)
            .output()
            .expect("audited Node/CDP helper attaches to the real v0.3.1 binary");
        let stdout = String::from_utf8(output.stdout).expect("CDP helper stdout is UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("CDP helper stderr is UTF-8");
        assert!(
            output.status.success(),
            "real v0.3.1 CDP acceptance failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(stdout.contains("R3_V031_REAL_BINARY_CDP=PASS\n"));
        assert!(!stdout.contains("R3_V031_REAL_BINARY_CDP=FAIL"));
        assert!(!stderr.contains("R3_V031_REAL_BINARY_CDP=FAIL"));

        let exit = close_exact_real_binary_normally(
            &mut child,
            REAL_WINDOW_TITLE,
            &environment.window_class,
        )
        .expect("the exact old window accepts one bounded normal WM_CLOSE");
        assert_eq!(exit.code(), Some(0), "real v0.3.1 exits normally");
        let stdout_digest = stdout_digest
            .join()
            .expect("real v0.3.1 stdout digest thread does not panic")
            .expect("real v0.3.1 stdout hashes without disclosure");
        let stderr_digest = stderr_digest
            .join()
            .expect("real v0.3.1 stderr digest thread does not panic")
            .expect("real v0.3.1 stderr hashes without disclosure");
        assert_eq!(
            sha256_hex(&fs::read(&environment.executable).expect("real v0.3.1 re-reads")),
            environment.executable_sha256,
            "real v0.3.1 executable remains unchanged after acceptance"
        );
        assert_eq!(
            sha256_hex(
                &fs::read(&mcp_config_path).expect("safe MCP default re-reads after old launch")
            ),
            mcp_config_sha256,
            "real v0.3.1 preserves the production stage safe MCP default"
        );
        println!("R3_V031_REAL_BINARY_NORMAL_CLOSE=PASS");
        println!("R3_V031_REAL_BINARY_STDOUT_BYTES={}", stdout_digest.bytes);
        println!("R3_V031_REAL_BINARY_STDOUT_SHA256={}", stdout_digest.sha256);
        println!("R3_V031_REAL_BINARY_STDERR_BYTES={}", stderr_digest.bytes);
        println!("R3_V031_REAL_BINARY_STDERR_SHA256={}", stderr_digest.sha256);
    }

    #[cfg(windows)]
    fn run_real_v040_current_binary(
        environment: &RealBinaryEnvironment,
        fixture: &RealV031Fixture,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        expected: &CompletedUpgrade,
    ) {
        assert_eq!(
            sha256_hex(
                &fs::read(&environment.current_executable)
                    .expect("current executable authenticates before launch")
            ),
            environment.current_executable_sha256
        );
        let run_id = uuid::Uuid::parse_str(&environment.current_run_id)
            .expect("current harness run UUID parses");
        assert_eq!(run_id.hyphenated().to_string(), environment.current_run_id);

        let mut command = std::process::Command::new(&environment.current_executable);
        command
            .current_dir(
                environment
                    .current_executable
                    .parent()
                    .expect("current executable has a parent"),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.env(CURRENT_CREDENTIAL_PREFIX_ENV, credentials.service_prefix());
        let mut child = ExactRealBinaryChild::new(
            command
                .spawn()
                .expect("Rust launches and retains the real current desktop process handle"),
        );
        let stdout_digest = drain_real_binary_output(
            child
                .child
                .stdout
                .take()
                .expect("current stdout pipe retained"),
        );
        let stderr_digest = drain_real_binary_output(
            child
                .child
                .stderr
                .take()
                .expect("current stderr pipe retained"),
        );
        let output = std::process::Command::new(&environment.node_executable)
            .arg(&environment.current_cdp_helper)
            .arg("--exe")
            .arg(&environment.current_executable)
            .arg("--exe-sha256")
            .arg(&environment.current_executable_sha256)
            .arg("--app-root")
            .arg(&environment.app_root)
            .arg("--app-version")
            .arg(&environment.current_app_version)
            .arg("--app-identifier")
            .arg(&environment.app_identifier)
            .arg("--pid")
            .arg(child.id().to_string())
            .arg("--port")
            .arg(&environment.current_cdp_port)
            .arg("--project-id")
            .arg(&fixture.project_id)
            .arg("--project-title-sha256")
            .arg(&fixture.project_title_sha256)
            .arg("--conversation-id")
            .arg(&fixture.conversation_id)
            .arg("--conversation-title-sha256")
            .arg(&fixture.conversation_title_sha256)
            .arg("--message-id")
            .arg(&fixture.message_id)
            .arg("--message-text-sha256")
            .arg(&fixture.message_text_sha256)
            .arg("--material-id")
            .arg(&fixture.material_id)
            .output()
            .expect("audited Node/CDP helper attaches to current desktop binary");
        let stdout = String::from_utf8(output.stdout).expect("current CDP stdout is UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("current CDP stderr is UTF-8");
        assert!(
            output.status.success(),
            "current desktop CDP acceptance failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(stdout.contains("R3_V040_REAL_CURRENT_BINARY_CDP=PASS\n"));
        assert!(!stderr.contains("R3_V040_REAL_CURRENT_BINARY_CDP=FAIL"));

        let exit = close_exact_real_binary_normally(
            &mut child,
            CURRENT_WINDOW_TITLE,
            &environment.current_window_class,
        )
        .expect("current window accepts bounded normal WM_CLOSE");
        assert_eq!(exit.code(), Some(0), "current desktop exits normally");
        let stdout_digest = stdout_digest
            .join()
            .expect("current stdout thread joins")
            .expect("current stdout hashes");
        let stderr_digest = stderr_digest
            .join()
            .expect("current stderr thread joins")
            .expect("current stderr hashes");
        assert_eq!(
            sha256_hex(&fs::read(&environment.current_executable).expect("current exe re-reads")),
            environment.current_executable_sha256
        );
        assert_completed_reupgrade_is_idempotent(
            &environment.app_root,
            credentials,
            fixture,
            expected,
        );
        println!("R3_V040_REAL_CURRENT_BINARY_NORMAL_CLOSE=PASS");
        println!("R3_V040_REAL_CURRENT_BINARY_IDEMPOTENT_REOPEN=PASS");
        println!(
            "R3_V040_REAL_CURRENT_BINARY_STDOUT_BYTES={}",
            stdout_digest.bytes
        );
        println!(
            "R3_V040_REAL_CURRENT_BINARY_STDOUT_SHA256={}",
            stdout_digest.sha256
        );
        println!(
            "R3_V040_REAL_CURRENT_BINARY_STDERR_BYTES={}",
            stderr_digest.bytes
        );
        println!(
            "R3_V040_REAL_CURRENT_BINARY_STDERR_SHA256={}",
            stderr_digest.sha256
        );
    }

    #[cfg(windows)]
    fn assert_completed_reupgrade_is_idempotent(
        root: &Path,
        credentials: &crate::approved_mcp::V031CrossProcessCredentialHarness,
        fixture: &RealV031Fixture,
        expected: &CompletedUpgrade,
    ) {
        let process_start = crate::commands::v031_upgrade_complete::
            observe_v031_upgrade_at_process_start_read_only(root)
            .expect("second terminal history authenticates read-only");
        assert_eq!(process_start.terminal_lineage_count(), 2);
        assert!(process_start.has_terminal_lineage_only());
        let exact =
            crate::v031_startup::observe_exact_current_profile_with_approved_workspace_for_test(
                root,
                &credentials.workspace,
            )
            .expect("second upgrade has an exact current five-slot profile");
        let crate::v031_startup::ExactCurrentProfileObservation::Exact(exact) = exact else {
            panic!("second upgrade must finish exact current")
        };
        assert_eq!(
            exact.workspace_instance_id().as_str(),
            expected.workspace_instance_id
        );
        let manager = migration_manager(root, credentials, &expected.workspace_instance_id);
        let before = regular_file_hashes(root);
        let first = crate::v031_startup::load_completed_v031_with_existing_managers_for_test(
            root,
            &process_start,
            &exact,
            &manager,
            &credentials.workspace,
        )
        .expect("second complete lineage reloads through the production terminal gate");
        let second = crate::v031_startup::load_completed_v031_with_existing_managers_for_test(
            root,
            &process_start,
            &exact,
            &manager,
            &credentials.workspace,
        )
        .expect("repeated terminal load is an ordinary idempotent no-op");
        assert_eq!(first.lineage_id(), expected.lineage_id);
        assert_eq!(second.lineage_id(), expected.lineage_id);
        assert_eq!(regular_file_hashes(root), before);

        let user = Connection::open(database::user_database_path(root))
            .expect("re-upgraded User database opens");
        let user_identity = user
            .query_row(
                "SELECT p.project_id,c.conversation_id,m.message_id
                 FROM projects p
                 JOIN conversations c ON c.project_id=p.project_id
                 JOIN messages m ON m.conversation_id=c.conversation_id",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("re-upgraded User synthetic identity reads");
        assert_eq!(user_identity.0, fixture.project_id);
        assert_eq!(user_identity.1, fixture.conversation_id);
        assert_eq!(user_identity.2, fixture.message_id);
        drop(user);

        let privacy = Connection::open(root.join("privacy/privacy-workflow.sqlite"))
            .expect("re-upgraded Privacy database opens");
        let privacy_identity = privacy
            .query_row(
                "SELECT b.privacy_case_id,m.material_id,r.redaction_id,
                        m.source_sha256,r.extraction_sha256,r.redacted_content_sha256,
                        m.project_id,m.legacy_case_id,m.migration_status,m.state,
                        r.generation_status
                 FROM project_privacy_case_bindings b
                 CROSS JOIN privacy_materials m
                 JOIN privacy_redactions r ON r.material_id=m.material_id
                 WHERE b.project_id=?1 AND m.material_id=?2",
                params![&fixture.project_id, &fixture.material_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, String>(10)?,
                    ))
                },
            )
            .expect("re-upgraded one-to-one binding and Privacy review read");
        assert!(privacy_identity.0.starts_with("case_"));
        assert_eq!(privacy_identity.0.len(), 37);
        assert!(privacy_identity.0[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(privacy_identity.1, fixture.material_id);
        assert_eq!(privacy_identity.2, fixture.redaction_id);
        assert_eq!(privacy_identity.3, fixture.source_sha256);
        assert_eq!(privacy_identity.4, fixture.extraction_sha256);
        assert_eq!(privacy_identity.5, fixture.suggested_redacted_sha256);
        assert_eq!(privacy_identity.6, None);
        assert_eq!(privacy_identity.7, None);
        assert_eq!(privacy_identity.8, "unassigned");
        assert_eq!(privacy_identity.9, "review_required");
        assert_eq!(privacy_identity.10, "ready");
        let counts = privacy
            .query_row(
                "SELECT
                    (SELECT COUNT(*) FROM project_privacy_case_bindings),
                    (SELECT COUNT(*) FROM privacy_materials),
                    (SELECT COUNT(*) FROM privacy_redactions)",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .expect("re-upgraded identity cardinalities read");
        assert_eq!(counts, (1, 1, 1));
        drop(privacy);

        let review = manager
            .load_review(&fixture.redaction_id)
            .expect("re-upgraded exact v0.3.1 Privacy review remains readable");
        assert_eq!(review.case_id, None);
        assert_eq!(review.material_id, fixture.material_id);
        assert_eq!(review.source_sha256, fixture.source_sha256);
        assert_eq!(review.extraction_sha256, fixture.extraction_sha256);
        assert_eq!(
            review.suggested_redacted_content_sha256,
            fixture.suggested_redacted_sha256
        );
        assert_eq!(review.review_state, "review_required");
        assert_eq!(review.pages.len(), 1);
        assert_eq!(
            sha256_hex(review.pages[0].original_text.as_bytes()),
            fixture.privacy_original_text_sha256
        );
        assert_eq!(
            sha256_hex(review.pages[0].redacted_text.as_bytes()),
            fixture.privacy_redacted_text_sha256
        );
    }

    #[cfg(windows)]
    fn regular_file_hashes(root: &Path) -> std::collections::BTreeMap<String, String> {
        fn visit(
            root: &Path,
            directory: &Path,
            result: &mut std::collections::BTreeMap<String, String>,
        ) {
            let mut entries = fs::read_dir(directory)
                .expect("R3 tree directory reads")
                .collect::<Result<Vec<_>, _>>()
                .expect("R3 tree entries read");
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("R3 tree metadata reads");
                assert!(!metadata.file_type().is_symlink());
                if metadata.is_dir() {
                    visit(root, &path, result);
                } else {
                    assert!(metadata.is_file());
                    let relative = path
                        .strip_prefix(root)
                        .expect("R3 tree entry stays below root")
                        .to_string_lossy()
                        .replace('\\', "/");
                    assert!(result
                        .insert(
                            relative,
                            sha256_hex(&fs::read(&path).expect("R3 tree file reads"))
                        )
                        .is_none());
                }
            }
        }

        let mut result = std::collections::BTreeMap::new();
        visit(root, root, &mut result);
        result
    }
}

#[cfg(test)]
mod recovery_semantic_tests {
    use super::*;

    fn fingerprint(
        component: V031RecoveryComponent,
        proof_seed: u64,
    ) -> V031RecoverySlotFingerprint {
        let component_name = match component {
            V031RecoveryComponent::UserDatabase => "user_database",
            V031RecoveryComponent::PrivacyDatabase => "privacy_database",
            V031RecoveryComponent::VaultStore => "vault_store",
            V031RecoveryComponent::ApprovedWorkspace => "approved_workspace",
            V031RecoveryComponent::WorkProducts => "work_products",
        };
        serde_json::from_value(serde_json::json!({
            "component": component_name,
            "directory": matches!(
                component,
                V031RecoveryComponent::VaultStore
                    | V031RecoveryComponent::ApprovedWorkspace
                    | V031RecoveryComponent::WorkProducts
            ),
            "proofSha256": format!("{proof_seed:064x}"),
            "totalBytes": proof_seed.saturating_add(1),
            "entryCount": 1,
        }))
        .expect("test fingerprint must deserialize")
    }

    fn fingerprints(seed: u64) -> [V031RecoverySlotFingerprint; 5] {
        std::array::from_fn(|index| fingerprint(RECOVERY_COMPONENTS[index], seed + index as u64))
    }

    fn empty_audit_slots() -> [RecoveryAuditSlotV1; 5] {
        std::array::from_fn(|index| RecoveryAuditSlotV1 {
            component: RECOVERY_COMPONENTS[index],
            active: None,
            incoming: None,
            rollback: None,
            cleanup: None,
        })
    }

    fn five_slot_commit_inventory(
        current: &[V031RecoverySlotFingerprint; 5],
        target: &[V031RecoverySlotFingerprint; 5],
    ) -> [RecoveryAuditSlotV1; 5] {
        let mut slots = empty_audit_slots();
        for index in 0..2 {
            slots[index].active = Some(target[index].clone());
            slots[index].rollback = Some(current[index].clone());
        }
        for index in 2..5 {
            slots[index].rollback = Some(current[index].clone());
        }
        slots
    }

    fn applied_inventory(commit: &[RecoveryAuditSlotV1; 5]) -> [RecoveryAuditSlotV1; 5] {
        let mut slots = empty_audit_slots();
        for index in 0..2 {
            slots[index].active = commit[index].active.clone();
        }
        slots
    }

    fn restored_layout(current: &[V031RecoverySlotFingerprint; 5]) -> ObservedRecoveryLayout {
        ObservedRecoveryLayout {
            slots: std::array::from_fn(|index| ObservedRecoverySlot {
                active: Some(current[index].clone()),
                incoming: None,
                rollback: None,
                cleanup: None,
            }),
            credential_delete_prefix: 0,
        }
    }

    fn assert_database_active_delete_prefix_is_accepted(component: V031RecoveryComponent) {
        let current_slots = fingerprints(1);
        let targets = fingerprints(101);
        let index = component_index(component);
        let mut audit_layout = restored_layout(&current_slots);
        audit_layout.slots[index].active = Some(targets[index].clone());
        audit_layout.slots[index].rollback = Some(current_slots[index].clone());

        let mut after_active_delete = audit_layout.clone();
        after_active_delete.slots[index].active = None;

        assert!(abort_layout_is_legal_reverse_prefix_after_validation(
            &after_active_delete,
            audit_layout,
            &current_slots,
        )
        .expect("validated abort layout must enumerate legal mutations"));
    }

    #[test]
    fn user_active_delete_before_rollback_install_is_a_legal_abort_prefix() {
        assert_database_active_delete_prefix_is_accepted(V031RecoveryComponent::UserDatabase);
    }

    #[test]
    fn privacy_active_delete_before_rollback_install_is_a_legal_abort_prefix() {
        assert_database_active_delete_prefix_is_accepted(V031RecoveryComponent::PrivacyDatabase);
    }

    #[test]
    fn five_slot_commit_requires_exact_current_rollbacks_and_absent_directory_actives() {
        let current = fingerprints(1);
        let target = fingerprints(101);
        let exact = five_slot_commit_inventory(&current, &target);
        assert!(audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::FiveSlotCommit,
            &exact,
        ));

        let mut directory_active = exact.clone();
        directory_active[component_index(V031RecoveryComponent::VaultStore)].active =
            Some(target[component_index(V031RecoveryComponent::VaultStore)].clone());
        assert!(!audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::FiveSlotCommit,
            &directory_active,
        ));

        let mut substituted_rollback = exact;
        substituted_rollback[component_index(V031RecoveryComponent::UserDatabase)].rollback =
            Some(target[component_index(V031RecoveryComponent::UserDatabase)].clone());
        assert!(!audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::FiveSlotCommit,
            &substituted_rollback,
        ));
    }

    #[test]
    fn five_slot_commit_rejects_a_substituted_noncurrent_database_target() {
        let current = fingerprints(1);
        let target = fingerprints(101);
        let mut substituted = five_slot_commit_inventory(&current, &target);
        assert!(database_target_fingerprints_match(
            &substituted,
            &target[component_index(V031RecoveryComponent::UserDatabase)],
            &target[component_index(V031RecoveryComponent::PrivacyDatabase)],
        ));

        substituted[component_index(V031RecoveryComponent::UserDatabase)].active =
            Some(fingerprint(V031RecoveryComponent::UserDatabase, 999));
        assert!(audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::FiveSlotCommit,
            &substituted,
        ));
        assert!(!database_target_fingerprints_match(
            &substituted,
            &target[component_index(V031RecoveryComponent::UserDatabase)],
            &target[component_index(V031RecoveryComponent::PrivacyDatabase)],
        ));
    }

    #[test]
    fn applied_inventory_cannot_impersonate_commit_targets_by_shape() {
        let current = fingerprints(1);
        let target = fingerprints(101);
        let commit = five_slot_commit_inventory(&current, &target);
        let applied = applied_inventory(&commit);
        assert!(audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::AppliedDowngrade,
            &applied,
        ));
        assert!(applied_target_fingerprints_match_commit(&commit, &applied,));

        let mut impersonator = applied;
        impersonator[component_index(V031RecoveryComponent::PrivacyDatabase)].active =
            Some(fingerprint(V031RecoveryComponent::PrivacyDatabase, 999));
        assert!(audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::AppliedDowngrade,
            &impersonator,
        ));
        assert!(!applied_target_fingerprints_match_commit(
            &commit,
            &impersonator,
        ));
    }

    #[test]
    fn aborted_report_requires_all_current_actives_and_no_residue() {
        let current = fingerprints(1);
        let target = fingerprints(101);
        let exact = std::array::from_fn(|index| RecoveryAuditSlotV1 {
            component: RECOVERY_COMPONENTS[index],
            active: Some(current[index].clone()),
            incoming: None,
            rollback: None,
            cleanup: None,
        });
        assert!(audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::AbortedCurrentRestored,
            &exact,
        ));

        let mut residue = exact.clone();
        residue[component_index(V031RecoveryComponent::PrivacyDatabase)].incoming =
            Some(target[component_index(V031RecoveryComponent::PrivacyDatabase)].clone());
        assert!(!audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::AbortedCurrentRestored,
            &residue,
        ));

        let mut substituted_active = exact;
        substituted_active[component_index(V031RecoveryComponent::WorkProducts)].active =
            Some(target[component_index(V031RecoveryComponent::WorkProducts)].clone());
        assert!(!audit_inventory_shape_matches_kind(
            &current,
            AuditEvidenceKind::AbortedCurrentRestored,
            &substituted_active,
        ));
    }
}

#[cfg(all(test, windows))]
#[path = "v031_migration_recovery_matrix_tests.rs"]
mod recovery_matrix_tests;

#[cfg(all(test, windows))]
#[path = "v031_migration_recovery_stage_tests.rs"]
mod stage_sequence_tests;
